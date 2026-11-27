package httproute

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"

	"github.com/djylb/netx"
	"github.com/djylb/netx/httphead"
	"github.com/djylb/netx/wsconn"
)

var errBadAccept = errors.New("httproute: backend answered the WebSocket handshake with a wrong Sec-WebSocket-Accept")

// hopFields are removed from requests and responses that are passed on.
var hopFields = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Http2-Settings"}

// extendedConnectProtocol reads the protocol as each HTTP server exposes
// it. HTTP/3 uses Proto for the token and for the version on ordinary
// CONNECT, where its slash makes it invalid as a token.
func extendedConnectProtocol(req *http.Request) string {
	var protocol string
	switch req.ProtoMajor {
	case 2:
		protocol = req.Header.Get(":protocol")
	case 3:
		protocol = req.Proto
	}
	if isToken(protocol) {
		return protocol
	}
	return ""
}

// proxyExtendedConnect translates WebSocket over HTTP/2 or HTTP/3
// (RFC 8441 and RFC 9220) to an HTTP/1.1 upgrade at the backend.
func proxyExtendedConnect(w http.ResponseWriter, req *http.Request, rs *reqState) {
	if !strings.EqualFold(rs.protocol, "websocket") {
		writeError(w, req, rs, http.StatusNotImplemented)
		return
	}
	if !upgradeAllowed(rs.route, rs.protocol) {
		writeError(w, req, rs, http.StatusBadRequest)
		return
	}
	out := req.Clone(req.Context())
	out.Method, out.Body, out.ContentLength, out.Proto, out.ProtoMajor, out.ProtoMinor = http.MethodGet, http.NoBody, 0, "HTTP/1.1", 1, 1
	stripHop(out.Header)
	for _, f := range []string{":protocol", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		out.Header.Del(f)
	}
	pr := &httputil.ProxyRequest{In: req, Out: out}
	rewrite(pr) //nolint:contextcheck // the ReverseProxy hook: the context is the request's
	out = pr.Out
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", "websocket")
	out.Header.Set("Sec-WebSocket-Key", key)
	res, err := rs.roundTrip(out)
	if err != nil {
		proxyError(w, out, err)
		return
	}
	backend, ok := res.Body.(io.ReadWriteCloser)
	if res.StatusCode/100 == 2 || res.StatusCode == http.StatusSwitchingProtocols && (!ok || !headerToken(res.Header, "Connection", "upgrade") || !strings.EqualFold(res.Header.Get("Upgrade"), "websocket") || res.Header.Get("Sec-WebSocket-Accept") != wsconn.AcceptKey(key)) {
		_ = res.Body.Close()
		proxyError(w, out, errBadAccept)
		return
	}
	res.Request = out
	if err := modifyResponse(res); err != nil { //nolint:contextcheck // the ReverseProxy hook: the context is the response's request's
		_ = res.Body.Close()
		proxyError(w, out, err)
		return
	}
	h := w.Header()
	maps.Copy(h, res.Header)
	stripHop(h)
	h.Del("Sec-WebSocket-Accept")
	if res.StatusCode != http.StatusSwitchingProtocols {
		// A refusal goes to the client as it is.
		defer func() { _ = res.Body.Close() }()
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, res.Body)
		return
	}
	stream := backend
	if b, ok := res.Body.(io.ReadWriteCloser); ok {
		stream = b // with the idle timeout of modifyResponse
	}
	// Close the wrapper after the copies, so no in-flight I/O can reset its timer.
	defer func() { _ = stream.Close() }()
	defer context.AfterFunc(req.Context(), func() { _ = backend.Close() })()
	rs.status = http.StatusOK
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		return
	}
	body := req.Body
	if body == nil {
		body = http.NoBody
	}
	done := make(chan struct{})
	defer func() {
		_ = backend.Close()
		_ = body.Close()
		<-done
	}()
	go func() {
		defer close(done)
		// EOF ends only the sending side. An error or cancellation
		// also ends the backend read, unblocking the response copy.
		_, err := io.Copy(stream, body)
		if err != nil || req.Context().Err() != nil || closeWrite(stream) != nil {
			_ = backend.Close()
		}
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil || rc.Flush() != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func closeWrite(w io.Writer) error {
	return (&netx.RelayEnd{Writer: w}).CloseWrite()
}

// upgradeAllowed reports whether the route allows the protocol token, as
// an Upgrade field or the :protocol of an extended CONNECT names it, without
// a version.
func upgradeAllowed(rt *route, token string) bool {
	name, _, _ := strings.Cut(httphead.TrimOWS(token), "/")
	return name != "" && slices.ContainsFunc(rt.upgrades, func(a string) bool { return strings.EqualFold(a, name) })
}

func headerToken(h http.Header, field, token string) bool {
	for _, v := range h.Values(field) {
		for t := range httphead.Tokens(v) {
			if strings.EqualFold(t, token) {
				return true
			}
		}
	}
	return false
}

func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for t := range httphead.Tokens(v) {
			h.Del(t)
		}
	}
	for _, f := range hopFields {
		h.Del(f)
	}
}
