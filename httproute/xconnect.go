package httproute

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
)

// wsGUID is the key suffix of RFC 6455 4.2.2.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var errBadAccept = errors.New("httproute: backend answered the WebSocket handshake with a wrong Sec-WebSocket-Accept")

// hopFields are removed from requests and responses that are passed on.
var hopFields = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Http2-Settings"}

// proxyExtendedConnect serves a WebSocket over an HTTP/2 stream (RFC 8441)
// from a backend that speaks WebSocket over HTTP/1.1: it sends the backend
// an upgrade request, answers the client with 200 once the backend
// switched protocols, and copies the stream both ways.
func proxyExtendedConnect(w http.ResponseWriter, req *http.Request, rs *reqState) {
	proto := req.Header.Get(":protocol")
	if !upgradeAllowed(rs.route, proto) {
		writeError(w, req, rs, http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(proto, "websocket") {
		writeError(w, req, rs, http.StatusNotImplemented)
		return
	}
	out := req.Clone(req.Context())
	out.Method, out.Body, out.ContentLength, out.Proto, out.ProtoMajor, out.ProtoMinor = http.MethodGet, http.NoBody, 0, "HTTP/1.1", 1, 1
	for _, f := range append(hopFields, ":protocol", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto") {
		out.Header.Del(f)
	}
	rewrite(&httputil.ProxyRequest{In: req, Out: out})
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", "websocket")
	out.Header.Set("Sec-WebSocket-Key", key)
	res, err := rs.transport.RoundTrip(out)
	if err != nil {
		proxyError(w, out, err)
		return
	}
	backend, ok := res.Body.(io.ReadWriteCloser)
	if res.StatusCode == http.StatusSwitchingProtocols && (!ok || res.Header.Get("Sec-WebSocket-Accept") != acceptKey(key)) {
		_ = res.Body.Close()
		proxyError(w, out, errBadAccept)
		return
	}
	res.Request = out
	if err := modifyResponse(res); err != nil {
		_ = res.Body.Close()
		proxyError(w, out, err)
		return
	}
	h := w.Header()
	for k, v := range res.Header {
		h[k] = v
	}
	for _, f := range append(hopFields, "Sec-Websocket-Accept") {
		h.Del(f)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		// A refusal goes to the client as it is.
		defer res.Body.Close()
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, res.Body)
		return
	}
	if b, ok := res.Body.(io.ReadWriteCloser); ok {
		backend = b // with the idle timeout of modifyResponse
	}
	defer backend.Close()
	defer context.AfterFunc(req.Context(), func() { _ = backend.Close() })()
	rs.status = http.StatusOK
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		return
	}
	// The client's half: its end closes the backend, which ends the copy
	// below. Reads of the request body end when the handler returns.
	go func() {
		_, _ = io.Copy(backend, req.Body)
		_ = backend.Close()
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := backend.Read(buf)
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

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// upgradeAllowed reports whether the route allows the protocol token, as
// an Upgrade field or the :protocol of an extended CONNECT names it, without
// a version.
func upgradeAllowed(rt *route, token string) bool {
	name, _, _ := strings.Cut(strings.TrimSpace(token), "/")
	return name != "" && slices.ContainsFunc(rt.upgrades, func(a string) bool { return strings.EqualFold(a, name) })
}
