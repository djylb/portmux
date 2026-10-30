package httproute

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/httprewrite"
	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/hostmatch"
)

// upstreamHost is the host of outbound URLs. Each upstream has a transport
// of its own, so one host keeps one pool per upstream; the Host field is
// the client's or a rule's.
const upstreamHost = "upstream"

var errNoUpstream = errors.New("httproute: request without an upstream")

type proxyHandler struct{}

func (proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rs := stateOf(req.Context())
	if rs == nil || rs.route == nil || rs.route.proxy == nil {
		// A Wrap that replaced the request's context.
		writePlainError(w, req, http.StatusInternalServerError)
		return
	}
	if t := rs.route.proxy.PathTemplate; t != nil {
		p, err := t.Expand(&httprewrite.Context{Request: req, Client: rs.client, Data: rs})
		if err != nil {
			rs.err = err
			writeError(w, req, rs, http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		rs.outPath = p
	}
	filterUpgrade(req, rs.route)
	if req.Method == http.MethodConnect {
		proxyExtendedConnect(w, req, rs)
		return
	}
	rs.router.proxy.ServeHTTP(w, req)
}

// filterUpgrade removes an Upgrade field whose protocols the route does not
// allow, and HTTP2-Settings, so that no upgrade to h2c reaches a backend
// and carries requests past the routes. It changes a copy of the header.
func filterUpgrade(req *http.Request, rt *route) {
	_, settings := req.Header["Http2-Settings"]
	ups := req.Header.Values("Upgrade")
	allowed := true
	for _, v := range ups {
		for tok := range strings.SplitSeq(v, ",") {
			if strings.TrimSpace(tok) != "" && !upgradeAllowed(rt, tok) {
				allowed = false
			}
		}
	}
	if !settings && allowed {
		return
	}
	req.Header = req.Header.Clone()
	req.Header.Del("Http2-Settings")
	if !allowed {
		req.Header.Del("Upgrade")
	}
}

// rewrite is ReverseProxy's Rewrite: it points the outbound request at the
// route's upstream, replaces the path and applies the request rules.
func rewrite(pr *httputil.ProxyRequest) {
	rs := stateOf(pr.In.Context())
	rt := rs.route
	up := rt.table.upstreams[rt.upstream]
	u := pr.Out.URL
	u.Scheme, u.Host, u.User, u.Fragment, u.RawFragment = "http", upstreamHost, nil, "", ""
	if up.Addr != "" {
		// Redirects without From then match the backend's own URLs.
		u.Host = up.Addr
	}
	if up.TLS != nil {
		u.Scheme = "https"
	}
	switch {
	case rs.outPath != "":
		u.Path, u.RawPath = rs.outPath, ""
	case rt.proxy.ReplacePath != "":
		replacePath(u, pr.In, rs)
	case !rt.proxy.SendRawPath && rs.path != "*":
		canonicalPath(u, pr.In, rs)
	}
	// Only a rule sets it: a client's could pass for the proxy's.
	pr.Out.Header.Del("X-Original-Path")
	// The server fills the inbound request's trailer map when the body
	// ends, and the transport sends the outbound one after the body:
	// share the map, as a copy would stay empty.
	pr.Out.Trailer = pr.In.Trailer
	if err := rt.rewriter.Rewrite(pr); err != nil {
		rs.router.opts.ErrorLog.Printf("httproute: route %q: %v", rt.name, err)
	}
	if up.TLS != nil && up.serverName == "" {
		// The server name is the outgoing Host's; the URL's host carries
		// it to the dial and keeps a pool per name.
		host := pr.Out.Host
		if host == "" {
			host = pr.In.Host
		}
		if name := hostmatch.SplitHost(host); name != "" {
			if strings.IndexByte(name, ':') >= 0 {
				name = "[" + name + "]"
			}
			u.Host = name
		}
	}
}

// replacePath replaces the route's path at the start of the request path,
// keeping the escapes of the rest as the client sent them where they can be
// told apart.
func replacePath(u *url.URL, in *http.Request, rs *reqState) {
	rt := rs.route
	rest := rs.path[len(rt.path):]
	u.Path, u.RawPath = joinPath(rt.proxy.ReplacePath, rest), ""
	esc, _ := escapedPath(in)
	if strings.IndexByte(esc, '%') < 0 {
		return
	}
	escRest, ok := escapedSuffix(cleanKeepSlash(esc), len(rt.path))
	if !ok {
		return
	}
	if dec, err := url.PathUnescape(escRest); err != nil || dec != rest {
		return
	}
	u.RawPath = joinPath((&url.URL{Path: rt.proxy.ReplacePath}).EscapedPath(), escRest)
}

// canonicalPath sends the path the route was chosen by, keeping the
// escapes the client sent where they decode to it.
func canonicalPath(u *url.URL, in *http.Request, rs *reqState) {
	u.Path, u.RawPath = rs.path, ""
	esc, _ := escapedPath(in)
	if strings.IndexByte(esc, '%') < 0 {
		return
	}
	if clean := cleanKeepSlash(esc); clean != rs.path {
		if dec, err := url.PathUnescape(clean); err == nil && dec == rs.path {
			u.RawPath = clean
		}
	}
}

// escapedSuffix returns what follows the first n decoded bytes of the
// escaped path esc.
func escapedSuffix(esc string, n int) (string, bool) {
	i := 0
	for d := 0; d < n; d++ {
		if i >= len(esc) {
			return "", false
		}
		if esc[i] == '%' {
			i += 3
		} else {
			i++
		}
	}
	if i > len(esc) {
		return "", false
	}
	return esc[i:], true
}

// joinPath appends rest, the part of a path after a prefix, to the
// replacement of the prefix.
func joinPath(prefix, rest string) string {
	switch {
	case rest == "":
		return prefix
	case strings.HasSuffix(prefix, "/") && rest[0] == '/':
		return prefix + rest[1:]
	case !strings.HasSuffix(prefix, "/") && rest[0] != '/' && rest[0] != ';':
		return prefix + "/" + rest
	}
	return prefix + rest
}

// cleanKeepSlash resolves "." and ".." segments and repeated slashes,
// keeping a trailing slash.
func cleanKeepSlash(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// roundTripper sends a request with the transport of its route's upstream,
// from the table the request was matched with.
type roundTripper struct{}

func (roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rs := stateOf(req.Context())
	if rs == nil || rs.transport == nil {
		return nil, errNoUpstream
	}
	return rs.transport.RoundTrip(req)
}

func modifyResponse(res *http.Response) error {
	rs := stateOf(res.Request.Context())
	rt := rs.route
	if res.StatusCode == http.StatusSwitchingProtocols {
		rs.status = http.StatusSwitchingProtocols
		if rwc, ok := res.Body.(io.ReadWriteCloser); ok && rt.idle > 0 {
			res.Body = newIdleConn(rwc, rt.idle)
		}
	}
	if err := rt.rewriter.ModifyResponse(res); err != nil {
		return err
	}
	if rt.proxy.InterceptErrors && res.StatusCode >= 400 {
		if pg := rs.errorPage(res.StatusCode); pg != nil {
			body := pg.render(rs.context(res.Request, res.StatusCode, res.Header))
			_ = res.Body.Close()
			res.Body = io.NopCloser(bytes.NewReader(body))
			res.ContentLength = int64(len(body))
			res.Header.Set("Content-Type", pg.contentType)
			res.Header.Set("Content-Length", strconv.Itoa(len(body)))
			for _, f := range []string{"Content-Encoding", "Content-Range", "Etag", "Last-Modified", "Trailer"} {
				res.Header.Del(f)
			}
			res.Trailer = nil
		}
	}
	return nil
}

// proxyError answers a failed round trip with the status for err, or with
// nothing when the client went away.
func proxyError(w http.ResponseWriter, req *http.Request, err error) {
	rs := stateOf(req.Context())
	if rs == nil {
		writePlainError(w, req, http.StatusBadGateway)
		return
	}
	rs.err = err
	if req.Context().Err() != nil {
		rs.status = StatusClientClosedRequest
		return
	}
	rs.router.opts.ErrorLog.Printf("httproute: route %q: %v", rs.route.name, err)
	writeError(w, req, rs, statusOf(err))
}

// statusOf maps the error of a round trip to a status.
func statusOf(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		if se.Status >= 400 && se.Status <= 599 {
			return se.Status
		}
		return http.StatusBadGateway
	}
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return http.StatusRequestEntityTooLarge
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// pool holds the transports of an upstream, and counts their connections
// so that a Router knows when a replaced pool has none left.
type pool struct {
	main  *http.Transport
	h1    *http.Transport // for upgrades when main speaks HTTP/2, else nil
	open  atomic.Int64
	drain *time.Timer // of a replaced pool with connections; under Router.mu
}

func (p *pool) RoundTrip(req *http.Request) (*http.Response, error) {
	if p.h1 != nil && req.Header.Get("Upgrade") != "" {
		return p.h1.RoundTrip(req)
	}
	return p.main.RoundTrip(req)
}

func (p *pool) CloseIdleConnections() {
	p.main.CloseIdleConnections()
	if p.h1 != nil {
		p.h1.CloseIdleConnections()
	}
}

// newPool returns the transports of an upstream. They dial through the
// upstream of the route of each request, so that a new Dial needs no new
// transport.
func newPool(u *upstream) *pool {
	transport := func(h2 bool) *http.Transport {
		t := &http.Transport{
			DialContext:            dialPlain,
			DialTLSContext:         dialTLS1,
			ResponseHeaderTimeout:  u.ResponseHeaderTimeout,
			IdleConnTimeout:        u.IdleConnTimeout,
			MaxIdleConns:           u.MaxIdleConns,
			MaxIdleConnsPerHost:    u.MaxIdleConns,
			MaxResponseHeaderBytes: u.MaxResponseHeaderBytes,
			DisableKeepAlives:      u.DisableKeepAlives,
			// A proxy passes Accept-Encoding and bodies on as they are.
			DisableCompression:    true,
			ExpectContinueTimeout: time.Second,
			Protocols:             new(http.Protocols),
		}
		switch {
		case !h2:
			t.Protocols.SetHTTP1(true)
		case u.TLS != nil:
			t.Protocols.SetHTTP1(true)
			t.Protocols.SetHTTP2(true)
			t.ForceAttemptHTTP2 = true
			t.DialTLSContext = dialTLS2
		default:
			t.Protocols.SetUnencryptedHTTP2(true)
		}
		return t
	}
	p := &pool{main: transport(u.HTTP2)}
	if u.HTTP2 {
		p.h1 = transport(false)
	}
	return p
}

// countedConn is a backend connection of a pool.
type countedConn struct {
	net.Conn
	pool *pool
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.pool.open.Add(-1) })
	return c.Conn.Close()
}

// NetConn returns the connection that Dial returned.
func (c *countedConn) NetConn() net.Conn { return c.Conn }

func dialPlain(ctx context.Context, _, addr string) (net.Conn, error) {
	return connect(ctx, addr, nil)
}

var (
	alpnHTTP1 = []string{"http/1.1"}
	alpnHTTP2 = []string{"h2", "http/1.1"}
)

func dialTLS1(ctx context.Context, _, addr string) (net.Conn, error) {
	return connect(ctx, addr, alpnHTTP1)
}

func dialTLS2(ctx context.Context, _, addr string) (net.Conn, error) {
	return connect(ctx, addr, alpnHTTP2)
}

// connect dials the upstream of the route of the request in ctx, within the
// upstream's dial timeout and until the Router closes, sends a PROXY header
// if the upstream wants one and, with alpn, runs TLS over the connection.
// addr is the outbound URL's host and port.
func connect(ctx context.Context, addr string, alpn []string) (net.Conn, error) {
	rs := stateOf(ctx)
	if rs == nil || rs.route == nil || rs.route.upstream < 0 || rs.transport == nil {
		return nil, errNoUpstream
	}
	up := rs.route.table.upstreams[rs.route.upstream]
	ctx, cancel := context.WithTimeout(ctx, up.DialTimeout)
	defer cancel()
	defer context.AfterFunc(rs.router.ctx, cancel)()
	c, err := callDial(ctx, up, rs)
	if err != nil {
		return nil, err
	}
	rs.transport.open.Add(1)
	c = &countedConn{Conn: c, pool: rs.transport}
	if up.ProxyProtocol != 0 {
		if err := sendProxyHeader(ctx, c, proxyproto.Version(up.ProxyProtocol), rs); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	if alpn == nil || up.TLS == nil {
		return c, nil
	}
	cfg := up.TLS.Clone()
	cfg.NextProtos = alpn
	cfg.ServerName = up.serverName
	if cfg.ServerName == "" {
		if h, _, err := net.SplitHostPort(addr); err == nil && h != upstreamHost {
			cfg.ServerName = h
		}
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close() // and c beneath it
		return nil, err
	}
	return tc, nil
}

// sendProxyHeader writes a PROXY header from the request's client to the
// address the request came in on, or one without addresses when they
// cannot be sent.
func sendProxyHeader(ctx context.Context, c net.Conn, v proxyproto.Version, rs *reqState) error {
	h := &proxyproto.Header{Version: v}
	if a := rs.client.Addr; a.IsValid() {
		src := net.TCPAddrFromAddrPort(a)
		var dst net.Addr
		if la, ok := ctx.Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
			dst = la
		}
		if hh, err := proxyproto.NewHeader(v, src, dst); err == nil {
			h = hh
		}
	}
	b, err := h.AppendBinary(nil)
	if err != nil {
		return err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetWriteDeadline(d)
		defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	}
	_, err = c.Write(b)
	return err
}

// idleConn closes an upgraded backend connection through which nothing
// passed for its timeout.
type idleConn struct {
	io.ReadWriteCloser
	d     time.Duration
	timer *time.Timer
}

func newIdleConn(c io.ReadWriteCloser, d time.Duration) *idleConn {
	ic := &idleConn{ReadWriteCloser: c, d: d}
	ic.timer = time.AfterFunc(d, func() { _ = c.Close() })
	return ic
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 {
		c.timer.Reset(c.d)
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Write(p)
	if n > 0 {
		c.timer.Reset(c.d)
	}
	return n, err
}

func (c *idleConn) Close() error {
	c.timer.Stop()
	return c.ReadWriteCloser.Close()
}

// callDial calls the upstream's Dial, turning a panic into an error: dials
// run in goroutines of the transport, where a panic would end the program.
func callDial(ctx context.Context, up *upstream, rs *reqState) (c net.Conn, err error) {
	defer func() {
		if p := recover(); p != nil {
			c, err = nil, fmt.Errorf("httproute: Dial of upstream %q panicked: %v", up.Name, p)
		}
	}()
	c, err = up.Dial(ctx, DialInfo{
		Upstream: up.Name,
		Addr:     up.Addr,
		Route:    rs.route.name,
		Host:     rs.host.String(),
		Client:   rs.client.Addr,
		TLS:      rs.tls,
	})
	if err != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("httproute: Dial of upstream %q returned no connection", up.Name)
	}
	return c, nil
}

type redirectHandler struct{}

func (redirectHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rs := stateOf(req.Context())
	if rs == nil || rs.route == nil || rs.route.redirect == nil {
		writePlainError(w, req, http.StatusInternalServerError)
		return
	}
	rt := rs.route
	to, err := rt.redirect.To.Expand(&httprewrite.Context{Request: req, Client: rs.client, Data: rs})
	if err != nil {
		rs.err = err
		writeError(w, req, rs, http.StatusInternalServerError)
		return
	}
	status := rt.redirect.Status
	if status == 0 {
		status = http.StatusFound
	}
	h := w.Header()
	h.Set("Location", to)
	h.Set("Content-Length", "0")
	respond(w, req, rs, status, nil)
}

type respondHandler struct{}

func (respondHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rs := stateOf(req.Context())
	if rs == nil || rs.route == nil || rs.route.respond == nil {
		writePlainError(w, req, http.StatusInternalServerError)
		return
	}
	r := rs.route.respond
	h := w.Header()
	for k, v := range r.Header {
		h[k] = append(h[k][:0:0], v...)
	}
	status := r.Status
	if status == 0 {
		status = http.StatusOK
	}
	body := r.Body
	if !bodyAllowed(status) {
		body = nil
	} else {
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	respond(w, req, rs, status, body)
}

// respond applies the route's response rules and writes the response.
func respond(w http.ResponseWriter, req *http.Request, rs *reqState, status int, body []byte) {
	if rules := rs.route.response; len(rules) > 0 {
		h := w.Header()
		c := &httprewrite.Context{Request: req, Client: rs.client, Data: rs,
			Response: &http.Response{StatusCode: status, Header: h, Request: req}}
		if err := httprewrite.ApplyHeader(h, rules, c); err != nil {
			rs.router.opts.ErrorLog.Printf("httproute: route %q: %v", rs.route.name, err)
		}
	}
	w.WriteHeader(status)
	if req.Method != http.MethodHead && len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func bodyAllowed(status int) bool {
	return status != http.StatusNoContent && status != http.StatusNotModified
}

// bufferPool lends ReverseProxy its copy buffers.
type bufferPool struct{}

var buffers = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

func (bufferPool) Get() []byte { return *buffers.Get().(*[]byte) }

func (bufferPool) Put(b []byte) {
	if cap(b) == 32<<10 {
		b = b[:cap(b)]
		buffers.Put(&b)
	}
}
