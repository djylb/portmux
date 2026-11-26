package httproute

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/djylb/netx/httphead"
	"github.com/djylb/netx/httprewrite"
	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/timeshim"
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
	if pick := rs.route.proxy.Pick; pick != nil {
		key, err := pick(req)
		if err != nil {
			rs.err = err
			writeError(w, req, rs, statusOf(err))
			return
		}
		rs.key = key
		if key != "" {
			rs.keyed = rs.transport.acquire(key)
			defer rs.transport.releaseRequest(rs.keyed)
		}
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
		for tok := range wire.Tokens(v) {
			if !upgradeAllowed(rt, tok) {
				allowed = false
			}
		}
	}
	if !settings && allowed {
		return
	}
	req.Header = req.Header.Clone()
	req.Header.Del("HTTP2-Settings")
	if !allowed {
		req.Header.Del("Upgrade")
	}
}

// rewrite is ReverseProxy's Rewrite: it points the outbound request at the
// route's upstream, replaces the path and applies the request rules.
func rewrite(pr *httputil.ProxyRequest) {
	rs := stateOf(pr.In.Context())
	rt := rs.route
	up := rs.up
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
	escRest, ok := escapedSuffix(httphead.CleanDecodedPath(esc), len(rt.path))
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
	if clean := httphead.CleanDecodedPath(esc); clean != rs.path {
		if dec, err := url.PathUnescape(clean); err == nil && dec == rs.path {
			u.RawPath = clean
		}
	}
}

// escapedSuffix returns what follows the first n decoded bytes of the
// escaped path esc.
func escapedSuffix(esc string, n int) (string, bool) {
	i := 0
	for range n {
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

// roundTripper sends a request with the transport of its route's upstream,
// from the table the request was matched with.
type roundTripper struct{}

func (roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rs := stateOf(req.Context())
	if rs == nil || rs.transport == nil {
		return nil, errNoUpstream
	}
	return rs.roundTrip(req)
}

// roundTrip sends req with the transports of the request's Pick key, or
// with the upstream's own without one.
func (rs *reqState) roundTrip(req *http.Request) (*http.Response, error) {
	if rs.keyed != nil {
		return rs.keyed.RoundTrip(req)
	}
	return rs.transport.RoundTrip(req)
}

func modifyResponse(res *http.Response) error {
	rs := stateOf(res.Request.Context())
	rt := rs.route
	if res.StatusCode == http.StatusSwitchingProtocols {
		rs.status = http.StatusSwitchingProtocols
		if rwc, ok := res.Body.(io.ReadWriteCloser); ok && rt.idle > 0 {
			res.Body = newIdleConn(rwc, rt.idle, rs.router.clock)
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
	if se, ok := errors.AsType[*StatusError](err); ok {
		if se.Status >= 400 && se.Status <= 599 {
			return se.Status
		}
		return http.StatusBadGateway
	}
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return http.StatusRequestEntityTooLarge
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// transports are the HTTP transports that share one pool of connections.
type transports struct {
	main *http.Transport
	h1   *http.Transport // for upgrades when main speaks HTTP/2, else nil
}

func (t *transports) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.h1 != nil && req.Header.Get("Upgrade") != "" {
		return t.h1.RoundTrip(req)
	}
	return t.main.RoundTrip(req)
}

func (t *transports) CloseIdleConnections() {
	t.main.CloseIdleConnections()
	if t.h1 != nil {
		t.h1.CloseIdleConnections()
	}
}

// pool holds the transports of an upstream and those of each Pick key, and
// counts their connections so that a Router knows when a replaced pool has
// none left.
type pool struct {
	retired atomic.Pointer[Router]
	transports
	open atomic.Int64

	up      *upstream // what the transports of keys are built from
	keys    map[string]*keyPool
	lru     keyPool // sentinel of the list of keys, most recently used first
	maxKeys int
	mu      sync.Mutex // guards keys, lru and the refs and links of its keyPools
}

// keyPool holds the transports of one Pick key. It stays in its pool while
// requests use it or it has connections, idle ones included, and leaves when
// the last of them ends, so that a key without connections costs nothing.
type keyPool struct {
	transports
	prev, next *keyPool // in pool.lru, nil when not in it; under pool.mu
	key        string
	refs       int // requests in progress and open connections; under pool.mu
}

// unlink takes k out of the list it is in, if any.
func (k *keyPool) unlink() {
	if k.prev != nil {
		k.prev.next, k.next.prev = k.next, k.prev
		k.prev, k.next = nil, nil
	}
}

// pushFront puts k first in the list of its pool.
func (p *pool) pushFront(k *keyPool) {
	k.unlink()
	if p.lru.next == nil {
		p.lru.next, p.lru.prev = &p.lru, &p.lru
	}
	k.prev, k.next = &p.lru, p.lru.next
	k.next.prev, p.lru.next = k, k
}

// acquire returns the transports of key, made when the key has none, for
// a request that calls release when it ends. Above maxKeys keys it closes
// the idle connections of the least recently used key and removes it from
// the index immediately. Requests using its transports keep them until release.
// Choosing the key takes constant time, however many keys there are.
func (p *pool) acquire(key string) *keyPool {
	p.mu.Lock()
	k := p.keys[key]
	if k == nil {
		k = &keyPool{transports: newTransports(p.up), key: key}
		p.keys[key] = k
	}
	k.refs++
	p.pushFront(k)
	var evict *keyPool
	if p.maxKeys > 0 && len(p.keys) > p.maxKeys && p.lru.prev != k {
		// Out of the list, so that the next eviction takes the next key
		// while this one waits for its requests to end.
		evict = p.lru.prev
		evict.unlink()
		delete(p.keys, evict.key)
	}
	p.mu.Unlock()
	if evict != nil {
		// Outside the lock: closing the connections releases them.
		evict.CloseIdleConnections()
	}
	return k
}

// release gives back a reference of acquire or of a connection of k.
func (p *pool) release(k *keyPool) (evicted bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k.refs--
	if p.keys[k.key] != k {
		return true
	}
	if k.refs == 0 {
		delete(p.keys, k.key)
		k.unlink()
	}
	return false
}

// releaseRequest closes idle connections again if eviction raced the request.
func (p *pool) releaseRequest(k *keyPool) {
	if p.release(k) {
		k.CloseIdleConnections()
	}
}

// hold adds a reference for a new connection of k.
func (p *pool) hold(k *keyPool) {
	p.mu.Lock()
	k.refs++
	p.mu.Unlock()
}

// CloseIdleConnections closes the idle connections of the upstream and of
// every key, whose keys then leave the pool unless requests use them.
func (p *pool) CloseIdleConnections() {
	p.transports.CloseIdleConnections()
	p.mu.Lock()
	keys := make([]*keyPool, 0, len(p.keys))
	for _, k := range p.keys {
		keys = append(keys, k)
	}
	p.mu.Unlock()
	for _, k := range keys {
		k.CloseIdleConnections()
	}
}

// perHost is the MaxIdleConnsPerHost of an upstream's transports, whose
// one host is the upstream: all of MaxIdleConns, or no limit when it is
// negative.
func perHost(maxIdle int) int {
	if maxIdle < 0 {
		return math.MaxInt
	}
	return maxIdle
}

// newPool returns the pool of an upstream.
func newPool(u *upstream) *pool {
	return &pool{transports: newTransports(u), up: u, maxKeys: u.MaxKeys, keys: map[string]*keyPool{}}
}

// newTransports returns the transports of an upstream. They dial through
// the upstream of the route of each request, so that a new Dial needs no
// new transport.
func newTransports(u *upstream) transports {
	transport := func(h2 bool) *http.Transport {
		t := &http.Transport{
			DialContext:            dialPlain,
			DialTLSContext:         dialTLS1,
			ResponseHeaderTimeout:  max(u.ResponseHeaderTimeout, 0),
			IdleConnTimeout:        max(u.IdleConnTimeout, 0), // 0 is none to http.Transport
			MaxIdleConns:           max(u.MaxIdleConns, 0),
			MaxIdleConnsPerHost:    perHost(u.MaxIdleConns),
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
	t := transports{main: transport(u.HTTP2)}
	if u.HTTP2 {
		t.h1 = transport(false)
	}
	return t
}

// countedConn is a backend connection of a pool, and of a key if keyed is
// set.
type countedConn struct {
	net.Conn
	pool  *pool
	keyed *keyPool
	once  sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() {
		if c.pool.open.Add(-1) == 0 {
			if owner := c.pool.retired.Load(); owner != nil {
				owner.dropEmptyPool(c.pool)
			}
		}
		if c.keyed != nil {
			c.pool.release(c.keyed)
		}
	})
	return c.Conn.Close()
}

// NetConn returns the connection that Dial returned.
func (c *countedConn) NetConn() net.Conn { return c.Conn }

// CloseWrite shuts down writing while the pool still owns the connection.
func (c *countedConn) CloseWrite() error { return closeWrite(c.Conn) }

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
func connect(ctx context.Context, addr string, alpn []string) (result net.Conn, dialErr error) {
	var c net.Conn
	defer func() {
		if v := recover(); v != nil {
			dialErr = portmux.NewPanicError(v)
			if c != nil {
				_ = c.Close()
			}
			result = nil
		}
	}()
	rs := stateOf(ctx)
	if rs == nil || rs.up == nil || rs.transport == nil {
		return nil, errNoUpstream
	}
	up := rs.up
	var cancel context.CancelFunc
	if up.DialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, up.DialTimeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	defer context.AfterFunc(rs.router.ctx, cancel)() //nolint:contextcheck // ends the dial with the Router, by design
	var err error
	c, err = callDial(ctx, up, rs)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		_ = c.Close()
		return nil, err
	}
	rs.transport.open.Add(1)
	if rs.keyed != nil {
		rs.transport.hold(rs.keyed)
	}
	c = &countedConn{Conn: c, pool: rs.transport, keyed: rs.keyed}
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
		if err = c.SetWriteDeadline(d); err != nil {
			return err
		}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = c.Close() })
	n, err := c.Write(b)
	if !stop() {
		<-done
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if _, ok := ctx.Deadline(); ok {
		return c.SetWriteDeadline(time.Time{})
	}
	return nil
}

// idleConn closes an upgraded backend connection through which nothing
// passed for its timeout.
type idleConn struct {
	io.ReadWriteCloser
	d      time.Duration
	mu     sync.Mutex
	closed bool
	timer  timeshim.Timer
}

func newIdleConn(c io.ReadWriteCloser, d time.Duration, clk timeshim.Clock) *idleConn {
	ic := &idleConn{ReadWriteCloser: c, d: d}
	timer := clk.AfterFunc(d, func() { _ = ic.Close() })
	ic.mu.Lock()
	ic.timer = timer
	closed := ic.closed
	ic.mu.Unlock()
	if closed {
		timer.Stop()
	}
	return ic
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleConn) touch() {
	c.mu.Lock()
	closed, timer := c.closed, c.timer
	c.mu.Unlock()
	if closed {
		return
	}
	timer.Reset(c.d)
	// A Close concurrent with Reset may have stopped the old timer.
	c.mu.Lock()
	closed = c.closed
	c.mu.Unlock()
	if closed {
		timer.Stop()
	}
}

func (c *idleConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	timer := c.timer
	c.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	return c.ReadWriteCloser.Close()
}

// CloseWrite shuts down writing and leaves the idle timer running for reads.
func (c *idleConn) CloseWrite() error { return closeWrite(c.ReadWriteCloser) }

var (
	errDialPanic  = errors.New("httproute: Dial panicked")
	errDialNoConn = errors.New("httproute: Dial returned no connection")
)

// callDial calls the upstream's Dial, turning a panic into an error: dials
// run in goroutines of the transport, where a panic would end the program.
func callDial(ctx context.Context, up *upstream, rs *reqState) (c net.Conn, err error) {
	defer func() {
		if p := recover(); p != nil {
			c, err = nil, fmt.Errorf("%w: upstream %q: %w", errDialPanic, up.Name, portmux.NewPanicError(p))
		}
	}()
	c, err = up.Dial(ctx, DialInfo{
		Upstream: up.Name,
		Key:      rs.key,
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
		return nil, fmt.Errorf("%w: upstream %q", errDialNoConn, up.Name)
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
	respond(w, req, rs, status, r.Body)
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
	if bodyAllowed(status) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	} else {
		body = nil
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(status)
	if req.Method != http.MethodHead && len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			rs.err = errors.Join(rs.err, err)
		}
	}
}

func bodyAllowed(status int) bool {
	return status >= 200 && status != http.StatusResetContent && status != http.StatusNoContent && status != http.StatusNotModified
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
