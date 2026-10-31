package httproute

import (
	"cmp"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx"
	"github.com/djylb/netx/forwarded"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/timeshim"
)

// StatusClientClosedRequest is the status that events report for requests
// whose client went away before a response, which get none.
const StatusClientClosedRequest = 499

// Options are the settings of a Router's server, fixed when it is created.
type Options struct {
	// ReadHeaderTimeout bounds reading a request's head, and the TLS
	// handshake of connections handed over as *tls.Conn; 0 means 10
	// seconds.
	ReadHeaderTimeout time.Duration
	// IdleTimeout closes keep-alive connections idle for longer; 0 means
	// 60 seconds.
	IdleTimeout time.Duration
	// MaxHeaderBytes limits request heads; 0 means 64 KiB.
	MaxHeaderBytes int
	// ErrorLog receives the server's and the proxy's errors; nil discards
	// them.
	ErrorLog *log.Logger
	// Clock is the source of time of the router: of event durations, the
	// timeouts of upgraded connections, the expiry of remembered Basic
	// credentials and the closing of replaced connection pools; nil means
	// timeshim.Real. Server timeouts and dial deadlines use the system clock.
	Clock timeshim.Clock
	// Observer, if set, is called once for every request when it is done.
	// It must not block.
	Observer func(Event)
}

// Event describes a request that a Router served.
type Event struct {
	// Route is the name of the route, empty when none matched.
	Route  string
	Method string
	// Host is the host name the client asked for, without its port.
	Host string
	// Path is the decoded, clean path.
	Path string
	// Client is the client, as Config.Resolver finds it.
	Client forwarded.Client
	// Status is the response status: 101 for upgrades,
	// StatusClientClosedRequest when the client went away first.
	Status int
	// Written counts the bytes of the response body.
	Written  int64
	Duration time.Duration
	// Err is the error of a failed proxy round trip.
	Err error
}

// Router routes requests by a Table. Create it with New.
type Router struct {
	opts  Options
	clock timeshim.Clock
	state atomic.Pointer[state]

	mu         sync.Mutex // guards transports, retired and closed
	transports map[transportKey]*pool
	retired    map[*pool]struct{} // replaced pools with connections in use
	closed     bool

	srv   *http.Server
	proxy *httputil.ReverseProxy
	ctx   context.Context // canceled by Shutdown and Close
	stop  context.CancelFunc

	ln       *netx.ChanListener // for ServeConn
	lnOnce   sync.Once
	lnDone   chan struct{}
	active   atomic.Int64
	closing  atomic.Bool
	drained  chan struct{}
	shutOnce sync.Once
}

// state is what a request is matched against: a table and the transports
// of its upstreams, by index.
type state struct {
	table      *Table
	transports []*pool
}

type ctxKey int

const (
	stateKey  ctxKey = iota // *reqState
	tlsKey                  // *tls.Conn found under a connection
	serverKey               // *Router whose server serves the request
)

// reqState is what a Router knows of a request it routed.
type reqState struct {
	router    *Router
	table     *Table
	route     *route
	id        string // request_id, made when first read
	groups    []int  // submatch indexes of a PathRegexp in path
	outPath   string // a Proxy's expanded PathTemplate
	inboundID string // X-Request-Id of a trusted proxy
	transport *pool
	host      hostmatch.Name
	path      string
	client    forwarded.Client
	tls       bool
	status    int // overrides the written status: 101 and 499
	err       error
}

func stateOf(ctx context.Context) *reqState {
	rs, _ := ctx.Value(stateKey).(*reqState)
	return rs
}

func requestData(in *http.Request) any { return stateOf(in.Context()) }

// RouteName returns the name of the route that a Router chose for r, for
// handlers that Route.Wrap installs.
func RouteName(r *http.Request) string {
	if rs := stateOf(r.Context()); rs != nil && rs.route != nil {
		return rs.route.name
	}
	return ""
}

// Client returns the client of r as the Router found it, for handlers that
// Route.Wrap installs.
func Client(r *http.Request) forwarded.Client {
	if rs := stateOf(r.Context()); rs != nil {
		return rs.client
	}
	return forwarded.Client{}
}

// New returns a Router without routes, which answers every request with
// 404 Not Found until Update gives it a Table.
func New(o Options) *Router {
	o.ReadHeaderTimeout = cmp.Or(o.ReadHeaderTimeout, 10*time.Second)
	o.IdleTimeout = cmp.Or(o.IdleTimeout, 60*time.Second)
	o.MaxHeaderBytes = cmp.Or(o.MaxHeaderBytes, 64<<10)
	if o.ErrorLog == nil {
		o.ErrorLog = log.New(io.Discard, "", 0)
	}
	r := &Router{
		opts:       o,
		clock:      timeshim.Or(o.Clock),
		transports: map[transportKey]*pool{},
		retired:    map[*pool]struct{}{},
		ln:         netx.NewChanListener(nil, 64),
		lnDone:     make(chan struct{}),
		drained:    make(chan struct{}, 1),
	}
	ctx, stop := context.WithCancel(context.Background())
	r.ctx, r.stop = context.WithValue(ctx, serverKey, r), stop
	r.state.Store(&state{table: &Table{hosts: &hostmatch.Map[[]*route]{}}})
	r.srv = &http.Server{
		Handler:           r,
		ReadHeaderTimeout: o.ReadHeaderTimeout,
		IdleTimeout:       o.IdleTimeout,
		MaxHeaderBytes:    o.MaxHeaderBytes,
		ErrorLog:          o.ErrorLog,
		BaseContext:       func(net.Listener) context.Context { return r.ctx },
		ConnContext:       connContext,
	}
	r.proxy = &httputil.ReverseProxy{
		Rewrite:        rewrite,
		Transport:      roundTripper{},
		ModifyResponse: modifyResponse,
		ErrorHandler:   proxyError,
		ErrorLog:       o.ErrorLog,
		BufferPool:     bufferPool{},
	}
	return r
}

// connContext keeps the TLS connection under a connection that is not one
// itself, such as one that a port multiplexer wraps, so that requests get
// its state.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*tls.Conn); ok {
		return ctx // the server reads it itself
	}
	for i := 0; i < 16; i++ {
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return ctx
		}
		if c = u.NetConn(); c == nil {
			return ctx
		}
		if tc, ok := c.(*tls.Conn); ok {
			return context.WithValue(ctx, tlsKey, tc)
		}
	}
	return ctx
}

// Update replaces the routes with those of t; requests already routed keep
// the table they were matched with. A nil t removes every route. Upstreams
// of t whose settings other than Dial equal those of an upstream of the
// same name in the current table keep its idle connections; idle
// connections of the others are closed. Update returns net.ErrClosed after
// Shutdown or Close.
func (r *Router) Update(t *Table) error {
	if t == nil {
		t = &Table{hosts: &hostmatch.Map[[]*route]{}}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	st := &state{table: t, transports: make([]*pool, len(t.upstreams))}
	next := make(map[transportKey]*pool, len(t.upstreams))
	for i, u := range t.upstreams {
		k := u.key()
		p := next[k]
		if p == nil {
			if p = r.transports[k]; p == nil {
				p = newPool(u)
			}
			next[k] = p
		}
		st.transports[i] = p
	}
	r.state.Store(st)
	for k, p := range r.transports {
		if next[k] != p {
			r.retired[p] = struct{}{}
		}
	}
	// Connections of replaced pools that were in use become idle later:
	// close them as they do, until none is left.
	for p := range r.retired {
		p.CloseIdleConnections()
		if p.open.Load() == 0 {
			delete(r.retired, p)
		} else if p.drain == nil {
			p.drain = r.clock.AfterFunc(retireTick, func() { r.drainRetired(p) })
		}
	}
	r.transports = next
	return nil
}

// Table returns the current table.
func (r *Router) Table() *Table { return r.state.Load().table }

// Serve serves the connections that l accepts until l fails or the Router
// is closed, after which it returns http.ErrServerClosed. It may run for any
// number of listeners at once, such as portmux routes, also wrapped by
// tls.NewListener.
func (r *Router) Serve(l net.Listener) error {
	return r.srv.Serve(l)
}

// ServeConn serves one connection, such as one that a portmux route hands
// over, plain or as a *tls.Conn whose handshake the server then runs within
// ReadHeaderTimeout; with "h2" in the TLS config's NextProtos, HTTP/2 is
// served too. The connection belongs to the Router from the call on: it is
// closed when it cannot be served, and ServeConn returns net.ErrClosed after
// Shutdown or Close. ServeConn does not wait for the connection to be
// served.
func (r *Router) ServeConn(c net.Conn) error {
	if r.closing.Load() {
		_ = c.Close()
		return net.ErrClosed
	}
	r.lnOnce.Do(func() {
		go func() {
			defer close(r.lnDone)
			_ = r.srv.Serve(r.ln)
		}()
	})
	if err := r.ln.Deliver(r.ctx, c); err != nil {
		_ = c.Close()
		return net.ErrClosed
	}
	return nil
}

// Shutdown stops accepting connections and waits, until ctx is done, for
// the requests on the Router's own connections to finish, as
// http.Server.Shutdown does. It then cancels what is left, upgraded
// connections such as WebSockets and requests that servers of the caller
// passed to ServeHTTP, waits for them to return and closes the idle
// connections to backends. Requests that such servers pass afterwards get
// 503 Service Unavailable.
func (r *Router) Shutdown(ctx context.Context) error {
	r.markClosed()
	err := r.srv.Shutdown(ctx)
	return r.finish(ctx, err)
}

// Close closes the Router's listeners and connections at once, cancels the
// requests in progress and waits for them to return, then closes the
// connections to backends.
func (r *Router) Close() error {
	r.markClosed()
	r.stop()
	err := r.srv.Close()
	return r.finish(context.Background(), err)
}

func (r *Router) markClosed() {
	r.closing.Store(true)
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
}

func (r *Router) finish(ctx context.Context, err error) error {
	_ = r.ln.Close()
	r.stop()
	for r.active.Load() != 0 {
		select {
		case <-r.drained:
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
			r.closeIdle()
			return err
		}
	}
	r.closeIdle()
	r.lnOnce.Do(func() { close(r.lnDone) })
	<-r.lnDone
	return err
}

// retireTick is how often a replaced pool closes the connections that
// went idle since.
const retireTick = 200 * time.Millisecond

// drainRetired closes the idle connections of a replaced pool, and drops
// the pool once it has none.
func (r *Router) drainRetired(p *pool) {
	p.CloseIdleConnections()
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.open.Load() == 0 {
		delete(r.retired, p)
		return
	}
	p.drain.Reset(retireTick)
}

func (r *Router) closeIdle() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.transports {
		p.CloseIdleConnections()
	}
	for p := range r.retired {
		p.CloseIdleConnections()
	}
}

func (r *Router) enter() bool {
	r.active.Add(1)
	if r.closing.Load() {
		r.leave()
		return false
	}
	return true
}

func (r *Router) leave() {
	if r.active.Add(-1) == 0 && r.closing.Load() {
		select {
		case r.drained <- struct{}{}:
		default:
		}
	}
}

// ServeHTTP routes a request.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !r.enter() {
		writePlainError(w, req, http.StatusServiceUnavailable)
		return
	}
	defer r.leave()
	st := r.state.Load()
	rs := &reqState{router: r, tls: req.TLS != nil}
	if r.opts.Observer == nil {
		r.route(w, req, st, rs)
		return
	}
	start := r.clock.Now()
	rec := &recorder{ResponseWriter: w}
	r.route(rec, req, st, rs)
	ev := Event{Method: req.Method, Host: rs.host.String(), Path: rs.path, Client: rs.client,
		Status: cmp.Or(rs.status, rec.status, http.StatusOK), Written: rec.written,
		Duration: r.clock.Now().Sub(start), Err: rs.err}
	if rs.route != nil {
		ev.Route = rs.route.name
	}
	r.opts.Observer(ev)
}

func (r *Router) route(w http.ResponseWriter, req *http.Request, st *state, rs *reqState) {
	t := st.table
	rs.table = t
	if req.Method == http.MethodConnect && req.Header.Get(":protocol") == "" {
		writeError(w, req, rs, http.StatusMethodNotAllowed)
		return
	}
	rs.host = hostmatch.NormalizeHost(req.Host)
	if !rs.host.Valid() {
		writeError(w, req, rs, http.StatusBadRequest)
		return
	}
	escaped, ok := escapedPath(req)
	if !ok {
		writeError(w, req, rs, http.StatusBadRequest)
		return
	}
	if escaped == "*" {
		rs.path = "*"
	} else if p, err := httphead.CleanPath(escaped); err == nil {
		rs.path = p
	} else {
		writeError(w, req, rs, http.StatusBadRequest)
		return
	}
	ctx := req.Context()
	if req.TLS == nil {
		if tc, ok := ctx.Value(tlsKey).(*tls.Conn); ok {
			cs := tc.ConnectionState()
			req.TLS, rs.tls = &cs, true
		}
	}
	peer, _ := forwarded.ParseNode(req.RemoteAddr)
	if t.resolver != nil {
		rs.client = t.resolver.Resolve(peer, req.Header)
	} else {
		rs.client = forwarded.Client{Addr: peer}
	}
	if t.resolver != nil && t.resolver.Trusted.Contains(peer.Addr()) {
		rs.inboundID = validRequestID(req.Header.Get("X-Request-Id"))
	}
	rt := t.match(rs.host, rs.path, req, rs)
	if rt == nil && t.abort {
		panic(http.ErrAbortHandler)
	}
	if rt == nil {
		writeError(w, req, rs, http.StatusNotFound)
		return
	}
	rs.route = rt
	if rt.upstream >= 0 {
		rs.transport = st.transports[rt.upstream]
	}
	if rt.https != nil && !rs.secure() {
		redirectHTTPS(w, req, rs)
		return
	}
	// The stream of an extended CONNECT is a tunnel, not a body to limit.
	if rt.maxBody > 0 && req.Body != nil && req.Body != http.NoBody && req.Method != http.MethodConnect {
		if req.ContentLength > rt.maxBody {
			writeError(w, req, rs, http.StatusRequestEntityTooLarge)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, rt.maxBody)
	}
	ctx = context.WithValue(ctx, stateKey, rs)
	if ctx.Value(serverKey) != r {
		// A server of the caller's: end the request when the Router
		// closes, as the Router's own server does.
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		defer context.AfterFunc(r.ctx, cancel)()
	}
	rt.handler.ServeHTTP(w, req.WithContext(ctx))
}

// secure reports whether the client reached this or a trusted proxy over
// TLS.
func (rs *reqState) secure() bool {
	if rs.tls {
		return true
	}
	return strings.EqualFold(rs.client.Proto, "https")
}

// escapedPath returns the path of the request target as the client sent
// it, "*" for "OPTIONS *", and false for a target with a fragment.
func escapedPath(req *http.Request) (string, bool) {
	target := req.RequestURI
	if strings.IndexByte(target, '#') >= 0 {
		return "", false
	}
	switch {
	case target == "*":
		return "*", true
	case strings.HasPrefix(target, "/"):
		if i := strings.IndexByte(target, '?'); i >= 0 {
			target = target[:i]
		}
		return target, true
	}
	return req.URL.EscapedPath(), true
}

func redirectHTTPS(w http.ResponseWriter, req *http.Request, rs *reqState) {
	h := rs.host.String()
	if strings.IndexByte(h, ':') >= 0 {
		h = "[" + h + "]"
	}
	if p := rs.route.https.Port; p != 0 && p != 443 {
		h += ":" + strconv.Itoa(p)
	}
	target := req.RequestURI
	if !strings.HasPrefix(target, "/") {
		target = req.URL.RequestURI()
	}
	w.Header().Set("Location", "https://"+h+target)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(cmp.Or(rs.route.https.Status, http.StatusPermanentRedirect))
}

// recorder records the status and size of a response for events. Unwrap
// lets http.ResponseController reach the writer's Flush and Hijack.
type recorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (w *recorder) WriteHeader(code int) {
	if w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }
