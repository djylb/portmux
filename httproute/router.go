package httproute

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
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
	"github.com/djylb/netx/httphead"
	"github.com/djylb/portmux"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/internal/pmap"
	"github.com/djylb/timeshim"
)

// StatusClientClosedRequest is the status that events report for requests
// whose client went away before a response, which get none.
const StatusClientClosedRequest = 499

// Options are the settings of a Router's server, fixed when it is created.
type Options struct {
	// ReadHeaderTimeout bounds reading a request's head, and the TLS handshake
	// of connections handed over as *tls.Conn; 0 means 10 seconds, and a
	// negative value means no timeout, as for http.Server.IdleTimeout. This
	// differs from http.Server.ReadHeaderTimeout, where 0 means no timeout.
	ReadHeaderTimeout time.Duration
	// IdleTimeout closes keep-alive connections idle for longer; 0 means 60
	// seconds, and a negative value means no timeout, as for
	// http.Server.IdleTimeout. This differs from http.Server.IdleTimeout, where
	// 0 means no timeout.
	IdleTimeout time.Duration
	// MaxHeaderBytes limits request heads; 0 or a negative value means 64
	// KiB, as for http.Server.MaxHeaderBytes, whose default it replaces.
	MaxHeaderBytes int
	// ErrorLog receives the server's and the proxy's errors; nil discards
	// them.
	ErrorLog *log.Logger
	// Clock is the source of time of the router: of event durations, the
	// idle timeouts of upgraded connections; nil means
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
	// Status is the response status, zero for an unobserved response on a hijacked connection, 101 for upgrades,
	// StatusClientClosedRequest when the client went away first.
	Status int
	// Written counts the bytes of the response body.
	Written  int64
	Duration time.Duration
	// Err reports a failed proxy round trip, an aborted request, or a recovered panic.
	Err error
}

// Router routes requests by a Table. Create it with New.
type Router struct {
	observerPanic atomic.Pointer[portmux.PanicError]
	opts          Options
	clock         timeshim.Clock
	state         atomic.Pointer[state]

	mu      sync.Mutex         // serialises Update; guards retired and closed
	retired map[*pool]struct{} // replaced pools with connections in use

	srv   *http.Server
	proxy *httputil.ReverseProxy
	ctx   context.Context //nolint:containedctx // The Router owns this lifetime context and cancels it to stop requests and dials.
	stop  context.CancelFunc

	ln          *netx.ChanListener // for ServeConn
	lnDone      chan struct{}
	active      atomic.Int64
	drained     chan struct{}
	drainedOnce sync.Once
	lnOnce      sync.Once
	closing     atomic.Bool
	closed      bool // under mu
}

// state is what a request is matched against: a table and its upstreams
// with their transports, by name.
type state struct {
	table     *Table
	upstreams pmap.Map[*binding]
}

// binding is an upstream of a table and the transports a Router holds for
// it. Upstreams of equal transport keys share them across updates.
type binding struct {
	up   *upstream
	pool *pool
}

// emptyTable is the Table of a Router without one.
var emptyTable = &Table{common: &common{}}

type ctxKey int

const (
	stateKey  ctxKey = iota // *reqState
	tlsKey                  // *connTLS of a TLS connection found under a connection
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
	up        *upstream // the route's upstream, or nil
	key       string    // of the Proxy's Pick
	keyed     *keyPool  // the transports of key, nil without one
	host      hostmatch.Name
	path      string
	protocol  string // the protocol token of an extended CONNECT
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

// RequestID returns the request_id of r (see Vars): the X-Request-Id of a
// trusted proxy, else 16 random hexadecimal digits made on first use; the
// same value templates and error pages of r show. It is "" outside a
// Router's handler. Call it from the goroutine serving r, such as in a
// handler that Route.Wrap installs.
func RequestID(r *http.Request) string {
	if rs := stateOf(r.Context()); rs != nil {
		return rs.requestID()
	}
	return ""
}

// New returns a Router without routes, which answers every request with
// 404 Not Found until Update gives it a Table.
func New(o Options) *Router {
	o.ReadHeaderTimeout = cmp.Or(o.ReadHeaderTimeout, 10*time.Second)
	o.IdleTimeout = cmp.Or(o.IdleTimeout, 60*time.Second)
	if o.MaxHeaderBytes <= 0 {
		o.MaxHeaderBytes = 64 << 10
	}
	if o.ErrorLog == nil {
		o.ErrorLog = log.New(io.Discard, "", 0)
	}
	r := &Router{
		opts:    o,
		clock:   timeshim.Or(o.Clock),
		retired: map[*pool]struct{}{},
		ln:      netx.NewChanListener(nil, 64),
		lnDone:  make(chan struct{}),
		drained: make(chan struct{}),
	}
	ctx, stop := context.WithCancel(context.Background())
	r.ctx, r.stop = context.WithValue(ctx, serverKey, r), stop
	r.state.Store(&state{table: emptyTable})
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
	if tc, ok := netx.ConnAs[*tls.Conn](c); ok {
		return context.WithValue(ctx, tlsKey, &connTLS{conn: tc})
	}
	return ctx
}

// connTLS is a TLS connection under the connection that a server serves.
// Its requests share its state once the handshake is complete, as those
// of a *tls.Conn that the server reads itself do.
type connTLS struct {
	conn *tls.Conn
	done atomic.Pointer[tls.ConnectionState]
}

func (c *connTLS) state() *tls.ConnectionState {
	if cs := c.done.Load(); cs != nil {
		return cs
	}
	cs := c.conn.ConnectionState()
	if cs.HandshakeComplete {
		c.done.Store(&cs)
	}
	return &cs
}

// Update replaces the routes with those of t; requests already routed keep
// the table they were matched with. A nil t removes every route. Upstreams
// of t whose settings other than Dial equal those of an upstream of the
// same name in the current table keep its idle connections for plain HTTP.
// A TLS pool is kept only for an unchanged compiled upstream; idle
// connections of the others are closed. Update returns net.ErrClosed after
// Shutdown or Close.
func (r *Router) Update(t *Table) error {
	if t == nil || t.common == nil {
		t = emptyTable
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	old := r.state.Load()
	// Only the upstreams that differ: none that t shares with the current
	// table, as one made of it by With does.
	bs := old.upstreams.Builder()
	var drop []*pool
	pmap.Diff(old.table.upstreams, t.upstreams, func(name string, _ upstreamEntry, _ bool, e upstreamEntry, has bool) {
		b, _ := bs.Get(name)
		u := e.up
		if has && b != nil && b.up == u {
			return
		}
		if has && b != nil && b.up.key() == u.key() {
			bs.Set(name, &binding{up: u, pool: b.pool})
			return
		}
		if b != nil {
			drop = append(drop, b.pool)
		}
		if has {
			bs.Set(name, &binding{up: u, pool: newPool(u)})
		} else {
			bs.Delete(name)
		}
	})
	r.state.Store(&state{table: t, upstreams: bs.Map()})
	for _, p := range drop {
		p.retired.Store(r)
		r.retired[p] = struct{}{}
	}
	r.mu.Unlock()
	// Connections of replaced pools that were in use become idle later:
	// close them as they do, until none is left.
	for _, p := range drop {
		p.CloseIdleConnections()
		r.dropEmptyPool(p)
	}
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
	if ctx.Err() != nil {
		_ = r.srv.Close()
	}
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
	if r.active.Load() == 0 {
		r.drainedOnce.Do(func() { close(r.drained) })
	}
	r.mu.Unlock()
}

func (r *Router) finish(ctx context.Context, err error) error {
	_ = r.ln.Close()
	r.stop()
	select {
	case <-r.drained:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
		r.closeIdle()
		return err
	}

	r.closeIdle()
	r.lnOnce.Do(func() { close(r.lnDone) })
	<-r.lnDone
	return err
}

// dropEmptyPool forgets a retired pool once its final connection closes.
func (r *Router) dropEmptyPool(p *pool) {
	r.mu.Lock()
	if p.open.Load() == 0 {
		delete(r.retired, p)
	}
	r.mu.Unlock()
}

func (r *Router) closeIdle() {
	r.mu.Lock()
	var pools []*pool
	for _, b := range r.state.Load().upstreams.All() {
		pools = append(pools, b.pool)
	}
	for p := range r.retired {
		pools = append(pools, p)
	}
	r.mu.Unlock()
	for _, p := range pools {
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
		r.drainedOnce.Do(func() { close(r.drained) })
	}
}

// ServeHTTP routes a request.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	entered := r.enter()
	if entered {
		defer r.leave()
	}
	rs := &reqState{router: r, tls: req.TLS != nil}
	rec := &recorder{ResponseWriter: w}
	var start time.Time
	defer func() {
		v := recover()
		cause, _ := v.(error)
		abort := errors.Is(cause, http.ErrAbortHandler)
		if v != nil {
			if abort {
				rs.err = http.ErrAbortHandler
				if rec.status == 0 && !rec.hijacked {
					rs.status = StatusClientClosedRequest
				}
			} else {
				rs.err = portmux.NewPanicError(v)
				r.opts.ErrorLog.Print(rs.err)
				if rec.status == 0 && !rec.hijacked {
					writePlainError(rec, req, http.StatusInternalServerError)
				} else {
					abort = true
				}
			}
		}
		if r.opts.Observer != nil {
			r.observe(req, rs, rec, start)
		}
		if abort {
			panic(http.ErrAbortHandler)
		}
	}()
	if r.opts.Observer != nil {
		start = r.clock.Now()
	}
	if !entered {
		writePlainError(rec, req, http.StatusServiceUnavailable)
		return
	}
	r.route(rec, req, r.state.Load(), rs)
}

// LastObserverPanic reports the most recent observer panic, or nil. The returned error is read-only.
func (r *Router) LastObserverPanic() *portmux.PanicError { return r.observerPanic.Load() }

func (r *Router) observe(req *http.Request, rs *reqState, rec *recorder, start time.Time) {
	defer func() {
		if v := recover(); v != nil {
			err := portmux.NewPanicError(v)
			r.observerPanic.Store(err)
			r.opts.ErrorLog.Print(err)
		}
	}()
	status := cmp.Or(rec.status, rs.status)
	if status == 0 && !rec.hijacked {
		status = http.StatusOK
	}
	ev := Event{Method: req.Method, Host: rs.host.String(), Path: rs.path, Client: rs.client, Status: status, Written: rec.written, Duration: r.clock.Now().Sub(start), Err: rs.err}
	if rs.route != nil {
		ev.Route = rs.route.name
	}
	r.opts.Observer(ev)
}

func (r *Router) route(rec *recorder, req *http.Request, st *state, rs *reqState) {
	w := rec.writer()
	t := st.table
	rs.table = t
	if req.Method == http.MethodConnect {
		rs.protocol = extendedConnectProtocol(req)
		if rs.protocol == "" {
			writeError(w, req, rs, http.StatusMethodNotAllowed)
			return
		}
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
		if ct, ok := ctx.Value(tlsKey).(*connTLS); ok {
			req.TLS, rs.tls = ct.state(), true
		}
	}
	peer, _ := forwarded.ParseNode(req.RemoteAddr)
	if t.common.resolver != nil {
		rs.client = t.common.resolver.Resolve(peer, req.Header)
	} else {
		rs.client = forwarded.Client{Addr: peer}
	}
	if t.common.resolver != nil && t.common.resolver.Trusted.Contains(peer.Addr()) {
		rs.inboundID = validRequestID(req.Header.Get("X-Request-ID"))
	}
	rt := t.match(rs.host, rs.path, req, rs)
	if rt == nil && t.common.abort {
		panic(http.ErrAbortHandler)
	}
	if rt == nil {
		writeError(w, req, rs, http.StatusNotFound)
		return
	}
	rs.route = rt
	if rt.upstream != "" {
		b, _ := st.upstreams.Get(rt.upstream)
		rs.up, rs.transport = b.up, b.pool
		defer func() {
			if b.pool.retired.Load() != nil {
				b.pool.CloseIdleConnections()
			}
		}()
	}
	// The stream of an extended CONNECT is a tunnel, not a body to limit.
	if rt.maxBody > 0 && req.Body != nil && req.Body != http.NoBody && req.Method != http.MethodConnect {
		if req.ContentLength > rt.maxBody {
			writeError(w, req, rs, http.StatusRequestEntityTooLarge)
			return
		}
		req.Body = http.MaxBytesReader(rec.ResponseWriter, req.Body, rt.maxBody)
	}
	if rt.https != nil && !rs.secure() {
		redirectHTTPS(w, req, rs)
		return
	}
	ctx = context.WithValue(ctx, stateKey, rs)
	if ctx.Value(serverKey) != r {
		// A server of the caller's: end the request when the Router
		// closes, as the Router's own server does.
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		defer context.AfterFunc(r.ctx, cancel)() //nolint:contextcheck // The Router lifetime also cancels requests served by a caller-owned server.
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

// recorder tracks the final response and bytes accepted before a hijack.
type recorder struct {
	http.ResponseWriter
	status   int
	written  int64
	hijacked bool
}

func (w *recorder) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
	if !w.hijacked && w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
	}
}

func (w *recorder) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if w.status == 0 && !w.hijacked {
		w.status = http.StatusOK
	}
	w.written += int64(n)
	return n, err
}

func (w *recorder) Unwrap() http.ResponseWriter {
	if _, ok := w.ResponseWriter.(unwrapper); ok {
		return struct {
			rawResponseWriter
			hijackRecorder
		}{rawResponseWriter{w.ResponseWriter}, hijackRecorder{w}}
	}
	return w.ResponseWriter
}

type rawResponseWriter struct{ http.ResponseWriter }

func (w rawResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type unwrapper interface{ Unwrap() http.ResponseWriter }

type flushRecorder struct{ r *recorder }

func (f flushRecorder) Flush() { _ = f.r.FlushError() }

func (w *recorder) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if w.status == 0 && !w.hijacked && !errors.Is(err, http.ErrNotSupported) {
		w.status = http.StatusOK
	}
	return err
}

type hijackRecorder struct{ r *recorder }

func (h hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(h.r.ResponseWriter).Hijack()
	if err == nil {
		h.r.hijacked = true
	}
	return conn, rw, err
}

// closeNotifier is the legacy notification method exposed by some HTTP servers.
type closeNotifier interface{ CloseNotify() <-chan bool }

type readFromRecorder struct{ *recorder }

func (w readFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	n, err := w.ResponseWriter.(io.ReaderFrom).ReadFrom(src)
	if n > 0 && w.status == 0 && !w.hijacked {
		w.status = http.StatusOK
	}
	w.written += n
	return n, err
}

type notifyRecorder struct {
	*recorder
	closeNotifier
}

type readNotifyRecorder struct {
	readFromRecorder
	closeNotifier
}

type flushHijack struct {
	flushRecorder
	hijackRecorder
}

// writer preserves the optional method set of the underlying writer. Go
// interface assertions inspect the concrete method set, so each combination
// must have its own concrete wrapper.
func (w *recorder) writer() http.ResponseWriter {
	const (
		flush = 1 << iota
		hijack
		push
		notify
		readFrom
	)
	var methods int
	if _, ok := w.ResponseWriter.(http.Flusher); ok {
		methods |= flush
	}
	if _, ok := w.ResponseWriter.(http.Hijacker); ok {
		methods |= hijack
	}
	p, ok := w.ResponseWriter.(http.Pusher)
	if ok {
		methods |= push
	}
	c, ok := w.ResponseWriter.(closeNotifier)
	if ok {
		methods |= notify
	}
	if _, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		methods |= readFrom
	}
	switch methods {
	case flush:
		return struct {
			*recorder
			flushRecorder
		}{w, flushRecorder{w}}
	case hijack:
		return struct {
			*recorder
			hijackRecorder
		}{w, hijackRecorder{w}}
	case flush | hijack:
		return struct {
			*recorder
			flushHijack
		}{w, flushHijack{flushRecorder{w}, hijackRecorder{w}}}
	case push:
		return struct {
			*recorder
			http.Pusher
		}{w, p}
	case flush | push:
		return struct {
			*recorder
			flushRecorder
			http.Pusher
		}{w, flushRecorder{w}, p}
	case hijack | push:
		return struct {
			*recorder
			hijackRecorder
			http.Pusher
		}{w, hijackRecorder{w}, p}
	case flush | hijack | push:
		return struct {
			*recorder
			flushHijack
			http.Pusher
		}{w, flushHijack{flushRecorder{w}, hijackRecorder{w}}, p}
	case notify:
		return notifyRecorder{w, c}
	case flush | notify:
		return struct {
			notifyRecorder
			flushRecorder
		}{notifyRecorder{w, c}, flushRecorder{w}}
	case hijack | notify:
		return struct {
			notifyRecorder
			hijackRecorder
		}{notifyRecorder{w, c}, hijackRecorder{w}}
	case flush | hijack | notify:
		return struct {
			notifyRecorder
			flushHijack
		}{notifyRecorder{w, c}, flushHijack{flushRecorder{w}, hijackRecorder{w}}}
	case push | notify:
		return struct {
			notifyRecorder
			http.Pusher
		}{notifyRecorder{w, c}, p}
	case flush | push | notify:
		return struct {
			notifyRecorder
			flushRecorder
			http.Pusher
		}{notifyRecorder{w, c}, flushRecorder{w}, p}
	case hijack | push | notify:
		return struct {
			notifyRecorder
			hijackRecorder
			http.Pusher
		}{notifyRecorder{w, c}, hijackRecorder{w}, p}
	case flush | hijack | push | notify:
		return struct {
			notifyRecorder
			flushHijack
			http.Pusher
		}{notifyRecorder{w, c}, flushHijack{flushRecorder{w}, hijackRecorder{w}}, p}
	case readFrom:
		return readFromRecorder{w}
	case flush | readFrom:
		return struct {
			readFromRecorder
			flushRecorder
		}{readFromRecorder{w}, flushRecorder{w}}
	case hijack | readFrom:
		return struct {
			readFromRecorder
			hijackRecorder
		}{readFromRecorder{w}, hijackRecorder{w}}
	case flush | hijack | readFrom:
		return struct {
			readFromRecorder
			flushHijack
		}{readFromRecorder{w}, flushHijack{flushRecorder{w}, hijackRecorder{w}}}
	case push | readFrom:
		return struct {
			readFromRecorder
			http.Pusher
		}{readFromRecorder{w}, p}
	case flush | push | readFrom:
		return struct {
			readFromRecorder
			flushRecorder
			http.Pusher
		}{readFromRecorder{w}, flushRecorder{w}, p}
	case hijack | push | readFrom:
		return struct {
			readFromRecorder
			hijackRecorder
			http.Pusher
		}{readFromRecorder{w}, hijackRecorder{w}, p}
	case flush | hijack | push | readFrom:
		return struct {
			readFromRecorder
			flushHijack
			http.Pusher
		}{readFromRecorder{w}, flushHijack{flushRecorder{w}, hijackRecorder{w}}, p}
	case notify | readFrom:
		return readNotifyRecorder{readFromRecorder{w}, c}
	case flush | notify | readFrom:
		return struct {
			readNotifyRecorder
			flushRecorder
		}{readNotifyRecorder{readFromRecorder{w}, c}, flushRecorder{w}}
	case hijack | notify | readFrom:
		return struct {
			readNotifyRecorder
			hijackRecorder
		}{readNotifyRecorder{readFromRecorder{w}, c}, hijackRecorder{w}}
	case flush | hijack | notify | readFrom:
		return struct {
			readNotifyRecorder
			flushHijack
		}{readNotifyRecorder{readFromRecorder{w}, c}, flushHijack{flushRecorder{w}, hijackRecorder{w}}}
	case push | notify | readFrom:
		return struct {
			readNotifyRecorder
			http.Pusher
		}{readNotifyRecorder{readFromRecorder{w}, c}, p}
	case flush | push | notify | readFrom:
		return struct {
			readNotifyRecorder
			flushRecorder
			http.Pusher
		}{readNotifyRecorder{readFromRecorder{w}, c}, flushRecorder{w}, p}
	case hijack | push | notify | readFrom:
		return struct {
			readNotifyRecorder
			hijackRecorder
			http.Pusher
		}{readNotifyRecorder{readFromRecorder{w}, c}, hijackRecorder{w}, p}
	case flush | hijack | push | notify | readFrom:
		return struct {
			readNotifyRecorder
			flushHijack
			http.Pusher
		}{readNotifyRecorder{readFromRecorder{w}, c}, flushHijack{flushRecorder{w}, hijackRecorder{w}}, p}
	default:
		return w
	}
}
