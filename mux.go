package portmux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/proxyproto"
)

// Mux distributes connections to routes by their first bytes. It serves any
// number of listeners, added with Serve and removed by closing them, and
// connections handed over with ServeConn. Routes can be added, changed and
// removed at any time. Its methods are safe for concurrent use.
type Mux struct {
	opts  atomic.Pointer[options]
	table atomic.Pointer[table]

	quit      chan struct{} // closed when no new connections are taken
	quitOnce  sync.Once
	closeOnce sync.Once
	closed    atomic.Bool

	undelivered pendingSet
	seq         atomic.Uint64 // orders routes added with equal priority
	accepts     atomic.Uint64 // numbers the connections from Serve
	slots       *slotLimit
	perClient   pendingLimit
	rate        atomic.Pointer[rateLimit]
	entries     atomic.Pointer[map[string]*entryConfig] // entries with options of their own
	bans        *banList
	total       stripedCounters

	// mu guards listeners, orders changes of the routes and options, which
	// are read without it.
	mu        sync.Mutex
	listeners map[net.Listener]*listener
	serving   sync.WaitGroup // Serve calls, which Shutdown waits for
}

// listener is the state of a listener being served.
type listener struct {
	entry string
	// addr is the listener's address, taken once outside m.mu, since a
	// listener such as a route of the same Mux wrapped for TLS looks it up
	// with m.mu.
	addr   net.Addr
	counts stripedCounters
	// The token bucket of WithRateLimitPerListener, used by Serve alone.
	tokens float64
	last   time.Time
}

// allow takes a token of the listener's bucket and reports whether there was
// one.
func (l *listener) allow(rate float64, burst int, now time.Time) bool {
	b := float64(max(burst, 1))
	if l.last.IsZero() {
		l.tokens = b
	} else {
		l.tokens = min(b, l.tokens+now.Sub(l.last).Seconds()*rate)
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// New returns a Mux without listeners or routes.
func New(opts ...Option) *Mux {
	m := &Mux{
		quit:      make(chan struct{}),
		listeners: make(map[net.Listener]*listener),
		slots:     newSlotLimit(),
		perClient: pendingLimit{count: make(map[netip.Prefix]int)},
		bans:      newBanList(),
	}
	o := newOptions(opts)
	m.opts.Store(&o)
	if o.rate > 0 {
		m.rate.Store(newRateLimit(o.rate, o.rateBurst))
	}
	m.table.Store(newTable(routeSet{}, nil))
	return m
}

// SetOptions changes options while the Mux serves; options that are not
// given keep their values. Limits apply to the connections accepted from then
// on, and connections being matched keep the timeouts and sizes they started
// with. Lowering WithMaxPending closes nothing at once: for each connection it
// accepts over the limit, Serve evicts the oldest undecided one, as at the
// limit, and waits until enough pending connections are gone. A new
// WithRateLimitPerClient starts every client with a full bucket.
func (m *Mux) SetOptions(opts ...Option) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.opts.Load()
	o := *old
	o.apply(opts)
	m.opts.Store(&o)
	if o.rate != old.rate || o.rateBurst != old.rateBurst {
		var l *rateLimit
		if o.rate > 0 {
			l = newRateLimit(o.rate, o.rateBurst)
		}
		m.rate.Store(l)
	}
	m.rebuildEntriesLocked()
	// A higher pending limit lets a waiting Serve go on.
	m.slots.signal()
}

// Config returns the settings of the Mux, as its options set them; see
// Entry.Config for those of an entry with options of its own.
func (m *Mux) Config() Config {
	return m.opts.Load().config()
}

// Listen adds an unnamed route with priority 0 for the matchers and returns
// it, a net.Listener of the connections it matches. Routes with equal
// priority are tried in the order they were added, so for a static setup
// Listen routes can simply be added from specific to general. After Close it
// returns a closed route, whose Accept returns net.ErrClosed, as a listener
// does. Listen panics on a nil matcher and without matchers, as a route
// without them matches nothing: take every connection with AnyBytes or
// Always, and add a route without matchers, such as a target of resolvers,
// with Add.
func (m *Mux) Listen(matchers ...Matcher) *Route {
	if len(matchers) == 0 {
		panic("portmux: Listen without matchers matches nothing; use AnyBytes or Always, or Add for a target of resolvers")
	}
	r, err := m.Add(RouteConfig{Matchers: matchers})
	if err != nil && !errors.Is(err, net.ErrClosed) {
		panic(err)
	}
	return r
}

// Add adds a route. Each change of the routes rebuilds what connections are
// matched against, in time that grows with the number of routes, so add many
// routes at once with Batch. After Close it returns net.ErrClosed with the
// route, closed.
func (m *Mux) Add(cfg RouteConfig) (*Route, error) {
	var r *Route
	err := m.Batch(func(b *Batch) error {
		var err error
		r, err = b.Add(cfg)
		return err
	})
	return r, err
}

// Upsert adds or changes the route named cfg.Name; see Batch.Upsert.
func (m *Mux) Upsert(cfg RouteConfig) (*Route, error) {
	var r *Route
	err := m.Batch(func(b *Batch) error {
		var err error
		r, err = b.Upsert(cfg)
		return err
	})
	return r, err
}

// Route returns the route with the given name, or nil.
func (m *Mux) Route(name string) *Route {
	return m.table.Load().names[name]
}

// Routes returns the current routes in matching order, fallback routes last.
func (m *Mux) Routes() []*Route {
	return slices.Clone(m.table.Load().order)
}

// Serve accepts connections from ln until ln fails or the Mux is shut down,
// and closes ln when it returns. Serve may run for several listeners at once;
// closing one of them only stops its Serve call. Temporary Accept errors are
// retried with a growing delay.
//
// After Shutdown or Close, Serve returns net.ErrClosed. Its connections
// belong to the entry with the empty name; Entry serves listeners of other
// entries.
func (m *Mux) Serve(ln net.Listener) error {
	return m.serve("", ln)
}

func (m *Mux) serve(entry string, ln net.Listener) error {
	if ln == nil {
		panic("portmux: nil listener")
	}
	l := &listener{entry: entry, addr: ln.Addr()}
	if !m.addListener(ln, l) {
		_ = ln.Close()
		return net.ErrClosed
	}
	defer m.serving.Done()
	defer m.removeListener(ln)

	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if m.quitting() {
				return net.ErrClosed
			}
			if !isTemporary(err) {
				return err
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			m.observe(Event{Entry: entry, Err: err})
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-m.quit:
				t.Stop()
				return net.ErrClosed
			}
			continue
		}
		delay = 0
		// Numbered in accept order, which the clock may not tell apart.
		seq := m.accepts.Add(1)
		stripe := uint8(seq % counterStripes)
		// A connection counts as accepted once it is served or rejected, so
		// that one waiting for a pending slot is not counted yet.
		a, err := m.admit(c, l)
		if err != nil {
			ev := Event{Entry: entry, Remote: c.RemoteAddr(), Local: c.LocalAddr(), Err: err}
			m.count(l, stripe, func(c *counters) { c.accepted.Add(1) })
			m.reject(l, stripe, err)
			_ = c.Close()
			m.observe(ev)
			continue
		}
		if !m.acquireSlot() {
			_ = c.Close()
			if a.counted {
				m.perClient.release(a.client)
			}
			return net.ErrClosed
		}
		// Pending from here, so that Shutdown, which waits for this loop
		// to stop, waits for the connection too.
		m.count(l, stripe, func(c *counters) {
			c.pending.Add(1)
			c.accepted.Add(1)
		})
		// The sniff timeout runs from here, so that the wait for a slot does
		// not use it up.
		go m.serveAccepted(c, a, l, arrival{start: time.Now(), seq: seq, stripe: stripe})
	}
}

// admission is the client of a connection admitted by Serve.
type admission struct {
	client  netip.Prefix // valid when a per-client rule needs it
	counted bool         // whether the pending limit per client counts it
	// policy reports that the PROXY protocol policy and the per-client
	// rules wait for serveConn, which calls the policy, the program's code,
	// in the connection's goroutine, so that a slow or failing policy does
	// not hold up the accept loop. proxy is its answer, and proxied that the
	// rules then wait for the header, whose source is the client; header
	// that there was one. The failures of a trusted peer itself, without a
	// header, do not count toward bans.
	policy  bool
	proxy   proxyproto.Policy
	proxied bool
	header  bool
}

// admit applies the listener's rate and the per-client rules to a connection
// accepted by Serve. With a PROXY protocol policy, it checks only that the
// peer is not banned: serveConn calls the policy and applies the rules, to
// the source of the header for a peer that sends one.
func (m *Mux) admit(c net.Conn, l *listener) (admission, error) {
	o, rate := m.settings(l.entry)
	if o.listenerRate > 0 && !l.allow(o.listenerRate, o.listenerBurst, time.Now()) {
		return admission{}, ErrRateLimited
	}
	if o.proxyPolicy != nil {
		if ap, ok := addrPort(c.RemoteAddr()); ok && m.bans.banned(ap.Addr(), m.bans.now()) {
			return admission{}, ErrBanned
		}
		return admission{policy: true}, nil
	}
	a := admission{proxy: proxyproto.Ignore}
	if o.maxPendingPerClient <= 0 && rate == nil && o.banFailures <= 0 && m.bans.size.Load() == 0 {
		return a, nil
	}
	return m.admitClient(a, c.RemoteAddr(), o, rate)
}

// proxyPolicyFor returns the PROXY protocol policy of o for c on entry.
func proxyPolicyFor(o *options, entry string, c net.Conn) proxyproto.Policy {
	if o.proxyPolicy == nil {
		return proxyproto.Ignore
	}
	return o.proxyPolicy(entry, c.RemoteAddr(), c.LocalAddr())
}

// admitClient applies the per-client rules to client, the peer of a
// connection or the source of its PROXY header, and records the client in a.
func (m *Mux) admitClient(a admission, client net.Addr, o *options, rate *rateLimit) (admission, error) {
	ap, ok := addrPort(client)
	if !ok {
		return a, nil
	}
	key := m.clientNet(ap.Addr())
	a.client = key
	switch {
	case m.bans.banned(ap.Addr(), m.bans.now()):
		return a, ErrBanned
	case rate != nil && !rate.allow(key):
		return a, ErrRateLimited
	case o.maxPendingPerClient <= 0:
		return a, nil
	case !m.perClient.acquire(key, o.maxPendingPerClient):
		return a, ErrPendingLimit
	}
	a.counted = true
	return a, nil
}

// freeAdmitted gives back the pending slot and the client's pending count of
// a.
func (m *Mux) freeAdmitted(a *admission) {
	if a.counted {
		m.perClient.release(a.client)
		a.counted = false
	}
	m.slots.release()
}

// releaseAdmitted frees, when held, the pending slot and the pending count
// per client of a connection accepted by Serve, and counts err, its failure
// if any, toward banning the client, unless the client is a peer trusted to
// send PROXY headers that sent none. It reports whether that banned the
// client.
func (m *Mux) releaseAdmitted(l *listener, a admission, held bool, err error) (banned bool) {
	if held {
		m.freeAdmitted(&a)
	}
	// A peer trusted to send PROXY headers, such as a load balancer, is not
	// banned for its own failures, which would refuse every client behind
	// it: only the sources of its headers are.
	if a.proxied && !a.header {
		return false
	}
	if o, _ := m.settings(l.entry); err != nil && o.banFailures > 0 && o.banTime > 0 && a.client.IsValid() && banWorthy(err) {
		return m.bans.fail(m.banKey(l.entry, a.client), m.bans.now(), o.banFailures, o.banWindow, o.banTime)
	}
	return false
}

// serveAccepted serves a connection from Serve in its own goroutine, which
// then runs the handler of its route, if any.
func (m *Mux) serveAccepted(c net.Conn, a admission, l *listener, at arrival) {
	handler, conn, _ := m.serveConn(c, l, a, l.entry, at)
	if handler != nil {
		_ = m.runHandler(handler, conn)
	}
}

// runHandler calls the handler of a route with conn. A panic is recovered:
// the connection is closed and the panic reported as a *PanicError, to the
// observer and to the caller.
func (m *Mux) runHandler(handler func(*Conn), conn *Conn) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = &PanicError{Value: p, Stack: debug.Stack()}
			_ = conn.Close()
			m.observe(Event{Entry: conn.entry, Remote: conn.RemoteAddr(), Local: conn.LocalAddr(), Route: conn.route, Err: err})
		}
	}()
	handler(conn)
	return nil
}

// ServeConn matches c and hands it to a route, in the calling goroutine. It
// returns nil once a route accepted c; for a route with a handler, it calls
// the handler and returns when the handler returns, or a *PanicError when
// the handler panicked. Otherwise it closes c and returns the reason, which
// the observer of WithObserver also receives.
//
// Connections passed to ServeConn skip the admission that Serve applies: the
// pending limits, the per-client rate limits and bans, and the listener rate.
// To keep them for connections that a program obtains itself, hand them to
// Serve through a net.Listener of its own, such as a channel listener.
// The sniff timeout and silence checks rely on c supporting read deadlines. c
// belongs to the entry with the empty name; Entry routes connections of other
// entries.
func (m *Mux) ServeConn(c net.Conn) error {
	return m.serveOne("", c)
}

func (m *Mux) serveOne(entry string, c net.Conn) error {
	at := arrival{start: time.Now(), stripe: newStripe()}
	// Pending before the check, so that Shutdown, which stops taking
	// connections before it waits for pending ones, either waits for this one
	// or makes the check fail.
	counts := m.total.at(at.stripe)
	counts.pending.Add(1)
	if m.quitting() {
		counts.pending.Add(-1)
		_ = c.Close()
		return net.ErrClosed
	}
	counts.accepted.Add(1)
	handler, conn, err := m.serveConn(c, nil, admission{}, entry, at)
	if handler != nil {
		err = m.runHandler(handler, conn)
	}
	return err
}

// Shutdown stops taking new connections, closes the listeners, and waits until
// every pending connection was delivered or rejected, or until ctx is done.
// It then closes the Mux. It returns ctx's error if ctx ended the wait, and
// otherwise the first error from closing a listener.
// Routes keep accepting connections while Shutdown waits, so their servers
// must still be running. Shutdown does not wait for handlers to return.
func (m *Mux) Shutdown(ctx context.Context) error {
	stopErr := m.stop()
	// Serve loops finish the connection they accepted last.
	served := make(chan struct{})
	go func() {
		m.serving.Wait()
		close(served)
	}()
	select {
	case <-served:
	case <-ctx.Done():
		_ = m.Close()
		return ctx.Err()
	}
	delay := time.Millisecond
	t := time.NewTimer(delay)
	defer t.Stop()
	for m.total.pending() > 0 {
		select {
		case <-ctx.Done():
			_ = m.Close()
			return ctx.Err()
		case <-t.C:
			delay = min(2*delay, 500*time.Millisecond)
			t.Reset(delay)
		}
	}
	_ = m.Close()
	return stopErr
}

// Close closes the listeners and every connection that was not delivered yet.
// Routes then return net.ErrClosed from Accept. Delivered connections are not
// affected. It returns the first error from closing a listener.
func (m *Mux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		// Changes applied before closed is set install routes that are
		// closed here; later ones close the routes they add themselves.
		m.mu.Lock()
		m.closed.Store(true)
		routes := m.table.Load().order
		m.mu.Unlock()
		err = m.stop()
		// Each route has its own done channel, so that Accept and dispatch
		// do not contend on a channel shared by the whole Mux.
		for _, r := range routes {
			r.closeListener()
		}
		m.undelivered.closeAll()
	})
	return err
}

// stop stops taking new connections and closes the listeners.
func (m *Mux) stop() error {
	var err error
	m.quitOnce.Do(func() {
		m.mu.Lock()
		close(m.quit)
		lns := m.listeners
		m.listeners = nil
		m.mu.Unlock()
		for ln := range lns {
			if cerr := ln.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
	})
	return err
}

func (m *Mux) quitting() bool {
	select {
	case <-m.quit:
		return true
	default:
		return false
	}
}

func (m *Mux) addListener(ln net.Listener, l *listener) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listeners == nil {
		return false
	}
	m.listeners[ln] = l
	m.serving.Add(1)
	return true
}

func (m *Mux) removeListener(ln net.Listener) {
	m.mu.Lock()
	delete(m.listeners, ln)
	m.mu.Unlock()
	_ = ln.Close()
}

// addr returns the address of the only listener of the entries, or of any
// entry when none are given, or a combined address when there are several.
func (m *Mux) addr(entries []string) net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	addrs := make(listenAddrs, 0, len(m.listeners))
	for _, l := range m.listeners {
		if len(entries) == 0 || slices.Contains(entries, l.entry) {
			addrs = append(addrs, l.addr)
		}
	}
	if len(addrs) == 1 {
		return addrs[0]
	}
	slices.SortFunc(addrs, func(a, b net.Addr) int { return strings.Compare(addrString(a), addrString(b)) })
	return addrs
}

// listenAddrs is the address of a route served on several listeners.
type listenAddrs []net.Addr

func (a listenAddrs) Network() string { return "portmux" }

func (a listenAddrs) String() string {
	s := make([]string, len(a))
	for i, addr := range a {
		s[i] = addrString(addr)
	}
	return strings.Join(s, ",")
}

// addrString returns the text of an address, which may be nil.
func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// acquireSlot takes a pending slot for a new connection. At the limit it
// closes the oldest undecided connection, whose goroutine frees its slot as it
// exits, and waits. It reports false when the Mux stops taking connections.
func (m *Mux) acquireSlot() bool {
	if m.slots.tryAcquire(m.opts.Load().maxPending) {
		return true
	}
	m.undelivered.evictOldest()
	m.slots.waiters.Add(1)
	defer m.slots.waiters.Add(-1)
	for {
		// Checked after registering as a waiter, so that no release is
		// missed.
		if m.slots.tryAcquire(m.opts.Load().maxPending) {
			if m.slots.waiters.Load() > 1 {
				m.slots.signal() // another slot may be free for the next waiter
			}
			return true
		}
		select {
		case <-m.slots.free:
		case <-m.quit:
			return false
		}
	}
}

func isTemporary(err error) bool {
	var te interface{ Temporary() bool }
	return errors.As(err, &te) && te.Temporary()
}
