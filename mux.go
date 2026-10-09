package portmux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	perIP       pendingLimit
	rate        atomic.Pointer[rateLimit]
	entries     atomic.Pointer[map[string]*entryConfig] // entries with options of their own
	bans        *banList
	total       stripedCounters

	// mu guards listeners, orders changes of the routes and options, which
	// are read without it.
	mu        sync.Mutex
	listeners map[net.Listener]*listener
}

// listener is the state of a listener being served.
type listener struct {
	entry  string
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
		perIP:     pendingLimit{count: make(map[netip.Addr]int)},
		bans:      newBanList(),
	}
	o := newOptions(opts)
	m.opts.Store(&o)
	if o.rate > 0 {
		m.rate.Store(newRateLimit(o.rate, o.rateBurst))
	}
	m.table.Store(newTable(routeSet{}))
	return m
}

// SetOptions changes options while the Mux serves; options that are not
// given keep their values. Limits apply to the connections accepted from then
// on, and connections being matched keep the timeouts and sizes they started
// with. Lowering WithMaxPending closes nothing: Serve waits until enough
// pending connections are gone. A new WithRateLimitPerIP starts every client
// with a full bucket.
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

// Match adds an unnamed route with priority 0 for the matchers and returns
// it. Routes with equal priority are tried in the order they were added, so
// for a static setup Match routes can simply be added from specific to
// general. Match panics on a nil matcher.
func (m *Mux) Match(matchers ...Matcher) *Route {
	r, err := m.Add(RouteConfig{Matchers: matchers})
	if err != nil {
		panic(err)
	}
	return r
}

// Add adds a route.
func (m *Mux) Add(cfg RouteConfig) (*Route, error) {
	var r *Route
	err := m.Batch(func(b *Batch) error {
		var err error
		r, err = b.Add(cfg)
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
	l := &listener{entry: entry}
	if !m.addListener(ln, l) {
		_ = ln.Close()
		return net.ErrClosed
	}
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
				m.perIP.release(a.client)
			}
			return net.ErrClosed
		}
		m.count(l, stripe, func(c *counters) { c.accepted.Add(1) })
		// The sniff timeout runs from here, so that the wait for a slot does
		// not use it up.
		go m.serveAccepted(c, a, l, arrival{start: time.Now(), seq: seq, stripe: stripe})
	}
}

// admission is the client of a connection admitted by Serve.
type admission struct {
	client  netip.Addr // valid when a per-client rule needs it
	counted bool       // whether the pending limit per client counts it
}

// admit applies the listener's rate and the per-client rules to a connection
// accepted by Serve.
func (m *Mux) admit(c net.Conn, l *listener) (admission, error) {
	o, rate := m.settings(l.entry)
	if o.listenerRate > 0 && !l.allow(o.listenerRate, o.listenerBurst, time.Now()) {
		return admission{}, ErrRateLimited
	}
	if o.maxPendingPerIP <= 0 && rate == nil && o.banFailures <= 0 && m.bans.size.Load() == 0 {
		return admission{}, nil
	}
	client, ok := clientKey(c.RemoteAddr())
	if !ok {
		return admission{}, nil
	}
	a := admission{client: client}
	switch {
	case m.bans.banned(client, m.bans.now()):
		return admission{}, ErrBanned
	case rate != nil && !rate.allow(client):
		return admission{}, ErrRateLimited
	case o.maxPendingPerIP <= 0:
		return a, nil
	case !m.perIP.acquire(client, o.maxPendingPerIP):
		return admission{}, ErrPendingLimit
	}
	a.counted = true
	return a, nil
}

// serveAccepted serves a connection from Serve in its own goroutine, which
// then runs the handler of its route, if any.
func (m *Mux) serveAccepted(c net.Conn, a admission, l *listener, at arrival) {
	handler, conn, err := m.serveConn(c, l, l.entry, at)
	if a.counted {
		m.perIP.release(a.client)
	}
	m.slots.release()
	if o, _ := m.settings(l.entry); err != nil && o.banFailures > 0 && a.client.IsValid() && banWorthy(err) {
		m.bans.fail(m.banKey(l.entry, a.client), m.bans.now(), o.banFailures, o.banWindow, o.banTime)
	}
	if handler != nil {
		handler(conn)
	}
}

// ServeConn matches c and hands it to a route, in the calling goroutine. It
// returns nil once a route accepted c; for a route with a handler, it calls
// the handler and returns when the handler returns. Otherwise it closes c and
// returns the reason, which is not passed to the error handler. Connections
// passed to ServeConn do not count against the pending limits. The sniff
// timeout and silence checks rely on c supporting read deadlines. c belongs
// to the entry with the empty name; Entry routes connections of other
// entries.
func (m *Mux) ServeConn(c net.Conn) error {
	return m.serveOne("", c)
}

func (m *Mux) serveOne(entry string, c net.Conn) error {
	if m.quitting() {
		_ = c.Close()
		return net.ErrClosed
	}
	at := arrival{start: time.Now(), stripe: newStripe()}
	m.total.at(at.stripe).accepted.Add(1)
	handler, conn, err := m.serveConn(c, nil, entry, at)
	if handler != nil {
		handler(conn)
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
	for ln, l := range m.listeners {
		if len(entries) == 0 || slices.Contains(entries, l.entry) {
			addrs = append(addrs, ln.Addr())
		}
	}
	if len(addrs) == 1 {
		return addrs[0]
	}
	return addrs
}

// listenAddrs is the address of a route served on several listeners.
type listenAddrs []net.Addr

func (a listenAddrs) Network() string { return "portmux" }

func (a listenAddrs) String() string {
	s := make([]string, len(a))
	for i, addr := range a {
		s[i] = addr.String()
	}
	return strings.Join(s, ",")
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
