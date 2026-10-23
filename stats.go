package portmux

import (
	"errors"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/tlshello"
)

// Snapshot is the state of a Mux at one moment.
type Snapshot struct {
	// Listeners lists the listeners being served and their entries.
	Listeners []ListenerInfo
	// Routes describes the routes in matching order, fallback routes last.
	Routes []RouteInfo
	Stats  Stats
}

// Snapshot returns the current listeners, routes and counters, for example
// for a status page. The routes are taken at one moment, so their order and
// configuration are consistent with each other.
func (m *Mux) Snapshot() Snapshot {
	t := m.table.Load()
	snap := Snapshot{Routes: make([]RouteInfo, len(t.order))}
	for i, r := range t.order {
		snap.Routes[i] = r.info(t)
	}
	m.mu.Lock()
	for _, l := range m.listeners {
		snap.Listeners = append(snap.Listeners, ListenerInfo{Entry: l.entry, Addr: l.addr, Stats: l.counts.stats()})
	}
	m.mu.Unlock()
	slices.SortFunc(snap.Listeners, func(a, b ListenerInfo) int {
		if c := strings.Compare(a.Entry, b.Entry); c != 0 {
			return c
		}
		return strings.Compare(addrString(a.Addr), addrString(b.Addr))
	})
	snap.Stats = m.Stats()
	return snap
}

// ListenerInfo describes a listener being served.
type ListenerInfo struct {
	Entry string
	Addr  net.Addr
	// Stats counts the connections accepted from this listener.
	Stats Stats
}

// Stats is a snapshot of connection counters, of a Mux or of one listener.
type Stats struct {
	// Accepted counts the connections accepted by Serve or passed to
	// ServeConn.
	Accepted uint64
	// Delivered counts the connections that a route accepted or passed to
	// its handler.
	Delivered uint64
	// Rejected counts the connections closed without being delivered. The
	// fields after Pending break it down by reason.
	Rejected uint64
	// Pending is the number of connections being matched or waiting for
	// their route to accept them. Only those being matched count against
	// WithMaxPending, so Pending can be above that limit.
	Pending int64
	// Open is the number of connections delivered, or waiting for Accept,
	// and not closed yet with Conn.Close.
	Open int64

	// NoMatch counts connections that no route matched.
	NoMatch uint64
	// Refused counts connections closed by reject routes.
	Refused uint64
	// Timeouts counts sniff and dispatch timeouts.
	Timeouts uint64
	// Evicted counts undecided connections closed at the pending limit.
	Evicted uint64
	// Limited counts connections closed by the rate and pending limits, or
	// because their route had too many connections queued or open
	// (ErrQueueFull, ErrConnLimit).
	Limited uint64
	// Banned counts connections closed because their client is banned.
	Banned uint64
	// Failed counts the rest: clients that closed or reset the connection,
	// invalid PROXY headers, panics of matchers, resolvers and PROXY policies,
	// and connections closed by Close. A connection whose handler panics was
	// counted as delivered.
	Failed uint64
}

// rejectReason classifies why a connection was not delivered.
type rejectReason uint8

const (
	reasonNoMatch rejectReason = iota
	reasonRefused
	reasonTimeout
	reasonEvicted
	reasonLimited
	reasonBanned
	reasonFailed
	numReasons
)

func reasonOf(err error) rejectReason {
	switch {
	case errors.Is(err, ErrNoMatch):
		return reasonNoMatch
	case errors.Is(err, ErrRefused):
		return reasonRefused
	case errors.Is(err, ErrSniffTimeout), errors.Is(err, ErrDispatchTimeout):
		return reasonTimeout
	case errors.Is(err, ErrEvicted):
		return reasonEvicted
	case errors.Is(err, ErrPendingLimit), errors.Is(err, ErrRateLimited), errors.Is(err, ErrQueueFull), errors.Is(err, ErrConnLimit):
		return reasonLimited
	case errors.Is(err, ErrBanned):
		return reasonBanned
	}
	return reasonFailed
}

// Stats returns the current counters of the Mux.
func (m *Mux) Stats() Stats {
	return m.total.stats()
}

// counterStripes is the number of stripes that the counters of a Mux and of
// a listener are spread over, so that connections handled on different cores
// do not contend for one cache line. A connection keeps one stripe: those
// from Serve take turns by accept order, those from ServeConn take one at
// random. Readers add the stripes up.
const counterStripes = 16

// stripedCounters holds the stripes of counters, each on cache lines of its
// own, also where lines are 128 bytes long.
type stripedCounters [counterStripes]struct {
	counters
	_ [128]byte
}

// newStripe picks the stripe of a connection from ServeConn.
func newStripe() uint8 {
	return uint8(rand.Uint32() % counterStripes)
}

func (c *stripedCounters) at(stripe uint8) *counters {
	return &c[stripe%counterStripes].counters
}

// stats adds the stripes up.
func (c *stripedCounters) stats() Stats {
	var st Stats
	for i := range c {
		s := c[i].stats()
		st.Accepted += s.Accepted
		st.Delivered += s.Delivered
		st.Pending += s.Pending
		st.Open += s.Open
		st.NoMatch += s.NoMatch
		st.Refused += s.Refused
		st.Timeouts += s.Timeouts
		st.Evicted += s.Evicted
		st.Limited += s.Limited
		st.Banned += s.Banned
		st.Failed += s.Failed
	}
	st.Rejected = st.NoMatch + st.Refused + st.Timeouts + st.Evicted + st.Limited + st.Banned + st.Failed
	return st
}

// pending returns the number of pending connections.
func (c *stripedCounters) pending() int64 {
	var n int64
	for i := range c {
		n += c[i].pending.Load()
	}
	return n
}

// counters counts connections, in one stripe.
type counters struct {
	accepted  atomic.Uint64
	delivered atomic.Uint64
	pending   atomic.Int64
	open      atomic.Int64
	rejected  [numReasons]atomic.Uint64
}

func (c *counters) stats() Stats {
	st := Stats{
		Accepted:  c.accepted.Load(),
		Delivered: c.delivered.Load(),
		Pending:   c.pending.Load(),
		Open:      c.open.Load(),
		NoMatch:   c.rejected[reasonNoMatch].Load(),
		Refused:   c.rejected[reasonRefused].Load(),
		Timeouts:  c.rejected[reasonTimeout].Load(),
		Evicted:   c.rejected[reasonEvicted].Load(),
		Limited:   c.rejected[reasonLimited].Load(),
		Banned:    c.rejected[reasonBanned].Load(),
		Failed:    c.rejected[reasonFailed].Load(),
	}
	st.Rejected = st.NoMatch + st.Refused + st.Timeouts + st.Evicted + st.Limited + st.Banned + st.Failed
	return st
}

// count applies f to a stripe of the counters of the Mux and, for a
// connection from Serve, of its listener.
func (m *Mux) count(l *listener, stripe uint8, f func(*counters)) {
	f(m.total.at(stripe))
	if l != nil {
		f(l.counts.at(stripe))
	}
}

// reject counts a connection that is closed without delivery.
func (m *Mux) reject(l *listener, stripe uint8, err error) {
	reason := reasonOf(err)
	m.count(l, stripe, func(c *counters) { c.rejected[reason].Add(1) })
}

// Event describes a connection that a Mux delivered or closed, or an Accept
// error that Serve retries; see WithObserver.
type Event struct {
	// Entry is the entry of the listener or of the ServeConn call.
	Entry string
	// Remote and Local are the connection's addresses, from the PROXY header
	// when one was parsed. They are nil for Accept errors.
	Remote net.Addr
	Local  net.Addr
	// Route is the route that took the connection, or nil.
	Route *Route
	// Err is why the connection was closed, or the Accept error; it is nil
	// for a delivered connection. A delivered connection whose route handler
	// panics is reported once more, after its delivery, with its Route and
	// a *PanicError; that event is not counted in Stats again.
	Err error
	// Elapsed is the time from taking the connection, as in
	// WithSniffTimeout, to the decision, by the monotonic clock, whose ticks are coarse on some systems such as
	// Windows.
	Elapsed time.Duration
	// Sniffed is the number of bytes read while matching, including a PROXY
	// header.
	Sniffed int
	// Name is the host name the client asked for, as Conn.RequestedName
	// returns it, from what matchers parsed, or "".
	Name string
	// ClientHello, HTTPRequest and HTTP2Request are what matchers parsed of
	// the connection, or nil, for example to log the fingerprint of a client
	// that was refused.
	ClientHello  *tlshello.Hello
	HTTPRequest  *httphead.Request
	HTTP2Request *httphead.Request
	// Banned reports that this connection's failure banned its client; see
	// WithBanPerClient.
	Banned bool
}

// observe passes ev to the observer, unless the Mux was closed.
func (m *Mux) observe(ev Event) {
	if fn := m.opts.Load().observer; fn != nil && (ev.Err == nil || !m.closed.Load()) {
		fn(ev)
	}
}
