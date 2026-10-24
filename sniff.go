package portmux

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/netx/proxyproto"
)

// errRouteGone reports that the chosen route was removed before it accepted
// the connection.
var errRouteGone = errors.New("portmux: route removed")

// sniffer holds the matching state of one connection. It is pooled.
type sniffer struct {
	conn     *Conn
	opts     *options
	in       Input
	buf      []byte
	off      int   // length of the PROXY header at the start of buf
	err      error // error of the last read, examined after its bytes
	start    time.Time
	seq      uint64    // accept order of a connection from Serve
	deadline time.Time // sniff deadline, zero without one
	armed    time.Time // read deadline currently set on the connection
	silentAt time.Duration
	table    *table
	rules    *ruleSet    // the table's rules for entry
	dead     []bool      // kept across uses of the sniffer
	via      *Route      // the route that decided the match
	timer    *time.Timer // dispatch timer, kept across uses of the sniffer
	empty    int         // consecutive reads without bytes or error

	// Membership in a pendingSet list, guarded by the shard's lock.
	list       *sniffList
	prev, next *sniffer
	evicted    atomic.Bool
}

// bufferTaken is called, when tests set it, each time a connection takes its
// read buffer.
var bufferTaken atomic.Pointer[func()]

// leftPending is called, when tests set it, each time a matched connection
// leaves the pending set.
var leftPending atomic.Pointer[func()]

// maxEmptyReads is how many reads in a row may return neither bytes nor an
// error before the connection is treated as broken, as in bufio.
const maxEmptyReads = 100

var snifferPool = sync.Pool{New: func() any { return new(sniffer) }}

// newSniffer takes a sniffer from the pool for conn, accepted at start, which
// keeps the options it starts with.
func newSniffer(conn *Conn, opts *options, start time.Time) *sniffer {
	s := snifferPool.Get().(*sniffer)
	s.conn, s.opts, s.start = conn, opts, start
	s.in.entry = conn.entry
	if opts.sniffTimeout > 0 {
		s.deadline = s.start.Add(opts.sniffTimeout)
	}
	return s
}

// release returns s to the pool, keeping its timer and the room of dead.
func (s *sniffer) release() {
	*s = sniffer{timer: s.timer, dead: s.dead[:0]}
	snifferPool.Put(s)
}

// arrival is when the Mux started on a connection, once it had a pending
// slot, and the counter stripe it uses. Connections from Serve are also
// numbered in accept order.
type arrival struct {
	start  time.Time
	seq    uint64
	stripe uint8
}

// serveConn matches c, which the caller counted as pending, and delivers it,
// with cs, the settings that the connection follows throughout. Connections
// from Serve come with their listener, which counts them, and their
// admission; they may be evicted while undecided. For a route with a
// handler, serveConn returns the handler instead of calling it, so that the
// connection no longer counts as pending while the handler runs.
func (m *Mux) serveConn(c net.Conn, l *listener, a admission, cs *connSettings, entry string, at arrival) (handler func(*Conn), conn *Conn, err error) {
	conn = &Conn{conn: c, entry: entry, stripe: at.stripe}
	s := newSniffer(conn, cs.opts, at.start)
	s.seq = at.seq
	m.undelivered.add(s, l != nil)
	// held reports that the connection holds the pending slot and the
	// client's pending count of its admission; it gives them back once
	// matched, so that one that waits for Accept holds neither.
	held, delivered := l != nil, false
	defer func() {
		if p := recover(); p != nil {
			err = &PanicError{Value: p, Stack: debug.Stack()}
		}
		err = m.settle(s, l, &a, cs, held, delivered, err)
	}()
	// Close may have run between add and here without seeing conn.
	if m.closed.Load() {
		return nil, conn, net.ErrClosed
	}
	// a is updated in place, so that settle sees what admission took
	// even when a panic cuts the steps short.
	if err = m.admitProxied(s, l, &a, cs); err != nil {
		return nil, conn, err
	}
	for {
		var r *Route
		if r, err = m.decide(s); err != nil {
			return nil, conn, err
		}
		var st routeState
		if err = m.claim(s, r, &st); err != nil {
			return nil, conn, err
		}
		m.open(conn, l, cs)
		// The buffer is dropped only once delivered: matched again, the
		// connection still reads into it.
		if st.handler != nil {
			delivered = true
			conn.dropEmpty()
			return st.handler, conn, nil
		}
		if held {
			// Matched, the connection waits only for its route, which
			// MaxQueued and the dispatch timeout bound: holding its slot
			// would let routes that the same Mux serves, such as one
			// nested inside TLS, take every slot while they wait for
			// their own connections, which need slots too.
			m.freeAdmitted(&a)
			held = false
		}
		if err = m.deliver(s, r, st); err == nil {
			delivered = true
			conn.dropEmpty()
			return nil, conn, nil
		}
		conn.closeOpen()
		if !errors.Is(err, errRouteGone) {
			return nil, conn, err
		}
		// Matched again, it may read again, which Close must interrupt.
		m.undelivered.add(s, false)
		if m.closed.Load() {
			return nil, conn, net.ErrClosed
		}
	}
}

// settle ends serveConn for the connection of s, with l, a and cs as
// serveConn got them, and err, why the connection was not delivered, if it
// was not: it counts the outcome, gives back what the connection holds,
// closes the connection unless delivered and reports it to the observer. held
// reports that the connection still holds its pending slot and the client's
// pending count. It returns err, or ErrEvicted for a connection evicted while
// it was undecided.
func (m *Mux) settle(s *sniffer, l *listener, a *admission, cs *connSettings, held, delivered bool, err error) error {
	conn, stripe := s.conn, s.conn.stripe
	m.undelivered.remove(s)
	if s.evicted.Load() && err != nil {
		err = ErrEvicted
	}
	// The event is taken before the sniffer, which holds what matching
	// found, goes back to the pool.
	observer := cs.opts.observer
	var ev Event
	if observer != nil {
		p := s.in.parsed()
		ev = conn.eventOf(&p, err)
		ev.Elapsed, ev.Sniffed = time.Since(s.start), len(s.buf)
	}
	s.release()
	// The outcome is counted before the connection leaves pending and
	// before the client sees it closed, so that the counts add up for
	// anyone who waited for either.
	var reason rejectReason
	if !delivered {
		reason = reasonOf(err)
	}
	m.count(l, stripe, func(c *counters) {
		if delivered {
			c.delivered.Add(1)
		} else {
			c.rejected[reason].Add(1)
		}
		c.pending.Add(-1)
	})
	// The pending slot and the client's pending count are freed, and a
	// failure counted toward a ban, before the client sees the
	// connection closed, so that a client that connects again at once
	// is held to the limits and bans that this connection leaves.
	if l != nil {
		ev.Banned = m.releaseAdmitted(l, a, cs, held, err)
	}
	if delivered {
		ev.Route = conn.route
	} else {
		_ = conn.Close()
	}
	if observer != nil {
		m.observeWith(observer, ev)
	}
	return err
}

// admitProxied calls the PROXY protocol policy, reads the header that it asks
// for, and then applies the per-client rules that waited for the policy, to
// the peer, or for the header, to its source; see admission. It records what
// it learns in a as it goes, also on failure and on a panic, for what settle
// gives back and counts toward bans.
func (m *Mux) admitProxied(s *sniffer, l *listener, a *admission, cs *connSettings) error {
	c, entry := s.conn.conn, s.in.entry
	var err error
	switch {
	case l == nil:
		a.proxy = proxyPolicyFor(cs.opts, entry, c)
	case a.policy:
		// Here rather than in the accept loop, which a slow or panicking
		// policy would hold up or bring down.
		if a.proxy = proxyPolicyFor(cs.opts, entry, c); a.proxy != proxyproto.Ignore {
			a.proxied = true
		} else if *a, err = m.admitClient(*a, c.RemoteAddr(), cs); err != nil {
			return err
		}
	}
	if err = s.readProxyHeader(a.proxy, &m.table); err != nil {
		return err
	}
	if a.proxied {
		// The client is the source of the header, if there was one.
		a.header = s.conn.proxy != nil
		*a, err = m.admitClient(*a, s.conn.RemoteAddr(), cs)
	}
	return err
}

// decide matches the connection of s until a route that is still open takes
// it, and checks that a route a resolver chose may serve it.
func (m *Mux) decide(s *sniffer) (*Route, error) {
	for {
		r, err := s.match(&m.table, s.opts.maxSniffBytes)
		if err != nil {
			return nil, err
		}
		if r.mux != m {
			return nil, errForeignRoute
		}
		if r.isClosed() {
			switch {
			case m.closed.Load():
				return nil, net.ErrClosed
			case s.via != r:
				// A resolver chose a route that is closed.
				return nil, ErrRouteClosed
			}
			continue // removed while matching: match against the new routes
		}
		if s.via != r {
			// A resolver chose r: it must serve the connection's entry.
			if st := m.table.Load().routes[r]; len(st.entries) > 0 && !slices.Contains(st.entries, s.in.entry) {
				return nil, ErrEntryMismatch
			}
		}
		return r, nil
	}
}

// claim hands the connection of s over to r, the route that decided it, takes
// it out of the pending set and counts it as matched and open on r. It sets st
// to the settings of r, or returns why r cannot take the connection.
func (m *Mux) claim(s *sniffer, r *Route, st *routeState) error {
	s.handOver(r)
	// A decided connection leaves the pending set, so that Close does not
	// close it once it is delivered.
	m.undelivered.remove(s)
	if f := leftPending.Load(); f != nil {
		(*f)()
	}
	if s.evicted.Load() {
		// Evicted while the last bytes were matched: the connection is
		// already closed.
		return ErrEvicted
	}
	// A connection that Close no longer reaches through the pending set
	// is not handed over once Close began, and the done channels of the
	// routes stop one that waits for Accept. One handed over is
	// delivered before Close began.
	if m.closed.Load() {
		return net.ErrClosed
	}
	r.matched.Add(1)
	if s.via != nil && s.via != r {
		s.via.matched.Add(1)
	}
	if r.reject {
		return ErrRefused
	}
	*st = m.table.Load().routes[r]
	if !r.tryOpen(st.maxConns) {
		return ErrConnLimit
	}
	return nil
}

// open counts conn, which its route counted as open, as open by the Mux and
// its listener l, and measures it for its close event when cs asks for one.
func (m *Mux) open(conn *Conn, l *listener, cs *connSettings) {
	conn.mux, conn.ln = m, l
	if o := cs.opts; o.closeEvents && o.observer != nil {
		conn.track = &connTrack{start: time.Now(), observe: o.observer}
	}
	conn.open.Store(true)
	m.count(l, conn.stripe, func(c *counters) { c.open.Add(1) })
}

// maxProxyHeaderLen is the longest PROXY header, a version 2 header with the
// largest payload.
const maxProxyHeaderLen = 16 + 0xffff

// readProxyHeader reads a PROXY header when mode expects one, then sets
// the addresses that matchers see. A missing header is reported with
// proxyproto.ErrNoHeader, an invalid one with an error wrapping
// proxyproto.ErrMalformed, and one cut short with io.ErrUnexpectedEOF. An
// optional header is taken to be missing when the client stays silent until
// a silence check of the routes in tables or the sniff deadline, which match
// then decides on.
func (s *sniffer) readProxyHeader(mode proxyproto.Policy, tables *atomic.Pointer[table]) error {
	defer func() {
		c := s.conn
		s.in.remote, s.in.local, s.in.proxy = c.RemoteAddr(), c.LocalAddr(), c.proxy
		s.in.peer = c.conn.RemoteAddr()
	}()
	if mode == proxyproto.Ignore {
		return nil
	}
	var rs *ruleSet
	if mode == proxyproto.Optional {
		s.useTable(tables.Load())
		rs = s.rules
	}
	for {
		h, n, err := proxyproto.Decode(s.buf)
		switch {
		case err == nil:
			s.conn.proxy, s.off = h, n
			return nil
		case errors.Is(err, proxyproto.ErrNoHeader):
			if mode == proxyproto.Required {
				return err
			}
			return nil
		case !errors.Is(err, io.ErrUnexpectedEOF):
			return err
		}
		if s.err != nil {
			if rs != nil && isTimeout(s.err) && len(s.buf) == 0 {
				return nil // a client that waits for the server
			}
			if errors.Is(s.err, io.EOF) && len(s.buf) > 0 {
				return io.ErrUnexpectedEOF
			}
			return s.readErr()
		}
		s.read(maxProxyHeaderLen, rs)
	}
}

// match reads until a route of the current table matches. Every decision
// uses the table loaded at that moment, so route changes also apply to
// connections that are still undecided.
func (s *sniffer) match(tables *atomic.Pointer[table], maxSniffBytes int) (*Route, error) {
	in := &s.in
	limit := s.off + maxSniffBytes
	for {
		if t := tables.Load(); t != s.table {
			s.useTable(t)
		}
		// A read for the PROXY header may have taken bytes beyond the limit,
		// which matchers do not see.
		in.data = s.buf[s.off:min(len(s.buf), limit)]
		eof := s.err != nil && errors.Is(s.err, io.EOF)
		if eof && len(in.data) == 0 {
			return nil, io.EOF
		}
		in.final = eof || len(s.buf) >= limit
		switch r, via, res := s.rules.evaluate(s.dead, in); res {
		case Match:
			s.via = via
			return r, nil
		case NoMatch:
			if r := s.rules.fallback; r != nil {
				s.via = r
				return r, nil
			}
			return nil, ErrNoMatch
		case NeedMore:
			// Read more below.
		}
		if s.err != nil {
			if !s.silenceDue() {
				// A client that sent bytes but stayed undecided goes to the
				// fallback route.
				if r := s.rules.fallback; r != nil && len(in.data) > 0 && isTimeout(s.err) {
					s.via = r
					return r, nil
				}
				return nil, s.readErr()
			}
			in.elapsed = time.Since(s.start)
			s.silentAt = in.elapsed
			r, via := s.rules.evaluateSilent(s.dead, in)
			in.elapsed = 0
			if r != nil {
				s.via = via
				return r, nil
			}
			s.err = nil
		}
		s.read(limit, s.rules)
	}
}

func (s *sniffer) useTable(t *table) {
	s.table = t
	s.rules = t.forEntry(s.in.entry)
	if n := len(s.rules.rules); n <= cap(s.dead) {
		s.dead = s.dead[:n]
		clear(s.dead)
	} else {
		s.dead = make([]bool, max(n, 16))[:n]
	}
}

// silenceDue reports whether the last read stopped at a silence check rather
// than at the sniff deadline.
func (s *sniffer) silenceDue() bool {
	if !isTimeout(s.err) || len(s.buf) > s.off {
		return false
	}
	return s.deadline.IsZero() || time.Now().Before(s.deadline)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// read appends at most limit-len(buf) bytes, growing the buffer as needed.
// Without bytes yet, the read deadline stops at the next silence check of t.
// The read error is kept in s.err for after the new bytes were examined.
func (s *sniffer) read(limit int, rs *ruleSet) {
	want := s.deadline
	if rs != nil && len(s.buf) == s.off {
		for _, d := range rs.silences {
			if d > s.silentAt {
				if w := s.start.Add(d); want.IsZero() || w.Before(want) {
					want = w
				}
				break
			}
		}
	}
	if !want.Equal(s.armed) {
		_ = s.conn.conn.SetReadDeadline(want)
		s.armed = want
	}
	if s.buf == nil {
		// Idle clients hold no buffer: wait until the connection is readable
		// before taking one from the pool.
		if err := waitReadable(s.conn.conn); err != nil {
			s.err = err
			return
		}
		s.conn.buf = getBuffer()
		s.buf = (*s.conn.buf)[:0]
		if f := bufferTaken.Load(); f != nil {
			(*f)()
		}
	}
	end := min(cap(s.buf), limit)
	if len(s.buf) == end {
		grown := make([]byte, len(s.buf), min(2*cap(s.buf), limit))
		copy(grown, s.buf)
		putBuffer(s.conn.buf)
		s.conn.buf = nil
		s.buf = grown
		end = cap(grown)
	}
	n, err := s.conn.conn.Read(s.buf[len(s.buf):end])
	s.buf = s.buf[:len(s.buf)+n]
	s.err = err
	if n == 0 && err == nil {
		if s.empty++; s.empty >= maxEmptyReads {
			s.err = io.ErrNoProgress
		}
	} else {
		s.empty = 0
	}
}

func (s *sniffer) readErr() error {
	if isTimeout(s.err) {
		return fmt.Errorf("%w: %w", ErrSniffTimeout, s.err)
	}
	return s.err
}

// handOver clears the read deadline and attaches the bytes read and the
// parses to the connection, with the route that matched it, if any.
func (s *sniffer) handOver(r *Route) {
	if !s.armed.IsZero() {
		_ = s.conn.conn.SetReadDeadline(time.Time{})
		s.armed = time.Time{}
	}
	c := s.conn
	c.pending = s.buf[s.off:]
	c.route = r
	// The connection keeps what matching found once the sniffer, which
	// holds it, goes back to the pool.
	p := s.in.parsed()
	p.values = slices.Clone(p.values) // nil, without allocating, when none were set
	if p.name != nil {
		name := *p.name
		p.name = &name
	}
	c.parsed = p
}

// deliver hands the connection to r's Accept, with the queue limit and the
// dispatch timeout of st, the route's settings, or else of the entry.
func (m *Mux) deliver(s *sniffer, r *Route, st routeState) error {
	conn := s.conn
	// A route whose server is waiting in Accept takes the connection without
	// a timer.
	select {
	case r.ch <- conn:
		return nil
	default:
	}
	q, d := s.opts.maxQueued, s.opts.dispatchTimeout
	if st.maxQueued != 0 {
		q = st.maxQueued
	}
	if st.dispatchTimeout != 0 {
		d = st.dispatchTimeout
	}
	// Counted without a limit too, for RouteInfo.Queued.
	queued := r.queued.Add(1)
	defer r.queued.Add(-1)
	if q > 0 && queued > int64(q) {
		return ErrQueueFull
	}
	var timeout <-chan time.Time
	if d > 0 {
		if s.timer == nil {
			s.timer = time.NewTimer(d)
		} else {
			s.timer.Reset(d)
		}
		defer s.timer.Stop()
		timeout = s.timer.C
	}
	select {
	case r.ch <- conn:
		return nil
	case <-r.done:
		if m.closed.Load() {
			return net.ErrClosed
		}
		return errRouteGone
	case <-timeout:
		return ErrDispatchTimeout
	}
}
