package portmux

import (
	"errors"
	"fmt"
	"io"
	"net"
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
	rules    *ruleSet // the table's rules for entry
	dead     []bool
	deadBuf  [16]bool
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

// release returns s to the pool, keeping its timer.
func (s *sniffer) release() {
	*s = sniffer{timer: s.timer}
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

// serveConn matches c and delivers it. Connections from Serve come with their
// listener, which counts them, and their admission; they may be evicted while
// undecided. For a route with a handler, serveConn returns the handler instead
// of calling it, so that the connection no longer counts as pending while the
// handler runs.
func (m *Mux) serveConn(c net.Conn, l *listener, a admission, entry string, at arrival) (handler func(*Conn), conn *Conn, err error) {
	stripe := at.stripe
	conn = &Conn{conn: c, entry: entry, stripe: stripe}
	m.count(l, stripe, func(c *counters) { c.pending.Add(1) })
	o, _ := m.settings(entry)
	s := newSniffer(conn, o, at.start)
	s.seq = at.seq
	m.undelivered.add(s, l != nil)
	delivered := false
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("portmux: matcher panicked: %v", p)
		}
		m.undelivered.remove(s)
		if s.evicted.Load() && err != nil {
			err = ErrEvicted
		}
		observed := s.opts.observer != nil
		var ev Event
		if observed {
			ev = Event{Entry: entry, Err: err, Elapsed: time.Since(s.start), Sniffed: len(s.buf)}
			ev.Remote, ev.Local = conn.RemoteAddr(), conn.LocalAddr()
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
			m.releaseAdmitted(l, a, err)
		}
		if delivered {
			ev.Route = conn.route
		} else {
			_ = conn.Close()
		}
		if observed {
			m.observe(ev)
		}
	}()
	// Close may have run between add and here without seeing conn.
	if m.closed.Load() {
		return nil, conn, net.ErrClosed
	}
	if err = s.readProxyHeader(s.opts.proxyPolicy, &m.table); err != nil {
		return nil, conn, err
	}
	for {
		var r *Route
		if r, err = s.match(&m.table, s.opts.maxSniffBytes); err != nil {
			return nil, conn, err
		}
		if r.mux != m {
			return nil, conn, errForeignRoute
		}
		if r.isClosed() {
			switch {
			case m.closed.Load():
				return nil, conn, net.ErrClosed
			case s.via != r:
				// A resolver chose a route that is closed.
				return nil, conn, ErrRouteClosed
			}
			continue // removed while matching: match against the new routes
		}
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
			return nil, conn, ErrEvicted
		}
		// A connection that Close no longer reaches through the pending set
		// is not handed over once Close began, and the done channels of the
		// routes stop one that waits for Accept. One handed over is
		// delivered before Close began.
		if m.closed.Load() {
			return nil, conn, net.ErrClosed
		}
		r.matched.Add(1)
		if s.via != nil && s.via != r {
			s.via.matched.Add(1)
		}
		if r.reject {
			return nil, conn, ErrRefused
		}
		if !r.tryOpen(m.table.Load().routes[r].maxConns) {
			return nil, conn, ErrRouteFull
		}
		conn.mux, conn.ln = m, l
		conn.open.Store(true)
		m.count(l, stripe, func(c *counters) { c.open.Add(1) })
		if r.handler != nil {
			delivered = true
			return r.handler, conn, nil
		}
		if err = m.deliver(s, r); err == nil {
			delivered = true
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

// maxProxyHeaderLen is the longest PROXY header, a version 2 header with the
// largest payload.
const maxProxyHeaderLen = 16 + 0xffff

// readProxyHeader reads a PROXY header when policy expects one, then sets
// the addresses that matchers see. A missing header is reported with
// proxyproto.ErrNoHeader, an invalid one with an error wrapping
// proxyproto.ErrMalformed, and one cut short with io.ErrUnexpectedEOF. An
// optional header is taken to be missing when the client stays silent until
// a silence check of the routes in tables or the sniff deadline, which match
// then decides on.
func (s *sniffer) readProxyHeader(policy func(entry string, peer, local net.Addr) proxyproto.Policy, tables *atomic.Pointer[table]) error {
	defer func() {
		c := s.conn
		s.in.remote, s.in.local, s.in.proxy = c.RemoteAddr(), c.LocalAddr(), c.proxy
		s.in.peer = c.conn.RemoteAddr()
	}()
	if policy == nil {
		return nil
	}
	c := s.conn.conn
	mode := policy(s.in.entry, c.RemoteAddr(), c.LocalAddr())
	if mode == proxyproto.Ignore {
		return nil
	}
	var rs *ruleSet
	if mode == proxyproto.Optional {
		s.useTable(tables.Load())
		rs = s.rules
	}
	for {
		h, n, err := proxyproto.Parse(s.buf)
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
		in.data = s.buf[s.off:]
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
	if n := len(s.rules.rules); n <= len(s.deadBuf) {
		s.dead = s.deadBuf[:n]
		clear(s.dead)
	} else {
		s.dead = make([]bool, n)
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
	c, in := s.conn, &s.in
	c.pending = s.buf[s.off:]
	c.route = r
	if in.tlsP.res == Match {
		c.hello = in.hello
	}
	if in.httpP.res == Match {
		c.req = in.req
	}
	if in.h2P.res == Match {
		c.req = in.req2
	}
}

// deliver hands the connection to r's Accept.
func (m *Mux) deliver(s *sniffer, r *Route) error {
	conn := s.conn
	// A route whose server is waiting in Accept takes the connection without
	// a timer.
	select {
	case r.ch <- conn:
		return nil
	default:
	}
	if q := s.opts.maxQueued; q > 0 {
		if r.queued.Add(1) > int64(q) {
			r.queued.Add(-1)
			return ErrRouteBusy
		}
		defer r.queued.Add(-1)
	}
	var timeout <-chan time.Time
	if d := s.opts.dispatchTimeout; d > 0 {
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
