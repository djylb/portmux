package portmux

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"testing"
	"testing/synctest"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/timeshim"
)

func TestDecisionKeepsPublishedRoute(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	oldCalls, newCalls := 0, 0
	var route *Route
	matcher := MatcherFunc(func(*Input) Result {
		if err := route.SetHandler(func(c *Conn) { newCalls++; _ = c.Close() }); err != nil {
			t.Fatal(err)
		}
		return Match
	})
	var err error
	route, err = m.Add(RouteConfig{Matchers: []Matcher{matcher}, Handler: func(c *Conn) { oldCalls++; _ = c.Close() }})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ServeConn(&memConn{}); err != nil || oldCalls != 1 || newCalls != 0 {
		t.Fatalf("old %d new %d err %v", oldCalls, newCalls, err)
	}
}

func TestResolverCannotDeliverUnpublishedRoute(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	var target *Route
	_, err := m.Add(RouteConfig{Resolve: func(*Input) (*Route, Result) { return target, Match }})
	if err != nil {
		t.Fatal(err)
	}
	err = m.Batch(func(b *Batch) error {
		var e error
		target, e = b.Add(RouteConfig{Handler: func(*Conn) { t.Fatal("unpublished handler ran") }})
		if e != nil {
			return e
		}
		return m.ServeConn(&memConn{})
	})
	if !errors.Is(err, ErrInvalidRoute) {
		t.Fatal(err)
	}
	if _, err = target.AcceptConn(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestBatchPanicClosesListener(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	var target *Route
	err := m.Batch(func(b *Batch) error {
		var err error
		target, err = b.Add(RouteConfig{})
		if err != nil {
			return err
		}
		panic("rollback")
	})
	if _, ok := errors.AsType[*PanicError](err); !ok {
		t.Fatal(err)
	}
	if _, err = target.AcceptConn(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestObserverPanicDoesNotInterruptHandler(t *testing.T) {
	calls := 0
	m := New(WithCloseEvents(true), WithObserver(func(Event) { calls++; panic("observer") }))
	defer func() { _ = m.Close() }()
	if err := m.ServeConn(&memConn{}); !errors.Is(err, ErrNoMatch) {
		t.Fatal(err)
	}
	_, err := m.Add(RouteConfig{Matchers: []Matcher{AnyBytes()}, Handler: func(c *Conn) { _ = c.Close() }})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ServeConn(&memConn{data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if p := m.LastObserverPanic(); p == nil || len(p.Stack) == 0 || calls != 3 || m.Stats().Open != 0 {
		t.Fatalf("calls %d, panic %v", calls, p)
	}
}

type deadlineConn struct {
	memConn
	failClear bool
}

func (c *deadlineConn) SetReadDeadline(d time.Time) error {
	if d.IsZero() == c.failClear {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestPeekDeadlineFailure(t *testing.T) {
	for _, failClear := range []bool{false, true} {
		raw := &deadlineConn{memConn: memConn{data: []byte("x")}, failClear: failClear}
		c, err := Peek(raw, Prefix("x"))
		if !errors.Is(err, io.ErrUnexpectedEOF) || (len(c.Unread()) == 1) != failClear {
			t.Fatalf("failClear %v, unread %q, err %v", failClear, c.Unread(), err)
		}
		_ = c.Close()
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 1, nil }
func TestWriteToKeepsShortPrefix(t *testing.T) {
	c := &Conn{conn: &memConn{}, pending: []byte("abc"), readErr: io.ErrUnexpectedEOF}
	if n, err := c.WriteTo(shortWriter{}); n != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("wrote %d: %v", n, err)
	}
	data, err := io.ReadAll(c)
	if string(data) != "bc" || !errors.Is(err, io.ErrUnexpectedEOF) || c.pending != nil {
		t.Fatalf("remaining %q: %v", data, err)
	}
}

func TestEntryBanPromotesAtCapacity(t *testing.T) {
	a, b := netip.AddrFrom4([4]byte{1}), netip.AddrFrom4([4]byte{2})
	key := banKey{client: netip.PrefixFrom(a, 32), entry: "entry", own: true}
	for _, policy := range []FullPolicy{FullFailOpen, FullFailClosed, FullEvictOldest} {
		l := newBanList(timeshim.Real)
		rec := records{max: 1, full: policy}
		if l.fail(key, 9*time.Second, 2, 10*time.Second, time.Second, rec) || !l.fail(key, 11*time.Second, 2, 10*time.Second, time.Second, rec) {
			t.Fatal("failed promotion", policy)
		}
		if !l.banned(a, 11*time.Second, rec, "", false) || l.size.Load() != 1 {
			t.Fatal("missing global ban", policy)
		}
		if l.banned(a, 12*time.Second, rec, key.entry, true) ||
			l.fail(key, 12*time.Second, 2, time.Second, time.Second, rec) ||
			!l.fail(key, 12*time.Second, 2, time.Second, time.Second, rec) {
			t.Fatal("same client lost its next failure window", policy)
		}
		if l.banned(b, 13*time.Second, rec, "", false) {
			t.Fatal("expired record refused new client", policy)
		}
	}
}

func TestReverseBucketTime(t *testing.T) {
	var l listener
	if !l.allow(1, 1, time.Time{}) || l.allow(1, 1, time.Time{}) {
		t.Fatal("listener refilled twice at the zero epoch")
	}
	b := tokenBucket{last: time.Second, tokens: 1}
	if !b.take(1, 1, 0) || b.last != time.Second || b.take(1, 1, time.Second) {
		t.Fatal(b)
	}
}

func TestPeekPanicReturnsPrefix(t *testing.T) {
	raw := &memConn{data: []byte("data")}
	c, err := Peek(raw, MatcherFunc(func(in *Input) Result {
		if len(in.Bytes()) == 0 {
			return NeedMore
		}
		panic("matcher")
	}))
	if _, ok := errors.AsType[*PanicError](err); !ok || string(c.Unread()) != "data" {
		t.Fatal(c.Unread(), err)
	}
	_ = c.Close()
}

type gatedWriter struct{ entered, release chan struct{} }

type gatedConn struct {
	memConn
	gate gatedWriter
}

func (c *gatedConn) Write(p []byte) (int, error) { return c.gate.Write(p) }

func TestCloseEventWaitsForWrite(t *testing.T) {
	raw := &gatedConn{gate: gatedWriter{make(chan struct{}), make(chan struct{})}}
	events := make(chan Event, 2)
	m := New(WithObserver(func(e Event) { events <- e }), WithCloseEvents(true))
	defer func() { _ = m.Close() }()
	_, err := m.Add(RouteConfig{Matchers: []Matcher{Always()}, Handler: func(c *Conn) {
		done := make(chan error, 1)
		go func() {
			_, writeErr := c.Write([]byte{'x'})
			done <- writeErr
		}()
		<-raw.gate.entered
		_ = c.Close()
		early := len(events) != 1
		close(raw.gate.release)
		if writeErr := <-done; writeErr != nil || early {
			t.Errorf("write error %v, early close event %v", writeErr, early)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ServeConn(raw); err != nil {
		t.Fatal(err)
	}
	if delivery, end := <-events, <-events; delivery.Closed || !end.Closed || end.Written != 1 {
		t.Fatal(delivery, end)
	}
}

func (w gatedWriter) Write([]byte) (int, error) { close(w.entered); <-w.release; return 1, nil }
func TestConcurrentPrefixRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Conn{conn: &memConn{data: []byte("z")}, pending: []byte("abc")}
		defer func() { _ = c.Close() }()
		w := gatedWriter{make(chan struct{}), make(chan struct{})}
		wrote := make(chan error, 1)
		go func() { _, err := c.WriteTo(w); wrote <- err }()
		<-w.entered
		got := make(chan string, 1)
		go func() { var p [2]byte; n, _ := c.Read(p[:]); got <- string(p[:n]) }()
		synctest.Wait()
		close(w.release)
		if err := <-wrote; !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(err)
		}
		if s := <-got; s != "bc" {
			t.Fatal(s)
		}
	})
}

func TestNilEntryOptions(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	before := len(m.Entries())
	e := m.Entry("new")
	e.SetOptions()
	e.SetOptions(nil)
	e.SetOptions(nil, nil)
	if len(m.Entries()) != before {
		t.Fatal(m.Entries())
	}
}

func TestDeliveryDurationFromZero(t *testing.T) {
	for _, handler := range []bool{false, true} {
		for _, delay := range []time.Duration{0, time.Hour} {
			clock := timeshim.NewFake(time.Time{})
			events := make(chan Event, 2)
			m := New(WithClock(clock), WithCloseEvents(true), WithObserver(func(e Event) {
				if handler && !e.Closed {
					clock.Advance(delay)
				}
				events <- e
			}))
			serve := func(c *Conn) { clock.Advance(time.Second); _ = c.Close() }
			cfg := RouteConfig{Matchers: []Matcher{Always()}}
			if handler {
				cfg.Handler = serve
			}
			r, err := m.Add(cfg)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- m.ServeConn(&memConn{}) }()
			if !handler {
				c, e := r.AcceptConn()
				if e != nil {
					t.Fatal(e)
				}
				serve(c)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			for range 2 {
				e := <-events
				if e.Closed && e.Duration != time.Second {
					t.Fatalf("handler %v delay %v: duration %v", handler, delay, e.Duration)
				}
			}
			_ = m.Close()
		}
	}
}

func TestPortableDescriptions(t *testing.T) {
	matcher := Regexp(regexp.MustCompilePOSIX("^a$"), 8)
	reloaded, err := ParseMatcher(describe(matcher), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []Matcher{matcher, reloaded} {
		if rule.Match(&Input{data: []byte("x\na\ny"), final: true}) != Match {
			t.Fatal(describe(rule))
		}
	}
	if _, err = FormatMatcher(And(Named("TLS()", SSH()))); err == nil {
		t.Fatal("accepted misleading description")
	}
	m := TLS()
	for range maxParseDepth - 1 {
		m = Not(m)
	}
	if _, err = FormatMatcher(m); err != nil {
		t.Fatal(err)
	}
	if _, err = FormatMatcher(Not(m)); err == nil {
		t.Fatal("accepted excessive nesting")
	}
	_, err = ParseMatcher("custom()", &Names{MatcherFuncs: map[string]func(...string) (Matcher, error){"custom": func(...string) (Matcher, error) { panic("factory") }}})
	if _, ok := errors.AsType[*PanicError](err); !ok {
		t.Fatal(err)
	}
}

type closeSensitiveConn struct {
	memConn
	closed bool
}

func (c *closeSensitiveConn) Close() error { c.closed = true; return nil }
func (c *closeSensitiveConn) RemoteAddr() net.Addr {
	if c.closed {
		panic("address after close")
	}
	return memRemote
}

func TestEventAddressLifetime(t *testing.T) {
	for _, observed := range []bool{true, false} {
		var events []Event
		m := New()
		if observed {
			m.SetOptions(WithObserver(func(e Event) { events = append(events, e) }))
		}
		_, err := m.Add(RouteConfig{Matchers: []Matcher{Prefix("x")}, Handler: func(c *Conn) { _ = c.Close(); panic("handler") }})
		if err != nil {
			t.Fatal(err)
		}
		err = m.ServeConn(&closeSensitiveConn{memConn: memConn{data: []byte("x")}})
		if _, ok := errors.AsType[*PanicError](err); !ok {
			t.Fatal(err)
		}
		m.SetOptions(WithProxyProtocol(func(string, net.Addr, net.Addr) proxyproto.Policy { panic("policy") }))
		err = m.ServeConn(&closeSensitiveConn{memConn: memConn{data: []byte("x")}})
		if _, ok := errors.AsType[*PanicError](err); !ok {
			t.Fatal(err)
		}
		if observed && (len(events) != 3 || events[0].Sniffed != 1 || events[1].Sniffed != 1 || events[0].Elapsed != events[1].Elapsed) {
			t.Fatal(events)
		}
		for _, e := range events {
			if e.Remote != memRemote || e.Peer != memRemote || e.Local != memLocal {
				t.Fatal(e)
			}
		}
		_ = m.Close()
	}
}

type reenterListener struct {
	net.Listener
	closeFunc func() error
}

func (l reenterListener) Close() error { return l.closeFunc() }
func TestCloseInProgress(t *testing.T) {
	m := New()
	release, entered := make(chan struct{}), make(chan error, 1)
	l := reenterListener{closeFunc: func() error { entered <- m.Close(); <-release; return io.ErrUnexpectedEOF }}
	m.listeners[&listener{}] = l
	result := make(chan error, 1)
	go func() { result <- m.Close() }()
	inner := <-entered
	overlap := m.Close()
	close(release)
	if err := <-result; !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(inner, net.ErrClosed) || !errors.Is(overlap, net.ErrClosed) {
		t.Fatal(err, inner, overlap)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

type panicSilencer struct{ Matcher }

func (panicSilencer) Silences(func(time.Duration)) { panic("silence") }

func TestPeekPreparationPanic(t *testing.T) {
	matcher := panicSilencer{Always()}
	p := NewPeeker([]Matcher{matcher})
	for _, peek := range []func(net.Conn) (*Conn, int, error){
		p.Peek,
		func(c net.Conn) (*Conn, int, error) { return PeekAny(c, []Matcher{matcher}) },
	} {
		raw := &memConn{data: []byte("x")}
		c, i, err := peek(raw)
		if e, ok := errors.AsType[*PanicError](err); !ok || e.Value != "silence" || i != -1 || c == nil {
			t.Fatal(i, err)
		}
		var b [1]byte
		if n, e := c.Read(b[:]); n != 1 || e != nil || b[0] != 'x' {
			t.Fatal(n, e)
		}
		_ = c.Close()
	}
}

type deliveryClock struct {
	timeshim.Clock
	fail bool
}

func (c *deliveryClock) Now() time.Time {
	if c.fail {
		panic("delivery clock")
	}
	return time.Time{}
}

func TestDeliveryWithFailedClock(t *testing.T) {
	for _, handler := range []bool{false, true} {
		clk := &deliveryClock{Clock: timeshim.Real}
		events := make(chan Event, 2)
		m := New(WithClock(clk), WithObserver(func(e Event) { events <- e }), WithCloseEvents(true))
		clk.fail = true
		cfg := RouteConfig{Matchers: []Matcher{Prefix("x")}}
		if handler {
			cfg.Handler = func(c *Conn) { _ = m.Close(); _ = c.Close() }
		}
		r, err := m.Add(cfg)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- m.ServeConn(&memConn{data: []byte("x")}) }()
		if !handler {
			c, e := r.AcceptConn()
			if c == nil || e != nil {
				t.Fatal(c, e)
			}
			_ = m.Close()
			_ = c.Close()
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		first, second := <-events, <-events
		if first.Closed {
			first, second = second, first
		}
		e, panicked := errors.AsType[*PanicError](second.Err)
		if first.Closed || first.Err != nil || !second.Closed || !panicked || e.Value != "delivery clock" || second.Duration != 0 || first.Sniffed != 1 || second.Sniffed != first.Sniffed || second.Elapsed != first.Elapsed || second.Route != r || first.Route != r {
			t.Fatal(first, second)
		}
		if st := m.Stats(); st.Open != 0 || st.Delivered != 1 || st.Pending != 0 {
			t.Fatal(st)
		}
		_ = m.Close()
	}
}

func TestObservationAndParserAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation allocates")
	}
	raw := &memConn{}
	m := New(WithObserver(func(Event) {}))
	defer func() { _ = m.Close() }()
	_, err := m.Add(RouteConfig{Matchers: []Matcher{Always()}, Handler: func(c *Conn) { _ = c.Close() }})
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() {
		if e := m.ServeConn(raw); e != nil {
			t.Fatal(e)
		}
	}); n > 1 {
		t.Errorf("handler allocated %v times", n)
	}
	request := []byte("GET /?q=one&v=%20 HTTP/1.1\r\n\r\n")
	if n := testing.AllocsPerRun(100, func() {
		if _, e := httphead.Parse(request); e != nil {
			t.Fatal(e)
		}
	}); n > 2 {
		t.Errorf("query allocated %v times", n)
	}
	stream := []byte("<stream:stream xmlns='jabber:server' xmlns:stream='" + streamNS + "'>")
	if n := testing.AllocsPerRun(100, func() {
		if matchXMPP(stream) != Match {
			t.Fatal("stream")
		}
	}); n != 0 {
		t.Errorf("XMPP allocated %v times", n)
	}
}
