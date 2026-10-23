package portmux

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/internal/testutil"
)

// TestChangesAfterClose checks that a closed Mux takes no routes.
func TestChangesAfterClose(t *testing.T) {
	m := New()
	_ = m.Close()
	r, err := m.Add(RouteConfig{Matchers: []Matcher{AnyBytes()}})
	if !errors.Is(err, net.ErrClosed) || r == nil {
		t.Fatalf("Add after Close = %v, %v", r, err)
	}
	if _, err := r.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept of a route added after Close = %v", err)
	}
	if l := m.Listen(AnyBytes()); l == nil || len(m.Routes()) != 0 {
		t.Fatalf("Listen after Close = %v, routes %v", l, m.Routes())
	}
	if err := m.Batch(func(*Batch) error { return nil }); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Batch after Close = %v", err)
	}
}

// TestResolverKeepsToEntries checks that a resolver cannot send a
// connection to a route limited to another entry.
func TestResolverKeepsToEntries(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	internal := mustAdd(t, m, RouteConfig{Entries: []string{"internal"}})
	open := mustAdd(t, m, RouteConfig{})
	mustAdd(t, m, RouteConfig{Resolve: func(in *Input) (*Route, Result) {
		if len(in.Bytes()) == 0 {
			return nil, NeedMore
		}
		if in.Bytes()[0] == 'I' {
			return internal, Match
		}
		return open, Match
	}})
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("I"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrEntryMismatch) {
		t.Fatalf("reported %v, want ErrEntryMismatch", err)
	}
	_, _ = dial(t, m).Write([]byte("O"))
	accept(t, open)
}

// TestHandlerPanic checks that a panicking handler closes only its
// connection and is reported.
func TestHandlerPanic(t *testing.T) {
	events := make(chan Event, 4)
	m := startMux(t, WithObserver(func(ev Event) {
		if ev.Err != nil {
			events <- ev
		}
	}))
	mustAdd(t, m, RouteConfig{Matchers: []Matcher{Prefix("P")}, Handler: func(*Conn) { panic("handler failed") }})
	ok := m.Listen(Prefix("O"))
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("P"))
	expectClosed(t, c)
	select {
	case ev := <-events:
		var pe *PanicError
		if !errors.As(ev.Err, &pe) || pe.Value != "handler failed" || len(pe.Stack) == 0 || ev.Route == nil {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event for the panic")
	}
	_, _ = dial(t, m).Write([]byte("O"))
	accept(t, ok)

	// ServeConn returns the panic.
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	go func() { _, _ = b.Write([]byte("P")) }()
	var pe *PanicError
	if err := m.ServeConn(a); !errors.As(err, &pe) {
		t.Fatalf("ServeConn = %v", err)
	}
}

// TestBanWithoutDuration checks that bans of no duration are not counted
// as bans.
func TestBanWithoutDuration(t *testing.T) {
	events := make(chan Event, 8)
	m := startMux(t, WithBanPerClient(1, time.Minute, 0), WithObserver(func(ev Event) { events <- ev }))
	m.Listen(Prefix("A"))
	serve(t, m)
	for range 2 {
		c := dial(t, m)
		_, _ = c.Write([]byte("X"))
		expectClosed(t, c)
		if ev := <-events; !errors.Is(ev.Err, ErrNoMatch) || ev.Banned {
			t.Fatalf("event %+v", ev)
		}
	}
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("Bans = %+v", bans)
	}
}

// waitForSilence is a matcher of its own that decides on silence.
type waitForSilence time.Duration

func (w waitForSilence) Match(in *Input) Result {
	switch {
	case len(in.Bytes()) > 0:
		return NoMatch
	case in.Elapsed() >= time.Duration(w):
		return Match
	}
	return NeedMore
}

func (w waitForSilence) Silences(add func(time.Duration)) { add(time.Duration(w)) }

// TestSilencerOfYourOwn checks that a matcher of its own is checked again
// for silence at the durations it reports.
func TestSilencerOfYourOwn(t *testing.T) {
	m := startMux(t)
	route := m.Listen(Named("banner", waitForSilence(50*time.Millisecond)))
	serve(t, m)
	start := time.Now()
	dial(t, m) // sends nothing
	accept(t, route)
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("delivered after %v", elapsed)
	}
}

// TestEntriesAndOptions checks Mux.Entries, ResetOptions of one setting and
// Config.Options.
func TestEntriesAndOptions(t *testing.T) {
	m := startMux(t)
	mustAdd(t, m, RouteConfig{Matchers: []Matcher{AnyBytes()}, Entries: []string{"web"}})
	m.Entry("lb").SetOptions(WithSniffTimeout(time.Second), WithMaxSniffBytes(512))
	serve(t, m)
	if got := m.Entries(); !slices.Equal(got, []string{"", "lb", "web"}) {
		t.Fatalf("Entries = %q", got)
	}

	lb := m.Entry("lb")
	lb.ResetOptions(WithSniffTimeout(0))
	if c := lb.Config(); c.SniffTimeout != DefaultSniffTimeout || c.MaxSniffBytes != 512 {
		t.Fatalf("after resetting the sniff timeout: %+v", c)
	}
	lb.ResetOptions()
	if got := m.Entries(); slices.Contains(got, "lb") {
		t.Fatalf("Entries after ResetOptions = %q", got)
	}

	m.SetOptions(WithMaxPending(7), WithClientPrefix(24, 56), WithMaxQueued(3), WithBanPerClient(4, time.Minute, time.Hour))
	want := m.Config()
	other := New(want.Options()...)
	defer func() { _ = other.Close() }()
	if got := other.Config(); got != want {
		t.Fatalf("Config of Options = %+v, want %+v", got, want)
	}
}

// TestBanPrefix checks bans of whole networks.
func TestBanPrefix(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	m.BanPrefix(netip.MustParsePrefix("::ffff:192.0.2.0/120"), time.Minute)
	now := m.bans.now()
	if !m.bans.banned(netip.MustParseAddr("192.0.2.77"), now) || m.bans.banned(netip.MustParseAddr("192.0.3.1"), now) {
		t.Fatal("192.0.2.0/24 not banned as IPv4")
	}
	if bans := m.Bans(); len(bans) != 1 || bans[0].Client != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("Bans = %+v", bans)
	}
	if m.UnbanPrefix(netip.MustParsePrefix("192.0.2.0/25")) || !m.UnbanPrefix(netip.MustParsePrefix("192.0.2.0/24")) {
		t.Fatal("UnbanPrefix")
	}
}

// TestRemoteIPFunc checks a block list that changes without route changes.
func TestRemoteIPFunc(t *testing.T) {
	var blocked atomic.Bool
	log := newErrorLog()
	m := startMux(t, log.option())
	mustAdd(t, m, RouteConfig{Priority: 1, Reject: true, Matchers: []Matcher{RemoteIPFunc(func(netip.Addr) bool { return blocked.Load() })}})
	route := m.Listen(AnyBytes())
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("x"))
	accept(t, route)
	blocked.Store(true)
	c := dial(t, m)
	_, _ = c.Write([]byte("x"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRefused) {
		t.Fatalf("reported %v", err)
	}
	if s := (RemoteIPFunc(func(netip.Addr) bool { return false })).(interface{ String() string }).String(); s != "RemoteIPFunc(...)" {
		t.Fatalf("String = %q", s)
	}

	// LocalIPFunc looks at the address the client connected to.
	var local atomic.Value
	in := NewInput(nil, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443})
	m2 := LocalIPFunc(func(a netip.Addr) bool { local.Store(a); return a == netip.MustParseAddr("192.0.2.1") })
	if m2.Match(in) != Match || local.Load() != netip.MustParseAddr("192.0.2.1") {
		t.Fatal("LocalIPFunc does not match the local address")
	}
	if m2.Match(NewInput(nil, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2)})) != NoMatch {
		t.Fatal("LocalIPFunc matched another address")
	}
}

type parsedKey struct{}

// TestConnCarriesParses checks the values and requests a Conn and an Event
// carry.
func TestConnCarriesParses(t *testing.T) {
	events := make(chan Event, 4)
	m := startMux(t, WithObserver(func(ev Event) { events <- ev }))
	web := m.Listen(MatcherFunc(func(in *Input) Result {
		req, res := in.HTTPRequest()
		if res == Match {
			in.SetValue(parsedKey{}, req.Method)
		}
		return res
	}))
	h2c := m.Listen(HTTP2())
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nHost: Web.Example:8080\r\n\r\n"))
	c := accept(t, web)
	if c.Value(parsedKey{}) != "GET" || c.HTTPRequest() == nil || c.HTTP2Request() != nil || c.RequestedName() != "web.example" {
		t.Fatalf("HTTP/1 Conn: value %v, request %v, h2c %v, name %q", c.Value(parsedKey{}), c.HTTPRequest(), c.HTTP2Request(), c.RequestedName())
	}
	if ev := <-events; ev.HTTPRequest == nil || ev.Name != "web.example" {
		t.Fatalf("event %+v", ev)
	}

	req, _ := http.NewRequest("GET", "http://h2c.example/x", nil)
	_, _ = dial(t, m).Write(testutil.H2CBytes(t, req))
	c = accept(t, h2c)
	if c.HTTP2Request() == nil || c.HTTPRequest() != nil || c.RequestedName() != "h2c.example" || c.Value(parsedKey{}) != nil {
		t.Fatalf("h2c Conn: request %v, h2c %v, name %q", c.HTTPRequest(), c.HTTP2Request(), c.RequestedName())
	}
	if ev := <-events; ev.HTTP2Request == nil || !strings.HasPrefix(ev.Name, "h2c") {
		t.Fatalf("event %+v", ev)
	}
}

// TestResolveHostsPassesClosedRoutes replaces the route of a name while
// connections arrive: a closed route is passed over, so none fails.
func TestResolveHostsPassesClosedRoutes(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	var hosts hostmatch.Map[*Route]
	old := mustAdd(t, m, RouteConfig{})
	hosts.Set("*", old)
	mustAdd(t, m, RouteConfig{Resolve: ResolveDomain(&hosts)})
	other := m.Listen(HTTP1()) // after the resolver, for names it passes on
	serve(t, m)

	// The old route is closed, the table still names it: the name goes on.
	_ = old.Close()
	_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))
	accept(t, other)

	// The replacement order: add, point the name, close the old one.
	next := mustAdd(t, m, RouteConfig{})
	hosts.Set("*", next)
	_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))
	accept(t, next)
}

// TestRouteConfigChecks checks that Listen needs matchers and that MaxConns
// is not negative.
func TestRouteConfigChecks(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Listen without matchers did not panic")
			}
		}()
		m.Listen()
	}()
	if _, err := m.Add(RouteConfig{MaxConns: -1}); !errors.Is(err, ErrInvalidRoute) {
		t.Errorf("Add with MaxConns -1 = %v", err)
	}
	r := m.Listen(AnyBytes())
	if err := r.SetMaxConns(-1); !errors.Is(err, ErrInvalidRoute) {
		t.Errorf("SetMaxConns(-1) = %v", err)
	}
	if s := (MatcherFunc(func(*Input) Result { return NoMatch })).String(); s != "MatcherFunc" {
		t.Errorf("MatcherFunc.String = %q", s)
	}
	if _, err := m.Upsert(RouteConfig{}); !errors.Is(err, ErrInvalidRoute) {
		t.Errorf("Upsert without a name = %v", err)
	}
}

type magicKey struct{}

// TestRequestedNameOfYourOwn routes a protocol of its own by the name a
// matcher sets, and reports it with the peer and values in events.
func TestRequestedNameOfYourOwn(t *testing.T) {
	events := make(chan Event, 4)
	m := startMux(t, WithObserver(func(ev Event) { events <- ev }))
	var hosts hostmatch.Map[*Route]
	target := mustAdd(t, m, RouteConfig{})
	hosts.Set("tunnel.example", target)
	magic := MatcherFunc(func(in *Input) Result {
		b := in.Bytes()
		if len(b) < 6 {
			return NeedMore
		}
		if string(b[:3]) != "MGC" {
			return NoMatch
		}
		in.SetRequestedName(string(b[3:6]) + ".example")
		in.SetValue(magicKey{}, "seen")
		return Match
	})
	mustAdd(t, m, RouteConfig{Matchers: []Matcher{magic}, Resolve: ResolveDomain(&hosts)})
	hosts.Set("Tun.example", target)
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("MGCtun"))
	c := accept(t, target)
	if c.RequestedName() != "tun.example" {
		t.Fatalf("RequestedName = %q", c.RequestedName())
	}
	ev := <-events
	if ev.Name != "tun.example" || ev.Value(magicKey{}) != "seen" || ev.Peer == nil || ev.Peer.String() != ev.Remote.String() {
		t.Fatalf("event %+v", ev)
	}
	in := NewInput(nil, nil)
	in.SetRequestedName("not a host")
	if _, res := in.RequestedName(); res != NoMatch {
		t.Fatalf("invalid name RequestedName = %v", res)
	}
}

// TestPeekAny tells which matcher took a connection.
func TestPeekAny(t *testing.T) {
	for data, want := range map[string]int{"SSH-2.0-x\r\n": 2, "GET / HTTP/1.1\r\nHost: h\r\n\r\n": 1, "\x00\x01": -1} {
		a, b := net.Pipe()
		go func() { _, _ = b.Write([]byte(data)); _ = b.Close() }()
		conn, i, err := PeekAny(a, []Matcher{TLS(), HTTP1(), SSH()})
		if i != want || (want >= 0) != (err == nil) {
			t.Errorf("%q: PeekAny = %d, %v; want %d", data, i, err, want)
		}
		if want < 0 && !errors.Is(err, ErrNoMatch) {
			t.Errorf("%q: error %v", data, err)
		}
		_ = conn.Close()
	}
}

// TestUpsertKeepsListener reloads routes by name: a route that stays keeps
// its listener, so a server waiting in Accept goes on, and one whose kind
// changes is replaced.
func TestUpsertKeepsListener(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	web, err := m.Upsert(RouteConfig{Name: "web", Matchers: []Matcher{Prefix("A")}})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, m)
	accepted := make(chan *Conn)
	go func() {
		for {
			c, err := web.AcceptConn()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()

	// New matchers and priority, the same route and listener.
	if r, err := m.Upsert(RouteConfig{Name: "web", Matchers: []Matcher{Prefix("B")}, Priority: 5}); err != nil || r != web {
		t.Fatalf("Upsert = %v, %v; want the same route", r, err)
	}
	_, _ = dial(t, m).Write([]byte("B"))
	if c := <-accepted; c == nil || web.Priority() != 5 {
		t.Fatal("updated route did not deliver")
	}

	// A handler and a resolver change in place.
	served := make(chan struct{}, 1)
	if err := web.SetHandler(func(c *Conn) { _ = c.Close(); served <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	_, _ = dial(t, m).Write([]byte("B"))
	<-served
	if err := web.SetHandler(nil); err != nil {
		t.Fatal(err)
	}

	// Becoming a reject route replaces it: the old listener closes.
	r, err := m.Upsert(RouteConfig{Name: "web", Matchers: []Matcher{Prefix("B")}, Reject: true})
	if err != nil || r == web || !r.Reject() {
		t.Fatalf("Upsert to reject = %v, %v", r, err)
	}
	if _, ok := <-accepted; ok {
		t.Fatal("old listener still open")
	}
	c := dial(t, m)
	_, _ = c.Write([]byte("B"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRefused) {
		t.Fatalf("reported %v", err)
	}
	if err := r.SetHandler(func(*Conn) {}); !errors.Is(err, ErrInvalidRoute) {
		t.Fatalf("SetHandler on a reject route = %v", err)
	}
}

// TestCloseEvents checks the events of closed connections.
func TestCloseEvents(t *testing.T) {
	events := make(chan Event, 8)
	m := startMux(t, WithCloseEvents(true), WithObserver(func(ev Event) { events <- ev }))
	route := m.Listen(Prefix("PING"))
	serve(t, m)

	client := dial(t, m)
	_, _ = client.Write([]byte("PING"))
	c := accept(t, route)
	if ev := <-events; ev.Closed || ev.Err != nil {
		t.Fatalf("delivery event %+v", ev)
	}
	readN(t, c, 4)
	_, _ = c.Write([]byte("PONG!"))
	time.Sleep(10 * time.Millisecond)
	_ = c.Close()
	_ = c.Close() // reported once
	ev := <-events
	if !ev.Closed || ev.Read != 4 || ev.Written != 5 || ev.Duration < 10*time.Millisecond || ev.Route != route {
		t.Fatalf("close event %+v", ev)
	}
	select {
	case ev := <-events:
		t.Fatalf("second close reported: %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}

	m.SetOptions(WithCloseEvents(false))
	_, _ = dial(t, m).Write([]byte("PING"))
	c = accept(t, route)
	<-events
	_ = c.Close()
	select {
	case ev := <-events:
		t.Fatalf("close reported without WithCloseEvents: %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}
}
