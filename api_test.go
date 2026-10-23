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
