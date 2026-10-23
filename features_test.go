package portmux

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/proxyproto"
)

var loopback = netip.MustParsePrefix("127.0.0.0/8")

func TestSilentRouteGetsServerFirstClients(t *testing.T) {
	m := startMux(t)
	web := m.Listen(HTTP1())
	m.Listen(TLS())
	ssh := m.Listen(SSH(), Silent(100*time.Millisecond))
	serve(t, m)

	start := time.Now()
	silent := dial(t, m)
	got := accept(t, ssh)
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("silent connection routed after %v", elapsed)
	}
	if got.HTTPRequest() != nil || got.Route() != ssh {
		t.Fatal("wrong metadata for a silent connection")
	}
	_, _ = got.Write([]byte("SSH-2.0-test\r\n"))
	if b := readN(t, silent, 5); string(b) != "SSH-2" {
		t.Fatalf("banner %q", b)
	}

	// A client that talks first is unaffected by the silence check.
	c := dial(t, m)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	accept(t, web)
}

func TestSilenceCheckThatFailsKeepsWaiting(t *testing.T) {
	m := startMux(t)
	web := m.Listen(HTTP1())
	elsewhere := netip.MustParsePrefix("192.0.2.0/24")
	never := m.Listen(And(RemoteIP(elsewhere), Silent(30*time.Millisecond)))
	later := m.Listen(Silent(150 * time.Millisecond))
	serve(t, m)

	// The first check finds no route, so the second one applies.
	start := time.Now()
	_ = dial(t, m)
	accept(t, later)
	if elapsed := time.Since(start); elapsed < 140*time.Millisecond {
		t.Fatalf("routed after %v", elapsed)
	}

	// Bytes that arrive after a failed check are matched as usual.
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
	c := dial(t, m)
	time.Sleep(80 * time.Millisecond)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	accept(t, web)
	expectNoAccept(t, never, 20*time.Millisecond)
}

func TestRemoteIPDecidesWithoutBytes(t *testing.T) {
	m := startMux(t)
	other := m.Listen(RemoteIP(netip.MustParsePrefix("192.0.2.0/24")))
	local := m.Listen(RemoteIP(loopback, netip.MustParsePrefix("::1/128")))
	serve(t, m)

	start := time.Now()
	_ = dial(t, m)
	accept(t, local)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("routed after %v", elapsed)
	}
	expectNoAccept(t, other, 20*time.Millisecond)
}

func TestAddressMatchersUseProxyHeader(t *testing.T) {
	m := startMux(t, WithProxyProtocol(func(_ string, _, _ net.Addr) proxyproto.Policy { return proxyproto.Required }))
	proxied := m.Listen(And(RemoteIP(netip.MustParsePrefix("192.0.2.0/24")), LocalIP(netip.MustParsePrefix("198.51.100.2/32")), LocalPort(443)))
	m.Listen(AnyBytes())
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("PROXY TCP4 192.0.2.1 198.51.100.2 40000 443\r\n"))
	got := accept(t, proxied)
	if got.RemoteAddr().String() != "192.0.2.1:40000" {
		t.Fatalf("RemoteAddr = %v", got.RemoteAddr())
	}
}

func TestAddressMatchers(t *testing.T) {
	in := &Input{
		remote: &net.TCPAddr{IP: net.ParseIP("::ffff:10.1.2.3"), Port: 5000},
		local:  &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8443},
	}
	tests := []struct {
		name string
		m    Matcher
		want Result
	}{
		{"remote v4 in mapped address", RemoteIP(netip.MustParsePrefix("10.0.0.0/8")), Match},
		{"remote mapped prefix", RemoteIP(netip.MustParsePrefix("::ffff:10.0.0.0/104")), Match},
		{"remote outside", RemoteIP(netip.MustParsePrefix("10.2.0.0/16")), NoMatch},
		{"no prefixes", RemoteIP(), NoMatch},
		{"local v6", LocalIP(netip.MustParsePrefix("2001:db8::/32")), Match},
		{"local port", LocalPort(80, 8443), Match},
		{"other port", LocalPort(80), NoMatch},
	}
	for _, tt := range tests {
		if got := tt.m.Match(in); got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
		}
	}
	unix := &Input{remote: &net.UnixAddr{Name: "/tmp/s", Net: "unix"}}
	if got := RemoteIP(netip.MustParsePrefix("0.0.0.0/0")).Match(unix); got != NoMatch {
		t.Errorf("unix address = %v", got)
	}
}

func TestCombinators(t *testing.T) {
	yes := MatcherFunc(func(*Input) Result { return Match })
	no := MatcherFunc(func(*Input) Result { return NoMatch })
	more := MatcherFunc(func(*Input) Result { return NeedMore })
	tests := []struct {
		name string
		m    Matcher
		want Result
	}{
		{"and all", And(yes, yes), Match},
		{"and early no", And(more, no), NoMatch},
		{"and waits", And(yes, more), NeedMore},
		{"and empty", And(), Match},
		{"or any", Or(no, yes), Match},
		{"or waits", Or(no, more), NeedMore},
		{"or none", Or(no, no), NoMatch},
		{"or empty", Or(), NoMatch},
		{"not match", Not(yes), NoMatch},
		{"not no", Not(no), Match},
		{"not more", Not(more), NeedMore},
	}
	for _, tt := range tests {
		if got := tt.m.Match(&Input{}); got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
		}
	}
	var got []time.Duration
	reportSilences([]Matcher{And(Or(Silent(2*time.Second)), Not(Silent(0)))}, func(d time.Duration) { got = append(got, d) })
	if len(got) != 2 || got[0] != 2*time.Second || got[1] != minSilence {
		t.Fatalf("silences = %v", got)
	}
	for name, fn := range map[string]func(){
		"And": func() { And(yes, nil) },
		"Or":  func() { Or(nil) },
		"Not": func() { Not(nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s(nil) did not panic", name)
				}
			}()
			fn()
		}()
	}
}

func TestSOCKSMatchers(t *testing.T) {
	user := "bob\x00"
	socks4 := append([]byte{4, 1, 0, 80, 192, 0, 2, 1}, user...)
	socks4a := append(append([]byte{4, 1, 0, 80, 0, 0, 0, 1}, user...), "example.com\x00"...)
	tests := []struct {
		name string
		m    Matcher
		data []byte
		want Result
	}{
		{"socks5 greeting", SOCKS5(), []byte{5, 2, 0, 2}, Match},
		{"socks5 partial", SOCKS5(), []byte{5, 2, 0}, NeedMore},
		{"socks5 no methods", SOCKS5(), []byte{5, 0}, NoMatch},
		{"socks5 other", SOCKS5(), []byte("GET"), NoMatch},
		{"socks5 empty", SOCKS5(), nil, NeedMore},
		{"socks4", SOCKS4(), socks4, Match},
		{"socks4 partial user", SOCKS4(), socks4[:10], NeedMore},
		{"socks4a", SOCKS4(), socks4a, Match},
		{"socks4a partial host", SOCKS4(), socks4a[:len(socks4a)-3], NeedMore},
		{"socks4 bad command", SOCKS4(), []byte{4, 3}, NoMatch},
		{"socks4 long user", SOCKS4(), append([]byte{4, 1, 0, 80, 1, 2, 3, 4}, bytes.Repeat([]byte("u"), 300)...), NoMatch},
	}
	for _, tt := range tests {
		if got := tt.m.Match(&Input{data: tt.data}); got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestServeConn(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	route := m.Listen(Prefix("TST"))

	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() { _, _ = c2.Write([]byte("TSTpipe")) }()
	done := make(chan error, 1)
	go func() { done <- m.ServeConn(c1) }()
	got := accept(t, route)
	if err := <-done; err != nil {
		t.Fatalf("ServeConn = %v", err)
	}
	if b := readN(t, got, 7); string(b) != "TSTpipe" {
		t.Fatalf("read %q", b)
	}

	c3, c4 := net.Pipe()
	go func() { _, _ = c4.Write([]byte("nope")) }()
	if err := m.ServeConn(c3); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("ServeConn = %v", err)
	}
	if _, err := c4.Read(make([]byte, 1)); err == nil {
		t.Fatal("rejected connection left open")
	}
}

func TestShutdownDeliversPendingConnections(t *testing.T) {
	m := startMux(t)
	web := m.Listen(HTTP1())
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n"))
	waitPending(t, m.Mux, 1)

	done := make(chan error, 1)
	go func() { done <- m.Shutdown(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	if _, err := net.Dial("tcp", m.Addr().String()); err == nil {
		t.Fatal("listener still accepts during Shutdown")
	}
	_, _ = c.Write([]byte("Host: h\r\n\r\n"))
	accept(t, web)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return")
	}
}

func TestShutdownGivesUpAtDeadline(t *testing.T) {
	m := startMux(t)
	m.Listen(HTTP1())
	serve(t, m)

	c := dial(t, m)
	waitPending(t, m.Mux, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v", err)
	}
	expectClosed(t, c)
}

func waitPending(t *testing.T, m *Mux, n int64) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if m.Stats().Pending == n {
			return
		}
	}
	t.Fatalf("pending = %d, want %d", m.Stats().Pending, n)
}

func TestMaxPendingPerClient(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithMaxPendingPerClient(1), WithSniffTimeout(time.Second))
	route := m.Listen(Prefix("A"))
	serve(t, m)

	_ = dial(t, m) // silent, holds the address's slot
	waitPending(t, m.Mux, 1)
	c := dial(t, m)
	_, _ = c.Write([]byte("A"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("reported %v", err)
	}
	expectNoAccept(t, route, 20*time.Millisecond)
}

func TestNestedMuxOverTLS(t *testing.T) {
	outer := startMux(t)
	secure := outer.Listen(TLS(SNI("tunnel.example.com")))
	serve(t, outer)

	inner := New()
	defer func() { _ = inner.Close() }()
	agents := inner.Listen(Prefix("AGENT/1\n"))
	go func() {
		_ = inner.Serve(tls.NewListener(secure, &tls.Config{Certificates: []tls.Certificate{certificate(t)}}))
	}()

	tc := tls.Client(dial(t, outer), &tls.Config{ServerName: "tunnel.example.com", InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tc.Write([]byte("AGENT/1\nhello")); err != nil {
		t.Fatal(err)
	}
	got := accept(t, agents)
	if b := readN(t, got, 13); string(b) != "AGENT/1\nhello" {
		t.Fatalf("read %q", b)
	}
	if _, ok := got.NetConn().(*tls.Conn); !ok {
		t.Fatalf("inner connection is %T", got.NetConn())
	}
}

func TestHeaderFilterAndLazyHeader(t *testing.T) {
	req, res := parseHTTP([]byte("GET / HTTP/1.1\r\nHost: h\r\nX-Kind: a, B\r\n" +
		"X-Any:\r\nx-kind: c\r\n\r\n"))
	if res != Match {
		t.Fatal(res)
	}
	tests := []struct {
		name   string
		filter HTTPFilter
		want   bool
	}{
		{"token", Header("X-Kind", "b"), true},
		{"second field", Header("x-KIND", "c"), true},
		{"missing token", Header("X-Kind", "d"), false},
		{"any value", Header("X-Any"), true},
		{"missing field", Header("X-None"), false},
	}
	for _, tt := range tests {
		if got := tt.filter.Match(req); got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
		}
	}
	h := req.Header()
	if got := h.Values("X-Kind"); len(got) != 2 || got[0] != "a, B" || got[1] != "c" {
		t.Fatalf("X-Kind = %q", got)
	}
	if got, ok := h["X-Any"]; !ok || got[0] != "" {
		t.Fatalf("X-Any = %q", got)
	}
	// Obsolete line folding is rejected rather than interpreted.
	for _, head := range []string{
		"GET / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n",
		"GET / HTTP/1.1\r\n X: first\r\n\r\n",
	} {
		if _, res := parseHTTP([]byte(head)); res != NoMatch {
			t.Errorf("folded %q: %v", head, res)
		}
	}
	if req.Header()["Host"] != nil {
		t.Fatal("Host in Header")
	}
}

// TestSilentWithoutDeadlineSupport checks that a connection that cannot
// extend deadlines is still matched by its bytes.
func TestSilentWithoutDeadlineSupport(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	m.Listen(Silent(time.Millisecond))
	web := m.Listen(Prefix("GET"))
	go func() { _ = m.ServeConn(&memConn{data: []byte("GET /")}) }()
	if b, err := io.ReadAll(io.LimitReader(accept(t, web), 5)); err != nil || string(b) != "GET /" {
		t.Fatalf("read %q, %v", b, err)
	}
}

func TestBrokenReaderIsRejected(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	m.Listen(Prefix("TST"))
	if err := m.ServeConn(&memConn{data: []byte("TS")}); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("ServeConn = %v", err)
	}
}

// TestEventNameAndBanned checks that observed events carry the name that
// matchers parsed and whether the connection banned its client.
func TestEventNameAndBanned(t *testing.T) {
	events := make(chan Event, 8)
	m := startMux(t, WithBanPerClient(2, time.Minute, time.Minute), WithObserver(func(ev Event) { events <- ev }))
	route := m.Listen(HTTP1(Host("served.test")))
	serve(t, m)
	next := func() Event {
		t.Helper()
		select {
		case ev := <-events:
			return ev
		case <-time.After(5 * time.Second):
			t.Fatal("no event")
			return Event{}
		}
	}

	_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nHost: served.test\r\n\r\n"))
	accept(t, route)
	if ev := next(); ev.Err != nil || ev.Name != "served.test" || ev.Banned {
		t.Fatalf("delivered %+v", ev)
	}
	for i, want := range []bool{false, true} {
		c := dial(t, m)
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: other.test\r\n\r\n"))
		expectClosed(t, c)
		if ev := next(); !errors.Is(ev.Err, ErrNoMatch) || ev.Name != "other.test" || ev.Banned != want {
			t.Fatalf("failure %d: %+v", i, ev)
		}
	}
	c := dial(t, m)
	expectClosed(t, c)
	if ev := next(); !errors.Is(ev.Err, ErrBanned) || ev.Banned {
		t.Fatalf("banned %+v", ev)
	}
}

type countingKey struct{}

// TestInputValues checks that a matcher of its own keeps state across calls
// on one connection, and that the state starts over for another.
func TestInputValues(t *testing.T) {
	var parses atomic.Int32
	magic := MatcherFunc(func(in *Input) Result {
		if in.Value(countingKey{}) == nil {
			parses.Add(1)
		}
		n := len(in.Bytes())
		in.SetValue(countingKey{}, n)
		if n < 4 {
			return NeedMore
		}
		if string(in.Bytes()[:4]) == "MAGI" {
			return Match
		}
		return NoMatch
	})
	m := startMux(t)
	route := m.Listen(magic)
	serve(t, m)
	for range 2 {
		c := dial(t, m)
		for _, b := range []string{"M", "A", "G", "I"} {
			_, _ = c.Write([]byte(b))
			time.Sleep(5 * time.Millisecond)
		}
		accept(t, route)
	}
	if n := parses.Load(); n != 2 {
		t.Fatalf("parse started %d times, want once per connection", n)
	}

	var in Input
	in.SetBytes([]byte("MAGIC"), false)
	in.SetValue(countingKey{}, 1)
	in.SetValue(countingKey{}, 2)
	if v := in.Value(countingKey{}); v != 2 {
		t.Fatalf("Value = %v", v)
	}
	in.SetBytes([]byte("M"), false)
	if v := in.Value(countingKey{}); v != nil {
		t.Fatalf("Value after shorter bytes = %v", v)
	}
}

// TestRouteDispatchSettings checks that a route's own dispatch timeout and
// queue limit override the entry's.
func TestRouteDispatchSettings(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithDispatchTimeout(time.Minute), WithMaxQueued(8))
	slow, err := m.Add(RouteConfig{Matchers: []Matcher{Prefix("S")}, DispatchTimeout: 50 * time.Millisecond, MaxQueued: 1})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, m)
	if info := slow.Info(); info.DispatchTimeout != 50*time.Millisecond || info.MaxQueued != 1 {
		t.Fatalf("Info = %+v", info)
	}

	// The route's timeout, not the entry's minute, ends the wait.
	start := time.Now()
	c := dial(t, m)
	_, _ = c.Write([]byte("S"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrDispatchTimeout) || time.Since(start) > 10*time.Second {
		t.Fatalf("reported %v after %v", err, time.Since(start))
	}

	// One connection queues; the next is over the route's limit.
	if err := slow.SetDispatchTimeout(-1); err != nil {
		t.Fatal(err)
	}
	_, _ = dial(t, m).Write([]byte("S"))
	waitUntil(t, "a connection is queued", func() bool { return slow.Info().Queued == 1 })
	c = dial(t, m)
	_, _ = c.Write([]byte("S"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("reported %v", err)
	}
	if err := slow.SetMaxQueued(0); err != nil {
		t.Fatal(err)
	}
	_, _ = dial(t, m).Write([]byte("S"))
	waitUntil(t, "the entry's limit applies", func() bool { return slow.Info().Queued == 2 })
	accept(t, slow)
	accept(t, slow)
}
