package portmux

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/portmux/internal/testutil"
)

// TestEvictionUnderSilentFlood fills the pending limit with idle connections
// and checks that a real client is still served long before they time out.
func TestEvictionUnderSilentFlood(t *testing.T) {
	m := startMux(t, WithMaxPending(8))
	route := m.Match(Prefix("A"))
	serve(t, m)

	idle := make([]net.Conn, 8)
	for i := range idle {
		idle[i] = dial(t, m)
	}
	waitPending(t, m.Mux, 8)

	start := time.Now()
	c := dial(t, m)
	_, _ = c.Write([]byte("A"))
	accept(t, route)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("served after %v", elapsed)
	}
	// The connection accepted first was the one closed.
	expectClosed(t, idle[0])
	if st := m.Stats(); st.Evicted == 0 {
		t.Fatalf("stats %+v", st)
	}
}

// TestSlotWaitKeepsSniffTimeout fills the pending budget with a matched
// connection that nobody accepts. The next client waits for the slot longer
// than its sniff timeout, and is matched once it has one.
func TestSlotWaitKeepsSniffTimeout(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithMaxPending(1), WithSniffTimeout(200*time.Millisecond),
		WithDispatchTimeout(time.Second), WithBanPerIP(1, time.Minute, time.Minute))
	route := m.Match(Prefix("GET"))
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("GET"))
	// Matched, it can no longer be evicted for the next one.
	for deadline := time.Now().Add(5 * time.Second); route.Info().Queued != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("not queued")
		}
	}
	_, _ = dial(t, m).Write([]byte("GET"))
	if err := log.wait(t); !errors.Is(err, ErrDispatchTimeout) {
		t.Fatalf("first connection: %v", err)
	}
	accept(t, route)
	if bans := m.Bans(); len(bans) != 0 {
		t.Fatalf("bans %+v", bans)
	}
}

// TestEvictionUnderSlowloris does the same with clients that send a partial
// request head and stall.
func TestEvictionUnderSlowloris(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithMaxPending(4))
	web := m.Match(HTTP1())
	serve(t, m)

	for range 4 {
		_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nX-Slow: "))
	}
	waitPending(t, m.Mux, 4)
	c := dial(t, m)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	accept(t, web)
	if err := log.wait(t); !errors.Is(err, ErrEvicted) {
		t.Fatalf("reported %v", err)
	}
}

func TestEvictionSparesMatchedConnections(t *testing.T) {
	var p pendingSet
	conns := make([]*closeCounter, 3)
	sniffers := make([]*sniffer, 3)
	for i := range sniffers {
		conns[i] = &closeCounter{}
		sniffers[i] = &sniffer{conn: &Conn{conn: conns[i]}}
		p.add(sniffers[i], i != 2) // the last one came from ServeConn
	}
	p.decided(sniffers[0])
	if !p.evictOldest() {
		t.Fatal("nothing evicted")
	}
	if conns[0].n != 0 || conns[1].n != 1 || conns[2].n != 0 || !sniffers[1].evicted.Load() {
		t.Fatalf("closed %d %d %d", conns[0].n, conns[1].n, conns[2].n)
	}
	if p.evictOldest() {
		t.Fatal("evicted a matched or handed-over connection")
	}
	for _, s := range sniffers {
		p.remove(s)
	}
	p.closeAll()
	if conns[0].n != 0 {
		t.Fatal("closeAll closed a removed connection")
	}
}

// TestEvictionFollowsAcceptOrder adds connections out of accept order, with
// start times a coarse clock does not tell apart, in shared and separate
// shards.
func TestEvictionFollowsAcceptOrder(t *testing.T) {
	var p pendingSet
	conns := map[uint64]*closeCounter{}
	for _, seq := range []uint64{33, 2, 17, 18, 1} {
		conns[seq] = &closeCounter{}
		p.add(&sniffer{conn: &Conn{conn: conns[seq], stripe: uint8(seq % counterStripes)}, seq: seq}, true)
	}
	for _, want := range []uint64{1, 2, 17, 18, 33} {
		if !p.evictOldest() {
			t.Fatal("nothing evicted")
		}
		for seq, c := range conns {
			if closed := seq <= want; (c.n == 1) != closed {
				t.Fatalf("after evicting %d: connection %d closed %d times", want, seq, c.n)
			}
		}
	}
}

type closeCounter struct {
	net.Conn
	n int
}

func (c *closeCounter) Close() error { c.n++; return nil }

func TestRateLimitPerIP(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithRateLimitPerIP(0.001, 2))
	route := m.Match(Prefix("A"))
	serve(t, m)

	for range 2 {
		_, _ = dial(t, m).Write([]byte("A"))
		accept(t, route)
	}
	c := dial(t, m)
	_, _ = c.Write([]byte("A"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("reported %v", err)
	}
	if st := m.Stats(); st.Limited != 1 || st.Rejected != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestRateLimitBuckets(t *testing.T) {
	l := newRateLimit(10, 2)
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	at := func(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }
	steps := []struct {
		client netip.Addr
		ms     int
		want   bool
	}{
		{a, 0, true}, {a, 0, true}, {a, 0, false}, // burst of 2
		{b, 0, true},   // clients are independent
		{a, 50, false}, // half a token
		{a, 100, true}, // 10 per second
		{a, 100, false},
		{a, 10_000, true}, {a, 10_000, true}, {a, 10_000, false}, // refilled to burst only
	}
	for i, st := range steps {
		if got := l.allowAt(st.client, at(st.ms)); got != st.want {
			t.Fatalf("step %d: allow = %v, want %v", i, got, st.want)
		}
	}
	// Full buckets are forgotten by a sweep.
	sh := &l.shards[0]
	for i := range l.shards {
		if len(l.shards[i].bucket) > 0 {
			sh = &l.shards[i]
		}
	}
	l.sweep(sh, at(60_000))
	if len(sh.bucket) != 0 {
		t.Fatalf("%d buckets left after sweep", len(sh.bucket))
	}
}

func TestRateLimitTracksBoundedClients(t *testing.T) {
	l := newRateLimit(1, 1)
	// Fill the tracked clients with exhausted buckets, then check that new
	// clients pass untracked instead of growing the maps.
	for i := range maxRateClients * 2 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.allowAt(ip, 0)
	}
	total := 0
	for i := range l.shards {
		total += len(l.shards[i].bucket)
	}
	if total > maxRateClients {
		t.Fatalf("tracking %d clients", total)
	}
}

func TestClientKeyGroupsIPv6Networks(t *testing.T) {
	k1, _ := clientKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1")})
	k2, _ := clientKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::9")})
	k3, _ := clientKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1")})
	k4, _ := clientKey(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1")})
	if k1 != k2 || k1 == k3 || k4 != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("keys %v %v %v %v", k1, k2, k3, k4)
	}
}

func TestRejectRouteClosesBeforeReading(t *testing.T) {
	m := startMux(t)
	block, err := m.Add(RouteConfig{Priority: 100, Reject: true, Matchers: []Matcher{RemoteIP(loopback)}})
	if err != nil {
		t.Fatal(err)
	}
	m.Match(Any())
	serve(t, m)

	start := time.Now()
	expectClosed(t, dial(t, m)) // sends nothing
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("closed after %v", elapsed)
	}
	waitPending(t, m.Mux, 0)
	if st := m.Stats(); st.Refused != 1 || block.Matched() != 1 || !block.Reject() {
		t.Fatalf("stats %+v, matched %d", st, block.Matched())
	}
	expectNoAccept(t, block, 20*time.Millisecond)
}

func TestBusyRouteDoesNotBlockOthers(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithMaxQueuedPerRoute(1))
	busy := m.Match(Prefix("A")) // its server never accepts
	other := m.Match(Prefix("B"))
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("A"))
	waitUntil(t, "a connection waits for the busy route", func() bool { return busy.Info().Queued == 1 })
	c := dial(t, m)
	_, _ = c.Write([]byte("A"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRouteBusy) {
		t.Fatalf("reported %v", err)
	}
	_, _ = dial(t, m).Write([]byte("B"))
	accept(t, other)
}

// TestInvalidAndShortInputs sends inputs that scanners and broken clients
// produce and checks that each connection is closed at once and that nothing
// is left pending.
func TestInvalidAndShortInputs(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	m.Match(Prefix("TST"))
	web := m.Match(HTTP1())
	m.Match(TLS())
	serve(t, m)

	inputs := []struct {
		name  string
		data  string
		close bool // the client half-closes after sending
	}{
		{"binary", "\x00\x01\x02\xff", false},
		{"nul", "\x00", false},
		{"one byte then close", "G", true},
		{"truncated tls header", "\x16\x03", true},
		{"tls with huge record then close", "\x16\x03\x01\xff\xff\x01", true},
		{"tls wrong handshake", "\x16\x03\x01\x00\x04\x02\x00\x00\x00", false},
		{"nul in header name", "GET / HTTP/1.1\r\nHo\x00st: x\r\n\r\n", false},
		{"long method", strings.Repeat("A", 64), false},
		{"http/2 version", "GET / HTTP/2.0\r\n\r\n", false},
		{"empty then close", "", true},
		{"random", string(randomBytes(512)), false},
	}
	for _, in := range inputs {
		start := time.Now()
		c := dial(t, m)
		_, _ = c.Write([]byte(in.data))
		if in.close {
			_ = c.(*net.TCPConn).CloseWrite()
		}
		expectClosed(t, c)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("%s: closed after %v", in.name, elapsed)
		}
		if err := log.wait(t); !errors.Is(err, ErrNoMatch) && !errors.Is(err, io.EOF) {
			t.Errorf("%s: reported %v", in.name, err)
		}
	}
	waitPending(t, m.Mux, 0)
	if st := m.Stats(); st.Delivered != 0 || st.Rejected != uint64(len(inputs)) {
		t.Fatalf("stats %+v", st)
	}
	expectNoAccept(t, web, 20*time.Millisecond)
}

func randomBytes(n int) []byte {
	r := rand.New(rand.NewPCG(7, 7))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	b[0] = 0xff // never a valid first byte for the routes in the test
	return b
}

func TestOversizedHeadIsRejected(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithMaxSniffBytes(1024))
	m.Match(HTTP1())
	serve(t, m)

	c := dial(t, m)
	go func() {
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nCookie: " + strings.Repeat("c", 4096) + "\r\n\r\n"))
	}()
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("reported %v", err)
	}
}

// addrConn is one end of a pipe that reports chosen addresses.
type addrConn struct {
	net.Conn
	remote, local net.Addr
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }
func (c *addrConn) LocalAddr() net.Addr  { return c.local }

// collect accepts from every route and sends the route's name for each
// connection.
func collect(routes map[string]*Route) <-chan string {
	got := make(chan string, 16)
	for name, r := range routes {
		go func() {
			for {
				c, err := r.AcceptConn()
				if err != nil {
					return
				}
				_ = c.Close()
				got <- name
			}
		}()
	}
	return got
}

// routeOf sends data from a client at remote to m through ServeConn and
// returns the name of the route that accepted it, or the error.
func routeOf(t *testing.T, m *Mux, got <-chan string, remote, data string) string {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	c := &addrConn{
		Conn:   server,
		remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote)),
		local:  &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443},
	}
	go func() { _, _ = client.Write([]byte(data)) }()
	err := m.ServeConn(c)
	if err != nil {
		return err.Error()
	}
	select {
	case name := <-got:
		return name
	case <-time.After(5 * time.Second):
		t.Fatal("no route accepted the connection")
		return ""
	}
}

// TestRoutingRecipes checks that block lists, allow lists, protocol and
// address conditions combine in any order through priorities and And/Not.
func TestRoutingRecipes(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	office := netip.MustParsePrefix("10.0.0.0/8")
	blocked := netip.MustParsePrefix("203.0.113.0/24")
	add := func(name string, priority int, reject bool, ms ...Matcher) *Route {
		r, err := m.Add(RouteConfig{Name: name, Priority: priority, Reject: reject, Matchers: ms})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	routes := map[string]*Route{
		"admin":    add("admin", 50, false, And(RemoteIP(office), Or(TLS(SNI("admin.example.com")), HTTP1(Host("admin.example.com"))))),
		"api-tls":  add("api-tls", 0, false, TLS(SNI("api.example.com"), ALPN("h2"))),
		"site-tls": add("site-tls", 0, false, TLS()),
		"web":      add("web", 0, false, HTTP1(NoneOf(Host("admin.example.com")))),
		"fallback": add("fallback", -100, false, And(Not(RemoteIP(office)), Any())),
	}
	add("blocklist", 100, true, RemoteIP(blocked))
	got := collect(routes)
	add("admin-outside", 40, true, Or(TLS(SNI("admin.example.com")), HTTP1(Host("admin.example.com"))))

	hello := func(sni string, alpn ...string) string {
		return string(testutil.ClientHelloBytes(t, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true}))
	}
	request := func(host string) string { return "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n" }
	refused := ErrRefused.Error()
	tests := []struct {
		name, remote, data, want string
	}{
		{"blocked address, before anything else", "203.0.113.9:1000", hello("api.example.com", "h2"), refused},
		{"admin over TLS from the office", "10.1.2.3:1000", hello("admin.example.com"), "admin"},
		{"admin over HTTP from the office", "10.1.2.3:1000", request("admin.example.com"), "admin"},
		{"admin from outside", "192.0.2.1:1000", hello("admin.example.com"), refused},
		{"admin HTTP from outside", "192.0.2.1:1000", request("ADMIN.example.com:80"), refused},
		{"API needs h2", "192.0.2.1:1000", hello("api.example.com", "h2"), "api-tls"},
		{"API without h2", "192.0.2.1:1000", hello("api.example.com"), "site-tls"},
		{"plain HTTP", "192.0.2.1:1000", request("www.example.com"), "web"},
		{"unknown protocol from outside", "192.0.2.1:1000", "SSH-2.0-x\r\n", "fallback"},
		{"unknown protocol from the office", "10.1.2.3:1000", "SSH-2.0-x\r\n", ErrNoMatch.Error()},
	}
	for _, tt := range tests {
		if name := routeOf(t, m, got, tt.remote, tt.data); name != tt.want {
			t.Errorf("%s: routed to %q, want %q", tt.name, name, tt.want)
		}
	}
	// Moving a route changes the order without touching the others.
	if err := routes["site-tls"].SetPriority(10); err != nil {
		t.Fatal(err)
	}
	if name := routeOf(t, m, got, "192.0.2.1:1000", hello("api.example.com", "h2")); name != "site-tls" {
		t.Fatalf("after reordering: %q", name)
	}
}

// TestHostileConnectionMix runs floods of idle, slow, garbage and valid
// connections at once and checks that every valid one is delivered.
func TestHostileConnectionMix(t *testing.T) {
	m := startMux(t, WithMaxPending(32), WithSniffTimeout(2*time.Second))
	web := m.Match(HTTP1(Host("ok.example")))
	m.Match(TLS())
	serve(t, m)
	go func() {
		for {
			c, err := web.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
			_ = c.Close()
		}
	}()

	stop := make(chan struct{})
	var attackers sync.WaitGroup
	payloads := []string{"", "GET / HTTP/1.1\r\nX: ", "\x16\x03\x01\x10\x00", "\xff\xfe garbage"}
	for _, payload := range payloads {
		attackers.Go(func() {
			tick := time.NewTicker(2 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
				c, err := net.Dial("tcp", m.Addr().String())
				if err != nil {
					continue
				}
				_, _ = c.Write([]byte(payload))
				time.AfterFunc(500*time.Millisecond, func() { _ = c.Close() })
			}
		})
	}
	time.Sleep(200 * time.Millisecond) // let the flood fill the pending limit
	defer func() {
		close(stop)
		attackers.Wait()
	}()

	for i := range 50 {
		c, err := net.Dial("tcp", m.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: ok.example\r\n\r\n")
		b, err := io.ReadAll(c)
		_ = c.Close()
		if err != nil || string(b) != "ok" {
			t.Fatalf("valid client %d: %q, %v (stats %+v)", i, b, err, m.Stats())
		}
	}
}

func TestRateLimitPerListener(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithRateLimitPerListener(0.001, 2))
	web := m.Match(Prefix("GET"))
	serve(t, m)
	for range 2 {
		_, _ = dial(t, m).Write([]byte("GET"))
		accept(t, web)
	}
	c := dial(t, m)
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("reported %v", err)
	}
	m.SetOptions(WithRateLimitPerListener(0, 0))
	_, _ = dial(t, m).Write([]byte("GET"))
	accept(t, web)
}
