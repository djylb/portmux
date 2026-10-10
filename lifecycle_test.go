package portmux

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/internal/testutil"
)

func TestFallbackTakesUnmatchedConnections(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithSniffTimeout(150*time.Millisecond))
	bridge := m.Match(Prefix("TST"))
	fallback := mustAdd(t, m, RouteConfig{Name: "default", Fallback: true})
	// Added after the fallback with a lower priority, yet still tried first.
	web := mustAdd(t, m, RouteConfig{Priority: -1000, Matchers: []Matcher{HTTP1()}})
	serve(t, m)

	// Ruled out by every route.
	_, _ = dial(t, m).Write([]byte("\xffdata"))
	if b := readN(t, accept(t, fallback), 5); string(b) != "\xffdata" {
		t.Fatalf("read %q", b)
	}
	// Undecided until the sniff timeout: delivered with its bytes intact.
	_, _ = dial(t, m).Write([]byte("TS"))
	got := accept(t, fallback)
	if b := readN(t, got, 2); string(b) != "TS" || got.Route() != fallback {
		t.Fatalf("read %q", b)
	}
	// Matched routes are unaffected.
	_, _ = dial(t, m).Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	accept(t, web)
	_, _ = dial(t, m).Write([]byte("TST"))
	accept(t, bridge)
	// A silent client is not taken.
	silent := dial(t, m)
	expectClosed(t, silent)
	if err := log.wait(t); !errors.Is(err, ErrSniffTimeout) {
		t.Fatalf("reported %v", err)
	}
	if routes := m.Routes(); routes[len(routes)-1] != fallback {
		t.Fatal("fallback is not listed last")
	}
}

func TestFallbackStandby(t *testing.T) {
	m := startMux(t)
	m.Match(Prefix("TST"))
	old := mustAdd(t, m, RouteConfig{Name: "old", Fallback: true})
	next := mustAdd(t, m, RouteConfig{Name: "next", Fallback: true, Priority: -1})
	serve(t, m)

	if !old.Info().Active || next.Info().Active {
		t.Fatal("the higher-priority fallback should be the active one")
	}
	// Removing the active fallback hands over to the standby one.
	_ = old.Close()
	if !next.Info().Active {
		t.Fatal("standby fallback not activated")
	}
	_, _ = dial(t, m).Write([]byte("x"))
	accept(t, next)

	for _, cfg := range []RouteConfig{
		{Fallback: true, Matchers: []Matcher{Any()}},
		{Fallback: true, Reject: true},
	} {
		if _, err := m.Add(cfg); !errors.Is(err, errFallbackConfig) {
			t.Errorf("Add(%+v) = %v", cfg, err)
		}
	}
	if err := next.SetMatchers(Any()); !errors.Is(err, errFallbackConfig) {
		t.Errorf("SetMatchers on a fallback = %v", err)
	}
}

func TestFallbackIsNotUsedForRefusedOrEmpty(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	mustAdd(t, m, RouteConfig{Reject: true, Matchers: []Matcher{Prefix("BAD")}})
	fallback := mustAdd(t, m, RouteConfig{Fallback: true})
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("BAD"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrRefused) {
		t.Fatalf("reported %v", err)
	}
	_ = dial(t, m).Close()
	if err := log.wait(t); !errors.Is(err, io.EOF) {
		t.Fatalf("reported %v", err)
	}
	expectNoAccept(t, fallback, 20*time.Millisecond)
}

func TestSnapshotDescribesRoutes(t *testing.T) {
	m := startMux(t)
	office := netip.MustParsePrefix("10.0.0.0/8")
	mustAdd(t, m, RouteConfig{Name: "block", Priority: 100, Reject: true, Matchers: []Matcher{
		RemoteIP(netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("2001:db8::/32")),
	}})
	admin := mustAdd(t, m, RouteConfig{Name: "admin", Priority: 50, Matchers: []Matcher{
		And(RemoteIP(office), Or(TLS(SNI("admin.example.com"), ALPN("h2")), HTTP1(Host("admin.example.com"), PathPrefix("/ui/"), WebSocket()))),
	}})
	mustAdd(t, m, RouteConfig{Name: "misc", Matchers: []Matcher{
		Prefix("TST"), SSH(), HTTP2Preface(), SOCKS5(), Silent(2 * time.Second), Not(LocalPort(80, 443)),
		Named("acme", MatcherFunc(func(*Input) Result { return NoMatch })), MatcherFunc(func(*Input) Result { return NoMatch }),
		HTTP1(Method("GET"), Path("/a"), Header("X-Kind", "a"), HTTPFilterFunc(func(*httphead.Request) bool { return true })),
	}})
	paused := mustAdd(t, m, RouteConfig{Name: "paused"})
	mustAdd(t, m, RouteConfig{Name: "default", Fallback: true})
	serve(t, m)

	waiting := make(chan struct{})
	go func() {
		close(waiting)
		_, _ = admin.Accept()
	}()
	<-waiting
	for deadline := time.Now().Add(5 * time.Second); admin.Info().Accepting != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Accepting not counted")
		}
	}

	snap := m.Snapshot()
	var names []string
	for _, r := range snap.Routes {
		names = append(names, r.Name)
	}
	if !slices.Equal(names, []string{"block", "admin", "misc", "paused", "default"}) {
		t.Fatalf("order %q", names)
	}
	want := map[string][]string{
		"block": {`RemoteIP(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 100.64.0.0/10, 2001:db8::/32)`},
		"admin": {`And(RemoteIP(10.0.0.0/8), Or(TLS(SNI("admin.example.com"), ALPN("h2")), HTTP1(Host("admin.example.com"), PathPrefix("/ui/"), WebSocket())))`},
		"misc": {`Prefix("TST")`, `SSH()`, `HTTP2Preface()`, `SOCKS5()`, `Silent(2s)`, `Not(LocalPort(80, 443))`,
			`acme`, `MatcherFunc`, `HTTP1(Method("GET"), Path("/a"), Header("X-Kind", "a"), HTTPFilterFunc)`},
	}
	for _, info := range snap.Routes {
		if w, ok := want[info.Name]; ok && !slices.Equal(info.Matchers, w) {
			t.Errorf("%s matchers:\n got %q\nwant %q", info.Name, info.Matchers, w)
		}
	}
	byName := map[string]RouteInfo{}
	for _, info := range snap.Routes {
		byName[info.Name] = info
	}
	if !byName["block"].Reject || !byName["block"].Active || byName["paused"].Active ||
		!byName["default"].Fallback || !byName["default"].Active || byName["admin"].Accepting != 1 {
		t.Fatalf("states %+v", byName)
	}
	if len(snap.Listeners) != 1 || snap.Listeners[0].Addr.String() != m.Addr().String() || snap.Listeners[0].Entry != "" {
		t.Fatalf("listeners %v", snap.Listeners)
	}

	_ = paused.Close()
	if info := paused.Info(); !info.Removed || info.Active {
		t.Fatalf("closed route info %+v", info)
	}
	if len(m.Snapshot().Routes) != 4 {
		t.Fatal("closed route still listed")
	}
}

func TestBatchPreviewAndNoDeadlock(t *testing.T) {
	m := startMux(t)
	a := mustAdd(t, m, RouteConfig{Name: "a", Priority: 10, Matchers: []Matcher{Any()}})
	b := mustAdd(t, m, RouteConfig{Name: "b", Priority: 0, Matchers: []Matcher{Any()}})

	err := m.Batch(func(bt *Batch) error {
		// Other methods of the Mux, even other batches, work inside a batch.
		if m.Route("a") != a || len(m.Snapshot().Routes) != 2 {
			return errors.New("reads inside a batch")
		}
		if err := b.SetPriority(1); err != nil {
			return err
		}
		c, err := bt.Add(RouteConfig{Name: "c", Priority: 5, Matchers: []Matcher{Any()}})
		if err != nil {
			return err
		}
		if got := bt.Routes(); !slices.Equal(got, []*Route{a, c, b}) {
			return errors.New("preview order")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Routes(); len(got) != 3 || got[0] != a || got[1].Name() != "c" || got[2] != b {
		t.Fatalf("order after commit: %v", got)
	}

	// A change that no longer applies when the batch commits fails as a
	// whole.
	err = m.Batch(func(bt *Batch) error {
		if err := bt.SetPriority(b, 100); err != nil {
			return err
		}
		if _, err := bt.Add(RouteConfig{Name: "d", Matchers: []Matcher{Any()}}); err != nil {
			return err
		}
		return b.Close() // removed by another call before this batch commits
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Batch = %v", err)
	}
	if m.Route("d") != nil {
		t.Fatal("a failed batch was partly applied")
	}
}

// TestClosedRouteReleasesEverything closes a route with waiting connections
// and checks that the route, its name and its connections are released.
func TestClosedRouteReleasesEverything(t *testing.T) {
	m := startMux(t)
	route := mustAdd(t, m, RouteConfig{Name: "r", Matchers: []Matcher{Prefix("A")}})
	fallback := mustAdd(t, m, RouteConfig{Fallback: true})
	serve(t, m)

	for range 3 {
		_, _ = dial(t, m).Write([]byte("A"))
	}
	waitPending(t, m.Mux, 3)
	if err := route.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		accept(t, fallback) // re-matched, not dropped
	}
	waitPending(t, m.Mux, 0)
	if _, err := route.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept = %v", err)
	}
	if m.Route("r") != nil || slices.Contains(m.Routes(), route) || route.Info().Queued != 0 {
		t.Fatal("closed route still referenced")
	}
	for _, e := range m.table.Load().other.rules {
		if e.route == route {
			t.Fatal("closed route still in the table")
		}
	}
	mustAdd(t, m, RouteConfig{Name: "r", Matchers: []Matcher{Prefix("A")}})
}

// TestNoGoroutineLeaks runs connections through every outcome, closes the Mux
// and checks that its goroutines are gone.
func TestNoGoroutineLeaks(t *testing.T) {
	before := runtime.NumGoroutine()
	func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		m := New(WithSniffTimeout(100*time.Millisecond), WithDispatchTimeout(100*time.Millisecond), WithMaxPending(4))
		served := m.Match(Prefix("A"))
		m.Match(Prefix("S")) // nobody accepts: dispatch timeouts
		m.Match(Silent(20 * time.Millisecond))
		errc := make(chan error, 1)
		go func() { errc <- m.Serve(ln) }()
		var accepted sync.WaitGroup
		accepted.Go(func() {
			for {
				c, err := served.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		})
		var clients sync.WaitGroup
		for i := range 40 {
			clients.Go(func() {
				c, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte([]string{"A", "S", "", "?", "AB", "T"}[i%6]))
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			})
		}
		clients.Wait()
		_ = m.Close()
		<-errc
		accepted.Wait()
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		n := runtime.NumGoroutine()
		if n <= before {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("%d goroutines before, %d after:\n%s", before, n, buf[:runtime.Stack(buf, true)])
		}
	}
}

// TestRejectionReleasesAtOnce checks that a connection that matches nothing
// gives back its slot, its per-IP count and its buffer immediately.
func TestRejectionReleasesAtOnce(t *testing.T) {
	m := startMux(t, WithMaxPendingPerIP(1), WithMaxPending(1))
	route := m.Match(Prefix("A"))
	serve(t, m)

	for range 20 {
		c := dial(t, m)
		_, _ = c.Write([]byte("X"))
		expectClosed(t, c)
	}
	_, _ = dial(t, m).Write([]byte("A"))
	accept(t, route)
	waitPending(t, m.Mux, 0)
	m.perIP.mu.Lock()
	n := len(m.perIP.count)
	m.perIP.mu.Unlock()
	if st := m.Stats(); n != 0 || st.NoMatch != 20 || st.Delivered != 1 || st.Evicted != 0 || st.Limited != 0 {
		t.Fatalf("per-IP entries %d, stats %+v", n, st)
	}
}

// TestIdleConnectionsHoldNoBuffer checks that an idle client does not take a
// read buffer on platforms that can wait for readable sockets.
func TestIdleConnectionsHoldNoBuffer(t *testing.T) {
	var taken atomic.Int64
	count := func() { taken.Add(1) }
	bufferTaken.Store(&count)
	defer bufferTaken.Store(nil)
	m := startMux(t)
	m.Match(HTTP1())
	serve(t, m)

	idle := make([]net.Conn, 50)
	for i := range idle {
		idle[i] = dial(t, m)
	}
	waitPending(t, m.Mux, int64(len(idle)))
	time.Sleep(20 * time.Millisecond)
	switch runtime.GOOS {
	case "linux", "android", "darwin", "ios", "freebsd", "netbsd", "openbsd", "windows":
		if n := taken.Load(); n != 0 {
			t.Fatalf("%d idle connections took a read buffer", n)
		}
	}
	// Bytes that arrive later, or were there before the wait, are read.
	_, _ = idle[0].Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	for deadline := time.Now().Add(5 * time.Second); m.Stats().Delivered+m.Stats().Rejected == 0 && taken.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("bytes after the wait were not read")
		}
	}
	early := dial(t, m)
	_, _ = early.Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"))
	time.Sleep(10 * time.Millisecond)
	route := m.Routes()[0]
	got := accept(t, route)
	got2 := accept(t, route)
	for _, c := range []*Conn{got, got2} {
		if c.HTTPRequest() == nil || c.HTTPRequest().Host != "h" {
			t.Fatalf("request %+v", c.HTTPRequest())
		}
	}
}

// TestStreamIntegrity sends a TLS hello followed by a megabyte of random
// bytes in odd-sized writes and checks that the server reads exactly them.
func TestStreamIntegrity(t *testing.T) {
	m := startMux(t)
	route := m.Match(TLS(SNI("bulk.example")))
	serve(t, m)

	hello := testutil.ClientHelloBytes(t, &tls.Config{ServerName: "bulk.example", InsecureSkipVerify: true})
	payload := make([]byte, 1<<20)
	_, _ = rand.Read(payload)
	want := append(slices.Clone(hello), payload...)
	c := dial(t, m)
	go func() {
		for rest := want; len(rest) > 0; {
			n := min(len(rest), 1+len(rest)%7919)
			if _, err := c.Write(rest[:n]); err != nil {
				return
			}
			rest = rest[n:]
		}
		_ = c.(*net.TCPConn).CloseWrite()
	}()
	got := accept(t, route)
	_ = got.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("received %d bytes that differ from the %d sent", buf.Len(), len(want))
	}
}

func TestSniffLimitIsClamped(t *testing.T) {
	if got := newOptions([]Option{WithMaxSniffBytes(math.MaxInt)}).maxSniffBytes; got != MaxSniffBytes {
		t.Fatalf("maxSniffBytes = %d", got)
	}
}

// closeCountingConn is a memConn that counts its Close calls.
type closeCountingConn struct {
	memConn
	closed int
}

func (c *closeCountingConn) Close() error { c.closed++; return nil }

// TestCloseStopsMatchedHandOver closes the Mux right after a connection was
// matched and left the pending set: it is passed neither to its handler nor
// to Accept but closed, so that nothing is handed over after Close.
func TestCloseStopsMatchedHandOver(t *testing.T) {
	for _, handler := range []bool{true, false} {
		m := New()
		handled := false
		cfg := RouteConfig{Matchers: []Matcher{Always()}}
		if handler {
			cfg.Handler = func(c *Conn) {
				handled = true
				_ = c.Close()
			}
		}
		r, err := m.Add(cfg)
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan error, 1)
		if !handler {
			go func() {
				c, err := r.Accept()
				if err == nil {
					_ = c.Close()
				}
				accepted <- err
			}()
			for r.Info().Accepting == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		closeMux := func() { _ = m.Close() }
		leftPending.Store(&closeMux)
		c := &closeCountingConn{}
		err = m.ServeConn(c)
		leftPending.Store(nil)
		if !errors.Is(err, net.ErrClosed) || handled || c.closed != 1 {
			t.Fatalf("handler %v: ServeConn = %v, handled %v, closed %d times", handler, err, handled, c.closed)
		}
		if !handler {
			if err := <-accepted; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Accept = %v", err)
			}
		}
		if st := m.Stats(); st.Delivered != 0 || st.Open != 0 || st.Pending != 0 || st.Failed != 1 {
			t.Fatalf("handler %v: stats %+v", handler, st)
		}
	}
}
