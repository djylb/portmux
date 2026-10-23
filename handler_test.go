package portmux

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestHandlerServesWithoutAccept serves routes with handlers, which run once
// the connection no longer counts as pending.
func TestHandlerServesWithoutAccept(t *testing.T) {
	type served struct {
		route   string
		pending int64
		data    string
	}
	got := make(chan served, 4)
	var m *testMux
	handler := func(name string) func(*Conn) {
		return func(c *Conn) {
			defer func() { _ = c.Close() }()
			buf := make([]byte, 3)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.ReadFull(c, buf)
			got <- served{name, m.Stats().Pending, string(buf)}
		}
	}
	m = startMux(t, WithMaxPending(1), WithDispatchTimeout(50*time.Millisecond))
	web := mustAdd(t, m, RouteConfig{Name: "web", Matchers: []Matcher{Prefix("GET")}, Handler: handler("web")})
	targets := mustAdd(t, m, RouteConfig{Name: "target", Handler: handler("target")})
	mustAdd(t, m, RouteConfig{Name: "resolver", Matchers: []Matcher{Prefix("RES")}, Resolve: func(*Input) (*Route, Result) {
		return targets, Match
	}})
	serve(t, m)

	// Long-lived handlers hold no pending slot: with a limit of one, both
	// connections are served while the first handler still runs.
	block := make(chan struct{})
	var once sync.Once
	slow := mustAdd(t, m, RouteConfig{Matchers: []Matcher{Prefix("SLOW")}, Handler: func(c *Conn) {
		defer func() { _ = c.Close() }()
		once.Do(func() { close(block) })
		<-m.quit
	}})
	_, _ = dial(t, m).Write([]byte("SLOW"))
	<-block
	_, _ = dial(t, m).Write([]byte("GET"))
	if s := <-got; s.route != "web" || s.pending != 0 || s.data != "GET" {
		t.Fatalf("served %+v", s)
	}
	_, _ = dial(t, m).Write([]byte("RES"))
	if s := <-got; s.route != "target" || s.data != "RES" {
		t.Fatalf("served %+v", s)
	}
	// Nothing reaches Accept, and no dispatch timeout applies.
	expectNoAccept(t, web, 100*time.Millisecond)
	if st := m.Stats(); st.Delivered != 3 || st.Timeouts != 0 || st.Pending != 0 {
		t.Fatalf("stats %+v", st)
	}
	if info := slow.Info(); !info.Handler || !info.Active {
		t.Fatalf("info %+v", info)
	}

	// ServeConn runs the handler in the calling goroutine.
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() { _, _ = client.Write([]byte("GET")) }()
	if err := m.ServeConn(server); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s.route != "web" {
			t.Fatalf("served %+v", s)
		}
	default:
		t.Fatal("ServeConn returned before the handler")
	}

	if _, err := m.Add(RouteConfig{Reject: true, Matchers: []Matcher{AnyBytes()}, Handler: func(*Conn) {}}); !errors.Is(err, errHandlerConfig) {
		t.Fatalf("Add = %v", err)
	}
}

// TestOpenConnections counts connections until Close and limits them per
// route.
func TestOpenConnections(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option())
	web := mustAdd(t, m, RouteConfig{Name: "web", Matchers: []Matcher{Prefix("GET")}, MaxConns: 2})
	done := make(chan struct{})
	handled := mustAdd(t, m, RouteConfig{Matchers: []Matcher{Prefix("H")}, Handler: func(c *Conn) {
		<-done
		_ = c.Close()
	}})
	serve(t, m)

	first := accept(t, func() net.Listener { _, _ = dial(t, m).Write([]byte("GET")); return web }())
	accept(t, func() net.Listener { _, _ = dial(t, m).Write([]byte("GET")); return web }())
	c := dial(t, m)
	_, _ = c.Write([]byte("GET"))
	expectClosed(t, c)
	if err := log.wait(t); !errors.Is(err, ErrConnLimit) {
		t.Fatalf("reported %v", err)
	}
	if info := web.Info(); info.Open != 2 || info.MaxConns != 2 {
		t.Fatalf("info %+v", info)
	}
	_ = first.Close()
	_ = first.Close() // counted once
	_, _ = dial(t, m).Write([]byte("GET"))
	accept(t, web)

	_, _ = dial(t, m).Write([]byte("H"))
	for deadline := time.Now().Add(5 * time.Second); handled.Info().Open != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("handled connection not open")
		}
	}
	if st := m.Stats(); st.Open != 3 {
		t.Fatalf("stats %+v", st)
	}
	if st := m.Snapshot().Listeners[0].Stats; st.Open != 3 {
		t.Fatalf("listener stats %+v", st)
	}
	close(done)
	for deadline := time.Now().Add(5 * time.Second); m.Stats().Open != 2; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("open %d after the handler closed", m.Stats().Open)
		}
	}

	// Raising the limit lets the next connection in.
	if err := web.SetMaxConns(0); err != nil || web.MaxConns() != 0 {
		t.Fatal(err)
	}
	_, _ = dial(t, m).Write([]byte("GET"))
	accept(t, web)
	if web.Info().Open != 3 {
		t.Fatalf("open %d", web.Info().Open)
	}
}
