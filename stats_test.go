package portmux

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestListenerStats counts the connections of each listener apart and reports
// errors with their entry.
func TestListenerStats(t *testing.T) {
	type report struct {
		entry string
		err   error
	}
	reports := make(chan report, 8)
	m := New(WithObserver(func(ev Event) {
		if ev.Err != nil {
			reports <- report{ev.Entry, ev.Err}
		}
	}))
	t.Cleanup(func() { _ = m.Close() })
	web, err := m.Add(RouteConfig{Entries: []string{"web"}, Matchers: []Matcher{Prefix("GET")}})
	if err != nil {
		t.Fatal(err)
	}
	a := listen(t, m.Entry("web"))
	b := listen(t, m.Entry("web"))
	waitServing(t, m, 2)

	_ = dialTo(t, a, "GET")
	accept(t, web)
	_ = dialTo(t, a, "BAD")
	if r := <-reports; r.entry != "web" || !errors.Is(r.err, ErrNoMatch) {
		t.Fatalf("reported %+v", r)
	}
	_ = dialTo(t, b, "GET")
	accept(t, web)
	waitPending(t, m, 0)

	stats := map[string]Stats{}
	for _, l := range m.Snapshot().Listeners {
		stats[l.Addr.String()] = l.Stats
	}
	if st := stats[a.Addr().String()]; st.Accepted != 2 || st.Delivered != 1 || st.NoMatch != 1 || st.Rejected != 1 {
		t.Fatalf("listener a %+v", st)
	}
	if st := stats[b.Addr().String()]; st.Accepted != 1 || st.Delivered != 1 || st.Rejected != 0 {
		t.Fatalf("listener b %+v", st)
	}
	if st := m.Stats(); st.Accepted != 3 || st.Delivered != 2 {
		t.Fatalf("total %+v", st)
	}
}

func TestObserver(t *testing.T) {
	events := make(chan Event, 8)
	m := startMux(t, WithObserver(func(ev Event) { events <- ev }))
	web := m.Match(HTTP1())
	serve(t, m)

	c := dial(t, m)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	accept(t, web)
	ev := <-events
	// The monotonic clock of Windows ticks too coarsely to tell a loopback
	// decision from none, so Elapsed may be zero.
	if ev.Route != web || ev.Err != nil || ev.Sniffed != 27 || ev.Elapsed < 0 || ev.Remote.String() != c.LocalAddr().String() {
		t.Fatalf("delivered event %+v", ev)
	}
	c = dial(t, m)
	_, _ = c.Write([]byte("\x00"))
	expectClosed(t, c)
	if ev := <-events; ev.Route != nil || !errors.Is(ev.Err, ErrNoMatch) || ev.Sniffed != 1 || ev.Local.String() != m.Addr().String() {
		t.Fatalf("rejected event %+v", ev)
	}
	// Connections passed to ServeConn are reported too.
	client, server := net.Pipe()
	go func() { _, _ = client.Write([]byte("?")); _ = client.Close() }()
	if err := m.Entry("pipe").ServeConn(server); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("ServeConn = %v", err)
	}
	if ev := <-events; ev.Entry != "pipe" || !errors.Is(ev.Err, ErrNoMatch) {
		t.Fatalf("ServeConn event %+v", ev)
	}
	// Closing the Mux is not reported.
	_ = dial(t, m)
	waitPending(t, m.Mux, 1)
	_ = m.Close()
	select {
	case ev := <-events:
		t.Fatalf("event after Close: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestStats(t *testing.T) {
	m := startMux(t)
	route := m.Match(Prefix("A"))
	serve(t, m)

	_, _ = dial(t, m).Write([]byte("A"))
	got := accept(t, route)
	if got.Route() != route {
		t.Fatal("Conn.Route")
	}
	rejected := dial(t, m)
	_, _ = rejected.Write([]byte("B"))
	expectClosed(t, rejected)
	waitPending(t, m.Mux, 0)
	st := m.Stats()
	if st.Accepted != 2 || st.Delivered != 1 || st.Rejected != 1 || route.Matched() != 1 {
		t.Fatalf("stats %+v, route delivered %d", st, route.Matched())
	}
}
