package portmux

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// send dials m, writes data and returns the client side.
func send(t *testing.T, m *testMux, data string) net.Conn {
	t.Helper()
	c := dial(t, m)
	if _, err := c.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	return c
}

func mustAdd(t *testing.T, m *testMux, cfg RouteConfig) *Route {
	t.Helper()
	r, err := m.Add(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPriorityOrdersRoutes(t *testing.T) {
	m := startMux(t)
	fallback := mustAdd(t, m, RouteConfig{Priority: -10, Matchers: []Matcher{AnyBytes()}})
	serve(t, m)
	// Added later, but tried first because of its higher priority.
	specific := m.Listen(Prefix("A"))

	send(t, m, "A")
	accept(t, specific)
	send(t, m, "B")
	accept(t, fallback)

	if got := m.Routes(); !slices.Equal(got, []*Route{specific, fallback}) {
		t.Fatalf("Routes() = %v", got)
	}
}

func TestEqualPriorityKeepsAddOrder(t *testing.T) {
	m := startMux(t)
	first := m.Listen(Prefix("A"))
	second := m.Listen(Prefix("A"))
	serve(t, m)

	send(t, m, "A")
	accept(t, first)
	if err := first.SetPriority(-1); err != nil {
		t.Fatal(err)
	}
	send(t, m, "A")
	accept(t, second)
	if first.Priority() != -1 || second.Priority() != 0 {
		t.Fatalf("priorities %d %d", first.Priority(), second.Priority())
	}
}

func TestSetMatchersKeepsListener(t *testing.T) {
	m := startMux(t)
	route := m.Listen(Prefix("A"))
	rest := m.Listen(AnyBytes())
	serve(t, m)

	if err := route.SetMatchers(Prefix("B")); err != nil {
		t.Fatal(err)
	}
	send(t, m, "B")
	accept(t, route)
	send(t, m, "A")
	accept(t, rest)
	if got := route.Matchers(); len(got) != 1 {
		t.Fatalf("Matchers() = %v", got)
	}
}

func TestPausedRoute(t *testing.T) {
	m := startMux(t)
	route := m.Listen(Prefix("A"))
	rest := m.Listen(AnyBytes())
	serve(t, m)

	if err := route.SetMatchers(); err != nil {
		t.Fatal(err)
	}
	send(t, m, "A")
	accept(t, rest)
	if err := route.SetMatchers(Prefix("A")); err != nil {
		t.Fatal(err)
	}
	send(t, m, "A")
	accept(t, route)

	paused := mustAdd(t, m, RouteConfig{Priority: 100})
	send(t, m, "A")
	accept(t, route)
	expectNoAccept(t, paused, 20*time.Millisecond)
}

func TestNamedRoutes(t *testing.T) {
	m := startMux(t)
	api := mustAdd(t, m, RouteConfig{Name: "api", Matchers: []Matcher{Prefix("A")}})
	if m.Route("api") != api || api.Name() != "api" || m.Route("missing") != nil {
		t.Fatal("lookup by name")
	}
	if _, err := m.Add(RouteConfig{Name: "api"}); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := api.Close(); err != nil {
		t.Fatal(err)
	}
	if err := api.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if m.Route("api") != nil {
		t.Fatal("removed route still found")
	}
	again := mustAdd(t, m, RouteConfig{Name: "api", Matchers: []Matcher{Prefix("A")}})
	serve(t, m)
	send(t, m, "A")
	accept(t, again)
}

func TestBatchIsAtomic(t *testing.T) {
	m := startMux(t)
	old := mustAdd(t, m, RouteConfig{Name: "web", Matchers: []Matcher{Prefix("A")}})
	serve(t, m)

	var replacement *Route
	err := m.Batch(func(b *Batch) error {
		if b.Route("web") != old {
			return errors.New("lookup in batch")
		}
		if err := b.Remove(old); err != nil {
			return err
		}
		if b.Route("web") != nil {
			return errors.New("removed name still visible")
		}
		var err error
		replacement, err = b.Add(RouteConfig{Name: "web", Matchers: []Matcher{Prefix("A")}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old route Accept = %v", err)
	}
	send(t, m, "A")
	accept(t, replacement)
}

func TestFailedBatchChangesNothing(t *testing.T) {
	m := startMux(t)
	route := m.Listen(Prefix("A"))
	serve(t, m)

	var added *Route
	var kept *Batch
	boom := errors.New("abort")
	err := m.Batch(func(b *Batch) error {
		kept = b
		added, _ = b.Add(RouteConfig{Name: "new", Priority: 10, Matchers: []Matcher{AnyBytes()}})
		_ = b.SetMatchers(route, Prefix("B"))
		_ = b.Remove(route)
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Batch = %v", err)
	}
	if m.Route("new") != nil || len(m.Routes()) != 1 {
		t.Fatal("failed batch was applied")
	}
	if _, err := added.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("route of a failed batch: Accept = %v", err)
	}
	if err := added.SetMatchers(AnyBytes()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetMatchers on a discarded route = %v", err)
	}
	if _, err := kept.Add(RouteConfig{}); !errors.Is(err, errBatchDone) {
		t.Fatalf("Batch used after return: %v", err)
	}
	send(t, m, "A")
	accept(t, route)
}

func TestBatchRejectsInvalidChanges(t *testing.T) {
	m := startMux(t)
	other := New()
	foreign := other.Listen(AnyBytes())
	removed := m.Listen(AnyBytes())
	_ = removed.Close()

	err := m.Batch(func(b *Batch) error {
		if _, err := b.Add(RouteConfig{Matchers: []Matcher{nil}}); err == nil {
			return errors.New("nil matcher accepted")
		}
		if err := b.SetPriority(foreign, 1); !errors.Is(err, errForeignRoute) {
			return fmt.Errorf("foreign route: %w", err)
		}
		if err := b.Remove(b.Route("missing")); !errors.Is(err, errNilRoute) {
			return fmt.Errorf("nil route: %w", err)
		}
		if err := b.SetPriority(removed, 1); !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("removed route: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := removed.SetPriority(1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetPriority on removed route = %v", err)
	}
}

func TestRemovedRouteHandsPendingConnectionOn(t *testing.T) {
	m := startMux(t)
	idle := m.Listen(Prefix("A"))
	rest := m.Listen(AnyBytes())
	serve(t, m)

	send(t, m, "AB")
	time.Sleep(50 * time.Millisecond) // matched to idle, waiting for Accept
	if err := idle.Close(); err != nil {
		t.Fatal(err)
	}
	got := accept(t, rest)
	if b := readN(t, got, 2); string(b) != "AB" {
		t.Fatalf("read %q", b)
	}
}

func TestRouteChangeAppliesToUndecidedConnection(t *testing.T) {
	m := startMux(t)
	m.Listen(HTTP1(Host("a.example")))
	serve(t, m)

	c := send(t, m, "GET / HTTP/1.1\r\n")
	time.Sleep(50 * time.Millisecond)
	// The connection is still undecided, so the new route takes part in the
	// next decision.
	added := mustAdd(t, m, RouteConfig{Priority: 1, Matchers: []Matcher{Prefix("GET ")}})
	_, _ = c.Write([]byte("Host: a.example\r\n\r\n"))
	accept(t, added)
}

// TestConcurrentRouteChanges changes routes while connections are matched and
// checks that every connection is delivered to a route that accepts it or
// closed.
func TestConcurrentRouteChanges(t *testing.T) {
	m := startMux(t, WithDispatchTimeout(time.Second))
	stable := mustAdd(t, m, RouteConfig{Priority: -100, Matchers: []Matcher{AnyBytes()}})
	serve(t, m)

	var served sync.WaitGroup
	echo := func(l net.Listener) {
		served.Go(func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					b := make([]byte, 1)
					if _, err := io.ReadFull(c, b); err == nil {
						_, _ = c.Write(b)
					}
				}()
			}
		})
	}
	echo(stable)

	stop := make(chan struct{})
	var ops atomic.Int64
	var churn sync.WaitGroup
	churn.Go(func() {
		rng := rand.New(rand.NewPCG(1, 2))
		var live []*Route
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Let other goroutines run on single-threaded ports such as
			// js/wasm, which do not preempt this loop.
			runtime.Gosched()
			ops.Add(1)
			switch op := rng.IntN(4); {
			case op == 0 || len(live) == 0:
				r, err := m.Add(RouteConfig{Priority: rng.IntN(5), Matchers: []Matcher{Prefix(string(rune('A' + rng.IntN(3))))}})
				if err == nil {
					live = append(live, r)
					echo(r)
				}
			case op == 1:
				i := rng.IntN(len(live))
				_ = live[i].Close()
				live = slices.Delete(live, i, i+1)
			case op == 2:
				_ = live[rng.IntN(len(live))].SetMatchers(Prefix(string(rune('A' + rng.IntN(3)))))
			default:
				_ = live[rng.IntN(len(live))].SetPriority(rng.IntN(5))
			}
		}
	})

	var clients sync.WaitGroup
	inflight := make(chan struct{}, 32)
	errs := make(chan error, 5000)
	// Keep connecting until enough route changes overlapped the traffic; the
	// cap only guards against a stalled churn goroutine.
	for i := 0; i < 5000 && (i < 200 || ops.Load() < 300); i++ {
		inflight <- struct{}{}
		clients.Go(func() {
			defer func() { <-inflight }()
			c, err := net.Dial("tcp", m.Addr().String())
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			want := byte('A' + i%4)
			if _, err := c.Write([]byte{want}); err != nil {
				errs <- err
				return
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(c, b); err != nil {
				errs <- err
				return
			}
			if b[0] != want {
				errs <- fmt.Errorf("echo %q, want %q", b, want)
			}
		})
	}
	clients.Wait()
	close(stop)
	churn.Wait()
	if n := ops.Load(); n < 300 {
		t.Errorf("only %d route changes ran during the test", n)
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestBatchAddAndRemove closes a route that one batch adds and removes.
func TestBatchAddAndRemove(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	var r *Route
	err := m.Batch(func(b *Batch) error {
		var err error
		if r, err = b.Add(RouteConfig{Name: "brief", Matchers: []Matcher{AnyBytes()}}); err != nil {
			return err
		}
		return b.Remove(r)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(); !errors.Is(err, net.ErrClosed) || m.Route("brief") != nil {
		t.Fatalf("Accept = %v", err)
	}
}

// TestOrderAfterChanges checks the order that changes keep up to date against
// a full sort, after random batches of additions, priority changes and
// removals.
func TestOrderAfterChanges(t *testing.T) {
	m := New()
	defer func() { _ = m.Close() }()
	r := rand.New(rand.NewPCG(1, 2))
	for range 300 {
		err := m.Batch(func(b *Batch) error {
			for range 1 + r.IntN(4) {
				routes := b.Routes()
				switch op := r.IntN(4); {
				case op == 0 || len(routes) == 0:
					cfg := RouteConfig{Priority: r.IntN(5), Fallback: r.IntN(8) == 0}
					if !cfg.Fallback {
						cfg.Matchers = []Matcher{AnyBytes()}
					}
					if _, err := b.Add(cfg); err != nil {
						return err
					}
				case op == 1:
					if err := b.Remove(routes[r.IntN(len(routes))]); err != nil {
						return err
					}
				default:
					if err := b.SetPriority(routes[r.IntN(len(routes))], r.IntN(5)); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		tb := m.table.Load()
		if want := tb.sorted(); !slices.Equal(tb.order, want) {
			t.Fatalf("order %v, want %v", tb.order, want)
		}
	}
}
