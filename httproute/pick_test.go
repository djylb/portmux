package httproute

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// Pick chooses a backend per request: connections are pooled per key and
// reused for the same key, and a *StatusError answers with its status.
func TestProxyPick(t *testing.T) {
	checkLeaks(t)
	addrs := map[string]string{}
	for _, name := range []string{"a", "b"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, name)
		}))
		t.Cleanup(srv.Close)
		addrs[name] = srv.Listener.Addr().String()
	}
	var mu sync.Mutex
	dials := map[string]int{}
	up := Upstream{Name: "group", Dial: func(ctx context.Context, d DialInfo) (net.Conn, error) {
		mu.Lock()
		dials[d.Key]++
		mu.Unlock()
		var dl net.Dialer
		return dl.DialContext(ctx, "tcp", addrs[d.Key])
	}}
	pick := func(r *http.Request) (string, error) {
		switch k := r.URL.Query().Get("to"); k {
		case "a", "b":
			return k, nil
		case "down":
			return "", &StatusError{Status: http.StatusServiceUnavailable}
		default:
			return "", errors.New("no member")
		}
	}
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{up},
		Routes:    []Route{{Proxy: &Proxy{Upstream: "group", Pick: pick}}},
	})
	c := client(t)
	for _, tc := range []struct {
		to     string
		status int
		body   string
	}{{"a", 200, "a"}, {"b", 200, "b"}, {"a", 200, "a"}, {"b", 200, "b"}, {"down", 503, ""}, {"x", 502, ""}} {
		res, body := get(t, c, "GET", base+"/?to="+tc.to, "h", nil)
		if res.StatusCode != tc.status || tc.body != "" && body != tc.body {
			t.Errorf("to=%s: %d %q", tc.to, res.StatusCode, body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if dials["a"] != 1 || dials["b"] != 1 || len(dials) != 2 {
		t.Errorf("dials %v, want one per key", dials)
	}
}

// Allow is asked also for remembered credentials, so that a disabled
// account is refused at once.
func TestBasicAuthAllow(t *testing.T) {
	checkLeaks(t)
	hash, err := HashPassword("pw", 1)
	if err != nil {
		t.Fatal(err)
	}
	var disabled atomic.Bool
	_, base := startRouter(t, Options{}, Config{Routes: []Route{{Respond: okRespond, BasicAuth: &BasicAuth{
		Users: map[string]string{"u": hash},
		Allow: func(_ *http.Request, user string) bool { return user == "u" && !disabled.Load() },
	}}}})
	c := client(t)
	auth := func(pass string) int {
		req, _ := http.NewRequest("GET", base+"/", nil)
		req.SetBasicAuth("u", pass)
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res.StatusCode
	}
	if s := auth("pw"); s != 200 {
		t.Errorf("allowed: %d", s)
	}
	disabled.Store(true)
	if s := auth("pw"); s != 401 {
		t.Errorf("disabled, remembered: %d", s)
	}
	disabled.Store(false)
	if s := auth("pw"); s != 200 {
		t.Errorf("enabled again: %d", s)
	}
	if s := auth("wrong"); s != 401 {
		t.Errorf("wrong password: %d", s)
	}
}

// With Pick, the server name sent to a TLS backend is still derived from
// the outgoing Host.
func TestPickServerName(t *testing.T) {
	checkLeaks(t)
	srv, roots, names := tlsBackend(t, false, echo)
	addr := srv.Listener.Addr().String()
	pick := func(*http.Request) (string, error) { return "k", nil }
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{{Name: "ip", Addr: addr, TLS: &tls.Config{RootCAs: roots}}},
		Routes:    []Route{{Proxy: &Proxy{Upstream: "ip", Pick: pick}}},
	})
	for _, host := range []string{"example.com", "[::1]:8443"} {
		before := len(names())
		res, _ := get(t, client(t), "GET", base+"/", host, nil)
		n := names()
		if res.StatusCode != 200 || res.Header.Get("Got-Host") != host {
			t.Errorf("%s: %d %v", host, res.StatusCode, res.Header)
		}
		if host == "example.com" && (len(n) != before+1 || n[before] != "example.com") {
			t.Errorf("server names %q", n[before:])
		}
	}
}

// poolOf returns the router's pool of the named upstream.
func poolOf(r *Router, name string) *pool {
	b, _ := r.state.Load().upstreams.Get(name)
	return b.pool
}

// keyCount returns the number of keys of the router's pool of the named
// upstream.
func keyCount(r *Router, name string) int {
	p := poolOf(r, name)
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.keys)
}

// Keys leave the pool with their last connection, above MaxKeys the least
// recently used one is closed, and requests without a key never add one.
func TestPickKeysRecycled(t *testing.T) {
	checkLeaks(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	dials := map[string]int{}
	up := Upstream{Name: "u", MaxKeys: 2, Dial: func(ctx context.Context, d DialInfo) (net.Conn, error) {
		mu.Lock()
		dials[d.Key]++
		mu.Unlock()
		var dl net.Dialer
		return dl.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	pick := func(r *http.Request) (string, error) { return r.URL.Query().Get("k"), nil }
	r, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{up},
		Routes:    []Route{{Proxy: &Proxy{Upstream: "u", Pick: pick}}},
	})
	c := client(t)
	for _, k := range []string{"", "a", "b", "a", "c", ""} {
		if res, _ := get(t, c, "GET", base+"/?k="+k, "h", nil); res.StatusCode != 200 {
			t.Fatalf("k=%q: %d", k, res.StatusCode)
		}
	}
	// "b" was the least recently used when "c" came.
	if n := keyCount(r, "u"); n != 2 {
		t.Errorf("%d keys, want 2", n)
	}
	mu.Lock()
	if dials[""] != 1 || dials["a"] != 1 || dials["b"] != 1 || dials["c"] != 1 {
		t.Errorf("dials %v", dials)
	}
	mu.Unlock()
	if res, _ := get(t, c, "GET", base+"/?k=b", "h", nil); res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	mu.Lock()
	if dials["b"] != 2 {
		t.Errorf("b reused an evicted connection: %v", dials)
	}
	mu.Unlock()
	// The proxy releases a key's request reference after the client has
	// already read the response, and a finished upstream connection may
	// return to the idle pool just after closeIdle, so allow it to settle.
	waitFor(t, "keys to be released", func() bool {
		r.closeIdle()
		return keyCount(r, "u") == 0
	})
}

// Concurrent requests over many keys share each key's pool and leave
// nothing behind.
func TestPickConcurrent(t *testing.T) {
	checkLeaks(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	up := Upstream{Name: "u", MaxKeys: 4, Addr: srv.Listener.Addr().String()}
	pick := func(r *http.Request) (string, error) { return r.URL.Query().Get("k"), nil }
	r, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{up},
		Routes:    []Route{{Proxy: &Proxy{Upstream: "u", Pick: pick}}},
	})
	c := client(t)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 20 {
				k := strconv.Itoa((i + j) % 8)
				req, _ := http.NewRequest("GET", base+"/?k="+k, nil)
				res, err := c.Do(req)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.ReadAll(res.Body)
				_ = res.Body.Close()
				if res.StatusCode != 200 {
					t.Error(res.StatusCode)
				}
			}
		})
	}
	wg.Wait()
	// The proxy releases a key's request reference after the client has
	// already read the response, and a finished upstream connection may
	// return to the idle pool just after closeIdle, so allow it to settle.
	waitFor(t, "keys to be released", func() bool {
		r.closeIdle()
		return keyCount(r, "u") == 0
	})
}

// TestPoolEvictsLRU checks that a pool over MaxKeys evicts its least
// recently used key, and that an evicted key in use is not chosen again.
func TestPoolEvictsLRU(t *testing.T) {
	u, err := compileUpstream(Upstream{Name: "u", Dial: noDial, MaxKeys: 2})
	if err != nil {
		t.Fatal(err)
	}
	p := newPool(u)
	a, b := p.acquire("a"), p.acquire("b")
	p.acquire("a") // a is now more recent than b
	c := p.acquire("c")
	if b.prev != nil || a.prev == nil || c.prev == nil {
		t.Fatalf("evicted the wrong key: a %v b %v c %v", a.prev != nil, b.prev != nil, c.prev != nil)
	}
	p.acquire("d") // b is out of the list: a goes now
	if a.prev != nil {
		t.Fatal("a still listed")
	}
	for _, k := range []*keyPool{a, a, b, c} {
		p.release(k)
	}
	if _, ok := p.keys["a"]; ok || len(p.keys) != 1 {
		t.Fatalf("keys left: %d", len(p.keys))
	}
}

// TestPoolEvictedKeyListedAgain checks that a key evicted while in use
// can be evicted again once its request ends while it keeps a connection,
// so that it does not stay in the pool for good.
func TestPoolEvictedKeyListedAgain(t *testing.T) {
	u, err := compileUpstream(Upstream{Name: "u", Addr: "x:1", MaxKeys: 2})
	if err != nil {
		t.Fatal(err)
	}
	p := newPool(u)
	ka := p.acquire("a") // a request on a
	p.acquire("b")
	p.acquire("c") // evicts a, in use
	if ka.prev != nil {
		t.Fatal("a still listed")
	}
	p.hold(ka) // a connection of a stays open
	p.release(ka)
	if ka.prev == nil {
		t.Fatal("a not listed again after its request ended")
	}
	evicted := false
	for _, k := range []string{"d", "e", "f", "g"} {
		kk := p.acquire(k)
		p.hold(kk)
		p.release(kk)
		evicted = evicted || ka.prev == nil
	}
	if !evicted {
		t.Error("a was never evicted again")
	}
}
