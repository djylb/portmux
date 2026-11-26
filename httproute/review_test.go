package httproute

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/djylb/portmux"
	"github.com/djylb/timeshim"
)

func TestAuthBoundaries(t *testing.T) {
	hash, err := HashPassword("p", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseHash(hash[:len(hash)-4]); !errors.Is(err, ErrHash) {
		t.Fatal(err)
	}
	b, err := compileAuth(&BasicAuth{Users: map[string]string{"u": hash}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if b.credentialID("u", "p\x00q") == b.credentialID("u\x00p", "q") {
		t.Fatal("ambiguous credential fields")
	}
	req.SetBasicAuth("u", "p")
	if !b.check(req) {
		t.Fatal("valid credential refused")
	}
	req.SetBasicAuth("u", "p\x00")
	if b.check(req) {
		t.Fatal("different credential accepted")
	}
	now := time.Unix(1, 0)
	id := [32]byte{}
	b.cache.add(id, now)
	if b.cache.has(id, now.Add(b.cache.ttl)) {
		t.Fatal("hit at expiry")
	}
	if _, err = compileAuth(&BasicAuth{Verify: func(*http.Request, string, string) bool { return true }, CacheTTL: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}

func TestTLSUpdateRequiresHandshake(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	roots := x509.NewCertPool()
	roots.AddCert(backend.Certificate())
	up := Upstream{Name: "tls", Addr: backend.Listener.Addr().String(), TLS: &tls.Config{RootCAs: roots, ServerName: backend.Certificate().DNSNames[0]}}
	r := New(Options{})
	defer func() { _ = r.Close() }()
	for _, want := range []int{http.StatusOK, http.StatusBadGateway} {
		tab, err := Build(Config{Upstreams: []Upstream{up}, Routes: []Route{{Proxy: &Proxy{Upstream: up.Name}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Update(tab); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != want {
			t.Fatalf("got %d want %d", w.Code, want)
		}
		up.TLS = up.TLS.Clone()
		up.TLS.RootCAs = x509.NewCertPool()
	}
}

func TestRouterCallbackPanicAndClosedObservation(t *testing.T) {
	var events []Event
	r := New(Options{Observer: func(e Event) { events = append(events, e) }})
	tab, err := Build(Config{Routes: []Route{{Respond: okRespond, Wrap: func(http.Handler) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("handler") })
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Update(tab); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)
	_ = r.Close()
	r.ServeHTTP(httptest.NewRecorder(), req)
	if len(events) != 2 || events[0].Status != 500 || events[1].Status != 503 {
		t.Fatal(events)
	}
	if _, ok := errors.AsType[*portmux.PanicError](events[0].Err); !ok {
		t.Fatal(events[0].Err)
	}
}

func TestCloseBroadcast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		tab, err := Build(Config{Routes: []Route{{Respond: okRespond, Wrap: func(http.Handler) http.Handler {
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		r := New(Options{})
		if err = r.Update(tab); err != nil {
			t.Fatal(err)
		}
		go r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		<-entered
		closed := make(chan error, 2)
		for range 2 {
			go func() { closed <- r.Close() }()
		}
		synctest.Wait()
		if len(closed) != 0 {
			t.Fatal("close returned with active request")
		}
		close(release)
		for range 2 {
			if err = <-closed; err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestRetiredPoolClosesLateRequest(t *testing.T) {
	base := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer base.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	tab, err := Build(Config{Upstreams: []Upstream{{Name: "u", Addr: base.Listener.Addr().String(), IdleConnTimeout: -1}}, Routes: []Route{{Proxy: &Proxy{Upstream: "u"}, Wrap: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { close(entered); <-release; next.ServeHTTP(w, req) })
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{})
	defer func() { _ = r.Close() }()
	if err = r.Update(tab); err != nil {
		t.Fatal(err)
	}
	old := poolOf(r, "u")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	done := make(chan struct{})
	go func() { defer close(done); r.ServeHTTP(w, req) }()
	<-entered
	err = r.Update(nil)
	close(release)
	<-done
	if err != nil || w.Code != http.StatusOK || old.open.Load() != 0 {
		t.Fatalf("update %v, status %d, open %d", err, w.Code, old.open.Load())
	}
}

func TestWrapBuildPanic(t *testing.T) {
	routes := []Route{{Name: "panic", Respond: okRespond, Wrap: func(http.Handler) http.Handler { panic("wrap") }}}
	base, err := Build(Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, e1 := Build(Config{Routes: routes})
	_, e2 := base.With(Changes{Routes: routes})
	for _, e := range []error{e1, e2} {
		p, ok := errors.AsType[*portmux.PanicError](e)
		if !errors.Is(e, ErrInvalidConfig) || !ok || len(p.Stack) == 0 {
			t.Errorf("lost cause: %v", e)
		}
	}
}

func TestFlushThenPanic(t *testing.T) {
	for _, observed := range []bool{false, true} {
		var ev Event
		opts := Options{}
		if observed {
			opts.Observer = func(e Event) { ev = e }
		}
		r := New(opts)
		func() {
			defer func() { _ = r.Close() }()
			tab, err := Build(Config{Routes: []Route{{Respond: okRespond, Wrap: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if _, ok := w.(http.Flusher); !ok {
						t.Error("missing Flusher")
					}
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Fatal(err)
					}
					panic("after flush")
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Update(tab); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			defer func() {
				err, _ := recover().(error)
				if !errors.Is(err, http.ErrAbortHandler) || w.Code != 200 || w.Body.Len() != 0 || observed && ev.Status != 200 {
					t.Errorf("observed %v: response %d %q, event %v", observed, w.Code, w.Body, ev)
				}
			}()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}
}

type hijackWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.conn, nil, nil }
func (w hijackWriter) Push(string, *http.PushOptions) error         { return nil }
func TestHijackThenPanic(t *testing.T) {
	for _, observed := range []bool{false, true} {
		var ev Event
		opts := Options{}
		if observed {
			opts.Observer = func(e Event) { ev = e }
		}
		r := New(opts)
		func() {
			defer func() { _ = r.Close() }()
			c, peer := net.Pipe()
			defer func() { _ = peer.Close(); _ = c.Close() }()
			w := hijackWriter{httptest.NewRecorder(), c}
			tab, err := Build(Config{Routes: []Route{{Respond: okRespond, Wrap: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if _, ok := w.(http.Pusher); !ok {
						t.Error("missing Pusher")
					}
					if _, ok := w.(http.Hijacker); !ok {
						t.Error("missing Hijacker")
					}
					if _, _, e := http.NewResponseController(w).Hijack(); e != nil {
						t.Fatal(e)
					}
					panic("after hijack")
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Update(tab); err != nil {
				t.Fatal(err)
			}
			defer func() {
				err, _ := recover().(error)
				if !errors.Is(err, http.ErrAbortHandler) || w.Body.Len() != 0 || observed && (ev.Status != 0 || ev.Err == nil) {
					t.Errorf("hijacked response %q, event %v", w.Body, ev)
				}
			}()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}
}

func TestRetiredPoolReleasesTimer(t *testing.T) {
	clock := timeshim.NewFake(time.Time{})
	r := New(Options{Clock: clock})
	defer func() { _ = r.Close() }()
	tab, err := Build(Config{Upstreams: []Upstream{{Name: "u", Dial: noDial}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Update(tab); err != nil {
		t.Fatal(err)
	}
	p := poolOf(r, "u")
	c, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	active := &countedConn{Conn: c, pool: p}
	p.open.Add(1)
	defer func() { _ = active.Close() }()
	if err = r.Update(nil); err != nil {
		t.Fatal(err)
	}
	_ = active.Close()
	if err = r.Close(); err != nil || clock.Pending() != 0 || len(r.retired) != 0 {
		t.Fatal(err, clock.Pending(), len(r.retired))
	}
}

func TestBodyLimitNotifiesServer(t *testing.T) {
	for _, observed := range []bool{false, true} {
		opts := Options{}
		if observed {
			opts.Observer = func(Event) {}
		}
		r := New(opts)
		func() {
			defer func() { _ = r.Close() }()
			tab, err := Build(Config{Routes: []Route{{Respond: okRespond, MaxRequestBody: 1, Wrap: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					_, err := io.Copy(io.Discard, req.Body)
					if _, ok := errors.AsType[*http.MaxBytesError](err); !ok {
						t.Errorf("read body: %v", err)
					}
					w.WriteHeader(http.StatusRequestEntityTooLarge)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Update(tab); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(r)
			defer srv.Close()
			req := httptest.NewRequest(http.MethodPost, srv.URL, strings.NewReader("ab"))
			req.RequestURI = ""
			req.ContentLength = -1
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if !resp.Close || resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatal(resp.Status, resp.Close)
			}
		}()
	}
}

func TestMixedCaseOverlap(t *testing.T) {
	for _, size := range []int{2, overlapIndexMin} {
		for _, foldedFirst := range []bool{false, true} {
			routes := []Route{{Path: "/Ab", Exact: true, Respond: okRespond, CaseInsensitivePath: foldedFirst}, {Path: "/ab", Exact: true, Respond: okRespond, CaseInsensitivePath: !foldedFirst}}
			for i := 2; i < size; i++ {
				routes = append(routes, Route{Path: "/" + strconv.Itoa(10+i), Exact: true, Respond: okRespond})
			}
			_, err := Build(Config{Routes: routes})
			if (err != nil) != foldedFirst || err != nil && !errors.Is(err, ErrInvalidConfig) {
				t.Fatal(size, foldedFirst, err)
			}
		}
	}
}

type notifyCopyWriter struct {
	*httptest.ResponseRecorder
	notify chan bool
	copied bool
}

func (w *notifyCopyWriter) CloseNotify() <-chan bool { return w.notify }
func (w *notifyCopyWriter) ReadFrom(src io.Reader) (int64, error) {
	w.copied = true
	return io.Copy(w.ResponseRecorder, src)
}

func TestWrapWriterCapabilities(t *testing.T) {
	for _, observed := range []bool{false, true} {
		var event Event
		opts := Options{}
		if observed {
			opts.Observer = func(e Event) { event = e }
		}
		r := New(opts)
		raw := &notifyCopyWriter{ResponseRecorder: httptest.NewRecorder(), notify: make(chan bool)}
		tab, err := Build(Config{Routes: []Route{{Respond: okRespond, Wrap: func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n, ok := w.(closeNotifier)
				if !ok || n.CloseNotify() != raw.notify {
					t.Fatal("lost close notification")
				}
				rf, ok := w.(io.ReaderFrom)
				if !ok {
					t.Fatal("lost ReaderFrom")
				}
				if _, ok = w.(http.Hijacker); ok {
					t.Fatal("unexpected Hijacker")
				}
				if _, ok = w.(http.Pusher); ok {
					t.Fatal("unexpected Pusher")
				}
				if _, e := rf.ReadFrom(strings.NewReader("abc")); e != nil {
					t.Fatal(e)
				}
			})
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Update(tab); err != nil {
			t.Fatal(err)
		}
		r.ServeHTTP(raw, httptest.NewRequest(http.MethodGet, "/", nil))
		if !raw.copied || raw.Body.String() != "abc" || observed && (event.Written != 3 || event.Status != http.StatusOK) {
			t.Fatal(raw.copied, event)
		}
		_ = r.Close()
	}
}
