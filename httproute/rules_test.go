package httproute

import (
	"bufio"
	"container/list"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/djylb/netx/forwarded"
	"github.com/djylb/portmux/hostmatch"
)

func TestBackendPath(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{backend(t, "b", echo)},
		Routes: []Route{
			{Path: "/raw", Proxy: &Proxy{Upstream: "b", SendRawPath: true}},
			{Proxy: &Proxy{Upstream: "b"}},
		},
	})
	for target, want := range map[string]string{
		"/x/../api/a%2Fb?q=1": "/api/a%2Fb?q=1", // the path the route saw, with its escapes
		"//api//x":            "/api/x",
		"/a%20b":              "/a%20b",
		"/raw//x/./y":         "/raw//x/./y",
	} {
		_, r := rawRequest(t, base, "GET "+target+" HTTP/1.1\r\nHost: x\r\nX-Original-Path: /forged\r\nConnection: close\r\n\r\n")
		res, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if got := res.Header.Get("Got-URI"); got != want {
			t.Errorf("%s: backend got %q, want %q", target, got, want)
		}
		if v := res.Header.Get("Got-X-Original-Path"); v != "" {
			t.Errorf("%s: X-Original-Path %q passed on", target, v)
		}
	}
}

func TestUpgradeAllowlist(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{backend(t, "b", echo)},
		Routes:    []Route{{Proxy: &Proxy{Upstream: "b"}}},
	})
	_, r := rawRequest(t, base, "GET /p HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n")
	res, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Got-Upgrade") != "" || res.Header.Get("Got-Http2-Settings") != "" {
		t.Errorf("h2c upgrade passed on: %d %v", res.StatusCode, res.Header)
	}
}

func TestFilters(t *testing.T) {
	checkLeaks(t)
	yes, no := true, false
	trusted, _ := forwarded.ParsePrefixSet("127.0.0.0/8")
	_, base := startRouter(t, Options{}, Config{
		Resolver:     &forwarded.Resolver{Trusted: trusted},
		AbortNoRoute: true,
		Routes: []Route{
			{Name: "secure", Hosts: []string{"a.com"}, TLS: &yes, Respond: okRespond, ResponseHeaders: rules(t, "X-Route: ${route}")},
			{Name: "plain", Hosts: []string{"a.com"}, TLS: &no, Respond: okRespond, ResponseHeaders: rules(t, "X-Route: ${route}")},
			{Name: "admin", Hosts: []string{"b.com"}, Path: "/admin", CaseInsensitivePath: true, Respond: okRespond,
				ResponseHeaders: rules(t, "X-Route: ${route}\nX-Id: ${request_id}")},
		},
	})
	c := client(t)
	for _, tc := range []struct {
		host, path, proto, want string
	}{
		{"a.com", "/", "", "plain"},
		{"a.com", "/", "https", "secure"}, // from a trusted proxy
		{"b.com", "/ADMIN/x", "", "admin"},
	} {
		h := http.Header{}
		if tc.proto != "" {
			h.Set("X-Forwarded-Proto", tc.proto)
		}
		res, _ := get(t, c, "GET", base+tc.path, tc.host, h)
		if res.Header.Get("X-Route") != tc.want {
			t.Errorf("%s%s %s: %q, want %q", tc.host, tc.path, tc.proto, res.Header.Get("X-Route"), tc.want)
		}
	}
	res, _ := get(t, c, "GET", base+"/admin", "b.com", http.Header{"X-Request-Id": {"abc-123"}})
	if res.Header.Get("X-Id") != "abc-123" {
		t.Errorf("request id of a trusted proxy: %q", res.Header.Get("X-Id"))
	}
	// No route: the connection closes without a response.
	_, r := rawRequest(t, base, "GET / HTTP/1.1\r\nHost: none.com\r\n\r\n")
	if _, err := http.ReadResponse(r, nil); err == nil {
		t.Error("a response without a route")
	}
}

func TestRequestIDUntrusted(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{Routes: []Route{{Respond: okRespond, ResponseHeaders: rules(t, "X-Id: ${request_id}")}}})
	res, _ := get(t, client(t), "GET", base+"/", "x", http.Header{"X-Request-Id": {"forged"}})
	if id := res.Header.Get("X-Id"); id == "forged" || len(id) != 16 {
		t.Errorf("request id %q", id)
	}
}

func TestAuthCache(t *testing.T) {
	c := &authCache{size: 2, ttl: time.Minute, index: map[[32]byte]*list.Element{}, order: list.New()}
	now := time.Unix(1000, 0)
	a, b, d := [32]byte{1}, [32]byte{2}, [32]byte{3}
	c.add(a, now)
	c.add(b, now)
	_ = c.has(a, now) // a is now the most recent
	c.add(d, now)
	if !c.has(a, now) || c.has(b, now) || !c.has(d, now) {
		t.Error("not the least recently used evicted")
	}
	if c.has(a, now.Add(time.Minute+time.Second)) {
		t.Error("expired entry found")
	}
}

func TestPatternsShared(t *testing.T) {
	// L4 and L7 refuse the same patterns.
	for _, p := range []string{"*a.com", "a.*.com", "api-*.a.com"} {
		if hostmatch.CheckPattern(p) == nil {
			t.Errorf("%q accepted", p)
		}
		if _, err := Build(Config{Routes: []Route{{Hosts: []string{p}, Respond: okRespond}}}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%q: %v", p, err)
		}
	}
}

// streamWriter is a ResponseWriter whose body goes to a pipe as it is
// written, as an HTTP/2 stream's does.
type streamWriter struct {
	header http.Header
	status chan int
	body   *io.PipeWriter
}

func (w *streamWriter) Header() http.Header         { return w.header }
func (w *streamWriter) WriteHeader(code int)        { w.status <- code }
func (w *streamWriter) Write(b []byte) (int, error) { return w.body.Write(b) }
func (w *streamWriter) Flush()                      {}

// TestH2WebSocket passes an extended CONNECT request, as net/http's HTTP/2
// server hands it over, to a WebSocket backend over HTTP/1.1. net/http has
// no client that sends one, so the request is made here.
func TestH2WebSocket(t *testing.T) {
	checkLeaks(t)
	tab, err := Build(Config{Upstreams: []Upstream{wsBackend(t)}, Routes: []Route{
		// The stream is not a body that MaxRequestBody limits.
		{Path: "/chat", Proxy: &Proxy{Upstream: "ws"}, MaxRequestBody: 4},
		{Path: "/none", Proxy: &Proxy{Upstream: "ws"}, Upgrades: []string{"other"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{})
	_ = r.Update(tab)
	t.Cleanup(func() { _ = r.Close() })
	// The allowlist holds for extended CONNECT too.
	refused := httptest.NewRecorder()
	connect, _ := http.NewRequest(http.MethodConnect, "https://a.example.com/none", http.NoBody)
	connect.RequestURI, connect.RemoteAddr = "/none", "127.0.0.1:5000"
	connect.Header.Set(":protocol", "websocket")
	r.ServeHTTP(refused, connect)
	if refused.Code != http.StatusBadRequest {
		t.Errorf("websocket on a route without it: %d", refused.Code)
	}
	reqBody, toBackend := io.Pipe()
	fromBackend, respBody := io.Pipe()
	req, _ := http.NewRequest(http.MethodConnect, "https://a.example.com/chat", reqBody)
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
	req.RequestURI, req.RemoteAddr = "/chat", "127.0.0.1:5000"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	w := &streamWriter{header: http.Header{}, status: make(chan int, 1), body: respBody}
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.ServeHTTP(w, req)
		_ = respBody.Close()
	}()
	if code := <-w.status; code != 200 {
		go func() { _, _ = io.Copy(io.Discard, fromBackend) }()
		t.Fatalf("status %d", code)
	}
	_, _ = io.WriteString(toBackend, "over h2\n")
	line, err := bufio.NewReader(fromBackend).ReadString('\n')
	if line != "over h2\n" {
		t.Fatalf("%q %v", line, err)
	}
	_ = toBackend.Close() // the client ends its stream
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end")
	}
}
