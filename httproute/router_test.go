package httproute

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/netx/forwarded"
)

// echo answers with what it received, as fields of its response.
var echo = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Got-Host", r.Host)
	h.Set("Got-URI", r.RequestURI)
	for k, v := range r.Header {
		h["Got-"+k] = v
	}
	body, _ := io.ReadAll(r.Body)
	_, _ = w.Write(body)
})

func TestProxy(t *testing.T) {
	checkLeaks(t)
	var infos []DialInfo
	var mu sync.Mutex
	up := backend(t, "b", echo)
	dial := up.Dial
	up.Dial = func(ctx context.Context, d DialInfo) (net.Conn, error) {
		mu.Lock()
		infos = append(infos, d)
		mu.Unlock()
		return dial(ctx, d)
	}
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{up},
		Routes: []Route{
			{Name: "api", Hosts: []string{"*.example.com"}, Path: "/api", Proxy: &Proxy{Upstream: "b", ReplacePath: "/v2"},
				RequestHeaders: rules(t, `
X-Real-IP: ${remote_addr}
X-Route: ${route} ${route_path} ${path_rest}
`),
				ResponseHeaders: rules(t, "X-Served-By: ${route}\nGot-Secret: ${unset}")},
			{Name: "host", Hosts: []string{"h.example.com"}, Proxy: &Proxy{Upstream: "b"},
				RequestHeaders: rules(t, "Host: backend.internal")},
		},
	})
	c := client(t)

	res, _ := get(t, c, "GET", base+"/api/users?q=1", "a.example.com:8080", http.Header{
		"Connection":          {"X-Hop, keep-alive"},
		"X-Hop":               {"1"},
		"Te":                  {"gzip"},
		"Proxy-Authorization": {"Basic eDp5"},
		"X-Forwarded-For":     {"1.2.3.4"},
		"Forwarded":           {"for=1.2.3.4"},
		"Secret":              {"s"},
	})
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	h := res.Header
	if got := h.Get("Got-URI"); got != "/v2/users?q=1" {
		t.Errorf("URI %q", got)
	}
	if got := h.Get("Got-Host"); got != "a.example.com:8080" {
		t.Errorf("Host %q, want the client's", got)
	}
	if got := h.Get("Got-X-Real-Ip"); got != "127.0.0.1" {
		t.Errorf("X-Real-IP %q", got)
	}
	if got := h.Get("Got-X-Route"); got != "api /api /users" {
		t.Errorf("X-Route %q", got)
	}
	// RFC 9110 7.6.1: hop-by-hop fields and those that Connection names
	// are not forwarded; forwarding fields only come from rules.
	for _, f := range []string{"Got-X-Hop", "Got-Te", "Got-Proxy-Authorization", "Got-X-Forwarded-For", "Got-Forwarded", "Got-Connection"} {
		if v, ok := h[f]; ok {
			t.Errorf("%s reached the backend: %q", f, v)
		}
	}
	if h.Get("X-Served-By") != "api" || h.Get("Got-Secret") != "" {
		t.Errorf("response rules not applied: %v", h)
	}

	res, _ = get(t, c, "GET", base+"/x", "h.example.com", nil)
	if got := res.Header.Get("Got-Host"); got != "backend.internal" {
		t.Errorf("rewritten Host %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(infos) == 0 || infos[0].Route != "api" || infos[0].Host != "a.example.com" || infos[0].Upstream != "b" ||
		infos[0].Client.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("dial info %+v", infos)
	}
}

func TestReplacePathKeepsEscapes(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{
		Upstreams: []Upstream{backend(t, "b", echo)},
		Routes:    []Route{{Path: "/api/", Proxy: &Proxy{Upstream: "b", ReplacePath: "/"}}},
	})
	for target, want := range map[string]string{
		"/api/a%2Fb/c%20d?x=%2F": "/a%2Fb/c%20d?x=%2F",
		"/api/x/../y":            "/y",
		"/api/":                  "/",
	} {
		_, r := rawRequest(t, base, "GET "+target+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		res, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if got := res.Header.Get("Got-URI"); got != want {
			t.Errorf("%s: backend got %q, want %q", target, got, want)
		}
	}
}

func TestRedirectRespond(t *testing.T) {
	checkLeaks(t)
	_, base := startRouter(t, Options{}, Config{Routes: []Route{
		{Path: "/old", Redirect: &Redirect{To: template(t, "https://${host}/new${path_rest}${is_args}${args}"), Status: 301}},
		{Path: "/hello", Respond: &Respond{Status: 201, Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("hi")},
			ResponseHeaders: rules(t, "X-Status: ${status}")},
		{Path: "/empty", Respond: &Respond{Status: 204, Body: []byte("ignored")}},
	}})
	c := client(t)
	res, _ := get(t, c, "GET", base+"/old/a?b=1", "Example.com", nil)
	if res.StatusCode != 301 || res.Header.Get("Location") != "https://example.com/new/a?b=1" {
		t.Errorf("redirect %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, body := get(t, c, "GET", base+"/hello", "x", nil)
	if res.StatusCode != 201 || body != "hi" || res.Header.Get("X-Status") != "201" || res.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("respond %d %q %v", res.StatusCode, body, res.Header)
	}
	res, body = get(t, c, "HEAD", base+"/hello", "x", nil)
	if res.StatusCode != 201 || body != "" || res.ContentLength != 2 {
		t.Errorf("HEAD %d %q %d", res.StatusCode, body, res.ContentLength)
	}
	res, body = get(t, c, "GET", base+"/empty", "x", nil)
	if res.StatusCode != 204 || body != "" {
		t.Errorf("204 %q", body)
	}
}

func TestRedirectHTTPS(t *testing.T) {
	checkLeaks(t)
	trusted, err := forwarded.ParsePrefixSet("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	_, base := startRouter(t, Options{}, Config{
		Resolver: &forwarded.Resolver{Trusted: trusted},
		Routes: []Route{
			{Hosts: []string{"a.example.com"}, RedirectHTTPS: &HTTPSRedirect{}, Respond: okRespond},
			{Hosts: []string{"b.example.com"}, RedirectHTTPS: &HTTPSRedirect{Port: 8443, Status: 301}, Respond: okRespond},
		},
	})
	c := client(t)
	res, _ := get(t, c, "GET", base+"/p?q", "a.example.com:80", nil)
	if res.StatusCode != 308 || res.Header.Get("Location") != "https://a.example.com/p?q" {
		t.Errorf("%d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = get(t, c, "GET", base+"/", "b.example.com", nil)
	if res.StatusCode != 301 || res.Header.Get("Location") != "https://b.example.com:8443/" {
		t.Errorf("%d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// A trusted proxy that terminated TLS.
	res, body := get(t, c, "GET", base+"/", "a.example.com", http.Header{"X-Forwarded-Proto": {"https"}})
	if res.StatusCode != 200 || body != "ok" {
		t.Errorf("behind a TLS proxy: %d", res.StatusCode)
	}
}

func TestErrors(t *testing.T) {
	checkLeaks(t)
	slow := make(chan struct{})
	t.Cleanup(func() { close(slow) })
	reject := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "backend page")
	})
	var bodyRead atomic.Bool
	expect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Read") != "" {
			_, _ = io.ReadAll(r.Body)
			bodyRead.Store(true)
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	slowUp := backend(t, "slow", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-slow:
		case <-r.Context().Done():
		}
	}))
	slowUp.ResponseHeaderTimeout = 50 * time.Millisecond
	_, base := startRouter(t, Options{}, Config{
		ErrorPages: map[int]ErrorPage{404: {Body: []byte("custom 404")}, 502: {ContentType: "text/plain", Body: []byte("bad gateway page")}},
		Upstreams: []Upstream{
			{Name: "down", Dial: noDial},
			{Name: "offline", Dial: func(context.Context, DialInfo) (net.Conn, error) {
				return nil, &StatusError{Status: 503, Err: errors.New("tunnel offline")}
			}},
			{Name: "panic", Dial: func(context.Context, DialInfo) (net.Conn, error) { panic("boom") }},
			slowUp,
			backend(t, "reject", reject),
			backend(t, "expect", expect),
			backend(t, "echo", echo),
		},
		Routes: []Route{
			{Path: "/down", Proxy: &Proxy{Upstream: "down"}},
			{Path: "/offline", Proxy: &Proxy{Upstream: "offline"}, ErrorPages: map[int]ErrorPage{503: {Body: []byte("route 503")}}},
			{Path: "/panic", Proxy: &Proxy{Upstream: "panic"}},
			{Path: "/slow", Proxy: &Proxy{Upstream: "slow"}},
			{Path: "/reject", Proxy: &Proxy{Upstream: "reject"}},
			{Path: "/intercept", Proxy: &Proxy{Upstream: "reject", InterceptErrors: true}, ErrorPages: map[int]ErrorPage{403: {Body: []byte("our 403")}}},
			{Path: "/expect", Proxy: &Proxy{Upstream: "expect"}},
			{Path: "/small", Proxy: &Proxy{Upstream: "echo"}, MaxRequestBody: 4},
		},
	})
	c := client(t)
	for _, tc := range []struct {
		path   string
		status int
		body   string
	}{
		{"/nothing", 404, "custom 404"},
		{"/down", 502, "bad gateway page"},
		{"/offline", 503, "route 503"},
		{"/panic", 502, "bad gateway page"},
		{"/slow", 504, "504 Gateway Timeout\n"},
		{"/reject", 403, "backend page"},
		{"/intercept", 403, "our 403"},
	} {
		res, body := get(t, c, "GET", base+tc.path, "x", nil)
		if res.StatusCode != tc.status || body != tc.body {
			t.Errorf("%s: %d %q, want %d %q", tc.path, res.StatusCode, body, tc.status, tc.body)
		}
	}

	for _, tc := range []struct{ request, status string }{
		{"GET /a/%2e%2e/b HTTP/1.1\r\nHost: x\r\n\r\n", "400"},
		{"GET / HTTP/1.1\r\nHost: a@b\r\n\r\n", "400"},
		{"CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\n", "405"},
		{"POST /small HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n12345", "413"},
		{"POST /small HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n", "413"},
	} {
		_, r := rawRequest(t, base, tc.request)
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 "+tc.status) {
			t.Errorf("%q: %q %v", tc.request, line, err)
		}
	}

	// RFC 9110 10.1.1: a backend that answers before reading the body
	// spares the client sending it; no 100 Continue reaches the client.
	_, r := rawRequest(t, base, "POST /expect HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n")
	res, err := http.ReadResponse(r, nil)
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("expect: %v %v", res, err)
	}
	if bodyRead.Load() {
		t.Error("the backend read a body")
	}
	// A backend that reads the body gets it after 100 Continue.
	conn, r := rawRequest(t, base, "POST /expect HTTP/1.1\r\nHost: x\r\nX-Read: 1\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n")
	res, err = http.ReadResponse(r, nil)
	if err != nil || res.StatusCode != 100 {
		t.Fatalf("expect: %v %v", res, err)
	}
	_, _ = io.WriteString(conn, "abc")
	res, err = http.ReadResponse(r, nil)
	if err != nil || res.StatusCode != 401 || !bodyRead.Load() {
		t.Fatalf("expect after 100: %v %v", res, err)
	}
}

func TestUpstreamTLS(t *testing.T) {
	checkLeaks(t)
	srv := httptest.NewTLSServer(echo)
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	up := Upstream{Name: "b", TLS: &tls.Config{InsecureSkipVerify: true}, Dial: func(ctx context.Context, _ DialInfo) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}}
	_, base := startRouter(t, Options{}, Config{Upstreams: []Upstream{up}, Routes: []Route{{Proxy: &Proxy{Upstream: "b"}}}})
	res, _ := get(t, client(t), "GET", base+"/tls", "a.example.com", nil)
	if res.StatusCode != 200 || res.Header.Get("Got-URI") != "/tls" {
		t.Errorf("%d %v", res.StatusCode, res.Header)
	}
}

func TestTrailers(t *testing.T) {
	checkLeaks(t)
	up := backend(t, "b", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Trailer", "X-Sum, X-Req-Trailer")
		_, _ = w.Write(body)
		w.Header().Set("X-Sum", fmt.Sprint(len(body)))
		w.Header().Set("X-Req-Trailer", r.Trailer.Get("X-Client"))
	}))
	_, base := startRouter(t, Options{}, Config{Upstreams: []Upstream{up}, Routes: []Route{{Proxy: &Proxy{Upstream: "b"}}}})
	req, _ := http.NewRequest("POST", base+"/", io.MultiReader(strings.NewReader("hello")))
	req.Trailer = http.Header{"X-Client": nil}
	req.ContentLength = -1
	req.Trailer.Set("X-Client", "c1")
	res, err := client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(body) != "hello" || res.Trailer.Get("X-Sum") != "5" || res.Trailer.Get("X-Req-Trailer") != "c1" {
		t.Errorf("%q %v", body, res.Trailer)
	}
}

// wsBackendHandler accepts upgrades to "echo" and echoes lines until EOF.
func wsBackendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		w.WriteHeader(http.StatusUpgradeRequired)
		return
	}
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	accept := ""
	if key := r.Header.Get("Sec-WebSocket-Key"); key != "" {
		accept = "Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n"
	}
	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+accept+"\r\n")
	_, _ = io.Copy(c, brw)
}

func wsBackend(t *testing.T) Upstream {
	return backend(t, "ws", http.HandlerFunc(wsBackendHandler))
}

func TestUpgrade(t *testing.T) {
	checkLeaks(t)
	var events []Event
	var mu sync.Mutex
	r, base := startRouter(t, Options{Observer: func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}}, Config{Upstreams: []Upstream{wsBackend(t)}, Routes: []Route{{Name: "ws", Proxy: &Proxy{Upstream: "ws"}}}})
	conn, br := rawRequest(t, base, "GET /chat HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	res, err := http.ReadResponse(br, nil)
	if err != nil || res.StatusCode != 101 {
		t.Fatalf("%v %v", res, err)
	}
	_, _ = io.WriteString(conn, "ping\n")
	if line, err := br.ReadString('\n'); line != "ping\n" {
		t.Fatalf("%q %v", line, err)
	}
	// Half-close: the backend sees EOF and ends, which ends the stream.
	_ = conn.(*net.TCPConn).CloseWrite()
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("after half-close: %v", err)
	}
	waitFor(t, "event", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events) == 1
	})
	if ev := events[0]; ev.Status != 101 || ev.Route != "ws" || ev.Path != "/chat" {
		t.Errorf("event %+v", ev)
	}

	// Closing the Router ends upgraded connections.
	conn, br = rawRequest(t, base, "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if res, err := http.ReadResponse(br, nil); err != nil || res.StatusCode != 101 {
		t.Fatalf("%v %v", res, err)
	}
	_ = r.Close()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("upgraded connection open after Close")
	}
	_ = conn
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUpdate(t *testing.T) {
	checkLeaks(t)
	b1 := backend(t, "b", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "one") }))
	b2 := backend(t, "b", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "two") }))
	t1, err := Build(Config{Upstreams: []Upstream{b1}, Routes: []Route{{Proxy: &Proxy{Upstream: "b"}}}})
	if err != nil {
		t.Fatal(err)
	}
	t2, err := Build(Config{Upstreams: []Upstream{b2}, Routes: []Route{{Proxy: &Proxy{Upstream: "b"}}}})
	if err != nil {
		t.Fatal(err)
	}
	r, base := startRouter(t, Options{}, Config{})
	if err := r.Update(t1); err != nil {
		t.Fatal(err)
	}
	tr := r.state.Load().transports[0]
	if err := r.Update(t2); err != nil {
		t.Fatal(err)
	}
	if r.state.Load().transports[0] != tr {
		t.Error("an upstream with the same settings got a new transport")
	}
	t3, _ := Build(Config{Upstreams: []Upstream{{Name: "b", Dial: b2.Dial, DisableKeepAlives: true}}, Routes: []Route{{Proxy: &Proxy{Upstream: "b"}}}})
	if err := r.Update(t3); err != nil || r.state.Load().transports[0] == tr {
		t.Error("an upstream with other settings kept its transport")
	}

	c := client(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				res, err := c.Get(base + "/")
				if err != nil {
					t.Error(err)
					return
				}
				body, _ := io.ReadAll(res.Body)
				_ = res.Body.Close()
				if s := string(body); s != "one" && s != "two" {
					t.Errorf("body %q", s)
					return
				}
			}
		})
	}
	for i := range 50 {
		_ = r.Update([]*Table{t1, t2}[i%2])
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	// Pools replaced while their connections were in use are dropped
	// once those are idle and closed.
	waitFor(t, "retired pools to go", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.retired) == 0
	})
	_ = r.Close()
	if err := r.Update(t1); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Update after Close: %v", err)
	}
}

// wrapped is a connection that wraps another, as a port multiplexer's
// connections do.
type wrapped struct{ net.Conn }

func (w wrapped) NetConn() net.Conn { return w.Conn }

func TestServeConn(t *testing.T) {
	checkLeaks(t)
	tab, err := Build(Config{Routes: []Route{{Respond: okRespond, ResponseHeaders: rules(t, "X-Scheme: ${scheme}\nX-Route: ${route}")}}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{})
	if err := r.Update(tab); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{certificate()}, NextProtos: []string{"h2", "http/1.1"}}
	for _, tc := range []struct {
		name   string
		server func(net.Conn) net.Conn
		client func(net.Conn) net.Conn
		scheme string
	}{
		{"plain", func(c net.Conn) net.Conn { return c }, func(c net.Conn) net.Conn { return c }, "http"},
		{"tls", func(c net.Conn) net.Conn { return tls.Server(c, cfg) },
			func(c net.Conn) net.Conn {
				return tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "a.example.com", NextProtos: []string{"http/1.1"}})
			}, "https"},
		{"wrapped tls", func(c net.Conn) net.Conn { return wrapped{tls.Server(c, cfg)} },
			func(c net.Conn) net.Conn {
				return tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "a.example.com"})
			}, "https"},
	} {
		cc, sc := net.Pipe()
		if err := r.ServeConn(tc.server(sc)); err != nil {
			t.Fatal(err)
		}
		c := tc.client(cc)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		go func() { _, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: a.example.com\r\nConnection: close\r\n\r\n") }()
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = res.Body.Close()
		// The synchronous pipe would block close_notify alerts sent both
		// ways at once.
		_ = cc.Close()
		if res.Header.Get("X-Scheme") != tc.scheme {
			t.Errorf("%s: scheme %q", tc.name, res.Header.Get("X-Scheme"))
		}
	}
	_ = r.Close()
	cc, sc := net.Pipe()
	defer func() { _ = cc.Close() }()
	if err := r.ServeConn(sc); !errors.Is(err, net.ErrClosed) {
		t.Errorf("ServeConn after Close: %v", err)
	}
}

func TestHTTP2(t *testing.T) {
	checkLeaks(t)
	up := backend(t, "b", echo)
	tab, err := Build(Config{Upstreams: []Upstream{up}, Routes: []Route{{Proxy: &Proxy{Upstream: "b"}, ResponseHeaders: rules(t, "X-Proto: ${scheme}")}}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{})
	_ = r.Update(tab)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{certificate()}, NextProtos: []string{"h2", "http/1.1"}}))
	}()
	t.Cleanup(func() { _ = r.Close(); <-done })
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(tr.CloseIdleConnections)
	req, _ := http.NewRequest("GET", "https://"+ln.Addr().String()+"/x", nil)
	req.Host = "a.example.com"
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.ProtoMajor != 2 || res.Header.Get("Got-Host") != "a.example.com" || res.Header.Get("X-Proto") != "https" {
		t.Errorf("proto %s, %v", res.Proto, res.Header)
	}
}

func TestExternalServerClose(t *testing.T) {
	checkLeaks(t)
	started := make(chan struct{})
	up := backend(t, "b", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		close(started)
		<-r.Context().Done()
	}))
	tab, _ := Build(Config{Upstreams: []Upstream{up}, Routes: []Route{{Name: "w", Proxy: &Proxy{Upstream: "b"},
		Wrap: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Wrapped", RouteName(r)+" "+Client(r).Addr.Addr().String())
				next.ServeHTTP(w, r)
			})
		}}}})
	r := New(Options{})
	_ = r.Update(tab)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	c := client(t)
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	<-started
	if res.Header.Get("X-Wrapped") != "w 127.0.0.1" {
		t.Errorf("wrap: %q", res.Header.Get("X-Wrapped"))
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waits for a request of another server")
	}
	if _, err := io.ReadAll(res.Body); err == nil {
		t.Log("body ended cleanly") // the server may end it either way
	}
	res2, body := get(t, c, "GET", srv.URL, "", nil)
	if res2.StatusCode != 503 {
		t.Errorf("after Close: %d %q", res2.StatusCode, body)
	}
}

func TestShutdown(t *testing.T) {
	checkLeaks(t)
	release := make(chan struct{})
	up := backend(t, "b", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		_, _ = io.WriteString(w, "done")
	}))
	r, base := startRouter(t, Options{}, Config{Upstreams: []Upstream{up}, Routes: []Route{{Proxy: &Proxy{Upstream: "b"}}}})
	c := client(t)
	got := make(chan string, 1)
	go func() {
		res, err := c.Get(base)
		if err != nil {
			got <- err.Error()
			return
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		got <- string(body)
	}()
	waitFor(t, "request", func() bool { return r.active.Load() == 1 })
	shut := make(chan error, 1)
	go func() { shut <- r.Shutdown(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	if s := <-got; s != "done" {
		t.Errorf("request during Shutdown: %q", s)
	}
	if err := <-shut; err != nil {
		t.Error(err)
	}
}
