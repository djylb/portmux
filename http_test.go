package portmux

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPFilters(t *testing.T) {
	req, res := parseHTTP([]byte("GET /ws/x HTTP/1.1\r\nHost: Bridge.Example.com:8024\r\n" +
		"Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	if res != Match {
		t.Fatal(res)
	}
	tests := []struct {
		name   string
		filter HTTPFilter
		want   bool
	}{
		{"host with port", Host("bridge.example.com"), true},
		{"host wildcard", Host("*.example.com"), true},
		{"host other", Host("example.com"), false},
		{"host empty", Host(""), false},
		{"method", Method("GET", "HEAD"), true},
		{"method case", Method("get"), false},
		{"path", Path("/ws/x"), true},
		{"path other", Path("/ws"), false},
		{"path prefix", PathPrefix("/ws/"), true},
		{"path prefix other", PathPrefix("/api"), false},
		{"websocket", WebSocket(), true},
	}
	for _, tt := range tests {
		if got := tt.filter.Match(req); got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
		}
	}
	plain, _ := parseHTTP([]byte("GET / HTTP/1.1\r\nConnection: upgrade\r\n\r\n"))
	if WebSocket().Match(plain) {
		t.Error("WebSocket matched a request without Upgrade")
	}
	if !Host("").Match(plain) {
		t.Error(`Host("") did not match a request without a host`)
	}
}

func TestHTTP1Matcher(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if got := HTTP1(Host("a.example")).Match(&Input{data: data}); got != Match {
		t.Fatalf("Match = %v", got)
	}
	if got := HTTP1(Host("b.example")).Match(&Input{data: data}); got != NoMatch {
		t.Fatalf("Match = %v", got)
	}
	if got := HTTP1().Match(&Input{data: data[:20]}); got != NeedMore {
		t.Fatalf("Match = %v", got)
	}
	if got := HTTP1().Match(&Input{data: data[:20], final: true}); got != NoMatch {
		t.Fatalf("Match on final = %v", got)
	}
}

func inputOf(data []byte) *Input {
	in := NewInput(nil, nil)
	in.SetBytes(data, false)
	return in
}

// TestH2CRouting routes gRPC and plain HTTP/2 requests of cleartext
// connections apart, and HTTP/1.1 elsewhere, through real clients.
func TestH2CRouting(t *testing.T) {
	m := startMux(t)
	grpc := m.Match(HTTP2(Header("content-type", "application/grpc")))
	h2 := m.Match(HTTP2())
	web := m.Match(HTTP1())
	serve(t, m)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	for name, l := range map[string]net.Listener{"grpc": grpc, "h2": h2, "web": web} {
		srv := &http.Server{Protocols: &protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, name+" "+r.Proto+" "+r.Host)
		})}
		go func() { _ = srv.Serve(l) }()
		t.Cleanup(func() { _ = srv.Close() })
	}
	get := func(h2c bool, contentType string) string {
		var p http.Protocols
		if h2c {
			p.SetUnencryptedHTTP2(true)
		} else {
			p.SetHTTP1(true)
		}
		tr := &http.Transport{Protocols: &p, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", m.Addr().String())
		}}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequest("POST", "http://svc.example.com/x", strings.NewReader("body"))
		req.Header.Set("Content-Type", contentType)
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	for _, tt := range []struct {
		h2c         bool
		contentType string
		want        string
	}{
		{true, "application/grpc", "grpc HTTP/2.0 svc.example.com"},
		{true, "application/json", "h2 HTTP/2.0 svc.example.com"},
		{false, "application/grpc", "web HTTP/1.1 svc.example.com"},
	} {
		if got := get(tt.h2c, tt.contentType); got != tt.want {
			t.Errorf("h2c %v, %s: %q, want %q", tt.h2c, tt.contentType, got, tt.want)
		}
	}
	if got := describe(HTTP2(Host("a"), Header("content-type", "application/grpc"))); got != `HTTP2(Host("a"), Header("content-type", "application/grpc"))` {
		t.Fatalf("description %s", got)
	}
}
