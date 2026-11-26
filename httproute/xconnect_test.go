package httproute

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// streamWriter makes response data available to the test as it is written.
type streamWriter struct {
	header http.Header
	status chan int
	body   *io.PipeWriter
}

func (w *streamWriter) Header() http.Header         { return w.header }
func (w *streamWriter) WriteHeader(code int)        { w.status <- code }
func (w *streamWriter) Write(b []byte) (int, error) { return w.body.Write(b) }
func (w *streamWriter) Flush()                      {}

// connectRequest uses the request representation delivered by each server.
func connectRequest(ctx context.Context, major int, path, protocol string, body io.Reader) *http.Request {
	const authority = "example.test:443"
	target := path
	if protocol == "" {
		target = authority
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodConnect, target, body)
	req.Host = authority
	req.TLS = &tls.ConnectionState{}
	req.ProtoMajor, req.ProtoMinor = major, 0
	if major == 2 {
		req.Proto = "HTTP/2.0"
		if protocol != "" {
			req.Header.Set(":protocol", protocol)
		}
	} else {
		req.Proto = protocol
		if protocol == "" {
			req.Proto = "HTTP/3.0"
		}
	}
	req.Header.Set("Sec-WebSocket-Version", "13")
	return req
}

func TestExtendedConnectWebSocket(t *testing.T) {
	checkLeaks(t)
	const finalFrame = "\x88\x02\x03\xe8" // WebSocket close frame, status 1000.
	up := backend(t, "ws", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/ordinary" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if req.URL.Path == "/refused" {
			http.Error(w, "backend refused", http.StatusForbidden)
			return
		}
		serveWebSocket(w, req, func(c net.Conn, brw *bufio.ReadWriter) {
			if _, err := io.Copy(c, brw); err == nil {
				// The client must end its sending direction before this frame exists.
				_, _ = io.WriteString(c, finalFrame)
			}
		})
	}))
	tab, err := Build(Config{Upstreams: []Upstream{up}, Routes: []Route{
		{Proxy: &Proxy{Upstream: "ws"}, MaxRequestBody: 4},
		{Path: "/idle", Proxy: &Proxy{Upstream: "ws"}, UpgradeIdleTimeout: time.Minute},
		{Path: "/denied", Proxy: &Proxy{Upstream: "ws"}, Upgrades: []string{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := New(Options{})
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Update(tab); err != nil {
		t.Fatal(err)
	}
	for _, version := range []struct {
		name  string
		major int
		path  string
	}{{"h2", 2, "/chat"}, {"h3", 3, "/idle"}} {
		t.Run(version.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, path, protocol string
				status               int
			}{
				{"ordinary", "/chat", "", http.StatusMethodNotAllowed},
				{"denied", "/denied", "websocket", http.StatusBadRequest},
				{"unsupported", "/chat", "unknown", http.StatusNotImplemented},
				{"ordinary-backend-success", "/ordinary", "websocket", http.StatusBadGateway},
				{"backend-refused", "/refused", "websocket", http.StatusForbidden},
			} {
				t.Run(tc.name, func(t *testing.T) {
					w := httptest.NewRecorder()
					r.ServeHTTP(w, connectRequest(t.Context(), version.major, tc.path, tc.protocol, http.NoBody))
					if w.Code != tc.status {
						t.Fatalf("status %d, want %d", w.Code, tc.status)
					}
				})
			}
			for _, end := range []string{"eof", "reset", "cancel"} {
				t.Run(end, func(t *testing.T) {
					ctx, timeout := context.WithTimeout(t.Context(), 5*time.Second)
					defer timeout()
					reqCtx, cancel := context.WithCancel(ctx)
					defer cancel()
					reqBody, toBackend := io.Pipe()
					fromBackend, respBody := io.Pipe()
					defer func() { _ = toBackend.Close() }()
					defer func() { _ = fromBackend.Close() }()
					stop := context.AfterFunc(ctx, func() {
						_ = toBackend.CloseWithError(ctx.Err())
						_ = fromBackend.CloseWithError(ctx.Err())
					})
					defer stop()
					req := connectRequest(reqCtx, version.major, version.path, "websocket", reqBody)
					w := &streamWriter{header: http.Header{}, status: make(chan int, 1), body: respBody}
					served := make(chan struct{})
					go func() {
						defer close(served)
						defer func() { _ = respBody.Close() }()
						r.ServeHTTP(w, req)
					}()
					select {
					case code := <-w.status:
						if code != http.StatusOK {
							t.Fatalf("status %d, want 200", code)
						}
						if w.header.Get("Upgrade") != "" || w.header.Get("Sec-WebSocket-Accept") != "" {
							t.Errorf("HTTP/1.1 handshake fields reached the client: %v", w.header)
						}
					case <-ctx.Done():
						t.Fatal("no handshake response")
					}
					const msg = "echo from the backend\n"
					if _, err := io.WriteString(toBackend, msg); err != nil {
						t.Fatal(err)
					}
					echo := make([]byte, len(msg))
					if _, err := io.ReadFull(fromBackend, echo); err != nil || string(echo) != msg {
						t.Fatalf("echo %q, error %v", echo, err)
					}
					var want string
					switch end {
					case "eof":
						_ = toBackend.Close()
						want = finalFrame
					case "reset":
						_ = toBackend.CloseWithError(errors.New("stream reset"))
					case "cancel":
						cancel()
					}
					got, err := io.ReadAll(fromBackend)
					if err != nil || string(got) != want {
						t.Fatalf("after %s got %q, error %v, want %q", end, got, err, want)
					}
					select {
					case <-served:
					case <-ctx.Done():
						t.Fatal("the handler did not exit")
					}
				})
			}
		})
	}
}
