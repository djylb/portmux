package httproute

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/httprewrite"
)

// checkLeaks fails the test when goroutines that it started are still
// running a few seconds after its cleanups. Register it first, so that it
// runs last.
func checkLeaks(t *testing.T) {
	t.Helper()
	base, _ := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			n, stacks := goroutines()
			if n <= base {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d goroutines, %d before:\n%s", n, base, stacks)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// goroutines counts the goroutines, without the one that js/wasm runs for
// events now and then, and returns their stacks.
func goroutines() (int, string) {
	buf := make([]byte, 1<<20)
	stacks := string(buf[:runtime.Stack(buf, true)])
	n := 0
	for _, g := range strings.Split(stacks, "\n\n") {
		if strings.HasPrefix(g, "goroutine ") && !strings.Contains(g, "runtime.handleEvent") {
			n++
		}
	}
	return n, stacks
}

// backend starts an HTTP server for h and returns an upstream that dials it.
func backend(t *testing.T, name string, h http.Handler) Upstream {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	return Upstream{Name: name, Dial: func(ctx context.Context, _ DialInfo) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}}
}

// startRouter serves a Router with the routes of c on a local port and
// returns it with its URL.
func startRouter(t *testing.T, o Options, c Config) (*Router, string) {
	t.Helper()
	tab, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	r := New(o)
	if err := r.Update(tab); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = r.Close()
		<-done
	})
	return r, "http://" + ln.Addr().String()
}

// client returns an HTTP client whose idle connections close with the test.
func client(t *testing.T) *http.Client {
	tr := &http.Transport{DisableCompression: true}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// get sends a request with host and returns the response with its body
// read.
func get(t *testing.T, c *http.Client, method, url, host string, header http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range header {
		req.Header[k] = v
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(body)
}

// rawRequest writes a request to a new connection to addr and returns the
// connection and a reader of it.
func rawRequest(t *testing.T, base, request string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	return c, bufio.NewReader(c)
}

func rules(t *testing.T, text string) []httprewrite.Rule {
	t.Helper()
	r, err := httprewrite.ParseRules(text, Vars())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func template(t *testing.T, src string) *httprewrite.Template {
	t.Helper()
	tm, err := httprewrite.Compile(src, Vars())
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

var (
	certOnce sync.Once
	testCert tls.Certificate
)

// certificate returns a self-signed certificate for example.com.
func certificate() tls.Certificate {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "httproute test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{"*.example.com", "example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		testCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return testCert
}
