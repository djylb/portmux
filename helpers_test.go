package portmux

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/djylb/netx/proxyproto"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/tlshello"
)

// testMux is a Mux with one loopback listener.
type testMux struct {
	*Mux
	ln net.Listener
}

func (m *testMux) Addr() net.Addr { return m.ln.Addr() }

// startMux creates a Mux and a loopback listener for it. Both are closed when
// the test ends; serve starts serving the listener.
func startMux(t *testing.T, opts ...Option) *testMux {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &testMux{Mux: New(opts...), ln: ln}
	t.Cleanup(func() {
		_ = m.Close()
		_ = ln.Close()
	})
	return m
}

func serve(t *testing.T, m *testMux) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- m.Serve(m.ln) }()
	t.Cleanup(func() {
		_ = m.Close()
		select {
		case err := <-errc:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("Serve returned %v, want net.ErrClosed", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Close")
		}
	})
	waitServing(t, m.Mux, 1)
}

// waitServing waits until m serves n listeners.
func waitServing(t *testing.T, m *Mux, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		m.mu.Lock()
		got := len(m.listeners)
		m.mu.Unlock()
		if got == n {
			return
		}
	}
	t.Fatalf("Mux does not serve %d listeners", n)
}

func dial(t *testing.T, m *testMux) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", m.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// accept accepts one connection from l, failing the test after a timeout.
func accept(t *testing.T, l net.Listener) *Conn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		t.Cleanup(func() { _ = r.c.Close() })
		return r.c.(*Conn)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
		return nil
	}
}

// expectNoAccept fails if l delivers a connection within d.
func expectNoAccept(t *testing.T, l net.Listener, d time.Duration) {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			ch <- c
		}
	}()
	select {
	case c := <-ch:
		_ = c.Close()
		t.Fatal("unexpected connection")
	case <-time.After(d):
	}
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	if c, ok := r.(net.Conn); ok {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

// errorLog collects the errors of the events passed to WithObserver.
type errorLog struct {
	mu   sync.Mutex
	errs []error
	ch   chan error
}

func newErrorLog() *errorLog {
	return &errorLog{ch: make(chan error, 64)}
}

func (l *errorLog) option() Option {
	return WithObserver(func(ev Event) {
		err := ev.Err
		if err == nil {
			return
		}
		l.mu.Lock()
		l.errs = append(l.errs, err)
		l.mu.Unlock()
		select {
		case l.ch <- err:
		default:
		}
	})
}

func (l *errorLog) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-l.ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("no error reported")
		return nil
	}
}

// expectClosed checks that the peer closes c without sending data.
// v2Header encodes a version 2 PROXY header for a connection from src to
// dst.
func v2Header(t *testing.T, src, dst net.Addr) []byte {
	t.Helper()
	h, err := proxyproto.NewHeader(proxyproto.V2, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitUntil waits until cond holds, failing the test after a timeout.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
	}
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %d, %v; want the connection closed", n, err)
	}
}

var (
	certOnce sync.Once
	testCert tls.Certificate
)

// certificate returns a self-signed certificate for any name.
func certificate(t testing.TB) tls.Certificate {
	t.Helper()
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "portmux test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{"*.example.com", "example.com", "localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		testCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return testCert
}

// resultOf turns an error of the parsers into a matcher result.
func resultOf(err error) Result {
	switch {
	case err == nil:
		return Match
	case errors.Is(err, io.ErrUnexpectedEOF):
		return NeedMore
	}
	return NoMatch
}

func parseHTTP(data []byte) (*httphead.Request, Result) {
	r, err := httphead.Parse(data)
	return r, resultOf(err)
}

func parseHello(data []byte) (*tlshello.Hello, Result) {
	h, err := tlshello.Parse(data)
	return h, resultOf(err)
}
