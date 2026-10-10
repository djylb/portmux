package portmux

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBanPerIP(t *testing.T) {
	log := newErrorLog()
	m := startMux(t, log.option(), WithBanPerIP(2, time.Minute, time.Minute))
	web := m.Match(Prefix("GET"))
	serve(t, m)

	// Closing without sending, as health checks do, does not count.
	expectFailure := func(data string, want error) {
		t.Helper()
		c := dial(t, m)
		if data != "" {
			_, _ = c.Write([]byte(data))
		}
		_ = c.(*net.TCPConn).CloseWrite()
		expectClosed(t, c)
		if err := log.wait(t); !errors.Is(err, want) {
			t.Fatalf("%q: reported %v, want %v", data, err, want)
		}
	}
	expectFailure("", io.EOF)
	expectFailure("XX", ErrNoMatch)
	_, _ = dial(t, m).Write([]byte("GET"))
	accept(t, web)
	expectFailure("YY", ErrNoMatch)
	// The second failure within the window bans the client before it sends.
	expectFailure("GET", ErrBanned)
	bans := m.Bans()
	if len(bans) != 1 || bans[0].Client != netip.MustParsePrefix("127.0.0.1/32") || time.Until(bans[0].Until) < 50*time.Second {
		t.Fatalf("Bans = %+v", bans)
	}
	if st := m.Stats(); st.Banned != 1 || st.NoMatch != 2 {
		t.Fatalf("stats %+v", st)
	}
	if !m.Unban(netip.MustParseAddr("127.0.0.1")) || m.Unban(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("Unban")
	}
	_, _ = dial(t, m).Write([]byte("GET"))
	accept(t, web)

	// Manual bans group IPv6 clients by /64 and lift with a zero duration.
	m.Ban(netip.MustParseAddr("2001:db8::1"), time.Hour)
	m.Ban(netip.MustParseAddr("::ffff:192.0.2.7"), time.Hour)
	got := map[string]bool{}
	for _, b := range m.Bans() {
		got[b.Client.String()] = true
	}
	if !got["2001:db8::/64"] || !got["192.0.2.7/32"] || len(got) != 2 {
		t.Fatalf("Bans = %v", got)
	}
	m.Ban(netip.MustParseAddr("2001:db8::2"), 0)
	if len(m.Bans()) != 1 {
		t.Fatalf("Bans after lifting = %+v", m.Bans())
	}
	m.Ban(netip.MustParseAddr("127.0.0.1"), time.Hour)
	expectFailure("GET", ErrBanned)
}

// TestBanAppliesAtOnce checks that a failure that bans the client counts
// before the client sees its connection closed, so that the client cannot
// slip in by connecting again at once.
func TestBanAppliesAtOnce(t *testing.T) {
	m := startMux(t, WithBanPerIP(1, time.Minute, time.Minute))
	m.Match(Prefix("GET")) // its server never accepts
	serve(t, m)

	for i := range uint64(20) {
		c := dial(t, m)
		_, _ = c.Write([]byte("XX"))
		expectClosed(t, c)
		c = dial(t, m)
		_, _ = c.Write([]byte("GET"))
		expectClosed(t, c)
		if st := m.Stats(); st.Banned != i+1 || st.Delivered != 0 || st.Pending != 0 {
			t.Fatalf("round %d: stats %+v", i, st)
		}
		m.Unban(netip.MustParseAddr("127.0.0.1"))
	}
}

func TestBanListBounds(t *testing.T) {
	l := newBanList()
	now := time.Duration(0)
	a := netip.MustParseAddr("192.0.2.1")
	l.fail(banKey{client: a}, now, 3, time.Second, time.Minute)
	l.fail(banKey{client: a}, now+2*time.Second, 3, time.Second, time.Minute) // a new window
	l.fail(banKey{client: a}, now+2*time.Second, 3, time.Second, time.Minute)
	if l.banned(a, now+2*time.Second) {
		t.Fatal("banned with failures in two windows")
	}
	l.fail(banKey{client: a}, now+2*time.Second, 3, time.Second, time.Minute)
	if !l.banned(a, now+2*time.Second) || l.banned(a, now+3*time.Minute) {
		t.Fatal("ban period")
	}
	// Expired clients are swept, and the list stops growing when full.
	for i := range maxBanClients + 100 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.fail(banKey{client: ip}, 10*time.Minute, 5, time.Second, time.Minute)
	}
	if n := l.size.Load(); n > maxBanClients {
		t.Fatalf("size %d", n)
	}
	for i := range rateSweepEvery * banShards {
		ip := netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)})
		l.fail(banKey{client: ip}, time.Hour, 5, time.Second, time.Minute)
	}
	if n := l.size.Load(); n > maxBanClients/2 {
		t.Fatalf("size %d after sweeping", n)
	}
}

// TestBanListScopes counts the failures of an entry with its own rule apart
// from the Mux's, each with its own window, and bans the client everywhere.
func TestBanListScopes(t *testing.T) {
	l := newBanList()
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	mux, own := banKey{client: a}, banKey{client: a, entry: "fast", own: true}
	// Two failures toward the Mux's rule of three in ten minutes.
	l.fail(mux, 0, 3, 10*time.Minute, time.Hour)
	l.fail(mux, time.Second, 3, 10*time.Minute, time.Hour)
	// Failures toward the entry's rule of three in a second, each in a window
	// of its own, neither ban nor reset the Mux's count.
	for i := range 4 {
		l.fail(own, time.Duration(2+2*i)*time.Second, 3, time.Second, time.Hour)
	}
	if l.banned(a, 10*time.Second) {
		t.Fatal("banned by failures in separate windows")
	}
	// Sweeps after failures with a short window keep the Mux's count.
	for i := range rateSweepEvery * banShards {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		l.fail(banKey{client: ip, entry: "fast", own: true}, time.Minute, 3, time.Second, time.Hour)
	}
	l.fail(mux, 2*time.Minute, 3, 10*time.Minute, time.Hour)
	if !l.banned(a, 2*time.Minute) {
		t.Fatal("not banned by the Mux's rule")
	}
	// The entry's rule bans the client as well.
	for range 3 {
		l.fail(banKey{client: b, entry: "fast", own: true}, time.Hour, 3, time.Second, time.Minute)
	}
	if !l.banned(b, time.Hour) || len(l.list(time.Hour)) != 2 {
		t.Fatalf("bans %+v", l.list(time.Hour))
	}
}

// TestExpiredBansAreForgotten checks that bans set by hand are forgotten once
// they ended, also when no failures are counted.
func TestExpiredBansAreForgotten(t *testing.T) {
	l := newBanList()
	const n = 100000
	for i := range n {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.set(banKey{client: ip}, time.Duration(i)*time.Millisecond, time.Second)
	}
	if size := l.size.Load(); size > n/4 {
		t.Fatalf("size %d after %d bans of a second over %v", size, n, n*time.Millisecond)
	}
	if bans := l.list(n*time.Millisecond + time.Second); len(bans) != 0 || l.size.Load() != 0 {
		t.Fatalf("%d bans, size %d after every ban ended", len(bans), l.size.Load())
	}
}
