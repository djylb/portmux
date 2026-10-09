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

func TestBanListBounds(t *testing.T) {
	l := newBanList()
	now := time.Duration(0)
	a := netip.MustParseAddr("192.0.2.1")
	l.fail(a, now, 3, time.Second, time.Minute)
	l.fail(a, now+2*time.Second, 3, time.Second, time.Minute) // a new window
	l.fail(a, now+2*time.Second, 3, time.Second, time.Minute)
	if l.banned(a, now+2*time.Second) {
		t.Fatal("banned with failures in two windows")
	}
	l.fail(a, now+2*time.Second, 3, time.Second, time.Minute)
	if !l.banned(a, now+2*time.Second) || l.banned(a, now+3*time.Minute) {
		t.Fatal("ban period")
	}
	// Expired clients are swept, and the list stops growing when full.
	for i := range maxBanClients + 100 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.fail(ip, 10*time.Minute, 5, time.Second, time.Minute)
	}
	if n := l.size.Load(); n > maxBanClients {
		t.Fatalf("size %d", n)
	}
	for i := range rateSweepEvery * banShards {
		ip := netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)})
		l.fail(ip, time.Hour, 5, time.Second, time.Minute)
	}
	if n := l.size.Load(); n > maxBanClients/2 {
		t.Fatalf("size %d after sweeping", n)
	}
}
