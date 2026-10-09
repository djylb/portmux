package ipmatch

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestSetMatchesLinearLookup(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 1))
	randomAddr := func() netip.Addr {
		if r.IntN(2) == 0 {
			return netip.AddrFrom4([4]byte{byte(r.IntN(4)), byte(r.Uint32()), byte(r.Uint32()), byte(r.Uint32())})
		}
		var b [16]byte
		b[0], b[1] = 0x20, byte(r.IntN(4))
		for i := 2; i < 16; i++ {
			b[i] = byte(r.Uint32())
		}
		return netip.AddrFrom16(b)
	}
	var prefixes []netip.Prefix
	for range 500 {
		a := randomAddr()
		prefixes = append(prefixes, netip.PrefixFrom(a, r.IntN(a.BitLen()+1)))
	}
	prefixes = append(prefixes,
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("::ffff:198.51.100.0/120"),
		netip.MustParsePrefix("ffff::/16"))
	set := NewSet(prefixes...)
	if set.ranges == nil {
		t.Fatal("no ranges for a long list")
	}
	linear := func(a netip.Addr) bool {
		for _, p := range prefixes {
			if a4 := p.Addr(); a4.Is4In6() {
				p = netip.PrefixFrom(a4.Unmap(), p.Bits()-96)
			}
			if p.Masked().Contains(a) {
				return true
			}
		}
		return false
	}
	probe := []netip.Addr{
		netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("198.51.100.7"),
		netip.MustParseAddr("ffff::1"), netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"),
	}
	for range 20000 {
		probe = append(probe, randomAddr())
	}
	for _, a := range probe {
		if got, want := set.Contains(a), linear(a); got != want {
			t.Fatalf("contains(%v) = %v, want %v", a, got, want)
		}
	}
}

func TestSet(t *testing.T) {
	set := NewSet(netip.MustParsePrefix("10.0.0.0/8"), netip.Prefix{}, netip.MustParsePrefix("2001:db8::/32"))
	if set.Len() != 2 || !set.Contains(netip.MustParseAddr("::ffff:10.1.1.1")) || set.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Fatalf("Set %s", set)
	}
	if set.String() != "Set(10.0.0.0/8, 2001:db8::/32)" {
		t.Fatalf("String = %s", set)
	}
}

// TestSetPrefixes merges long sets and prints the fewest prefixes that cover
// them.
func TestSetPrefixes(t *testing.T) {
	var prefixes []netip.Prefix
	for i := range 8 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i), 0}), 24))
	}
	prefixes = append(prefixes,
		netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.2.2/31"),
		netip.MustParsePrefix("::ffff:198.51.100.0/120"),
		netip.MustParsePrefix("2001:db8::/33"), netip.MustParsePrefix("2001:db8:8000::/33"))
	s := NewSet(prefixes...)
	want := "Set(10.0.0.0/21, 192.0.2.1/32, 192.0.2.2/31, 198.51.100.0/24, 2001:db8::/32)"
	if s.String() != want || s.Len() != len(prefixes) {
		t.Fatalf("String = %s, Len = %d", s, s.Len())
	}
	again := NewSet(s.Prefixes()...)
	for _, a := range []string{"10.0.7.255", "10.0.8.0", "192.0.2.0", "192.0.2.3", "198.51.100.9", "2001:db8:ffff::1", "2001:db9::"} {
		addr := netip.MustParseAddr(a)
		if s.Contains(addr) != again.Contains(addr) {
			t.Errorf("%s: the printed prefixes differ", a)
		}
	}
	// A range up to the top of the family ends with its last prefix.
	top := NewSet(append(prefixes[:8:8], netip.MustParsePrefix("128.0.0.0/1"))...)
	if got := top.Prefixes(); got[len(got)-1].String() != "128.0.0.0/1" {
		t.Fatalf("Prefixes = %v", got)
	}
}
