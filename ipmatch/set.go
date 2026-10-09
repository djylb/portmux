package ipmatch

import (
	"net/netip"
	"slices"
	"strings"
)

// rangeMin is the number of prefixes from which a Set searches
// merged address ranges instead of checking each prefix.
const rangeMin = 8

// Set is a set of IP prefixes. IPv4-mapped
// IPv6 prefixes and addresses count as IPv4. Long lists, such as block lists,
// are merged into sorted ranges and looked up by binary search. A Set
// is safe for concurrent use.
type Set struct {
	list   []netip.Prefix
	ranges []addrRange // sorted, disjoint and not adjacent
	count  int
}

type addrRange struct {
	lo, hi netip.Addr
}

// NewSet builds a set from prefixes. Invalid prefixes are ignored.
func NewSet(prefixes ...netip.Prefix) *Set {
	ps := &Set{}
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		ps.list = append(ps.list, p.Masked())
	}
	ps.count = len(ps.list)
	if len(ps.list) < rangeMin {
		return ps
	}
	ranges := make([]addrRange, len(ps.list))
	for i, p := range ps.list {
		ranges[i] = addrRange{lo: p.Addr(), hi: lastAddr(p)}
	}
	slices.SortFunc(ranges, func(a, b addrRange) int { return a.lo.Compare(b.lo) })
	merged := ranges[:1]
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if next := last.hi.Next(); next.IsValid() && r.lo.Compare(next) <= 0 && r.lo.BitLen() == last.hi.BitLen() {
			if r.hi.Compare(last.hi) > 0 {
				last.hi = r.hi
			}
			continue
		}
		if r.hi.Compare(last.hi) <= 0 && r.lo.BitLen() == last.hi.BitLen() {
			continue // inside the last range, which ends at the family's top
		}
		merged = append(merged, r)
	}
	ps.list, ps.ranges = nil, slices.Clip(merged)
	return ps
}

// Len returns the number of valid prefixes the set was built from.
func (ps *Set) Len() int { return ps.count }

// Contains reports whether a is inside one of the prefixes.
func (ps *Set) Contains(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if ps.ranges == nil {
		for _, p := range ps.list {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	i, _ := slices.BinarySearchFunc(ps.ranges, a, func(r addrRange, a netip.Addr) int {
		if r.lo.Compare(a) > 0 {
			return 1
		}
		return -1
	})
	return i > 0 && a.Compare(ps.ranges[i-1].hi) <= 0
}

// lastAddr returns the highest address of a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		setHostBits(b[:], p.Bits())
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	setHostBits(b[:], p.Bits())
	return netip.AddrFrom16(b)
}

func setHostBits(b []byte, bits int) {
	for i := bits; i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
}

// String describes the set, as in Set(10.0.0.0/8, 192.168.0.0/16).
func (ps *Set) String() string {
	prefixes := ps.Prefixes()
	text := make([]string, len(prefixes))
	for i, p := range prefixes {
		text[i] = p.String()
	}
	return "Set(" + strings.Join(text, ", ") + ")"
}

// Prefixes returns the prefixes of the set, masked. A long set returns the
// fewest prefixes that cover the same addresses, in increasing order.
func (ps *Set) Prefixes() []netip.Prefix {
	if ps.ranges == nil {
		return slices.Clone(ps.list)
	}
	var out []netip.Prefix
	for _, r := range ps.ranges {
		out = appendRangePrefixes(out, r.lo, r.hi)
	}
	return out
}

// appendRangePrefixes appends the fewest prefixes that cover lo to hi.
func appendRangePrefixes(dst []netip.Prefix, lo, hi netip.Addr) []netip.Prefix {
	for {
		// The shortest prefix that starts at lo and ends no later than hi.
		bits := lo.BitLen()
		for bits > 0 {
			wider := netip.PrefixFrom(lo, bits-1)
			if wider.Masked().Addr() != lo || lastAddr(wider).Compare(hi) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(lo, bits)
		dst = append(dst, p)
		end := lastAddr(p)
		if end.Compare(hi) >= 0 {
			return dst
		}
		lo = end.Next()
	}
}
