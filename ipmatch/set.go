package ipmatch

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/djylb/netx/forwarded"
)

// rangeMin is the number of prefixes from which a Set searches
// merged address ranges instead of checking each prefix.
const rangeMin = 8

// Set is a set of IP prefixes. IPv4-mapped
// IPv6 prefixes and addresses count as IPv4. Long lists, such as block lists,
// are merged into sorted ranges and looked up by binary search. A Set
// is safe for concurrent use.
type Set struct {
	list  []netip.Prefix
	index *forwarded.PrefixSet
	count int
}

// NewSet builds a set from prefixes. Invalid prefixes are ignored.
func NewSet(prefixes ...netip.Prefix) *Set {
	ps := &Set{}
	for _, p := range prefixes {
		if p.IsValid() {
			ps.list = append(ps.list, NormalizePrefix(p))
		}
	}
	ps.count = len(ps.list)
	if len(ps.list) < rangeMin {
		return ps
	}
	ps.list = compactPrefixes(ps.list)
	ps.index = forwarded.NewPrefixSet(ps.list...)
	return ps
}

// NormalizeAddr returns a as a Set compares it: without a zone, and an
// IPv4-mapped IPv6 address as IPv4.
func NormalizeAddr(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}

// NormalizePrefix returns p as a Set keeps it: masked, and an IPv4-mapped
// IPv6 prefix of at least 96 bits as IPv4. Shorter IPv4-mapped prefixes,
// which hold more than IPv4 addresses, stay IPv6.
func NormalizePrefix(p netip.Prefix) netip.Prefix {
	addr, bits := p.Addr(), p.Bits()
	if addr.Is4In6() && bits >= 96 {
		addr, bits = addr.Unmap(), bits-96
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

// Len returns the number of valid prefixes the set was built from.
func (ps *Set) Len() int { return ps.count }

// Contains reports whether a is inside one of the prefixes.
func (ps *Set) Contains(a netip.Addr) bool {
	a = NormalizeAddr(a)
	if ps.index != nil {
		return ps.index.Contains(a)
	}
	for _, p := range ps.list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// compactPrefixes builds the minimal ordered CIDR representation for enumeration.
func compactPrefixes(list []netip.Prefix) []netip.Prefix {
	slices.SortFunc(list, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	out := list[:0]
	for _, p := range list {
		out = appendPrefix(out, p)
	}
	return slices.Clone(out)
}

// appendPrefix discards contained prefixes and joins adjacent siblings.
func appendPrefix(out []netip.Prefix, p netip.Prefix) []netip.Prefix {
	for len(out) > 0 {
		prev := out[len(out)-1]
		if prev.Contains(p.Addr()) {
			return out
		}
		if prev.Bits() != p.Bits() || p.Bits() == 0 {
			break
		}
		parent := netip.PrefixFrom(prev.Addr(), p.Bits()-1).Masked()
		if !parent.Contains(p.Addr()) {
			break
		}
		p, out = parent, out[:len(out)-1]
	}
	return append(out, p)
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
	return slices.Clone(ps.list)
}
