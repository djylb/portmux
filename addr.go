package portmux

import (
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/djylb/portmux/ipmatch"
)

// RemoteIP matches connections from a client address inside one of the
// prefixes. The address comes from the PROXY protocol header when one was
// parsed. It decides before any byte arrives, so on its own it also routes
// protocols in which the server speaks first.
//
// Long lists, such as block lists, are looked up by binary search.
func RemoteIP(prefixes ...netip.Prefix) Matcher {
	return ipMatcher{name: "RemoteIP", set: ipmatch.NewSet(prefixes...), remote: true}
}

// LocalIP matches connections to a local address inside one of the prefixes,
// which tells apart the interfaces of a wildcard listener. The address comes
// from the PROXY protocol header when one was parsed.
func LocalIP(prefixes ...netip.Prefix) Matcher {
	return ipMatcher{name: "LocalIP", set: ipmatch.NewSet(prefixes...)}
}

type ipMatcher struct {
	name   string
	set    *ipmatch.Set
	remote bool
}

func (m ipMatcher) Match(in *Input) Result {
	a := in.local
	if m.remote {
		a = in.remote
	}
	return matchAddr(a, func(ap netip.AddrPort) bool { return m.set.Contains(ap.Addr()) })
}

func (m ipMatcher) String() string { return call(m.name, m.set.Prefixes(), netip.Prefix.String) }

// LocalPort matches connections to one of the local ports, which tells apart
// the listeners when one Mux serves several. The port comes from the PROXY
// protocol header when one was parsed.
func LocalPort(ports ...uint16) Matcher {
	return portMatcher(slices.Clone(ports))
}

type portMatcher []uint16

func (p portMatcher) Match(in *Input) Result {
	return matchAddr(in.local, func(ap netip.AddrPort) bool { return slices.Contains(p, ap.Port()) })
}

func (p portMatcher) String() string {
	return call("LocalPort", p, func(port uint16) string { return strconv.Itoa(int(port)) })
}

func matchAddr(a net.Addr, ok func(netip.AddrPort) bool) Result {
	if ap, valid := addrPort(a); valid && ok(ap) {
		return Match
	}
	return NoMatch
}

// addrPort extracts an IP address and port with IPv4-mapped IPv6 addresses
// unmapped.
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	var ap netip.AddrPort
	switch a := a.(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	case nil:
		return netip.AddrPort{}, false
	default:
		var err error
		if ap, err = netip.ParseAddrPort(a.String()); err != nil {
			return netip.AddrPort{}, false
		}
	}
	if !ap.Addr().IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
