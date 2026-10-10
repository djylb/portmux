package portmux

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/tlshello"
)

// TLS matches connections that start with a well-formed TLS ClientHello and
// pass every filter. It waits for the complete ClientHello, so the parsed
// hello is always available from Conn.ClientHello.
func TLS(filters ...TLSFilter) Matcher {
	if slices.Contains(filters, nil) {
		panic("portmux: nil filter")
	}
	return tlsMatcher(slices.Clone(filters))
}

type tlsMatcher []TLSFilter

func (t tlsMatcher) Match(in *Input) Result {
	hello, res := in.ClientHello()
	if res != Match {
		return res
	}
	for _, f := range t {
		if !f.Match(hello) {
			return NoMatch
		}
	}
	return Match
}

func (t tlsMatcher) String() string { return call("TLS", t, describe[TLSFilter]) }

// SNI accepts ClientHellos whose server name matches one of the patterns. A
// pattern is a host name, "*.example.com" for any name below example.com, or
// "*" for any name. The empty pattern accepts a ClientHello without SNI.
// Names compare case-insensitively.
func SNI(patterns ...string) TLSFilter {
	return sniFilter{patterns: slices.Clone(patterns), hosts: hostmatch.NewSet(patterns...)}
}

type sniFilter struct {
	patterns []string
	hosts    *hostmatch.Set
}

func (f sniFilter) Match(h *tlshello.Hello) bool { return f.hosts.MatchName(h.Name()) }

// SNIRegexp accepts ClientHellos whose server name, lowercased, matches re.
// ClientHellos without SNI, or with a name that has bytes that no DNS name or
// IP address has, never match.
func SNIRegexp(re *regexp.Regexp) TLSFilter {
	return newRegexpFilter("SNIRegexp", re, func(h *tlshello.Hello, re *regexp.Regexp) bool {
		n := h.Name()
		return n.Valid() && n.String() != "" && re.MatchString(n.String())
	})
}

// MinTLSVersion accepts ClientHellos that offer at least version v, such as
// tls.VersionTLS12, judged as servers negotiate: by the highest version of
// supported_versions up to TLS 1.3 or, without that extension, by
// legacy_version up to TLS 1.2. It turns away clients that only speak older
// versions.
func MinTLSVersion(v uint16) TLSFilter {
	return minVersionFilter(v)
}

type minVersionFilter uint16

func (f minVersionFilter) Match(h *tlshello.Hello) bool { return negotiableVersion(h) >= uint16(f) }

// negotiableVersion returns the highest version that a server can agree on
// with the client (RFC 8446, Section 4.2.1), or zero for none.
func negotiableVersion(h *tlshello.Hello) uint16 {
	const tls12, tls13 = 0x0303, 0x0304
	if len(h.SupportedVersions) == 0 {
		return min(h.Version, tls12)
	}
	top := uint16(0)
	for _, v := range h.SupportedVersions {
		if v <= tls13 && v > top {
			top = v // GREASE values are all above TLS 1.3
		}
	}
	return top
}

func (f minVersionFilter) String() string { return "MinTLSVersion(" + versionName(uint16(f)) + ")" }

// versionName returns "1.0" to "1.3" for the TLS versions, and the hex value
// of others, as ParseMatcher reads them.
func versionName(v uint16) string {
	if v >= 0x0301 && v <= 0x0304 {
		return "1." + strconv.Itoa(int(v-0x0301))
	}
	return fmt.Sprintf("0x%04x", v)
}

func (f sniFilter) String() string { return call("SNI", f.patterns, quote) }

// ALPN accepts ClientHellos that offer at least one of the protocols.
func ALPN(protocols ...string) TLSFilter {
	return alpnFilter(slices.Clone(protocols))
}

type alpnFilter []string

func (f alpnFilter) Match(h *tlshello.Hello) bool {
	for _, p := range h.ALPN {
		if slices.Contains(f, p) {
			return true
		}
	}
	return false
}

func (f alpnFilter) String() string { return call("ALPN", f, quote) }
