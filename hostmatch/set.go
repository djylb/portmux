package hostmatch

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Set matches host names against patterns, as nginx and Envoy match server
// names:
//
//   - an exact name, such as "example.com";
//   - "*.example.com", any name below example.com, at any depth, but not
//     example.com itself; a wildcard certificate covers one level only, so
//     "a.b.example.com" may be routed but get no certificate;
//   - ".example.com", example.com and every name below it;
//   - "*", any name;
//   - "", the request or ClientHello without a name.
//
// No other wildcards exist: CheckPattern refuses them, and NewSet and
// Map.Set panic on them; check patterns from configurations with
// CheckPattern first. Names compare case-insensitively and ignore one trailing dot.
// Names with bytes that no DNS name or IP address has, such as '@', a space,
// NUL or any byte above 0x7F, match no pattern, so that
// "user@admin.example.com" cannot reach a route meant for another name. Long
// lists of exact names are looked up in a map. A Set is safe for concurrent
// use.
type Set struct {
	patterns []string
	exact    []string
	index    map[string]struct{}
	suffixes []string // ".example.com" for "*.example.com" and ".example.com"
	any      bool
	empty    bool
}

// indexMin is the number of exact names from which lookups use a map
// instead of comparing each name.
const indexMin = 8

// NewSet compiles the patterns. It panics on a pattern that CheckPattern
// refuses, such as "api-*.example.com", which older versions matched.
func NewSet(patterns ...string) *Set {
	for _, p := range patterns {
		mustPattern(p)
	}
	h := &Set{patterns: slices.Clone(patterns)}
	for _, p := range patterns {
		switch hp := parseHostPattern(p); {
		case hp.kind == patternExact && hp.key == "":
			h.empty = true
		case hp.kind == patternAny:
			h.any = true
		case hp.kind == patternExact:
			h.exact = append(h.exact, hp.key)
		case hp.kind == patternDot:
			h.exact = append(h.exact, hp.key[1:])
			h.suffixes = append(h.suffixes, hp.key)
		default:
			h.suffixes = append(h.suffixes, hp.key)
		}
	}
	if len(h.exact) >= indexMin {
		h.index = make(map[string]struct{}, len(h.exact))
		for _, name := range h.exact {
			h.index[name] = struct{}{}
		}
	}
	return h
}

// Patterns returns the patterns the set was built from.
func (h *Set) Patterns() []string { return slices.Clone(h.patterns) }

// ErrPattern reports a pattern that CheckPattern rejects.
var ErrPattern = errors.New("hostmatch: invalid pattern")

// CheckPattern reports whether p is one of the patterns of Set: an exact
// name, "*.name", ".name", "*" or "". Names have labels of ASCII letters,
// digits, '-' and '_' separated by single dots, with an optional trailing
// dot, or are IP addresses (IPv6 without brackets). It refuses wildcards in
// other places, such as "*a.example.com", which some read as example.com and
// its subdomains, and which would match "evila.example.com", or
// "a.*.example.com", and names that are not ASCII: convert IDNs to A-labels
// first.
func CheckPattern(p string) error {
	if p == "" || p == "*" {
		return nil
	}
	name := strings.TrimSuffix(p, ".")
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		name = rest
	} else if rest, ok := strings.CutPrefix(name, "."); ok {
		name = rest
	}
	if name == "" {
		return fmt.Errorf("%w: %q has no name", ErrPattern, p)
	}
	if strings.IndexByte(name, ':') >= 0 {
		if _, err := netip.ParseAddr(name); err != nil || name != p {
			return fmt.Errorf("%w: %q is not an IPv6 address", ErrPattern, p)
		}
		return nil
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			return fmt.Errorf("%w: %q has an empty label", ErrPattern, p)
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; c == '*' {
				return fmt.Errorf("%w: %q has '*' where only a leading \"*.\" may be", ErrPattern, p)
			} else if c >= 0x80 || !hostTable[c] || c == '%' {
				return fmt.Errorf("%w: %q has the byte %q", ErrPattern, p, c)
			}
		}
	}
	return nil
}

func mustPattern(p string) {
	if err := CheckPattern(p); err != nil {
		panic(err.Error())
	}
}

// String describes the set, as in Set("*.example.com", "example.com").
func (h *Set) String() string {
	quoted := make([]string, len(h.patterns))
	for i, p := range h.patterns {
		quoted[i] = strconv.Quote(p)
	}
	return "Set(" + strings.Join(quoted, ", ") + ")"
}

// Match reports whether host matches one of the patterns. host is a bare name
// or IP address without a port; see SplitHost for HTTP Host values.
func (h *Set) Match(host string) bool {
	return h.MatchName(Normalize(host))
}

// MatchName reports whether a prepared name matches one of the patterns.
func (h *Set) MatchName(n Name) bool {
	switch {
	case !n.valid:
		return false
	case n.name == "":
		return h.empty
	case h.any:
		return true
	}
	if h.index != nil {
		if _, ok := h.index[n.name]; ok {
			return true
		}
	} else if slices.Contains(h.exact, n.name) {
		return true
	}
	for _, s := range h.suffixes {
		if len(n.name) > len(s) && strings.HasSuffix(n.name, s) {
			return true
		}
	}
	return false
}
