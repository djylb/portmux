package hostmatch

import (
	"slices"
	"strconv"
	"strings"
)

// Set matches host names against patterns. A pattern is an exact name, or
// has '*' wildcards that each
// stand for one or more characters, dots included: "*.example.com" is any
// name below example.com, "api-*.example.com" any name starting with "api-"
// in it, and "*" any name. The empty pattern matches when there is no name,
// such as a ClientHello without SNI.
//
// Names compare case-insensitively and ignore one trailing dot. Names with
// bytes that no DNS name or IP address has, such as '@', a space or NUL, match
// no pattern, so that "user@admin.example.com" cannot reach a route meant for
// another name. Long lists of exact names are looked up in a map. A Set is
// safe for concurrent use.
type Set struct {
	patterns []string
	exact    []string
	index    map[string]struct{}
	suffixes []string // ".example.com" for "*.example.com"
	globs    []string // other patterns with '*'
	any      bool
	empty    bool
}

// indexMin is the number of exact names from which lookups use a map
// instead of comparing each name.
const indexMin = 8

// NewSet compiles the patterns.
func NewSet(patterns ...string) *Set {
	h := &Set{patterns: slices.Clone(patterns)}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSuffix(p, "."))
		switch {
		case p == "":
			h.empty = true
		case p == "*":
			h.any = true
		case !strings.Contains(p, "*"):
			h.exact = append(h.exact, p)
		case strings.HasPrefix(p, "*.") && !strings.Contains(p[2:], "*"):
			h.suffixes = append(h.suffixes, p[1:])
		default:
			h.globs = append(h.globs, p)
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
	for _, g := range h.globs {
		if glob(g, n.name) {
			return true
		}
	}
	return false
}
