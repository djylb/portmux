package hostmatch

import (
	"iter"
	"strings"
	"sync"
	"sync/atomic"
)

// Map maps host name patterns to values and looks names up by specificity,
// as virtual hosts are chosen. Patterns are those of Set. The patterns that
// match a name rank, most specific first:
//
//   - the exact name;
//   - ".name", which takes the name itself as well as the names below it;
//   - the wildcards by the length of their suffix, so that
//     "*.api.example.com" comes before "*.example.com" for
//     "v1.api.example.com", and ".api.example.com" before "*.example.com";
//     of a "*." and a "." pattern with the same suffix, the "*." one first;
//   - "*", which matches any name.
//
// Lookup returns the first of them, LookupFunc the first whose value a
// function accepts, and Matches all of them in this order, so that a policy
// of your own can skip patterns whose values do not apply. The empty pattern
// matches a ClientHello or request without a name. Names with bytes that no
// DNS name has match no pattern. Set panics on patterns that CheckPattern
// refuses, such as "api-*.example.com", which older versions matched.
//
// A Map is safe for concurrent use, and its zero value is an empty map ready
// to use. Lookups take no lock and cost a few map lookups whatever the
// number of patterns. Patterns can be set and deleted while lookups run.
type Map[V any] struct {
	exact    sync.Map // name -> *hostEntry[V]
	self     sync.Map // "example.com" -> *hostEntry[V], for ".example.com"
	suffixes sync.Map // ".example.com" -> *hostEntry[V], for "*.example.com"
	dots     sync.Map // ".example.com" -> *hostEntry[V], for ".example.com"
	// longest is the length of the longest suffix ever set, so that a lookup
	// tries only the dots at which a suffix can start, however long the name.
	longest atomic.Int64
	any     atomic.Pointer[hostEntry[V]]
	mu      sync.Mutex // serialises changes of "*" and ".name" patterns
	n       atomic.Int64
}

// hostEntry is a pattern, as it compares, and its value.
type hostEntry[V any] struct {
	pattern string
	value   V
}

// hostPattern is a pattern normalized as Set compares it.
type hostPattern struct {
	key  string // the name, or the suffix with its leading dot
	kind uint8
}

const (
	patternExact  uint8 = iota // also patterns that match nothing
	patternSuffix              // "*.example.com"
	patternDot                 // ".example.com"
	patternAny                 // "*"
)

func parseHostPattern(p string) hostPattern {
	p = strings.ToLower(p)
	if p != "." {
		p = strings.TrimSuffix(p, ".")
	}
	switch {
	case p == "*":
		return hostPattern{kind: patternAny}
	case strings.HasPrefix(p, "*.") && len(p) > 2:
		return hostPattern{key: p[1:], kind: patternSuffix}
	case strings.HasPrefix(p, ".") && len(p) > 1:
		return hostPattern{key: p, kind: patternDot}
	}
	// A name, or a pattern with '*' elsewhere, which no name matches.
	return hostPattern{key: p, kind: patternExact}
}

// String returns the pattern as it compares.
func (p hostPattern) String() string {
	switch p.kind {
	case patternSuffix:
		return "*" + p.key
	case patternAny:
		return "*"
	default: // patternExact and patternDot
		return p.key
	}
}

// Set maps pattern to v, replacing the value it had. It panics on a
// pattern that CheckPattern refuses.
func (m *Map[V]) Set(pattern string, v V) {
	mustPattern(pattern)
	p := parseHostPattern(pattern)
	e := &hostEntry[V]{pattern: p.String(), value: v}
	var loaded bool
	switch p.kind {
	case patternExact:
		_, loaded = m.exact.Swap(p.key, e)
	case patternSuffix:
		m.raiseLongest(len(p.key))
		_, loaded = m.suffixes.Swap(p.key, e)
	case patternDot:
		m.mu.Lock()
		m.raiseLongest(len(p.key))
		_, loaded = m.dots.Swap(p.key, e)
		m.self.Store(p.key[1:], e)
		m.mu.Unlock()
	case patternAny:
		loaded = m.any.Swap(e) != nil
	}
	if !loaded {
		m.n.Add(1)
	}
}

// raiseLongest raises longest before a suffix is stored, so that lookups
// that find the suffix also try its dot.
func (m *Map[V]) raiseLongest(n int) {
	for {
		if cur := m.longest.Load(); cur >= int64(n) || m.longest.CompareAndSwap(cur, int64(n)) {
			return
		}
	}
}

// Delete removes pattern and reports whether it was set.
func (m *Map[V]) Delete(pattern string) bool {
	p := parseHostPattern(pattern)
	deleted := false
	switch p.kind {
	case patternExact:
		_, deleted = m.exact.LoadAndDelete(p.key)
	case patternSuffix:
		_, deleted = m.suffixes.LoadAndDelete(p.key)
	case patternDot:
		m.mu.Lock()
		_, deleted = m.dots.LoadAndDelete(p.key)
		m.self.Delete(p.key[1:])
		m.mu.Unlock()
	case patternAny:
		deleted = m.any.Swap(nil) != nil
	}
	if deleted {
		m.n.Add(-1)
	}
	return deleted
}

// Get returns the value of pattern itself, without matching.
func (m *Map[V]) Get(pattern string) (V, bool) {
	var e *hostEntry[V]
	switch p := parseHostPattern(pattern); p.kind {
	case patternExact:
		e = loadEntry[V](&m.exact, p.key)
	case patternSuffix:
		e = loadEntry[V](&m.suffixes, p.key)
	case patternDot:
		e = loadEntry[V](&m.dots, p.key)
	case patternAny:
		e = m.any.Load()
	}
	if e == nil {
		var zero V
		return zero, false
	}
	return e.value, true
}

// Lookup returns the value of the most specific pattern that matches host, a
// bare name or IP address without a port, and that pattern as it compares:
// lowercased and without a trailing dot.
func (m *Map[V]) Lookup(host string) (v V, pattern string, ok bool) {
	m.walk(Normalize(host), func(p string, x V) bool {
		v, pattern, ok = x, p, true
		return false
	})
	return v, pattern, ok
}

// LookupFunc returns the value and pattern of the most specific pattern
// that matches host and whose value accept accepts, so that a name falls back
// to wider patterns when the value of a narrower one does not apply. It is
// Matches without allocating; accept must not call methods of m that change
// it.
func (m *Map[V]) LookupFunc(host string, accept func(pattern string, v V) bool) (v V, pattern string, ok bool) {
	return m.LookupNameFunc(Normalize(host), accept)
}

// LookupNameFunc is LookupFunc for a prepared name, which it does not prepare
// again.
func (m *Map[V]) LookupNameFunc(n Name, accept func(pattern string, v V) bool) (v V, pattern string, ok bool) {
	m.walk(n, func(p string, x V) bool {
		if accept(p, x) {
			v, pattern, ok = x, p, true
			return false
		}
		return true
	})
	return v, pattern, ok
}

// Matches yields every pattern that matches host, most specific first, with
// its value. Stop early to keep the first pattern whose value applies, as in
// a lookup that falls back to wider patterns:
//
//	for pattern, rules := range sites.Matches(host) {
//		if rule := rules.For(path); rule != nil {
//			return rule
//		}
//	}
func (m *Map[V]) Matches(host string) iter.Seq2[string, V] {
	n := Normalize(host)
	return func(yield func(string, V) bool) { m.walk(n, yield) }
}

// walk yields the patterns that match n, most specific first.
func (m *Map[V]) walk(n Name, yield func(string, V) bool) {
	if !n.valid {
		return
	}
	if e := loadEntry[V](&m.exact, n.name); e != nil && !yield(e.pattern, e.value) {
		return
	}
	if n.name == "" {
		return
	}
	if e := loadEntry[V](&m.self, n.name); e != nil && !yield(e.pattern, e.value) {
		return
	}
	// Suffixes come longest first, from the first dot on. Dots further from
	// the end than the longest suffix start none.
	for i := max(1, len(n.name)-int(m.longest.Load())); i < len(n.name); i++ {
		if n.name[i] != '.' {
			continue
		}
		if e := loadEntry[V](&m.suffixes, n.name[i:]); e != nil && !yield(e.pattern, e.value) {
			return
		}
		if e := loadEntry[V](&m.dots, n.name[i:]); e != nil && !yield(e.pattern, e.value) {
			return
		}
	}
	if e := m.any.Load(); e != nil {
		yield(e.pattern, e.value)
	}
}

func loadEntry[V any](m *sync.Map, key string) *hostEntry[V] {
	x, ok := m.Load(key)
	if !ok {
		return nil
	}
	e, _ := x.(*hostEntry[V])
	return e
}

// Len returns the number of patterns.
func (m *Map[V]) Len() int {
	return int(m.n.Load())
}

// All yields every pattern, as it compares, with its value, in no particular
// order. Patterns set or deleted while it runs may or may not be yielded.
func (m *Map[V]) All() iter.Seq2[string, V] {
	return func(yield func(string, V) bool) {
		more := true
		each := func(_, x any) bool {
			e := x.(*hostEntry[V])
			more = yield(e.pattern, e.value)
			return more
		}
		for _, sm := range []*sync.Map{&m.exact, &m.suffixes, &m.dots} {
			if sm.Range(each); !more {
				return
			}
		}
		if e := m.any.Load(); e != nil {
			yield(e.pattern, e.value)
		}
	}
}
