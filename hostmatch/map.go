package hostmatch

import (
	"cmp"
	"iter"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Map maps host name patterns to values and looks names up by specificity,
// as virtual hosts are chosen. Patterns are those of Set.
// The patterns that match a name rank, most specific first:
//
//   - the exact name;
//   - the patterns with '*' by the number of their literal characters, so
//     that "*.api.example.com" comes before "*.example.com" and
//     "api-*.example.com" before both for "api-1.example.com"; on a tie a
//     "*." pattern comes first, then the pattern with fewer '*', then the
//     lower one in byte order;
//   - "*", which matches any name.
//
// Lookup returns the first of them, LookupFunc the first whose value a
// function accepts, and Matches all of them in this order, so that a policy
// of your own can skip patterns whose values do not apply. The
// empty pattern matches a ClientHello or request without a name. Names with
// bytes that no DNS name has match no pattern.
//
// A Map is safe for concurrent use, and its zero value is an empty map
// ready to use. Lookups take no lock and cost a few map lookups whatever the
// number of patterns, and patterns can be set and deleted while lookups run.
type Map[V any] struct {
	exact    sync.Map // name -> *hostEntry[V]
	suffixes sync.Map // ".example.com" -> *hostEntry[V], for "*.example.com"
	mu       sync.Mutex
	rest     atomic.Pointer[hostRest[V]] // the other patterns, replaced on change
	n        atomic.Int64
}

// hostEntry is a pattern, as it compares, and its value.
type hostEntry[V any] struct {
	pattern string
	value   V
}

// hostRest holds the patterns that are not exact names or "*." suffixes.
type hostRest[V any] struct {
	globs []hostGlob[V] // in matching order
	any   *hostEntry[V] // "*", or nil
}

type hostGlob[V any] struct {
	hostEntry[V]
	literal int // number of bytes that are not '*'
	stars   int
}

// hostPattern is a pattern normalized as Set compares it.
type hostPattern struct {
	key  string // the name, the suffix with its leading dot, or the pattern
	kind uint8
}

const (
	patternExact uint8 = iota
	patternSuffix
	patternGlob
	patternAny
)

func parseHostPattern(p string) hostPattern {
	p = strings.ToLower(strings.TrimSuffix(p, "."))
	switch {
	case p == "*":
		return hostPattern{kind: patternAny}
	case !strings.Contains(p, "*"):
		return hostPattern{key: p, kind: patternExact}
	case strings.HasPrefix(p, "*.") && !strings.Contains(p[2:], "*"):
		return hostPattern{key: p[1:], kind: patternSuffix}
	}
	return hostPattern{key: p, kind: patternGlob}
}

// String returns the pattern as it compares.
func (p hostPattern) String() string {
	switch p.kind {
	case patternSuffix:
		return "*" + p.key
	case patternAny:
		return "*"
	default: // patternExact and patternGlob
		return p.key
	}
}

// Set maps pattern to v, replacing the value it had.
func (m *Map[V]) Set(pattern string, v V) {
	p := parseHostPattern(pattern)
	e := &hostEntry[V]{pattern: p.String(), value: v}
	switch p.kind {
	case patternExact:
		if _, loaded := m.exact.Swap(p.key, e); !loaded {
			m.n.Add(1)
		}
	case patternSuffix:
		if _, loaded := m.suffixes.Swap(p.key, e); !loaded {
			m.n.Add(1)
		}
	default:
		m.changeRest(func(r *hostRest[V]) bool {
			if p.kind == patternAny {
				added := r.any == nil
				r.any = e
				return added
			}
			if i := r.index(p.key); i >= 0 {
				r.globs[i].hostEntry = *e
				return false
			}
			literal := len(p.key) - strings.Count(p.key, "*")
			r.globs = append(r.globs, hostGlob[V]{hostEntry: *e, literal: literal, stars: len(p.key) - literal})
			slices.SortFunc(r.globs, func(a, b hostGlob[V]) int {
				if c := cmp.Compare(b.literal, a.literal); c != 0 {
					return c
				}
				if c := cmp.Compare(a.stars, b.stars); c != 0 {
					return c
				}
				return strings.Compare(a.pattern, b.pattern)
			})
			return true
		})
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
	default:
		m.changeRest(func(r *hostRest[V]) bool {
			if p.kind == patternAny {
				deleted, r.any = r.any != nil, nil
			} else if i := r.index(p.key); i >= 0 {
				r.globs = slices.Delete(r.globs, i, i+1)
				deleted = true
			}
			return false
		})
	}
	if deleted {
		m.n.Add(-1)
	}
	return deleted
}

func (r *hostRest[V]) index(pattern string) int {
	return slices.IndexFunc(r.globs, func(g hostGlob[V]) bool { return g.pattern == pattern })
}

// changeRest replaces the other patterns with a changed copy. change reports
// whether it added a pattern.
func (m *Map[V]) changeRest(change func(*hostRest[V]) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var r hostRest[V]
	if cur := m.rest.Load(); cur != nil {
		r = *cur
		r.globs = slices.Clone(cur.globs)
	}
	if change(&r) {
		m.n.Add(1)
	}
	m.rest.Store(&r)
}

// Get returns the value of pattern itself, without matching.
func (m *Map[V]) Get(pattern string) (V, bool) {
	var e *hostEntry[V]
	switch p := parseHostPattern(pattern); p.kind {
	case patternExact:
		e = loadEntry[V](&m.exact, p.key)
	case patternSuffix:
		e = loadEntry[V](&m.suffixes, p.key)
	default:
		r := m.rest.Load()
		switch {
		case r == nil:
		case p.kind == patternAny:
			e = r.any
		default:
			if i := r.index(p.key); i >= 0 {
				e = &r.globs[i].hostEntry
			}
		}
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
	m.walk(Normalize(host), func(p string, x V) bool {
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
	r := m.rest.Load()
	var globs []hostGlob[V]
	if r != nil {
		globs = r.globs
	}
	// Suffixes come longest first, from the first dot on; a glob comes before
	// a suffix with fewer literal characters than it has.
	g := 0
	for i := 1; i < len(n.name); i++ {
		if n.name[i] != '.' {
			continue
		}
		e := loadEntry[V](&m.suffixes, n.name[i:])
		if e == nil {
			continue
		}
		for ; g < len(globs) && globs[g].literal > len(n.name)-i; g++ {
			if glob(globs[g].pattern, n.name) && !yield(globs[g].pattern, globs[g].value) {
				return
			}
		}
		if !yield(e.pattern, e.value) {
			return
		}
	}
	for ; g < len(globs); g++ {
		if glob(globs[g].pattern, n.name) && !yield(globs[g].pattern, globs[g].value) {
			return
		}
	}
	if r != nil && r.any != nil {
		yield(r.any.pattern, r.any.value)
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
		if m.exact.Range(each); !more {
			return
		}
		if m.suffixes.Range(each); !more {
			return
		}
		r := m.rest.Load()
		if r == nil {
			return
		}
		for _, g := range r.globs {
			if !yield(g.pattern, g.value) {
				return
			}
		}
		if r.any != nil {
			yield(r.any.pattern, r.any.value)
		}
	}
}
