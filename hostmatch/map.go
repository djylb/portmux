package hostmatch

import (
	"errors"

	"github.com/djylb/portmux/internal/panicerr"
	"iter"
	"strings"
	"sync/atomic"

	"github.com/djylb/portmux/internal/pmap"
)

// Snapshot maps host name patterns to values and looks names up by
// specificity, as virtual hosts are chosen. Patterns are those of Set. The
// patterns that match a name rank, most specific first:
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
// DNS name has match no pattern. With panics on patterns that CheckPattern
// refuses, such as "api-*.example.com".
//
// A Snapshot is immutable and safe for concurrent use; a nil or zero
// Snapshot is empty. With and Without return a new Snapshot that shares all
// but the changed paths with the old one, so a change costs a few small
// copies whatever the number of patterns, and a Snapshot of a few patterns
// is a few small nodes. Lookups cost a few hash lookups whatever the number
// of patterns. Load many patterns at once with a MapBuilder.
type Snapshot[V any] struct {
	exact    pmap.Map[hostEntry[V]] // name
	self     pmap.Map[hostEntry[V]] // "example.com", for ".example.com"
	suffixes pmap.Map[hostEntry[V]] // ".example.com", for "*.example.com"
	dots     pmap.Map[hostEntry[V]] // ".example.com", for ".example.com"
	any      *hostEntry[V]
	// longest is the length of the longest suffix ever set, so that a lookup
	// tries only the dots at which a suffix can start, however long the name.
	longest int
}

// Map is a Snapshot that changes in place: Set and Delete publish a new
// Snapshot, which lookups then see. Lookups take no lock. Concurrent writers
// publish by compare-and-swap. Its zero value is ready to use. Use TryEdit
// to apply many changes as one.
type Map[V any] struct {
	cur atomic.Pointer[Snapshot[V]]
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

// Get returns the value of pattern itself, without matching.
func (s *Snapshot[V]) Get(pattern string) (V, bool) {
	if s == nil {
		var zero V
		return zero, false
	}
	return get(pattern, s.exact.Get, s.suffixes.Get, s.dots.Get, s.any)
}

type getter[V any] func(string) (hostEntry[V], bool)

func get[V any](pattern string, exact, suffixes, dots getter[V], anyEntry *hostEntry[V]) (V, bool) {
	var e hostEntry[V]
	ok := false
	switch p := parseHostPattern(pattern); p.kind {
	case patternExact:
		e, ok = exact(p.key)
	case patternSuffix:
		e, ok = suffixes(p.key)
	case patternDot:
		e, ok = dots(p.key)
	case patternAny:
		if anyEntry != nil {
			e, ok = *anyEntry, true
		}
	}
	return e.value, ok
}

// With returns s with pattern mapped to v. It panics on a pattern that
// CheckPattern refuses.
func (s *Snapshot[V]) With(pattern string, v V) *Snapshot[V] {
	b := s.Builder()
	b.Set(pattern, v)
	return b.Snapshot()
}

// Without returns s without pattern.
func (s *Snapshot[V]) Without(pattern string) *Snapshot[V] {
	b := s.Builder()
	b.Delete(pattern)
	return b.Snapshot()
}

// Len returns the number of patterns.
func (s *Snapshot[V]) Len() int {
	if s == nil {
		return 0
	}
	n := s.exact.Len() + s.suffixes.Len() + s.dots.Len()
	if s.any != nil {
		n++
	}
	return n
}

// Lookup returns the value of the most specific pattern that matches host, a
// bare name or IP address without a port, and that pattern as it compares:
// lowercased and without a trailing dot.
func (s *Snapshot[V]) Lookup(host string) (v V, pattern string, ok bool) {
	s.walk(Normalize(host), func(p string, x V) bool {
		v, pattern, ok = x, p, true
		return false
	})
	return v, pattern, ok
}

// LookupFunc returns the value and pattern of the most specific pattern
// that matches host and whose value accept accepts, so that a name falls back
// to wider patterns when the value of a narrower one does not apply. It is
// Matches without allocating.
func (s *Snapshot[V]) LookupFunc(host string, accept func(pattern string, v V) bool) (v V, pattern string, ok bool) {
	return s.LookupNameFunc(Normalize(host), accept)
}

// LookupNameFunc is LookupFunc for a prepared name, which it does not prepare
// again.
func (s *Snapshot[V]) LookupNameFunc(n Name, accept func(pattern string, v V) bool) (v V, pattern string, ok bool) {
	s.walk(n, func(p string, x V) bool {
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
func (s *Snapshot[V]) Matches(host string) iter.Seq2[string, V] {
	n := Normalize(host)
	return func(yield func(string, V) bool) { s.walk(n, yield) }
}

// walk yields the patterns that match n, most specific first.
func (s *Snapshot[V]) walk(n Name, yield func(string, V) bool) {
	if s == nil || !n.valid {
		return
	}
	h := pmap.Hash(n.name)
	if e, ok := s.exact.GetHashed(h, n.name); ok && !yield(e.pattern, e.value) {
		return
	}
	if n.name == "" {
		return
	}
	if e, ok := s.self.GetHashed(h, n.name); ok && !yield(e.pattern, e.value) {
		return
	}
	// Suffixes come longest first, from the first dot on. Dots further from
	// the end than the longest suffix start none.
	if s.suffixes.Len()+s.dots.Len() > 0 {
		for i := max(1, len(n.name)-s.longest); i < len(n.name); i++ {
			if n.name[i] != '.' {
				continue
			}
			if e, ok := s.suffixes.Get(n.name[i:]); ok && !yield(e.pattern, e.value) {
				return
			}
			if e, ok := s.dots.Get(n.name[i:]); ok && !yield(e.pattern, e.value) {
				return
			}
		}
	}
	if s.any != nil {
		yield(s.any.pattern, s.any.value)
	}
}

// All yields every pattern, as it compares, with its value, in no particular
// order.
func (s *Snapshot[V]) All() iter.Seq2[string, V] {
	return func(yield func(string, V) bool) {
		if s == nil {
			return
		}
		for _, m := range []*pmap.Map[hostEntry[V]]{&s.exact, &s.suffixes, &s.dots} {
			for _, e := range m.All() {
				if !yield(e.pattern, e.value) {
					return
				}
			}
		}
		if s.any != nil {
			yield(s.any.pattern, s.any.value)
		}
	}
}

// MapBuilder changes a Snapshot in place, without the copies that With
// makes, to set many patterns at once. Its zero value starts from an empty
// Snapshot. A MapBuilder is not safe for concurrent use.
type MapBuilder[V any] struct {
	// The builders of the maps of base that changed, or nil.
	exact, self, suffixes, dots *pmap.Builder[hostEntry[V]]
	any                         *hostEntry[V]
	base                        Snapshot[V]
}

// Builder returns a MapBuilder that starts from s, which it does not change.
func (s *Snapshot[V]) Builder() *MapBuilder[V] {
	b := &MapBuilder[V]{}
	if s != nil {
		b.base = *s
		b.any = s.any
	}
	return b
}

// edit returns the builder *bp of m, made on first use.
func edit[V any](bp **pmap.Builder[hostEntry[V]], m pmap.Map[hostEntry[V]]) *pmap.Builder[hostEntry[V]] {
	if *bp == nil {
		*bp = m.Builder()
	}
	return *bp
}

// Grow hints that about n exact names are to be set, so that a MapBuilder
// that starts from an empty Snapshot makes room for them at once.
func (b *MapBuilder[V]) Grow(n int) {
	if b.exact == nil && b.base.exact.Len() == 0 {
		edit(&b.exact, b.base.exact).Grow(n)
	}
}

// Set maps pattern to v, replacing the value it had. It panics on a
// pattern that CheckPattern refuses.
func (b *MapBuilder[V]) Set(pattern string, v V) {
	mustPattern(pattern)
	p := parseHostPattern(pattern)
	e := hostEntry[V]{pattern: p.String(), value: v}
	switch p.kind {
	case patternExact:
		edit(&b.exact, b.base.exact).Set(p.key, e)
	case patternSuffix:
		b.base.longest = max(b.base.longest, len(p.key))
		edit(&b.suffixes, b.base.suffixes).Set(p.key, e)
	case patternDot:
		b.base.longest = max(b.base.longest, len(p.key))
		edit(&b.dots, b.base.dots).Set(p.key, e)
		edit(&b.self, b.base.self).Set(p.key[1:], e)
	case patternAny:
		b.any = &e
	}
}

// Update sets pattern to what fn returns for its value, and whether it had
// one. The callback may snapshot or edit b. It panics on a pattern that
// CheckPattern refuses.
func (b *MapBuilder[V]) Update(pattern string, fn func(old V, ok bool) V) {
	mustPattern(pattern)
	old, ok := b.Get(pattern)
	b.Set(pattern, fn(old, ok))
}

// Delete removes pattern and reports whether it was set.
func (b *MapBuilder[V]) Delete(pattern string) bool {
	p := parseHostPattern(pattern)
	switch p.kind {
	case patternExact:
		return del(edit(&b.exact, b.base.exact), p.key)
	case patternSuffix:
		return del(edit(&b.suffixes, b.base.suffixes), p.key)
	case patternDot:
		edit(&b.self, b.base.self).Delete(p.key[1:])
		return del(edit(&b.dots, b.base.dots), p.key)
	case patternAny:
		had := b.any != nil
		b.any = nil
		return had
	}
	return false
}

func del[V any](b *pmap.Builder[V], key string) bool {
	n := b.Len()
	b.Delete(key)
	return b.Len() < n
}

// view returns the map of base, or of its builder when it changed.
func view[V any](bp *pmap.Builder[hostEntry[V]], m pmap.Map[hostEntry[V]]) getter[V] {
	if bp != nil {
		return bp.Get
	}
	return m.Get
}

// Get returns the value of pattern itself, without matching.
func (b *MapBuilder[V]) Get(pattern string) (V, bool) {
	return get(pattern, view(b.exact, b.base.exact), view(b.suffixes, b.base.suffixes), view(b.dots, b.base.dots), b.any)
}

// Snapshot returns the patterns set so far. Later changes of b do not
// change it.
func (b *MapBuilder[V]) Snapshot() *Snapshot[V] {
	s := b.base // b.base.longest follows Set
	s.any = b.any
	for _, x := range []struct {
		b *pmap.Builder[hostEntry[V]]
		m *pmap.Map[hostEntry[V]]
	}{{b.exact, &s.exact}, {b.self, &s.self}, {b.suffixes, &s.suffixes}, {b.dots, &s.dots}} {
		if x.b != nil {
			*x.m = x.b.Map()
		}
	}
	if s.suffixes.Len()+s.dots.Len() == 0 {
		s.longest = 0
	}
	b.base = s
	return &s
}

// Load returns the current Snapshot, which later changes of m leave as it
// is.
func (m *Map[V]) Load() *Snapshot[V] { return m.cur.Load() }

// PanicError describes a panic recovered from an edit callback.
type PanicError = panicerr.PanicError

// ErrEditConflict reports that another edit published a snapshot first.
var ErrEditConflict = errors.New("hostmatch: snapshot changed during edit")

// TryEdit applies the changes that fn makes to b as one: lookups see all of
// them or none. It calls fn once, outside any lock. If a concurrent edit
// published first, it returns ErrEditConflict. A callback panic returns a
// *PanicError. Either error discards the entire batch.
func (m *Map[V]) TryEdit(fn func(b *MapBuilder[V])) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = panicerr.New(v)
		}
	}()
	if !m.tryEdit(fn) {
		return ErrEditConflict
	}
	return nil
}

func (m *Map[V]) tryEdit(fn func(b *MapBuilder[V])) bool {
	old := m.cur.Load()
	b := old.Builder()
	fn(b)
	next := b.Snapshot()
	return m.cur.CompareAndSwap(old, next)
}

// Set maps pattern to v, replacing the value it had. It panics on a
// pattern that CheckPattern refuses.
func (m *Map[V]) Set(pattern string, v V) {
	for {
		if m.tryEdit(func(b *MapBuilder[V]) { b.Set(pattern, v) }) {
			return
		}
	}
}

// Delete removes pattern and reports whether it was set.
func (m *Map[V]) Delete(pattern string) (deleted bool) {
	for {
		if m.tryEdit(func(b *MapBuilder[V]) { deleted = b.Delete(pattern) }) {
			return deleted
		}
	}
}

// Get returns the value of pattern itself, without matching.
func (m *Map[V]) Get(pattern string) (V, bool) { return m.Load().Get(pattern) }

// Lookup is Snapshot.Lookup on the current patterns.
func (m *Map[V]) Lookup(host string) (v V, pattern string, ok bool) { return m.Load().Lookup(host) }

// LookupFunc is Snapshot.LookupFunc on the current patterns; accept must
// not change m.
func (m *Map[V]) LookupFunc(host string, accept func(pattern string, v V) bool) (v V, pattern string, ok bool) {
	return m.Load().LookupFunc(host, accept)
}

// LookupNameFunc is Snapshot.LookupNameFunc on the current patterns.
func (m *Map[V]) LookupNameFunc(n Name, accept func(pattern string, v V) bool) (v V, pattern string, ok bool) {
	return m.Load().LookupNameFunc(n, accept)
}

// Matches is Snapshot.Matches on the patterns current when it is called.
func (m *Map[V]) Matches(host string) iter.Seq2[string, V] { return m.Load().Matches(host) }

// Len returns the number of patterns.
func (m *Map[V]) Len() int { return m.Load().Len() }

// All is Snapshot.All on the patterns current when it is called.
func (m *Map[V]) All() iter.Seq2[string, V] { return m.Load().All() }

// Canonical returns pattern as Snapshot and Map compare it: lowercased and
// without a trailing dot, so that two spellings of one pattern give the
// same string.
func Canonical(pattern string) string { return parseHostPattern(pattern).String() }
