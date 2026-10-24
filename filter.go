package portmux

import (
	"slices"

	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/tlshello"
)

// Filter restricts what a protocol matcher accepts. HTTP1 takes filters of
// *httphead.Request and TLS filters of *tlshello.Hello. Filters given to one matcher
// must all pass; AllOf, AnyOf and NoneOf combine filters of one protocol in
// any nesting.
type Filter[T any] interface {
	Match(v T) bool
}

// HTTPFilter restricts the requests accepted by HTTP1.
type HTTPFilter = Filter[*httphead.Request]

// TLSFilter restricts the ClientHellos accepted by TLS.
type TLSFilter = Filter[*tlshello.Hello]

// FilterFunc adapts a function to the Filter interface.
type FilterFunc[T any] func(v T) bool

// HTTPFilterFunc adapts a function to HTTPFilter.
type HTTPFilterFunc = FilterFunc[*httphead.Request]

// TLSFilterFunc adapts a function to TLSFilter.
type TLSFilterFunc = FilterFunc[*tlshello.Hello]

// Match calls f(v).
func (f FilterFunc[T]) Match(v T) bool { return f(v) }

func (f FilterFunc[T]) String() string {
	switch any(f).(type) {
	case HTTPFilterFunc:
		return "HTTPFilterFunc"
	case TLSFilterFunc:
		return "TLSFilterFunc"
	}
	return "FilterFunc"
}

// AllOf passes when every filter passes, and when there are none.
func AllOf[T any](filters ...Filter[T]) Filter[T] {
	return newFilterSet(allOf, filters)
}

// AnyOf passes when at least one filter passes.
func AnyOf[T any](filters ...Filter[T]) Filter[T] {
	return newFilterSet(anyOf, filters)
}

// NoneOf passes when no filter passes, which excludes what they describe, as
// in HTTP1(Host("*.example.com"), NoneOf(Host("admin.example.com"))).
func NoneOf[T any](filters ...Filter[T]) Filter[T] {
	return newFilterSet(noneOf, filters)
}

// allFilters returns the result of a matcher whose parser returned v and res:
// res unless it is Match, and then whether v passes every filter.
func allFilters[T any](filters []Filter[T], v T, res Result) Result {
	if res != Match {
		return res
	}
	for _, f := range filters {
		if !f.Match(v) {
			return NoMatch
		}
	}
	return Match
}

type setKind uint8

const (
	allOf setKind = iota
	anyOf
	noneOf
)

func newFilterSet[T any](kind setKind, filters []Filter[T]) filterSet[T] {
	if slices.Contains(filters, nil) {
		panic("portmux: nil filter")
	}
	return filterSet[T]{kind: kind, filters: slices.Clone(filters)}
}

type filterSet[T any] struct {
	kind    setKind
	filters []Filter[T]
}

func (s filterSet[T]) Match(v T) bool {
	// AllOf looks for a failing filter, AnyOf and NoneOf for a passing one,
	// which decides at once.
	for _, f := range s.filters {
		if f.Match(v) != (s.kind == allOf) {
			return s.kind == anyOf
		}
	}
	return s.kind != anyOf
}

func (s filterSet[T]) String() string {
	return call([...]string{"AllOf", "AnyOf", "NoneOf"}[s.kind], s.filters, describe[Filter[T]])
}
