package portmux

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/djylb/portmux/httphead"
)

// Result is the decision of a Matcher for the input seen so far.
type Result uint8

const (
	// NoMatch means the connection does not belong to the route.
	NoMatch Result = iota
	// Match means the connection belongs to the route.
	Match
	// NeedMore means the input seen so far is not enough to decide.
	NeedMore
)

// String returns the name of the result.
func (r Result) String() string {
	switch r {
	case NoMatch:
		return "NoMatch"
	case Match:
		return "Match"
	case NeedMore:
		return "NeedMore"
	default:
		return "Result(" + strconv.Itoa(int(r)) + ")"
	}
}

// Matcher decides whether a connection belongs to a route.
//
// Match is first called before any byte arrived, with an empty Input, so that
// matchers such as RemoteIP can decide at once. It is called again with a
// longer Input each time it returned NeedMore. A matcher that needs bytes
// therefore returns NeedMore while the input is too short to decide, including
// when it is empty. Decisions must be final: once Match or NoMatch has been
// returned for some input, every longer input that starts with it must get the
// same answer.
//
// A Matcher is called from many goroutines at once, must not block, and must
// not retain the Input or its bytes.
type Matcher interface {
	Match(in *Input) Result
}

// MatcherFunc adapts a function to the Matcher interface. Wrap it in Named to
// give it a description for Snapshot.
type MatcherFunc func(in *Input) Result

// Match calls f(in).
func (f MatcherFunc) Match(in *Input) Result {
	return f(in)
}

// Named gives m a description, which Snapshot and RouteInfo show instead of
// its type. Built-in matchers describe themselves, as in TLS(SNI("a.example")).
func Named(name string, m Matcher) Matcher {
	if m == nil {
		panic("portmux: nil matcher")
	}
	return namedMatcher{name: name, m: m}
}

type namedMatcher struct {
	name string
	m    Matcher
}

func (n namedMatcher) Match(in *Input) Result           { return n.m.Match(in) }
func (n namedMatcher) String() string                   { return n.name }
func (n namedMatcher) silences(add func(time.Duration)) { reportSilences([]Matcher{n.m}, add) }

// describe returns the description of a matcher or filter: its String method,
// or else its type.
func describe[T any](v T) string {
	if s, ok := any(v).(fmt.Stringer); ok {
		return s.String()
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", v), "portmux.")
}

// call formats a constructor call such as Name(arg1, arg2).
func call[T any](name string, args []T, format func(T) string) string {
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('(')
	for i, a := range args {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(format(a))
	}
	b.WriteByte(')')
	return b.String()
}

func quote(s string) string { return strconv.Quote(s) }

// silencer is implemented by matchers that decide on silence. The Mux checks
// silent connections again at each reported duration after accepting them.
type silencer interface {
	silences(add func(time.Duration))
}

// And matches when every matcher matches. It decides NoMatch as soon as one
// of them does.
func And(matchers ...Matcher) Matcher {
	return andMatcher(checkedMatchers(matchers))
}

// Or matches when any matcher matches. A route already accepts any of its
// matchers; Or is for nesting inside And and Not.
func Or(matchers ...Matcher) Matcher {
	return orMatcher(checkedMatchers(matchers))
}

// Not inverts m: Match becomes NoMatch and NoMatch becomes Match, also when m
// still needs more of an input that is final.
func Not(m Matcher) Matcher {
	if m == nil {
		panic("portmux: nil matcher")
	}
	return notMatcher{m}
}

func checkedMatchers(ms []Matcher) []Matcher {
	if slices.Contains(ms, nil) {
		panic("portmux: nil matcher")
	}
	return slices.Clone(ms)
}

type andMatcher []Matcher

func (a andMatcher) String() string { return call("And", a, describe[Matcher]) }

func (a andMatcher) Match(in *Input) Result {
	res := Match
	for _, m := range a {
		switch m.Match(in) {
		case Match:
		case NeedMore:
			res = NeedMore
		default:
			return NoMatch
		}
	}
	return res
}

func (a andMatcher) silences(add func(time.Duration)) { reportSilences(a, add) }

type orMatcher []Matcher

func (o orMatcher) String() string { return call("Or", o, describe[Matcher]) }

func (o orMatcher) Match(in *Input) Result {
	return matchAny(o, in)
}

func (o orMatcher) silences(add func(time.Duration)) { reportSilences(o, add) }

type notMatcher struct{ m Matcher }

func (n notMatcher) String() string { return "Not(" + describe(n.m) + ")" }

func (n notMatcher) Match(in *Input) Result {
	switch n.m.Match(in) {
	case Match:
		return NoMatch
	case NeedMore:
		if in.final {
			return Match // m does not match, as the routes count it
		}
		return NeedMore
	default:
		return Match
	}
}

func (n notMatcher) silences(add func(time.Duration)) { reportSilences([]Matcher{n.m}, add) }

func matchAny(ms []Matcher, in *Input) Result {
	res := NoMatch
	for _, m := range ms {
		switch m.Match(in) {
		case Match:
			return Match
		case NeedMore:
			res = NeedMore
		default: // NoMatch, and results that a matcher must not return
		}
	}
	return res
}

func reportSilences(ms []Matcher, add func(time.Duration)) {
	for _, m := range ms {
		if s, ok := m.(silencer); ok {
			s.silences(add)
		}
	}
}

// Any matches every connection that has sent at least one byte. To take the
// connections that no other route accepts, prefer a fallback route, which
// also takes those left undecided at the sniff timeout; see RouteConfig.
func Any() Matcher {
	return anyMatcher{}
}

type anyMatcher struct{}

func (anyMatcher) Match(in *Input) Result {
	if len(in.data) > 0 {
		return Match
	}
	return NeedMore
}

func (anyMatcher) String() string { return "Any()" }

// Always matches every connection at once, before reading anything. On an
// entry whose listeners serve one service alone, a route with Always hands
// connections over without sniffing, buffering or waiting, so that protocols
// in which the server speaks first work too.
func Always() Matcher {
	return alwaysMatcher{}
}

type alwaysMatcher struct{}

func (alwaysMatcher) Match(*Input) Result { return Match }
func (alwaysMatcher) String() string      { return "Always()" }

// Prefix matches connections whose first bytes equal one of the prefixes.
func Prefix(prefixes ...string) Matcher {
	return prefixMatcher{prefixes: slices.Clone(prefixes), name: "Prefix"}
}

type prefixMatcher struct {
	prefixes []string
	name     string // the constructor, for String
}

func (p prefixMatcher) Match(in *Input) Result { return matchPrefixes(in.data, p.prefixes) }

func (p prefixMatcher) String() string {
	if p.name != "Prefix" {
		return p.name + "()"
	}
	return call(p.name, p.prefixes, quote)
}

// maxRegexpBytes bounds the n of Regexp, as ParseMatcher reads it.
const maxRegexpBytes = 1 << 30

// Regexp matches connections whose first n bytes match re. It waits for n
// bytes, or for fewer when the client sends no more or the sniff limit is
// reached, and then decides once, running re once per connection however
// often the routes ask again; anchor re with ^ to match from the first byte.
// Prefix is cheaper for fixed strings.
func Regexp(re *regexp.Regexp, n int) Matcher {
	if re == nil {
		panic("portmux: nil regexp")
	}
	return &regexpMatcher{re: re, n: min(max(n, 1), maxRegexpBytes)}
}

type regexpMatcher struct {
	re *regexp.Regexp
	n  int
}

func (m *regexpMatcher) Match(in *Input) Result {
	if len(in.data) < m.n && !in.final {
		return NeedMore
	}
	if res, ok := in.recalled(m); ok {
		return res
	}
	res := matchIf(m.re.Match(in.data[:min(len(in.data), m.n)]))
	in.remember(m, res)
	return res
}

func (m *regexpMatcher) String() string {
	return "Regexp(" + quote(m.re.String()) + ", " + strconv.Itoa(m.n) + ")"
}

// minSilence is the shortest silence that Silent waits for.
const minSilence = time.Millisecond

// Silent matches connections that sent nothing during d after they were
// accepted, which is how protocols in which the server speaks first look,
// such as SMTP, FTP, MySQL or SSH clients that wait for the server banner.
// Shorter durations than one millisecond are raised to it.
//
// The Mux checks silent connections at that time regardless of the order of
// the routes: the first route that accepts the silent connection gets it, and
// routes that are still waiting for bytes do not hold it back. A connection
// that sent anything never matches. Checking for silence extends the read
// deadline of the connection, which every connection from the net package
// supports.
func Silent(d time.Duration) Matcher {
	return silentMatcher(max(d, minSilence))
}

type silentMatcher time.Duration

func (s silentMatcher) Match(in *Input) Result {
	switch {
	case len(in.data) > 0:
		return NoMatch
	case in.elapsed >= time.Duration(s):
		return Match
	}
	return NeedMore
}

func (s silentMatcher) silences(add func(time.Duration)) { add(time.Duration(s)) }

func (s silentMatcher) String() string { return "Silent(" + time.Duration(s).String() + ")" }

// HTTP2Preface matches cleartext HTTP/2 connections that start with the client
// connection preface, as sent with prior knowledge (h2c). HTTP/2 over TLS is
// matched with TLS(ALPN("h2")).
func HTTP2Preface() Matcher {
	return prefixMatcher{prefixes: []string{httphead.HTTP2Preface}, name: "HTTP2Preface"}
}

// SSH matches SSH clients that send their identification string before the
// server's, as OpenSSH does. Use Silent for clients that wait for the server.
func SSH() Matcher {
	return prefixMatcher{prefixes: []string{"SSH-"}, name: "SSH"}
}

func matchPrefixes(b []byte, prefixes []string) Result {
	res := NoMatch
	for _, p := range prefixes {
		if len(b) >= len(p) {
			if string(b[:len(p)]) == p {
				return Match
			}
		} else if string(b) == p[:len(b)] {
			res = NeedMore
		}
	}
	return res
}
