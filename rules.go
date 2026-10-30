package portmux

import (
	"fmt"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"

	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/tlshello"
)

// Names supplies the matchers and filters of your own that ParseMatcher
// finds by name. Each is used where its kind is expected.
type Names struct {
	// Matchers, HTTPFilters and TLSFilters are found by an identifier without
	// arguments, such as office in And(office, TLS()). They keep the name as
	// their description, so that the parsed matcher prints the text again.
	Matchers    map[string]Matcher
	HTTPFilters map[string]HTTPFilter
	TLSFilters  map[string]TLSFilter
	// MatcherFuncs, HTTPFilterFuncs and TLSFilterFuncs build matchers and
	// filters from calls with arguments, such as Country("CN") or
	// JA4("t13d1516h2_8daaf6152771_e5627efa2ab1"): they are called with the
	// arguments as text, strings unquoted and bare words as written. Their
	// results should describe themselves as the call, so that the parsed
	// matcher prints the text again. A built-in name cannot be replaced.
	MatcherFuncs    map[string]func(args ...string) (Matcher, error)
	HTTPFilterFuncs map[string]func(args ...string) (HTTPFilter, error)
	TLSFilterFuncs  map[string]func(args ...string) (TLSFilter, error)
}

// ParseError reports text that ParseMatcher cannot parse.
type ParseError struct {
	Text   string
	Offset int // byte offset of the problem in Text
	Msg    string
	// Err is the error of a function of Names that failed, or nil.
	Err error
}

// maxErrorContext bounds the bytes of the text that a ParseError quotes on
// each side of its offset.
const maxErrorContext = 40

func (e *ParseError) Error() string {
	text := e.Text
	if len(text) > 2*maxErrorContext {
		lo := min(max(e.Offset-maxErrorContext, 0), len(text))
		hi := min(lo+2*maxErrorContext, len(text))
		text = text[lo:hi]
		if lo > 0 {
			text = "..." + text
		}
		if hi < len(e.Text) {
			text += "..."
		}
	}
	return fmt.Sprintf("portmux: matcher %q: %s at offset %d", text, e.Msg, e.Offset)
}

// Unwrap returns the error of a function of Names, or nil.
func (e *ParseError) Unwrap() error { return e.Err }

// ParseMatcher parses a matcher from the text that matchers describe
// themselves with, as in
//
//	And(RemoteIP(10.0.0.0/8), TLS(SNI("*.example.com"), MinTLSVersion(1.2)))
//
// so that routes can be kept in configuration files and databases: every
// built-in matcher and filter prints text that ParseMatcher turns into an
// equal matcher, except RemoteIPFunc and LocalIPFunc, whose functions have no
// text; name them in names to keep them as text. Strings are Go string literals; prefixes, ports, durations
// and versions are written bare. names, which may be nil, supplies the
// matchers and filters of your own.
//
// Calls nest at most 100 deep, and regular expressions are limited to about
// 1000 instructions, so that a rule cannot exhaust the stack or make each
// connection cost much; build larger ones in code.
func ParseMatcher(text string, names *Names) (Matcher, error) {
	p := &parser{text: text, names: names}
	if names == nil {
		p.names = &Names{}
	}
	n, err := p.parse()
	if err != nil {
		return nil, err
	}
	return p.matcher(n)
}

// node is a parsed call, bare word or string.
type node struct {
	text string // the name of a call, the word, or the string's value
	args []*node
	pos  int
	call bool
	str  bool
}

type parser struct {
	text  string
	pos   int
	depth int // calls being parsed
	names *Names
}

const (
	// maxParseDepth bounds the nesting of calls, which the parser and the
	// descriptions of the matchers follow recursively.
	maxParseDepth = 100
	// maxRuleRegexpSize bounds the size of a regular expression in rule
	// text, about its number of instructions, which its cost per byte
	// follows.
	maxRuleRegexpSize = 1000
)

func (p *parser) fail(pos int, format string, args ...any) *ParseError {
	return &ParseError{Text: p.text, Offset: pos, Msg: fmt.Sprintf(format, args...)}
}

func (p *parser) parse() (*node, error) {
	n, err := p.node()
	if err != nil {
		return nil, err
	}
	if p.skipSpace(); p.pos < len(p.text) {
		return nil, p.fail(p.pos, "unexpected %q", p.text[p.pos:p.pos+1])
	}
	return n, nil
}

func (p *parser) skipSpace() {
	for p.pos < len(p.text) && strings.IndexByte(" \t\r\n", p.text[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *parser) node() (*node, error) {
	p.skipSpace()
	start := p.pos
	if p.pos >= len(p.text) {
		return nil, p.fail(p.pos, "unexpected end")
	}
	if c := p.text[p.pos]; c == '"' || c == '`' {
		quoted, err := strconv.QuotedPrefix(p.text[p.pos:])
		if err != nil {
			return nil, p.fail(p.pos, "invalid string")
		}
		s, _ := strconv.Unquote(quoted)
		p.pos += len(quoted)
		return &node{text: s, pos: start, str: true}, nil
	}
	for p.pos < len(p.text) && strings.IndexByte("(),\"` \t\r\n", p.text[p.pos]) < 0 {
		p.pos++
	}
	if p.pos == start {
		return nil, p.fail(p.pos, "unexpected %q", p.text[p.pos:p.pos+1])
	}
	n := &node{text: p.text[start:p.pos], pos: start}
	if p.skipSpace(); p.pos >= len(p.text) || p.text[p.pos] != '(' {
		return n, nil
	}
	n.call = true
	if p.depth++; p.depth > maxParseDepth {
		return nil, p.fail(start, "calls nested deeper than %d", maxParseDepth)
	}
	defer func() { p.depth-- }()
	p.pos++
	for {
		if p.skipSpace(); p.pos < len(p.text) && p.text[p.pos] == ')' && len(n.args) == 0 {
			p.pos++
			return n, nil
		}
		arg, err := p.node()
		if err != nil {
			return nil, err
		}
		n.args = append(n.args, arg)
		p.skipSpace()
		switch {
		case p.pos >= len(p.text):
			return nil, p.fail(p.pos, "missing )")
		case p.text[p.pos] == ',':
			p.pos++
		case p.text[p.pos] == ')':
			p.pos++
			return n, nil
		default:
			return nil, p.fail(p.pos, "expected , or )")
		}
	}
}

// builtin is a built-in matcher or filter that ParseMatcher knows by name:
// how many arguments its call takes, at least lo and, unless hi is negative,
// at most hi, and how it is built from them. The String method of each type
// writes the same name and arguments, which the tests of ParseMatcher hold
// together.
type builtin[T any] struct {
	lo, hi int
	build  func(p *parser, args []*node) (T, error)
}

// The built-in matchers, HTTP filters and TLS filters by name. They are set
// in init: their builders parse nested calls with the parser, which looks
// them up, so initializing them where they are declared would be an
// initialization cycle.
var (
	builtinMatchers    map[string]builtin[Matcher]
	builtinHTTPFilters map[string]builtin[HTTPFilter]
	builtinTLSFilters  map[string]builtin[TLSFilter]
)

func init() {
	builtinMatchers = map[string]builtin[Matcher]{
		"AnyBytes": noArgs(AnyBytes), "Always": noArgs(Always), "SSH": noArgs(SSH), "HTTP2Preface": noArgs(HTTP2Preface),
		"SOCKS4": noArgs(SOCKS4), "SOCKS5": noArgs(SOCKS5), "PostgreSQL": noArgs(PostgreSQL), "MQTT": noArgs(MQTT),
		"RDP": noArgs(RDP), "OpenVPN": noArgs(OpenVPN), "XMPP": noArgs(XMPP), "DNS": noArgs(DNS),

		"And":       variadic((*parser).matcher, And),
		"Or":        variadic((*parser).matcher, Or),
		"Prefix":    variadic((*parser).str, Prefix),
		"Domain":    variadic((*parser).hostPattern, Domain),
		"RemoteIP":  variadic((*parser).prefix, RemoteIP),
		"LocalIP":   variadic((*parser).prefix, LocalIP),
		"LocalPort": variadic((*parser).port, LocalPort),
		"HTTP1":     variadic((*parser).httpFilter, HTTP1),
		"HTTP2":     variadic((*parser).httpFilter, HTTP2),
		"TLS":       variadic((*parser).tlsFilter, TLS),
		"Not": {1, 1, func(p *parser, args []*node) (Matcher, error) {
			m, err := p.matcher(args[0])
			if err != nil {
				return nil, err
			}
			return Not(m), nil
		}},
		"Regexp": {2, 2, func(p *parser, args []*node) (Matcher, error) {
			re, err := p.regexp(args[0])
			if err != nil {
				return nil, err
			}
			size, err := p.int(args[1], maxRegexpBytes)
			if err != nil {
				return nil, err
			}
			return Regexp(re, size), nil
		}},
		"Silent": {1, 1, func(p *parser, args []*node) (Matcher, error) {
			d, err := time.ParseDuration(args[0].text)
			if err != nil || args[0].call || args[0].str {
				return nil, p.fail(args[0].pos, "invalid duration")
			}
			return Silent(d), nil
		}},
	}
	builtinHTTPFilters = map[string]builtin[HTTPFilter]{
		"Host":       variadic((*parser).hostPattern, Host),
		"Path":       variadic((*parser).str, Path),
		"PathPrefix": variadic((*parser).str, PathPrefix),
		"Method":     variadic((*parser).str, Method),
		"HostRegexp": oneRegexp(HostRegexp),
		"PathRegexp": oneRegexp(PathRegexp),
		"Header":     nameAndStrings(Header),
		"Query":      nameAndStrings(Query),
		"WebSocket":  noArgs(WebSocket),
		"HeaderRegexp": {2, 2, func(p *parser, args []*node) (HTTPFilter, error) {
			name, err := p.str(args[0])
			if err != nil {
				return nil, err
			}
			re, err := p.regexp(args[1])
			if err != nil {
				return nil, err
			}
			return HeaderRegexp(name, re), nil
		}},
	}
	addFilterSets(builtinHTTPFilters, (*parser).httpFilter)
	builtinTLSFilters = map[string]builtin[TLSFilter]{
		"SNI":       variadic((*parser).hostPattern, SNI),
		"ALPN":      variadic((*parser).str, ALPN),
		"SNIRegexp": oneRegexp(SNIRegexp),
		"MinTLSVersion": {1, 1, func(p *parser, args []*node) (TLSFilter, error) {
			v, ok := parseVersion(args[0].text)
			if !ok || args[0].call || args[0].str {
				return nil, p.fail(args[0].pos, "invalid TLS version")
			}
			return MinTLSVersion(v), nil
		}},
	}
	addFilterSets(builtinTLSFilters, (*parser).tlsFilter)
}

// noArgs is a built-in without arguments.
func noArgs[T any](f func() T) builtin[T] {
	return builtin[T]{0, 0, func(*parser, []*node) (T, error) { return f(), nil }}
}

// variadic is a built-in of any number of arguments, each read with arg.
func variadic[A, T any](arg func(*parser, *node) (A, error), f func(...A) T) builtin[T] {
	return builtin[T]{0, -1, func(p *parser, args []*node) (T, error) {
		vs, err := each(args, func(n *node) (A, error) { return arg(p, n) })
		if err != nil {
			var zero T
			return zero, err
		}
		return f(vs...), nil
	}}
}

// oneRegexp is a built-in of one regular expression.
func oneRegexp[T any](f func(*regexp.Regexp) T) builtin[T] {
	return builtin[T]{1, 1, func(p *parser, args []*node) (T, error) {
		re, err := p.regexp(args[0])
		if err != nil {
			var zero T
			return zero, err
		}
		return f(re), nil
	}}
}

// nameAndStrings is a built-in of a name and any number of strings after it.
func nameAndStrings[T any](f func(string, ...string) T) builtin[T] {
	return builtin[T]{1, -1, func(p *parser, args []*node) (T, error) {
		ss, err := each(args, p.str)
		if err != nil {
			var zero T
			return zero, err
		}
		return f(ss[0], ss[1:]...), nil
	}}
}

// addFilterSets adds AllOf, AnyOf and NoneOf of the filters that one reads.
func addFilterSets[T any](builtins map[string]builtin[Filter[T]], one func(*parser, *node) (Filter[T], error)) {
	builtins["AllOf"] = variadic(one, AllOf[T])
	builtins["AnyOf"] = variadic(one, AnyOf[T])
	builtins["NoneOf"] = variadic(one, NoneOf[T])
}

// buildBuiltin builds the built-in that the call n names; ok reports whether
// n names one.
func buildBuiltin[T any](p *parser, n *node, builtins map[string]builtin[T]) (v T, ok bool, err error) {
	b, ok := builtins[n.text]
	if !ok {
		return v, false, nil
	}
	if err := p.count(n, b.lo, b.hi); err != nil {
		return v, true, err
	}
	v, err = b.build(p, n.args)
	return v, true, err
}

func (p *parser) matcher(n *node) (Matcher, error) {
	if n.str {
		return nil, p.fail(n.pos, "expected a matcher, found a string")
	}
	if !n.call {
		m, ok := p.names.Matchers[n.text]
		switch {
		case !ok:
			return nil, p.fail(n.pos, "unknown matcher %s", n.text)
		case m == nil:
			return nil, p.fail(n.pos, "matcher %s is nil", n.text)
		}
		return Named(n.text, m), nil
	}
	if m, ok, err := buildBuiltin(p, n, builtinMatchers); ok {
		return m, err
	}
	return custom(p, n, p.names.MatcherFuncs, "matcher")
}

// custom builds a call with a function of Names.
func custom[T any](p *parser, n *node, funcs map[string]func(args ...string) (T, error), kind string) (T, error) {
	var zero T
	build, ok := funcs[n.text]
	if !ok {
		return zero, p.fail(n.pos, "unknown %s %s", kind, n.text)
	}
	args, err := each(n.args, func(a *node) (string, error) {
		if a.call {
			return "", p.fail(a.pos, "expected a string or a word")
		}
		return a.text, nil
	})
	if err != nil {
		return zero, err
	}
	v, err := build(args...)
	switch {
	case err != nil:
		e := p.fail(n.pos, "%s: %v", n.text, err)
		e.Err = err
		return zero, e
	case any(v) == nil:
		return zero, p.fail(n.pos, "%s returned no %s", n.text, kind)
	}
	return v, nil
}

func (p *parser) httpFilter(n *node) (HTTPFilter, error) {
	switch {
	case n.str:
		return nil, p.fail(n.pos, "expected an HTTP filter, found a string")
	case !n.call:
		f, ok := p.names.HTTPFilters[n.text]
		switch {
		case !ok:
			return nil, p.fail(n.pos, "unknown HTTP filter %s", n.text)
		case f == nil:
			return nil, p.fail(n.pos, "HTTP filter %s is nil", n.text)
		}
		return namedFilter[*httphead.Request]{name: n.text, f: f}, nil
	}
	if f, ok, err := buildBuiltin(p, n, builtinHTTPFilters); ok {
		return f, err
	}
	return custom(p, n, p.names.HTTPFilterFuncs, "HTTP filter")
}

func (p *parser) tlsFilter(n *node) (TLSFilter, error) {
	switch {
	case n.str:
		return nil, p.fail(n.pos, "expected a TLS filter, found a string")
	case !n.call:
		f, ok := p.names.TLSFilters[n.text]
		switch {
		case !ok:
			return nil, p.fail(n.pos, "unknown TLS filter %s", n.text)
		case f == nil:
			return nil, p.fail(n.pos, "TLS filter %s is nil", n.text)
		}
		return namedFilter[*tlshello.Hello]{name: n.text, f: f}, nil
	}
	if f, ok, err := buildBuiltin(p, n, builtinTLSFilters); ok {
		return f, err
	}
	return custom(p, n, p.names.TLSFilterFuncs, "TLS filter")
}

func each[T any](args []*node, parse func(*node) (T, error)) ([]T, error) {
	out := make([]T, 0, len(args))
	for _, a := range args {
		v, err := parse(a)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// count checks that n has at least lo and, unless hi is negative, at most hi
// arguments.
func (p *parser) count(n *node, lo, hi int) error {
	switch {
	case len(n.args) < lo:
		return p.fail(n.pos, "%s needs %s", n.text, arguments(lo))
	case hi >= 0 && len(n.args) > hi:
		return p.fail(n.pos, "%s takes %s", n.text, arguments(hi))
	}
	return nil
}

func arguments(n int) string {
	if n == 1 {
		return "1 argument"
	}
	return strconv.Itoa(n) + " arguments"
}

func (p *parser) str(n *node) (string, error) {
	if !n.str {
		return "", p.fail(n.pos, "expected a string")
	}
	return n.text, nil
}

// hostPattern is a string that hostmatch.CheckPattern accepts.
func (p *parser) hostPattern(n *node) (string, error) {
	s, err := p.str(n)
	if err != nil {
		return "", err
	}
	if err := hostmatch.CheckPattern(s); err != nil {
		return "", p.fail(n.pos, "%v", err)
	}
	return s, nil
}

func (p *parser) regexp(n *node) (*regexp.Regexp, error) {
	s, err := p.str(n)
	if err != nil {
		return nil, err
	}
	// The size is estimated on the parsed expression, before compiling it
	// spends it.
	parsed, err := syntax.Parse(s, syntax.Perl)
	if err != nil {
		return nil, p.fail(n.pos, "%v", err)
	}
	if regexpSize(parsed) > maxRuleRegexpSize {
		return nil, p.fail(n.pos, "regular expression larger than %d instructions", maxRuleRegexpSize)
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, p.fail(n.pos, "%v", err)
	}
	return re, nil
}

// regexpSize estimates the instructions of re with its repetitions written
// out, stopping just above maxRuleRegexpSize.
func regexpSize(re *syntax.Regexp) int {
	size := 1
	switch re.Op {
	case syntax.OpLiteral:
		size = len(re.Rune)
	case syntax.OpRepeat:
		times := re.Max
		if times < 0 {
			times = re.Min + 1
		}
		return min(max(times, 1)*regexpSize(re.Sub[0]), maxRuleRegexpSize+1)
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpCharClass, syntax.OpAnyCharNotNL,
		syntax.OpAnyChar, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpCapture,
		syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpConcat, syntax.OpAlternate:
		// One instruction, and those of the subexpressions below.
	}
	for _, sub := range re.Sub {
		if size += regexpSize(sub); size > maxRuleRegexpSize {
			break
		}
	}
	return min(size, maxRuleRegexpSize+1)
}

func (p *parser) int(n *node, maxValue int) (int, error) {
	v, err := strconv.Atoi(n.text)
	if err != nil || n.str || n.call || v < 0 || v > maxValue {
		return 0, p.fail(n.pos, "expected a number up to %d", maxValue)
	}
	return v, nil
}

// port reads a port number.
func (p *parser) port(n *node) (uint16, error) {
	v, err := p.int(n, 65535)
	return uint16(v), err
}

// prefix reads an IP prefix, or an address that stands for a single one.
func (p *parser) prefix(n *node) (netip.Prefix, error) {
	if n.str || n.call {
		return netip.Prefix{}, p.fail(n.pos, "expected an IP prefix")
	}
	if pf, err := netip.ParsePrefix(n.text); err == nil {
		return pf, nil
	}
	a, err := netip.ParseAddr(n.text)
	if err != nil {
		return netip.Prefix{}, p.fail(n.pos, "expected an IP prefix")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// namedFilter gives a filter found by ParseMatcher its name as description.
type namedFilter[T any] struct {
	name string
	f    Filter[T]
}

func (n namedFilter[T]) Match(v T) bool { return n.f.Match(v) }
func (n namedFilter[T]) String() string { return n.name }
