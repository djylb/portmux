package portmux

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

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
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("portmux: matcher %q: %s at offset %d", e.Text, e.Msg, e.Offset)
}

// ParseMatcher parses a matcher from the text that matchers describe
// themselves with, as in
//
//	And(RemoteIP(10.0.0.0/8), TLS(SNI("*.example.com"), MinTLSVersion(1.2)))
//
// so that routes can be kept in configuration files and databases: every
// built-in matcher and filter prints text that ParseMatcher turns into an
// equal matcher. Strings are Go string literals; prefixes, ports, durations
// and versions are written bare. names, which may be nil, supplies the
// matchers and filters of your own.
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
	names *Names
}

func (p *parser) fail(pos int, format string, args ...any) error {
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

// matcherArgs lists the matchers that take no arguments.
var matcherArgs = map[string]func() Matcher{
	"Any": Any, "Always": Always, "SSH": SSH, "HTTP2Preface": HTTP2Preface,
	"SOCKS4": SOCKS4, "SOCKS5": SOCKS5, "PostgreSQL": PostgreSQL, "MQTT": MQTT,
	"RDP": RDP, "OpenVPN": OpenVPN, "XMPP": XMPP, "DNS": DNS,
}

func (p *parser) matcher(n *node) (Matcher, error) {
	if n.str {
		return nil, p.fail(n.pos, "expected a matcher, found a string")
	}
	if !n.call {
		m, ok := p.names.Matchers[n.text]
		if !ok {
			return nil, p.fail(n.pos, "unknown matcher %s", n.text)
		}
		return Named(n.text, m), nil
	}
	if f, ok := matcherArgs[n.text]; ok {
		if err := p.count(n, 0, 0); err != nil {
			return nil, err
		}
		return f(), nil
	}
	switch n.text {
	case "And", "Or":
		ms, err := each(n.args, p.matcher)
		if err != nil {
			return nil, err
		}
		if n.text == "And" {
			return And(ms...), nil
		}
		return Or(ms...), nil
	case "Not":
		if err := p.count(n, 1, 1); err != nil {
			return nil, err
		}
		m, err := p.matcher(n.args[0])
		if err != nil {
			return nil, err
		}
		return Not(m), nil
	case "Prefix", "Domain":
		ss, err := each(n.args, p.str)
		if err != nil {
			return nil, err
		}
		if n.text == "Prefix" {
			return Prefix(ss...), nil
		}
		return Domain(ss...), nil
	case "Regexp":
		if err := p.count(n, 2, 2); err != nil {
			return nil, err
		}
		re, err := p.regexp(n.args[0])
		if err != nil {
			return nil, err
		}
		size, err := p.int(n.args[1], maxRegexpBytes)
		if err != nil {
			return nil, err
		}
		return Regexp(re, size), nil
	case "Silent":
		if err := p.count(n, 1, 1); err != nil {
			return nil, err
		}
		d, err := time.ParseDuration(n.args[0].text)
		if err != nil || n.args[0].call {
			return nil, p.fail(n.args[0].pos, "invalid duration")
		}
		return Silent(d), nil
	case "RemoteIP", "LocalIP":
		prefixes, err := each(n.args, p.prefix)
		if err != nil {
			return nil, err
		}
		if n.text == "RemoteIP" {
			return RemoteIP(prefixes...), nil
		}
		return LocalIP(prefixes...), nil
	case "LocalPort":
		ports, err := each(n.args, func(a *node) (uint16, error) {
			v, err := p.int(a, 65535)
			return uint16(v), err
		})
		if err != nil {
			return nil, err
		}
		return LocalPort(ports...), nil
	case "HTTP1", "HTTP2":
		fs, err := each(n.args, p.httpFilter)
		if err != nil {
			return nil, err
		}
		if n.text == "HTTP1" {
			return HTTP1(fs...), nil
		}
		return HTTP2(fs...), nil
	case "TLS":
		fs, err := each(n.args, p.tlsFilter)
		if err != nil {
			return nil, err
		}
		return TLS(fs...), nil
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
	if err != nil {
		return zero, p.fail(n.pos, "%s: %v", n.text, err)
	}
	return v, nil
}

func (p *parser) httpFilter(n *node) (HTTPFilter, error) {
	if !n.call && !n.str {
		f, ok := p.names.HTTPFilters[n.text]
		if !ok {
			return nil, p.fail(n.pos, "unknown HTTP filter %s", n.text)
		}
		return namedFilter[*httphead.Request]{name: n.text, f: f}, nil
	}
	if f, ok, err := filterSetOf(n, p.httpFilter); ok || err != nil {
		return f, err
	}
	if !n.call {
		return nil, p.fail(n.pos, "expected an HTTP filter, found a string")
	}
	switch n.text {
	case "Host", "Path", "PathPrefix", "Method":
		ss, err := each(n.args, p.str)
		if err != nil {
			return nil, err
		}
		return map[string]func(...string) HTTPFilter{"Host": Host, "Path": Path, "PathPrefix": PathPrefix, "Method": Method}[n.text](ss...), nil
	case "HostRegexp", "PathRegexp":
		if err := p.count(n, 1, 1); err != nil {
			return nil, err
		}
		re, err := p.regexp(n.args[0])
		if err != nil {
			return nil, err
		}
		if n.text == "HostRegexp" {
			return HostRegexp(re), nil
		}
		return PathRegexp(re), nil
	case "HeaderRegexp":
		if err := p.count(n, 2, 2); err != nil {
			return nil, err
		}
		name, err := p.str(n.args[0])
		if err != nil {
			return nil, err
		}
		re, err := p.regexp(n.args[1])
		if err != nil {
			return nil, err
		}
		return HeaderRegexp(name, re), nil
	case "Header", "Query":
		if err := p.count(n, 1, -1); err != nil {
			return nil, err
		}
		ss, err := each(n.args, p.str)
		if err != nil {
			return nil, err
		}
		if n.text == "Header" {
			return Header(ss[0], ss[1:]...), nil
		}
		return Query(ss[0], ss[1:]...), nil
	case "WebSocket":
		if err := p.count(n, 0, 0); err != nil {
			return nil, err
		}
		return WebSocket(), nil
	}
	return custom(p, n, p.names.HTTPFilterFuncs, "HTTP filter")
}

func (p *parser) tlsFilter(n *node) (TLSFilter, error) {
	if !n.call && !n.str {
		f, ok := p.names.TLSFilters[n.text]
		if !ok {
			return nil, p.fail(n.pos, "unknown TLS filter %s", n.text)
		}
		return namedFilter[*tlshello.Hello]{name: n.text, f: f}, nil
	}
	if f, ok, err := filterSetOf(n, p.tlsFilter); ok || err != nil {
		return f, err
	}
	if !n.call {
		return nil, p.fail(n.pos, "expected a TLS filter, found a string")
	}
	switch n.text {
	case "SNI", "ALPN":
		ss, err := each(n.args, p.str)
		if err != nil {
			return nil, err
		}
		if n.text == "SNI" {
			return SNI(ss...), nil
		}
		return ALPN(ss...), nil
	case "SNIRegexp":
		if err := p.count(n, 1, 1); err != nil {
			return nil, err
		}
		re, err := p.regexp(n.args[0])
		if err != nil {
			return nil, err
		}
		return SNIRegexp(re), nil
	case "MinTLSVersion":
		if err := p.count(n, 1, 1); err != nil {
			return nil, err
		}
		v, ok := parseVersion(n.args[0].text)
		if !ok || n.args[0].call {
			return nil, p.fail(n.args[0].pos, "invalid TLS version")
		}
		return MinTLSVersion(v), nil
	}
	return custom(p, n, p.names.TLSFilterFuncs, "TLS filter")
}

// filterSetOf parses AllOf, AnyOf and NoneOf; ok reports whether n is one.
func filterSetOf[T any](n *node, one func(*node) (Filter[T], error)) (f Filter[T], ok bool, err error) {
	if !n.call {
		return nil, false, nil
	}
	var kind setKind
	switch n.text {
	case "AllOf":
		kind = allOf
	case "AnyOf":
		kind = anyOf
	case "NoneOf":
		kind = noneOf
	default:
		return nil, false, nil
	}
	fs, err := each(n.args, one)
	if err != nil {
		return nil, false, err
	}
	return newFilterSet(kind, fs), true, nil
}

// parseVersion reads a TLS version as versionName writes it.
func parseVersion(s string) (uint16, bool) {
	if minor, ok := strings.CutPrefix(s, "1."); ok && len(minor) == 1 && minor[0] >= '0' && minor[0] <= '3' {
		return 0x0301 + uint16(minor[0]-'0'), true
	}
	if hexText, ok := strings.CutPrefix(s, "0x"); ok {
		v, err := strconv.ParseUint(hexText, 16, 16)
		return uint16(v), err == nil
	}
	return 0, false
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
		return p.fail(n.pos, "%s needs %d arguments", n.text, lo)
	case hi >= 0 && len(n.args) > hi:
		return p.fail(n.pos, "%s takes %d arguments", n.text, hi)
	}
	return nil
}

func (p *parser) str(n *node) (string, error) {
	if !n.str {
		return "", p.fail(n.pos, "expected a string")
	}
	return n.text, nil
}

func (p *parser) regexp(n *node) (*regexp.Regexp, error) {
	s, err := p.str(n)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, p.fail(n.pos, "%v", err)
	}
	return re, nil
}

func (p *parser) int(n *node, maxValue int) (int, error) {
	v, err := strconv.Atoi(n.text)
	if err != nil || n.str || n.call || v < 0 || v > maxValue {
		return 0, p.fail(n.pos, "expected a number up to %d", maxValue)
	}
	return v, nil
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
