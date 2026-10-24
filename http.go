package portmux

import (
	"regexp"
	"slices"
	"strings"

	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
)

// HTTP1 matches connections that start with an HTTP/1.x request and pass every
// filter. It waits for the complete request head, so the parsed request is
// always available from Conn.HTTPRequest. Requests with more than one Host
// header or with obsolete line folding are not matched, since servers
// disagree on what they mean.
//
// Any method token is accepted, including extension methods. Bytes that cannot
// start a request line, such as a TLS record, are rejected immediately.
func HTTP1(filters ...HTTPFilter) Matcher {
	if slices.Contains(filters, nil) {
		panic("portmux: nil filter")
	}
	return httpMatcher(slices.Clone(filters))
}

type httpMatcher []HTTPFilter

func (h httpMatcher) Match(in *Input) Result {
	req, res := in.HTTPRequest()
	return allFilters(h, req, res)
}

func (h httpMatcher) String() string { return call("HTTP1", h, describe[HTTPFilter]) }

// Host accepts requests whose host, without its port, matches one of the
// patterns. Patterns work as in SNI; the empty pattern accepts a request
// without a host.
func Host(patterns ...string) HTTPFilter {
	return hostFilter{patterns: slices.Clone(patterns), hosts: hostmatch.NewSet(patterns...)}
}

type hostFilter struct {
	patterns []string
	hosts    *hostmatch.Set
}

func (f hostFilter) Match(r *httphead.Request) bool { return f.hosts.MatchName(r.Name()) }
func (f hostFilter) String() string                 { return call("Host", f.patterns, quote) }

// Method accepts requests with one of the methods. Methods are case-sensitive.
func Method(methods ...string) HTTPFilter {
	return listFilter{name: "Method", values: slices.Clone(methods), field: func(r *httphead.Request) string { return r.Method }}
}

// Path accepts requests whose decoded path equals one of the paths.
func Path(paths ...string) HTTPFilter {
	return listFilter{name: "Path", values: slices.Clone(paths), field: func(r *httphead.Request) string { return r.Path }}
}

// PathPrefix accepts requests whose path is one of the prefixes or lies below
// it: PathPrefix("/api") accepts "/api" and "/api/v1" but not "/apis", and
// PathPrefix("/api/") accepts only paths below "/api/".
func PathPrefix(prefixes ...string) HTTPFilter {
	return listFilter{name: "PathPrefix", values: slices.Clone(prefixes), prefix: true, field: func(r *httphead.Request) string { return r.Path }}
}

// listFilter compares a request field with a list of values.
type listFilter struct {
	name   string
	values []string
	prefix bool
	field  func(*httphead.Request) string
}

func (f listFilter) Match(r *httphead.Request) bool {
	v := f.field(r)
	for _, want := range f.values {
		if v == want || f.prefix && hasPathPrefix(v, want) {
			return true
		}
	}
	return false
}

// hasPathPrefix reports whether path is prefix or lies below it, at a
// segment boundary.
func hasPathPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	// ';' starts the parameters of the last segment, which Tomcat and Jetty
	// remove.
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/' || path[len(prefix)] == ';'
}

// Query accepts requests whose query string has the parameter with one of
// the values, or with any value when none are given. Values are compared
// after decoding and case-sensitively.
func Query(name string, values ...string) HTTPFilter {
	return queryFilter{name: name, values: slices.Clone(values)}
}

type queryFilter struct {
	name   string
	values []string
}

func (f queryFilter) Match(r *httphead.Request) bool {
	got, ok := r.Query()[f.name]
	if !ok {
		return false
	}
	if len(f.values) == 0 {
		return true
	}
	for _, v := range got {
		if slices.Contains(f.values, v) {
			return true
		}
	}
	return false
}

func (f queryFilter) String() string {
	return call("Query", append([]string{f.name}, f.values...), quote)
}

// HostRegexp accepts requests whose host, lowercased and without its port,
// matches re. Hosts with bytes that no DNS name or IP address has never match.
func HostRegexp(re *regexp.Regexp) HTTPFilter {
	return newRegexpFilter("HostRegexp", re, func(r *httphead.Request, re *regexp.Regexp) bool {
		n := r.Name()
		return n.Valid() && n.String() != "" && re.MatchString(n.String())
	})
}

// PathRegexp accepts requests whose path, decoded and resolved as Path is,
// matches re.
func PathRegexp(re *regexp.Regexp) HTTPFilter {
	return newRegexpFilter("PathRegexp", re, func(r *httphead.Request, re *regexp.Regexp) bool {
		return re.MatchString(r.Path)
	})
}

// HeaderRegexp accepts requests with a field of the given name whose value
// matches re. Every field of that name is tried.
func HeaderRegexp(name string, re *regexp.Regexp) HTTPFilter {
	if re == nil {
		panic("portmux: nil regexp")
	}
	return headerRegexpFilter{name: name, re: re}
}

type headerRegexpFilter struct {
	name string
	re   *regexp.Regexp
}

func (f headerRegexpFilter) Match(r *httphead.Request) bool {
	for v := range r.Values(f.name) {
		if f.re.MatchString(v) {
			return true
		}
	}
	return false
}

func (f headerRegexpFilter) String() string {
	return call("HeaderRegexp", []string{f.name, f.re.String()}, quote)
}

// regexpFilter matches a value of a request or hello with a regular
// expression. match is given the expression rather than the values one by
// one, so that matching allocates nothing.
type regexpFilter[T any] struct {
	name  string
	re    *regexp.Regexp
	match func(T, *regexp.Regexp) bool
}

func newRegexpFilter[T any](name string, re *regexp.Regexp, match func(T, *regexp.Regexp) bool) regexpFilter[T] {
	if re == nil {
		panic("portmux: nil regexp")
	}
	return regexpFilter[T]{name: name, re: re, match: match}
}

func (f regexpFilter[T]) Match(v T) bool { return f.match(v, f.re) }

func (f regexpFilter[T]) String() string { return call(f.name, []string{f.re.String()}, quote) }

func (f listFilter) String() string { return call(f.name, f.values, quote) }

// Header accepts requests with a field of the given name whose value, as a
// comma-separated list, contains one of the tokens, compared
// case-insensitively. Without tokens, any value is accepted.
func Header(name string, tokens ...string) HTTPFilter {
	return headerFilter{name: name, tokens: slices.Clone(tokens)}
}

type headerFilter struct {
	name   string
	tokens []string
}

func (f headerFilter) Match(r *httphead.Request) bool {
	for v := range r.Values(f.name) {
		if len(f.tokens) == 0 || hasToken(v, f.tokens) {
			return true
		}
	}
	return false
}

func (f headerFilter) String() string {
	return call("Header", append([]string{f.name}, f.tokens...), quote)
}

// WebSocket accepts WebSocket upgrade requests: the Connection header lists
// "upgrade" and the Upgrade header lists "websocket".
func WebSocket() HTTPFilter {
	return webSocketFilter{}
}

type webSocketFilter struct{}

var (
	connectionUpgrade = headerFilter{name: "Connection", tokens: []string{"upgrade"}}
	upgradeWebSocket  = headerFilter{name: "Upgrade", tokens: []string{"websocket"}}
)

func (webSocketFilter) Match(r *httphead.Request) bool {
	return connectionUpgrade.Match(r) && upgradeWebSocket.Match(r)
}

func (webSocketFilter) String() string { return "WebSocket()" }

func hasToken(list string, tokens []string) bool {
	for part := range strings.SplitSeq(list, ",") {
		part = strings.Trim(part, " \t")
		for _, t := range tokens {
			if strings.EqualFold(part, t) {
				return true
			}
		}
	}
	return false
}

// HTTP2 matches cleartext HTTP/2 connections with prior knowledge (h2c)
// whose first request passes every filter, as HTTP1 does for HTTP/1.x: the
// filters see the request's :method, :path and :authority as Method, Path
// and Host, and its header fields. It waits for the client connection
// preface, the SETTINGS frame that follows it and the header block of the
// first request, so the parsed request is available from Conn.HTTP2Request.
//
// Clients that wait for the server's SETTINGS frame before they send a
// request, as some gRPC implementations do, cannot be matched by their
// request; route them with HTTP2Preface, which matches the preface alone.
func HTTP2(filters ...HTTPFilter) Matcher {
	if slices.Contains(filters, nil) {
		panic("portmux: nil filter")
	}
	return http2Matcher(slices.Clone(filters))
}

type http2Matcher []HTTPFilter

func (h http2Matcher) Match(in *Input) Result {
	req, res := in.HTTP2Request()
	return allFilters(h, req, res)
}

func (h http2Matcher) String() string { return call("HTTP2", h, describe[HTTPFilter]) }
