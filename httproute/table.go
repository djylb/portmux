package httproute

import (
	"cmp"
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/djylb/netx/forwarded"
	"github.com/djylb/netx/httprewrite"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
)

// Table is a built set of routes. It is immutable and safe for concurrent
// use, also by several Routers.
type Table struct {
	routes     []*route
	hosts      *hostmatch.Map[[]*route] // filled by Build, never changed after
	upstreams  []*upstream
	errorPages map[int]*page
	resolver   *forwarded.Resolver
	levels     bool // some route has an exact path or a regexp
	abort      bool // AbortNoRoute
}

// route is a Route as a Table holds it.
type route struct {
	name     string
	index    int
	path     string
	upgrades []string
	tls      *bool          // the TLS filter
	re       *regexp.Regexp // PathRegexp
	methods  []string
	headers  []HeaderMatch // canonical names
	https    *HTTPSRedirect
	upstream int // index in Table.upstreams, or -1
	proxy    *Proxy
	redirect *Redirect
	respond  *Respond
	maxBody  int64
	idle     time.Duration // of upgraded connections
	pages    map[int]*page
	response []httprewrite.Rule
	rewriter *httprewrite.Rewriter
	handler  http.Handler // the action, wrapped
	table    *Table
	exact    bool
	ci       bool // CaseInsensitivePath
	raw      bool // Path ended with '*': a prefix of bytes, not segments
}

// upstream is an Upstream as a Table holds it, with defaults applied.
type upstream struct {
	Upstream
	// serverName is the TLS server name unless the outgoing Host's.
	serverName string
}

// transportKey holds the settings of an upstream that its transport is
// built with; a Router reuses a transport for an equal key.
type transportKey struct {
	name                  string
	dialTimeout           time.Duration
	responseHeaderTimeout time.Duration
	idleConnTimeout       time.Duration
	maxIdleConns          int
	maxResponseHeader     int64
	disableKeepAlives     bool
	http2                 bool
	tls                   bool
}

func (u *upstream) key() transportKey {
	return transportKey{
		name:                  u.Name,
		tls:                   u.TLS != nil,
		dialTimeout:           u.DialTimeout,
		responseHeaderTimeout: u.ResponseHeaderTimeout,
		idleConnTimeout:       u.IdleConnTimeout,
		maxIdleConns:          u.MaxIdleConns,
		maxResponseHeader:     u.MaxResponseHeaderBytes,
		disableKeepAlives:     u.DisableKeepAlives,
		http2:                 u.HTTP2,
	}
}

// Build checks and compiles a Config. Errors wrap ErrInvalidConfig. The
// Table keeps the Config's slices, maps and templates, which must not change
// afterwards.
func Build(c Config) (*Table, error) {
	t := &Table{hosts: &hostmatch.Map[[]*route]{}, resolver: c.Resolver, abort: c.AbortNoRoute}
	var err error
	if t.errorPages, err = compilePages(c.ErrorPages); err != nil {
		return nil, err
	}
	upstreams := make(map[string]int, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if err := checkUpstream(u); err != nil {
			return nil, err
		}
		if _, dup := upstreams[u.Name]; dup {
			return nil, invalid("upstream %q appears twice", u.Name)
		}
		upstreams[u.Name] = len(t.upstreams)
		u.DialTimeout = cmp.Or(u.DialTimeout, 10*time.Second)
		u.IdleConnTimeout = cmp.Or(u.IdleConnTimeout, 90*time.Second)
		u.MaxIdleConns = cmp.Or(u.MaxIdleConns, 64)
		u.MaxResponseHeaderBytes = cmp.Or(u.MaxResponseHeaderBytes, 64<<10)
		if u.ProxyProtocol != 0 {
			u.DisableKeepAlives = true // a header names one client
		}
		if u.Dial == nil {
			addr := u.Addr
			u.Dial = func(ctx context.Context, _ DialInfo) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", addr)
			}
		}
		cu := &upstream{Upstream: u, serverName: u.ServerName}
		if u.TLS != nil && cu.serverName == "" {
			cu.serverName = u.TLS.ServerName
		}
		if h, _, err := net.SplitHostPort(u.Addr); err == nil && cu.serverName == "" && h != "" {
			if _, err := netip.ParseAddr(h); err != nil {
				cu.serverName = h // a name, not an address
			}
		}
		t.upstreams = append(t.upstreams, cu)
	}
	names := make(map[string]bool, len(c.Routes))
	for i, r := range c.Routes {
		rt, err := t.compile(i, r, upstreams)
		if err != nil {
			if r.Name != "" {
				return nil, invalidRoute(r.Name, err)
			}
			return nil, invalidRoute("#"+strconv.Itoa(i), err)
		}
		if r.Name != "" {
			if names[r.Name] {
				return nil, invalid("route %q appears twice", r.Name)
			}
			names[r.Name] = true
		}
		t.routes = append(t.routes, rt)
		hosts := r.Hosts
		if len(hosts) == 0 || slices.Contains(hosts, "*") {
			// "*" also takes requests without a host, as no Hosts do.
			hosts = append(slices.Clone(hosts), "*", "")
		}
		for _, h := range hosts {
			list, _ := t.hosts.Get(h) // the same pattern in another spelling is one
			if slices.Contains(list, rt) {
				continue
			}
			t.hosts.Set(h, append(list, rt))
		}
	}
	for pattern, list := range t.hosts.All() {
		if err := checkOverlap(pattern, list); err != nil {
			return nil, err
		}
	}
	// Exact paths first, then regexps, then prefixes from the longest,
	// each in the order of the Config.
	for _, list := range t.hosts.All() {
		slices.SortStableFunc(list, func(a, b *route) int {
			if c := cmp.Compare(a.level(), b.level()); c != 0 {
				return c
			}
			if c := cmp.Compare(len(b.path), len(a.path)); c != 0 {
				return c
			}
			// Of equal prefixes, the one of whole segments first.
			return cmp.Compare(b2i(a.raw), b2i(b.raw))
		})
	}
	return t, nil
}

func invalidRoute(name string, err error) error {
	return invalid("route %s: %s", name, strings.TrimPrefix(err.Error(), ErrInvalidConfig.Error()+": "))
}

func checkUpstream(u Upstream) error {
	switch {
	case u.Name == "":
		return invalid("upstream without a name")
	case u.Dial == nil && u.Addr == "":
		return invalid("upstream %q has neither Dial nor Addr", u.Name)
	case u.ProxyProtocol != 0 && u.ProxyProtocol != 1 && u.ProxyProtocol != 2:
		return invalid("upstream %q: PROXY protocol version %d", u.Name, u.ProxyProtocol)
	case u.ProxyProtocol != 0 && u.HTTP2:
		return invalid("upstream %q: PROXY protocol with HTTP2, whose connections carry many clients", u.Name)
	case u.DialTimeout < 0 || u.ResponseHeaderTimeout < 0 || u.IdleConnTimeout < 0:
		return invalid("upstream %q has a negative timeout", u.Name)
	case u.MaxIdleConns < 0 || u.MaxResponseHeaderBytes < 0:
		return invalid("upstream %q has a negative limit", u.Name)
	}
	if u.Addr != "" {
		if _, _, err := net.SplitHostPort(u.Addr); err != nil {
			return invalid("upstream %q: address %q is not host:port", u.Name, u.Addr)
		}
	}
	return nil
}

func checkHost(p string) error {
	if err := hostmatch.CheckPattern(p); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// checkOverlap refuses routes of one host pattern that never match because
// a route before them matches all they do: the same path at the same level,
// and conditions that the earlier route's include.
func checkOverlap(pattern string, list []*route) error {
	for j, b := range list {
		for _, a := range list[:j] {
			if a.level() != b.level() || a.pathKey() != b.pathKey() || a.ci != b.ci {
				continue
			}
			if !covers(a, b) {
				continue
			}
			if covers(b, a) {
				return invalid("routes %s and %s match the same requests for host %q", a.label(), b.label(), pattern)
			}
			return invalid("route %s never matches for host %q: route %s before it matches all it does", b.label(), pattern, a.label())
		}
	}
	return nil
}

// covers reports whether a matches every request that b matches, of the
// same host and path.
func covers(a, b *route) bool {
	if len(a.methods) > 0 && (len(b.methods) == 0 || !subset(b.methods, a.methods)) {
		return false
	}
	if a.tls != nil && (b.tls == nil || *a.tls != *b.tls) {
		return false
	}
	for _, ha := range a.headers {
		if !slices.ContainsFunc(b.headers, func(hb HeaderMatch) bool {
			return hb.Name == ha.Name && (len(ha.Values) == 0 || len(hb.Values) > 0 && subset(hb.Values, ha.Values))
		}) {
			return false
		}
	}
	return true
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

func (rt *route) pathKey() string {
	switch {
	case rt.re != nil:
		return rt.re.String()
	case rt.ci && rt.raw:
		return strings.ToLower(rt.path) + "*"
	case rt.ci:
		return strings.ToLower(rt.path)
	case rt.raw:
		return rt.path + "*"
	}
	return rt.path
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (rt *route) label() string {
	if rt.name != "" {
		return strconv.Quote(rt.name)
	}
	return "#" + strconv.Itoa(rt.index)
}

func (t *Table) compile(i int, r Route, upstreams map[string]int) (*route, error) {
	rt := &route{name: r.Name, index: i, path: r.Path, exact: r.Exact, ci: r.CaseInsensitivePath, upstream: -1, table: t,
		methods: r.Methods, https: r.RedirectHTTPS, maxBody: r.MaxRequestBody,
		idle: r.UpgradeIdleTimeout, response: r.ResponseHeaders}
	if r.PathRegexp != "" {
		if r.Path != "" || r.Exact {
			return nil, invalid("PathRegexp with Path or Exact")
		}
		if len(r.PathRegexp) > MaxRegexpLen {
			return nil, invalid("PathRegexp longer than %d bytes", MaxRegexpLen)
		}
		src := r.PathRegexp
		if r.CaseInsensitivePath {
			src = "(?i)" + src
		}
		re, err := regexp.Compile(src)
		if err != nil {
			return nil, invalid("PathRegexp: %v", err)
		}
		rt.re = re
		t.levels = true
	} else {
		if rt.path == "" {
			rt.path = "/"
		}
		if p, ok := strings.CutSuffix(rt.path, "*"); ok {
			if r.Exact {
				return nil, invalid("exact path %q ends with '*'", r.Path)
			}
			rt.path, rt.raw = p, true
		}
		if !isCleanPath(rt.path) && !(rt.raw && isCleanPath(rt.path+"x")) {
			return nil, invalid("path %q is not a clean absolute path", r.Path)
		}
		t.levels = t.levels || r.Exact
	}
	for _, h := range r.Hosts {
		if err := checkHost(h); err != nil {
			return nil, err
		}
	}
	rt.upgrades = r.Upgrades
	if rt.upgrades == nil {
		rt.upgrades = []string{"websocket"}
	}
	for _, u := range rt.upgrades {
		if !isToken(u) {
			return nil, invalid("upgrade %q is not a token", u)
		}
	}
	if r.TLS != nil {
		v := *r.TLS
		rt.tls = &v
	}
	for _, m := range r.Methods {
		if !isToken(m) {
			return nil, invalid("method %q is not a token", m)
		}
	}
	for _, h := range r.Headers {
		if !isToken(h.Name) {
			return nil, invalid("header field name %q is not a token", h.Name)
		}
		rt.headers = append(rt.headers, HeaderMatch{Name: textproto.CanonicalMIMEHeaderKey(h.Name), Values: h.Values})
	}
	if s := r.RedirectHTTPS; s != nil {
		if s.Port < 0 || s.Port > 65535 {
			return nil, invalid("https port %d", s.Port)
		}
		if s.Status != 0 && !validRedirectStatus(s.Status) {
			return nil, invalid("https redirect status %d", s.Status)
		}
	}
	if r.MaxRequestBody < 0 || r.UpgradeIdleTimeout < 0 {
		return nil, invalid("negative MaxRequestBody or UpgradeIdleTimeout")
	}
	var err error
	if rt.pages, err = compilePages(r.ErrorPages); err != nil {
		return nil, err
	}
	for _, rule := range slices.Concat(r.RequestHeaders, r.ResponseHeaders) {
		if !isToken(rule.Name) {
			return nil, invalid("header rule for %q, not a field name", rule.Name)
		}
	}
	actions := 0
	var action http.Handler
	if p := r.Proxy; p != nil {
		actions++
		idx, ok := upstreams[p.Upstream]
		if !ok {
			return nil, invalid("unknown upstream %q", p.Upstream)
		}
		if p.ReplacePath != "" && !isCleanPath(p.ReplacePath) {
			return nil, invalid("replace path %q is not a clean absolute path", p.ReplacePath)
		}
		if p.ReplacePath != "" && (p.PathTemplate != nil || rt.re != nil) {
			return nil, invalid("ReplacePath with PathTemplate or PathRegexp")
		}
		rt.upstream, rt.proxy = idx, p
		rt.rewriter = &httprewrite.Rewriter{
			Request:   r.RequestHeaders,
			Response:  r.ResponseHeaders,
			Redirects: p.Redirects,
			Resolver:  t.resolver,
			Data:      requestData,
		}
		action = proxyHandler{}
	} else if len(r.RequestHeaders) > 0 {
		return nil, invalid("request header rules without a Proxy")
	}
	if rd := r.Redirect; rd != nil {
		actions++
		if rd.To == nil {
			return nil, invalid("redirect without a target")
		}
		if rd.Status != 0 && !validRedirectStatus(rd.Status) {
			return nil, invalid("redirect status %d", rd.Status)
		}
		rt.redirect = rd
		action = redirectHandler{}
	}
	if rs := r.Respond; rs != nil {
		actions++
		if rs.Status != 0 && (rs.Status < 200 || rs.Status > 599) {
			return nil, invalid("response status %d, not 200 to 599", rs.Status)
		}
		rt.respond = rs
		action = respondHandler{}
	}
	if actions != 1 {
		return nil, invalid("%d actions, want one of Proxy, Redirect and Respond", actions)
	}
	if r.BasicAuth != nil {
		auth, err := compileAuth(r.BasicAuth)
		if err != nil {
			return nil, err
		}
		action = authHandler{auth: auth, next: action}
	}
	if r.Wrap != nil {
		action = r.Wrap(action)
		if action == nil {
			return nil, invalid("Wrap returned nil")
		}
	}
	rt.handler = action
	return rt, nil
}

// match returns the route for a request with the host name n and the clean
// path p, or nil. Of the routes whose host patterns match, an exact path
// comes first, then a regexp, then the longest prefix; at each level, the
// route of the most specific pattern, then the first in the Config. Groups
// of a regexp's match are stored in rs.
func (t *Table) match(n hostmatch.Name, p string, req *http.Request, rs *reqState) *route {
	var prefix *route
	if !t.levels {
		t.hosts.LookupNameFunc(n, func(_ string, list []*route) bool {
			if rt := firstPrefix(list, p, req, rs, prefix); rt != nil {
				prefix = rt
			}
			// A prefix that is the whole path cannot be beaten.
			return prefix != nil && len(prefix.path) == len(p)
		})
		return prefix
	}
	// Patterns with regexps, most specific first, to try once no exact
	// path matched.
	var exact *route
	var stack [4][]*route
	regexps := stack[:0]
	t.hosts.LookupNameFunc(n, func(_ string, list []*route) bool {
		i := 0
		for ; i < len(list) && list[i].exact; i++ {
			if list[i].matchesExact(p) && list[i].accepts(req, rs) {
				exact = list[i]
				return true
			}
		}
		if i < len(list) && list[i].re != nil && p != "*" {
			regexps = append(regexps, list[i:])
		}
		if rt := firstPrefix(list, p, req, rs, prefix); rt != nil {
			prefix = rt
		}
		return false
	})
	if exact != nil {
		return exact
	}
	for _, list := range regexps {
		for _, rt := range list {
			if rt.re == nil {
				break
			}
			if rt.accepts(req, rs) && rt.matchRegexp(p, rs) {
				return rt
			}
		}
	}
	return prefix
}

// firstPrefix returns the first prefix route of list, sorted as Build sorts
// it, that takes the request and is longer than best.
func firstPrefix(list []*route, p string, req *http.Request, rs *reqState, best *route) *route {
	for _, rt := range list {
		if rt.exact || rt.re != nil {
			continue
		}
		if best != nil && len(rt.path) <= len(best.path) {
			return nil // sorted by length: no longer route follows
		}
		if rt.hasPrefix(p) && rt.accepts(req, rs) {
			return rt
		}
	}
	return nil
}

func (rt *route) matchesExact(p string) bool {
	if rt.ci {
		return len(p) == len(rt.path) && asciiFoldPrefix(p, rt.path)
	}
	return p == rt.path
}

func (rt *route) hasPrefix(p string) bool {
	switch {
	case rt.raw && rt.ci:
		return asciiFoldPrefix(p, rt.path)
	case rt.raw:
		return strings.HasPrefix(p, rt.path)
	case !rt.ci:
		return httphead.HasPathPrefix(p, rt.path)
	}
	if !asciiFoldPrefix(p, rt.path) {
		return false
	}
	// The same bytes in the case of the path, as HasPathPrefix compares.
	return httphead.HasPathPrefix(p, p[:len(rt.path)])
}

// asciiFoldPrefix reports whether s starts with prefix, ASCII letters
// compared without regard to case.
func asciiFoldPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a, b := s[i], prefix[i]
		if a != b && (a|0x20 != b|0x20 || a|0x20 < 'a' || a|0x20 > 'z') {
			return false
		}
	}
	return true
}

func (rt *route) matchRegexp(p string, rs *reqState) bool {
	if rt.re.NumSubexp() == 0 {
		return rt.re.MatchString(p)
	}
	m := rt.re.FindStringSubmatchIndex(p)
	if m == nil {
		return false
	}
	if rs != nil {
		rs.groups = m
	}
	return true
}

// level orders the routes of a host pattern: exact paths, regexps,
// prefixes.
func (rt *route) level() int {
	switch {
	case rt.exact:
		return 0
	case rt.re != nil:
		return 1
	}
	return 2
}

func (rt *route) accepts(req *http.Request, rs *reqState) bool {
	if rt.tls != nil && *rt.tls != rs.secure() {
		return false
	}
	if len(rt.methods) > 0 && !slices.Contains(rt.methods, req.Method) {
		return false
	}
	for _, h := range rt.headers {
		values := req.Header[h.Name]
		if len(values) == 0 {
			return false
		}
		if len(h.Values) > 0 && !slices.ContainsFunc(values, func(v string) bool { return slices.Contains(h.Values, v) }) {
			return false
		}
	}
	return true
}
