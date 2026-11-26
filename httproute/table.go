package httproute

import (
	"cmp"
	"context"
	"errors"
	"fmt"
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
	"github.com/djylb/portmux"
	"github.com/djylb/portmux/hostmatch"
	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/internal/pmap"
)

// Table is a built set of routes. It is immutable and safe for concurrent
// use, also by several Routers. Build makes one from a Config and With
// changes one, sharing all that the change leaves alone.
type Table struct {
	hosts     *hostmatch.Snapshot[[]*route] // sorted as match takes them
	common    *common
	named     pmap.Map[*route]
	upstreams pmap.Map[upstreamEntry]
	routes    int
	levels    int // routes with an exact path or a regexp
	next      int // order of the next route added
}

// common is what all routes of a Table and those it is changed into share.
type common struct {
	errorPages map[int]*page
	resolver   *forwarded.Resolver
	abort      bool // AbortNoRoute
}

// route is a Route as a Table holds it.
type route struct {
	name     string
	path     string
	upstream string   // name of the Proxy's upstream, or ""
	hosts    []string // canonical patterns, each once
	upgrades []string
	tls      *bool          // the TLS filter
	re       *regexp.Regexp // PathRegexp
	methods  []string
	headers  []HeaderMatch // canonical names
	https    *HTTPSRedirect
	proxy    *Proxy
	redirect *Redirect
	respond  *Respond
	pages    map[int]*page
	response []httprewrite.Rule
	rewriter *httprewrite.Rewriter
	handler  http.Handler // the action, wrapped
	order    int          // in the Config, or as With added it; breaks ties
	maxBody  int64
	idle     time.Duration // of upgraded connections
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

// upstreamEntry is an upstream of a Table and the number of its routes
// that proxy to it.
type upstreamEntry struct {
	up   *upstream
	refs int
}

// transportKey holds the settings of an upstream that its transport is
// built with; a Router reuses a transport for an equal key.
type transportKey struct {
	name                  string
	dialTimeout           time.Duration
	responseHeaderTimeout time.Duration
	idleConnTimeout       time.Duration
	maxIdleConns          int
	maxKeys               int
	maxResponseHeader     int64
	disableKeepAlives     bool
	http2                 bool
	tlsPolicy             *upstream
}

// defaultUpgrades are the upgrades of a Route without Upgrades; it is
// never changed.
var defaultUpgrades = []string{"websocket"}

// Changes are what With changes in a Table. They apply in this order:
// RemoveRoutes, RemoveUpstreams, Upstreams, Routes.
type Changes struct {
	// Routes are added, or replace the route of the same Name, which keeps
	// its place in the order that breaks ties; added ones come after all
	// others. Each must have a Name.
	Routes []Route
	// RemoveRoutes names routes to remove; each must exist.
	RemoveRoutes []string
	// Upstreams are added, or replace the upstream of the same Name.
	Upstreams []Upstream
	// RemoveUpstreams names upstreams to remove; each must exist and no
	// route may proxy to it after the change.
	RemoveUpstreams []string
}

// Build checks and compiles a Config. Errors wrap ErrInvalidConfig. The
// Table keeps the Config's slices, maps and templates, which must not change
// afterwards.
func Build(c Config) (*Table, error) {
	cm := &common{resolver: c.Resolver, abort: c.AbortNoRoute}
	var err error
	if cm.errorPages, err = compilePages(c.ErrorPages); err != nil {
		return nil, err
	}
	return (&Table{common: cm}).apply(Changes{Routes: c.Routes, Upstreams: c.Upstreams}, true)
}

// With returns t with the changes applied; t stays as it is. Only the host
// patterns of the routes it adds, replaces or removes are compiled again,
// and the result shares everything else with t, so that its cost follows
// the size of the change and of the hosts it touches, not of the Table. A
// Router that is updated with the result keeps the transports of the
// upstreams it leaves alone. Errors wrap ErrInvalidConfig; the result is
// the Table that Build makes of t's Config changed in the same way.
func (t *Table) With(c Changes) (*Table, error) {
	return t.apply(c, false)
}

func (t *Table) apply(c Changes, build bool) (*Table, error) {
	cm := t.common
	if cm == nil {
		cm = &common{}
	}
	nt := &Table{common: cm, routes: t.routes, levels: t.levels, next: t.next}
	ups := t.upstreams.Builder()
	named := t.named.Builder()
	hosts := t.hosts.Builder()
	if build {
		named.Grow(len(c.Routes))
		hosts.Grow(len(c.Routes)) // most routes name a host of their own
		ups.Grow(len(c.Upstreams))
	}
	// Routes that proxy to upstreams that the changes remove, by name.
	var gone map[string]int
	ref := func(name string, d int) {
		if _, ok := gone[name]; ok {
			gone[name] += d
			return
		}
		ups.Update(name, func(e upstreamEntry, _ bool) upstreamEntry {
			e.refs += d
			return e
		})
	}
	// Routes that leave, and the host patterns whose lists With copied:
	// both stay empty in Build, whose lists are all new.
	var removed map[*route]bool
	var touched map[string]bool
	touch := func(h string) {
		if build || touched[h] {
			return
		}
		if touched == nil {
			touched = map[string]bool{}
		}
		touched[h] = true
		old, _ := hosts.Get(h)
		hosts.Set(h, slices.Clone(old))
	}
	drop := func(rt *route) {
		if removed == nil {
			removed = map[*route]bool{}
		}
		removed[rt] = true
		nt.routes--
		nt.levels -= b2i(rt.level() < 2)
		for _, h := range rt.hosts {
			touch(h)
		}
		if rt.upstream != "" {
			ref(rt.upstream, -1)
		}
	}
	for _, name := range c.RemoveRoutes {
		rt, ok := named.Get(name)
		if !ok {
			return nil, invalid("removing unknown route %q", name)
		}
		named.Delete(name)
		drop(rt)
	}
	for _, name := range c.RemoveUpstreams {
		e, ok := ups.Get(name)
		if !ok {
			return nil, invalid("removing unknown upstream %q", name)
		}
		if gone == nil {
			gone = map[string]int{}
		}
		gone[name] = e.refs
		ups.Delete(name)
	}
	// Names that the changes set, to refuse them twice; Build, which starts
	// empty, finds them in what it built so far.
	var seen map[string]bool
	if !build {
		seen = map[string]bool{}
	}
	for _, u := range c.Upstreams {
		cu, err := compileUpstream(u)
		if err != nil {
			return nil, err
		}
		e, had := ups.Get(u.Name)
		if build && had || seen[u.Name] {
			return nil, invalid("upstream %q appears twice", u.Name)
		}
		if n, ok := gone[u.Name]; ok {
			e.refs = n // added again
			delete(gone, u.Name)
		}
		if seen != nil {
			seen[u.Name] = true
		}
		ups.Set(u.Name, upstreamEntry{up: cu, refs: e.refs})
	}
	clear(seen)
	for i := range c.Routes {
		r := &c.Routes[i] // Routes are large: no copy
		if r.Name == "" && !build {
			return nil, invalid("route #%d of the changes has no name", i)
		}
		old, had := named.Get(r.Name)
		if r.Name != "" && (build && had || seen[r.Name]) {
			return nil, invalid("route %q appears twice", r.Name)
		}
		order := nt.next
		if had && r.Name != "" {
			order = old.order
			drop(old)
		} else {
			nt.next++
		}
		rt, err := cm.compile(r, ups)
		if err != nil {
			if r.Name != "" {
				return nil, invalidRoute(strconv.Quote(r.Name), err)
			}
			return nil, invalidRoute("#"+strconv.Itoa(i), err)
		}
		rt.order = order
		if r.Name != "" {
			if seen != nil {
				seen[r.Name] = true
			}
			named.Set(r.Name, rt)
		}
		nt.routes++
		nt.levels += b2i(rt.level() < 2)
		if rt.upstream != "" {
			ref(rt.upstream, 1)
		}
		for _, h := range rt.hosts {
			touch(h)
			hosts.Update(h, func(list []*route, _ bool) []*route { return append(list, rt) })
		}
	}
	for name, n := range gone {
		if n != 0 {
			return nil, invalid("removing upstream %q, to which %d routes proxy", name, n)
		}
	}
	sort := func(h string, list []*route) error {
		if removed != nil {
			list = slices.DeleteFunc(list, func(rt *route) bool { return removed[rt] })
		}
		if len(list) == 0 {
			hosts.Delete(h)
			return nil
		}
		if err := sortHost(h, list); err != nil {
			return err
		}
		if !build {
			hosts.Set(h, list)
		}
		return nil
	}
	if build {
		// The lists are new: sort them where they are.
		for h, list := range hosts.Snapshot().All() {
			if err := sort(h, list); err != nil {
				return nil, err
			}
		}
	} else {
		for h := range touched {
			list, _ := hosts.Get(h)
			if err := sort(h, list); err != nil {
				return nil, err
			}
		}
	}
	nt.hosts, nt.named, nt.upstreams = hosts.Snapshot(), named.Map(), ups.Map()
	return nt, nil
}

// sortHost sorts the routes of a host pattern as match takes them: exact
// paths first, then regexps, then prefixes from the longest, each in their
// order; and refuses routes that never match.
func sortHost(pattern string, list []*route) error {
	slices.SortFunc(list, func(a, b *route) int {
		if c := cmp.Compare(a.level(), b.level()); c != 0 {
			return c
		}
		if c := cmp.Compare(len(b.path), len(a.path)); c != 0 {
			return c
		}
		// Of equal prefixes, the one of whole segments first.
		if c := cmp.Compare(b2i(a.raw), b2i(b.raw)); c != 0 {
			return c
		}
		return cmp.Compare(a.order, b.order)
	})
	// Routes of one path key have one level, length and rawness, so they
	// are in one run of the sorted list.
	for i := 0; i < len(list); {
		j := i + 1
		for j < len(list) && list[j].level() == list[i].level() && len(list[j].path) == len(list[i].path) && list[j].raw == list[i].raw {
			j++
		}
		if err := checkOverlap(pattern, list[i:j]); err != nil {
			return err
		}
		i = j
	}
	return nil
}

// overlapIndexMin is the length of a run from which checkOverlap groups
// routes by path instead of comparing every pair.
const overlapIndexMin = 16

// checkOverlap refuses routes of one host pattern that never match because
// a route before them matches all they do: the same path at the same level,
// and conditions that the earlier route's include. run is in order.
func checkOverlap(pattern string, run []*route) error {
	if len(run) < overlapIndexMin {
		return checkPairs(pattern, run)
	}
	groups := map[string][]*route{}
	for _, rt := range run {
		k := rt.pathGroup()
		groups[k] = append(groups[k], rt)
	}
	for _, g := range groups {
		if err := checkPairs(pattern, g); err != nil {
			return err
		}
	}
	return nil
}

func checkPairs(pattern string, list []*route) error {
	for j, b := range list {
		for _, a := range list[:j] {
			if !a.coversPath(b) {
				continue
			}
			if !covers(a, b) {
				continue
			}
			if b.coversPath(a) && covers(b, a) {
				return invalid("routes %s and %s match the same requests for host %q", a.label(), b.label(), pattern)
			}
			return invalid("route %s never matches for host %q: route %s before it matches all it does", b.label(), pattern, a.label())
		}
	}
	return nil
}

func compileUpstream(u Upstream) (*upstream, error) {
	if err := checkUpstream(u); err != nil {
		return nil, err
	}
	u.DialTimeout = cmp.Or(u.DialTimeout, 10*time.Second)
	u.IdleConnTimeout = cmp.Or(u.IdleConnTimeout, 90*time.Second)
	u.MaxIdleConns = cmp.Or(u.MaxIdleConns, 64)
	u.MaxKeys = cmp.Or(u.MaxKeys, 1024)
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
	return cu, nil
}

func (u *upstream) key() transportKey {
	// TLS configs can contain callbacks and mutable trust stores. Only an unchanged
	// compiled upstream can carry its verified connections to the next table.
	var policy *upstream
	if u.TLS != nil {
		policy = u
	}
	return transportKey{
		name:                  u.Name,
		tlsPolicy:             policy,
		dialTimeout:           u.DialTimeout,
		responseHeaderTimeout: u.ResponseHeaderTimeout,
		idleConnTimeout:       u.IdleConnTimeout,
		maxIdleConns:          u.MaxIdleConns,
		maxKeys:               u.MaxKeys,
		maxResponseHeader:     u.MaxResponseHeaderBytes,
		disableKeepAlives:     u.DisableKeepAlives,
		http2:                 u.HTTP2,
	}
}

func invalidRoute(name string, err error) error {
	if errors.Is(err, ErrInvalidConfig) {
		return fmt.Errorf("route %s: %w", name, err)
	}
	return fmt.Errorf("%w: route %s: %w", ErrInvalidConfig, name, err)
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
	case u.MaxResponseHeaderBytes < 0:
		return invalid("upstream %q has a negative MaxResponseHeaderBytes %d", u.Name, u.MaxResponseHeaderBytes)
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

// Runs already share the path level, length and raw-prefix mode.
func (rt *route) pathGroup() string {
	if rt.re != nil {
		return rt.re.String()
	}
	return asciiLower(rt.path)
}

func (rt *route) coversPath(b *route) bool {
	if rt.re != nil {
		return rt.re.String() == b.re.String()
	}
	if rt.ci {
		return asciiFoldPrefix(rt.path, b.path)
	}
	return rt.path == b.path && (!b.ci || !strings.ContainsAny(b.path, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"))
}

func asciiLower(s string) string {
	for i := range len(s) {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 32
				}
			}
			return string(b)
		}
	}
	return s
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
	return "#" + strconv.Itoa(rt.order)
}

func (cm *common) compile(r *Route, upstreams *pmap.Builder[upstreamEntry]) (compiled *route, compileErr error) {
	defer func() {
		if v := recover(); v != nil {
			compiled = nil
			compileErr = portmux.NewPanicError(v)
		}
	}()
	rt := &route{name: r.Name, path: r.Path, exact: r.Exact, ci: r.CaseInsensitivePath,
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
			return nil, invalid("CaseInsensitivePath requires a literal Path; specify case matching in PathRegexp")
		}
		re, err := regexp.Compile(src)
		if err != nil {
			return nil, invalid("PathRegexp: %v", err)
		}
		rt.re = re
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
		if !isCleanPath(rt.path) && (!rt.raw || !isCleanPath(rt.path+"x")) {
			return nil, invalid("path %q is not a clean absolute path", r.Path)
		}
	}
	for _, h := range r.Hosts {
		if err := checkHost(h); err != nil {
			return nil, err
		}
		if c := hostmatch.Canonical(h); !slices.Contains(rt.hosts, c) {
			rt.hosts = append(rt.hosts, c)
		}
	}
	if len(r.Hosts) == 0 || slices.Contains(rt.hosts, "*") {
		// "*" also takes requests without a host, as no Hosts do.
		for _, h := range []string{"*", ""} {
			if !slices.Contains(rt.hosts, h) {
				rt.hosts = append(rt.hosts, h)
			}
		}
	}
	rt.upgrades = r.Upgrades
	if rt.upgrades == nil {
		rt.upgrades = defaultUpgrades
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
		if strings.EqualFold(h.Name, "Host") {
			return nil, invalid("use Hosts to match Host")
		}
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
	if r.MaxRequestBody < 0 {
		return nil, invalid("negative MaxRequestBody %d", r.MaxRequestBody)
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
		if _, ok := upstreams.Get(p.Upstream); !ok {
			return nil, invalid("unknown upstream %q", p.Upstream)
		}
		if p.ReplacePath != "" && !isCleanPath(p.ReplacePath) {
			return nil, invalid("replace path %q is not a clean absolute path", p.ReplacePath)
		}
		if p.ReplacePath != "" && (p.PathTemplate != nil || rt.re != nil) {
			return nil, invalid("ReplacePath with PathTemplate or PathRegexp")
		}
		rt.upstream, rt.proxy = p.Upstream, p
		rt.rewriter = &httprewrite.Rewriter{
			Request:   r.RequestHeaders,
			Response:  r.ResponseHeaders,
			Redirects: p.Redirects,
			Resolver:  cm.resolver,
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
	if t.levels == 0 {
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
	for i := range len(prefix) {
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
