package httproute

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/djylb/netx/forwarded"
	"github.com/djylb/netx/httprewrite"
)

// MaxRegexpLen bounds the length of Route.PathRegexp.
const MaxRegexpLen = 4096

// ErrInvalidConfig is wrapped by the errors of Build.
var ErrInvalidConfig = errors.New("httproute: invalid config")

// Config is what a Table is built from: the routes, the backends they
// proxy to and what all of them share.
type Config struct {
	// Routes in the order that breaks ties between equally specific routes.
	Routes []Route
	// Upstreams are the backends that Proxy actions name.
	Upstreams []Upstream
	// ErrorPages answer the errors of routes without a page of their own
	// for the status, and of requests that match no route.
	ErrorPages map[int]ErrorPage
	// AbortNoRoute answers requests that match no route by closing the
	// connection, or resetting the stream of HTTP/2, without a response,
	// instead of 404 Not Found.
	AbortNoRoute bool
	// Resolver, if set, finds the client of a request behind trusted
	// proxies, for the client variables, DialInfo.Client and the scheme
	// that RedirectHTTPS checks. Without it the client is the TCP peer.
	Resolver *forwarded.Resolver
}

// Route matches requests and acts on them. It has exactly one of Proxy,
// Redirect and Respond.
type Route struct {
	// Name identifies the route in events and the ${route} variable.
	// Names that are not empty must be unique.
	Name string
	// Hosts are host name patterns as hostmatch takes them, such as
	// "example.com", "*.example.com", "api-*.example.com" and "*", which
	// hostmatch.CheckPattern must accept; "" matches requests without a
	// host. "*", like no Hosts at all, matches every request, also those
	// without a host. Names and patterns compare in lower case and without
	// a trailing dot, and non-ASCII names are refused: convert IDNs to
	// A-labels first.
	Hosts []string
	// Path is the path prefix, decoded and clean, matched by whole
	// segments, ';' also ending one: "/api" matches "/api", "/api/v1" and
	// "/api;v=1" but not "/apix". Empty means "/". A Path that ends with
	// "/" matches only paths below it. A Path that ends with '*' is a
	// prefix of bytes: "/api*" also matches "/apix".
	Path string
	// Exact makes Path match only the path itself, as nginx's
	// "location =" does.
	Exact bool
	// CaseInsensitivePath compares Path, or PathRegexp, without regard to
	// the case of ASCII letters, for backends that do so, such as on
	// Windows file systems, where "/ADMIN" reaches "/admin".
	CaseInsensitivePath bool
	// PathRegexp, if set, matches the decoded, clean path with a Go
	// regular expression (RE2, linear in the path) instead of Path, which
	// must then be empty. Like nginx's "~" it is not anchored: "/admin"
	// matches "/public/admin-ui"; anchor it with ^ and $ to match whole
	// paths. Its groups are the variables ${match_1} to ${match_9}. It is
	// at most MaxRegexpLen bytes long. The path "*" of "OPTIONS *"
	// matches no regexp.
	PathRegexp string
	// Methods, if any, are the methods the route takes, case-sensitively.
	Methods []string
	// Headers, if any, must all match.
	Headers []HeaderMatch
	// TLS, if set, takes only requests that came over TLS (true) or not
	// (false): over a TLS connection, or from a trusted proxy that
	// Config.Resolver finds and that recorded "https". Neither the
	// scheme of an absolute request target nor fields from untrusted
	// clients count.
	TLS *bool
	// RedirectHTTPS, if set, redirects requests that did not come over
	// TLS to https before the action runs.
	RedirectHTTPS *HTTPSRedirect
	// BasicAuth, if set, requires HTTP Basic authentication after
	// RedirectHTTPS and before the action.
	BasicAuth *BasicAuth

	Proxy    *Proxy
	Redirect *Redirect
	Respond  *Respond

	// RequestHeaders change the request a Proxy sends; a rule on Host
	// rewrites the host. Compile them with Vars.
	RequestHeaders []httprewrite.Rule
	// ResponseHeaders change the responses of the route's action, after
	// a Proxy's Redirects; error responses are not changed.
	ResponseHeaders []httprewrite.Rule
	// ErrorPages answer the route's errors, before those of the Config.
	ErrorPages map[int]ErrorPage
	// MaxRequestBody, if positive, limits request bodies; larger ones
	// are answered with 413 Content Too Large. It does not limit the
	// streams of upgraded connections and of WebSockets over HTTP/2.
	MaxRequestBody int64
	// Upgrades are the protocols that the Upgrade field of a request may
	// name, compared without regard to case; nil means "websocket". A
	// request that names another has its Upgrade field removed and goes
	// on as an ordinary request, and HTTP2-Settings is always removed, so
	// that no upgrade to h2c carries requests past the routes. Extended
	// CONNECT requests of HTTP/2 (RFC 8441) are routed by their path and
	// proxied to the backend as WebSocket upgrades over HTTP/1.1.
	Upgrades []string
	// UpgradeIdleTimeout, if positive, closes an upgraded connection,
	// such as a WebSocket, through which no bytes passed either way for
	// that long. Zero means none.
	UpgradeIdleTimeout time.Duration
	// Wrap, if set, wraps the action once, when the table is built, for
	// authentication, limits or metrics of the caller's. RouteName and
	// Client read the route and client of a request in it. The handler
	// must return when the request's context is done.
	Wrap func(http.Handler) http.Handler
}

// HeaderMatch matches a request header field: present with any value when
// Values is empty, else with one of the values exactly.
type HeaderMatch struct {
	Name   string
	Values []string
}

// HTTPSRedirect redirects requests that did not come over TLS to the same
// URL with the https scheme.
type HTTPSRedirect struct {
	// Port is the port of the https URL; 0 and 443 leave it out.
	Port int
	// Status is 301, 302, 303, 307 or 308; 0 means 308 Permanent
	// Redirect.
	Status int
}

// Proxy passes requests on to an upstream, as a reverse proxy.
type Proxy struct {
	// Upstream names one of Config.Upstreams.
	Upstream string
	// PathTemplate, if set, is the path to send instead of the
	// client's, such as "/users/${match_1}" for a PathRegexp route; the
	// query goes on as it was. It is expanded decoded and escaped as a
	// path. It excludes ReplacePath.
	PathTemplate *httprewrite.Template
	// ReplacePath, if not empty, replaces the route's Path at the start of
	// the request path: with Path "/api", ReplacePath "/v2" sends
	// "/api/users" as "/v2/users", and ReplacePath "/" sends it as
	// "/users". Escapes in the rest of the path are kept. Empty sends the
	// path as the client sent it.
	ReplacePath string
	// Redirects rewrite the Location and Refresh fields of responses,
	// from the backend's address to the public one.
	Redirects []httprewrite.Redirect
	// SendRawPath sends the path as the client sent it, such as with "//"
	// or "/../" in it, instead of the decoded, clean path the route was
	// chosen by, for applications that need the path as it was, such as
	// one that holds a URL. Backends may then read another path than the
	// route did.
	SendRawPath bool
	// InterceptErrors replaces the body of a backend response with status
	// 400 or above by the error page for its status, when there is one.
	InterceptErrors bool
}

// Redirect answers with a redirect to the expansion of To.
type Redirect struct {
	// To is the target, such as "https://example.com${request_uri}".
	// Compile it with Vars.
	To *httprewrite.Template
	// Status is 301, 302, 303, 307 or 308; 0 means 302 Found.
	Status int
}

// Respond answers with a fixed response.
type Respond struct {
	// Status is 200 to 599; 0 means 200 OK.
	Status int
	// Header holds fields to send; Content-Length is set from Body.
	Header http.Header
	// Body is the content, not sent for HEAD requests and statuses that
	// have none.
	Body []byte
}

// ErrorPage is the response for an error status.
type ErrorPage struct {
	// ContentType is the media type; empty means
	// "text/html; charset=utf-8".
	ContentType string
	// Body is the content, in which ${name} is replaced by the value of a
	// variable, those of httprewrite and of Vars, such as ${status} and
	// ${request_id}, and $$ by $. Values are HTML-escaped when the
	// ContentType is HTML. Unknown variables fail Build.
	Body []byte
}

// Upstream is a backend that Proxy actions pass requests to. Each upstream
// keeps its own pool of idle connections, which a Router keeps across
// Updates while the upstream's settings other than Dial stay the same.
type Upstream struct {
	// Name identifies the upstream; it must be unique and not empty.
	Name string
	// Addr is the backend's address as "host:port", passed to Dial in
	// DialInfo.Addr. It may be empty when Dial needs none.
	Addr string
	// Dial connects to the backend. It is called with the context of the
	// request that needs a new connection, bounded by DialTimeout and
	// canceled when the Router closes. Nil dials Addr over TCP.
	Dial DialFunc
	// TLS, if set, runs TLS over what Dial returns. Its NextProtos is
	// replaced as HTTP2 asks.
	TLS *tls.Config
	// ServerName is the name that TLS sends and verifies. Empty means
	// TLS.ServerName, else the host of Addr when it is a name, else the
	// Host of the outgoing request, in which case connections are pooled
	// by that host.
	ServerName string
	// ProxyProtocol, if 1 or 2, sends a PROXY protocol header of that
	// version first on each connection, from the client as
	// Config.Resolver finds it to the address the request came in on.
	// Connections then carry one request each, as DisableKeepAlives
	// does; it cannot be used with HTTP2.
	ProxyProtocol int
	// DialTimeout bounds Dial and the TLS handshake; 0 means 10 seconds.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds the wait for a response's header after
	// the request is written; 0 means none. It ends in 504.
	ResponseHeaderTimeout time.Duration
	// IdleConnTimeout closes idle connections; 0 means 90 seconds.
	IdleConnTimeout time.Duration
	// MaxIdleConns limits idle connections; 0 means 64.
	MaxIdleConns int
	// MaxResponseHeaderBytes limits response heads; 0 means 64 KiB.
	MaxResponseHeaderBytes int64
	// DisableKeepAlives uses each connection for one request only, so
	// that Dial sees every request, such as to choose a backend per
	// client.
	DisableKeepAlives bool
	// HTTP2 speaks HTTP/2 to the backend: over TLS when the backend
	// offers it by ALPN, else HTTP/1.1; without TLS, h2c with prior
	// knowledge. Upgrades such as WebSockets always use HTTP/1.1.
	HTTP2 bool
}

// DialFunc connects to a backend for a request. A connection is reused by
// later requests of the same upstream unless keep-alives are disabled, so
// DialInfo describes the request that needed it. Return a *StatusError to
// answer with a status of your choice, such as 503 when a backend is
// offline.
type DialFunc func(ctx context.Context, d DialInfo) (net.Conn, error)

// DialInfo describes the request that needs a new backend connection.
type DialInfo struct {
	Upstream string
	// Addr is Upstream.Addr.
	Addr  string
	Route string
	// Host is the host the client asked for, without its port.
	Host string
	// Client is the client, as Config.Resolver finds it, else the TCP
	// peer; it is invalid when the peer's address is not an IP address.
	Client netip.AddrPort
	// TLS reports whether the request came over TLS.
	TLS bool
}

// StatusError is an error that a DialFunc returns to answer the request
// with Status.
type StatusError struct {
	Status int
	Err    error
}

func (e *StatusError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("httproute: status %d", e.Status)
	}
	return fmt.Sprintf("httproute: status %d: %v", e.Status, e.Err)
}

func (e *StatusError) Unwrap() error { return e.Err }

// BasicAuth requires HTTP Basic authentication (RFC 7617). Requests
// without valid credentials get 401 Unauthorized with a challenge for
// Realm. The Authorization field goes on to a backend; a request rule
// "Authorization: ${unset}" removes it.
type BasicAuth struct {
	// Realm names the protected space; empty means "restricted".
	Realm string
	// Users maps user names to hashes from HashPassword. Every check
	// costs as many rounds as the hash with the most, also for unknown
	// users, so that response times do not tell which users exist.
	Users map[string]string
	// Verify, if set, checks credentials instead of Users, such as
	// against a store of the caller's. It must not block for long.
	Verify func(r *http.Request, user, password string) bool
	// CacheSize bounds the credentials of Users remembered as verified,
	// the least recently used dropped first; 0 means 1024, and a negative
	// value turns remembering off.
	CacheSize int
	// CacheTTL is how long verified credentials are remembered; 0 means
	// five minutes.
	CacheTTL time.Duration
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidConfig}, args...)...)
}

func validRedirectStatus(s int) bool {
	switch s {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// isToken reports whether s is an HTTP token, as method and field names are.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 || c <= ' ' || strings.IndexByte("\"(),/:;<=>?@[\\]{}\x7f", c) >= 0 {
			return false
		}
	}
	return true
}

// isCleanPath reports whether p is a clean absolute path, as request paths
// are resolved, keeping a trailing slash.
func isCleanPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c == p
}
