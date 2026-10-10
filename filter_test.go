package portmux

import (
	"crypto/tls"
	"regexp"
	"testing"

	"github.com/djylb/portmux/httphead"
	"github.com/djylb/portmux/internal/testutil"
	"github.com/djylb/portmux/tlshello"
)

func parsedRequest(t *testing.T, host, path string) *httphead.Request {
	t.Helper()
	req, res := parseHTTP([]byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
	if res != Match {
		t.Fatalf("parse %s%s: %v", host, path, res)
	}
	return req
}

func TestHTTPFilterCombinations(t *testing.T) {
	tests := []struct {
		name   string
		filter HTTPFilter
		host   string
		path   string
		want   bool
	}{
		// OR within one filter and with AnyOf.
		{"either host", Host("a.example", "b.example"), "b.example", "/", true},
		{"any of hosts", AnyOf(Host("a.example"), Host("b.example")), "c.example", "/", false},
		// NOT: a wildcard except one name.
		{"subdomain", AllOf(Host("*.example.com"), NoneOf(Host("admin.example.com"))), "www.example.com", "/", true},
		{"excluded subdomain", AllOf(Host("*.example.com"), NoneOf(Host("admin.example.com"))), "ADMIN.example.com:8080", "/", false},
		{"none of several", NoneOf(Host("a.example"), PathPrefix("/internal/")), "b.example", "/internal/x", false},
		// (host a AND /api/) OR host b.
		{"first group", AnyOf(AllOf(Host("a.example"), PathPrefix("/api/")), Host("b.example")), "a.example", "/api/v1", true},
		{"first group other path", AnyOf(AllOf(Host("a.example"), PathPrefix("/api/")), Host("b.example")), "a.example", "/web", false},
		{"second group", AnyOf(AllOf(Host("a.example"), PathPrefix("/api/")), Host("b.example")), "b.example", "/web", true},
		// Empty sets.
		{"empty AllOf", AllOf[*httphead.Request](), "x", "/", true},
		{"empty AnyOf", AnyOf[*httphead.Request](), "x", "/", false},
		{"empty NoneOf", NoneOf[*httphead.Request](), "x", "/", true},
		{"func", HTTPFilterFunc(func(r *httphead.Request) bool { return r.Path == "/f" }), "x", "/f", true},
	}
	for _, tt := range tests {
		if got := tt.filter.Match(parsedRequest(t, tt.host, tt.path)); got != tt.want {
			t.Errorf("%s: %s on %s%s = %v, want %v", tt.name, describe(tt.filter), tt.host, tt.path, got, tt.want)
		}
	}
}

func TestTLSFilterCombinations(t *testing.T) {
	hello := func(sni string, alpn ...string) *tlshello.Hello {
		return &tlshello.Hello{ServerName: sni, ALPN: alpn}
	}
	public := AllOf(SNI("*.example.com"), NoneOf(SNI("admin.example.com", "*.internal.example.com")))
	tests := []struct {
		filter TLSFilter
		hello  *tlshello.Hello
		want   bool
	}{
		{public, hello("www.example.com"), true},
		{public, hello("admin.example.com"), false},
		{public, hello("db.internal.example.com"), false},
		{AnyOf(ALPN("h2"), SNI("legacy.example.com")), hello("legacy.example.com", "http/1.1"), true},
		{AnyOf(ALPN("h2"), SNI("legacy.example.com")), hello("www.example.com", "http/1.1"), false},
		{NoneOf(ALPN("acme-tls/1")), hello("www.example.com", "acme-tls/1"), false},
	}
	for _, tt := range tests {
		if got := tt.filter.Match(tt.hello); got != tt.want {
			t.Errorf("%s on %+v = %v, want %v", describe(tt.filter), tt.hello, got, tt.want)
		}
	}
}

func TestFilterDescriptions(t *testing.T) {
	tests := map[string]Matcher{
		`HTTP1(Host("*.example.com"), NoneOf(Host("admin.example.com"), PathPrefix("/internal/")))`: HTTP1(Host("*.example.com"), NoneOf(Host("admin.example.com"), PathPrefix("/internal/"))),
		`HTTP1(AnyOf(AllOf(Host("a.example"), Method("POST")), Header("X-Kind", "b")))`:             HTTP1(AnyOf(AllOf(Host("a.example"), Method("POST")), Header("X-Kind", "b"))),
		`TLS(AllOf(SNI("*.example.com"), NoneOf(ALPN("acme-tls/1"))))`:                              TLS(AllOf(SNI("*.example.com"), NoneOf(ALPN("acme-tls/1")))),
		`TLS(TLSFilterFunc)`: TLS(TLSFilterFunc(func(*tlshello.Hello) bool { return true })),
	}
	for want, m := range tests {
		if got := describe(m); got != want {
			t.Errorf("describe = %s\n          want %s", got, want)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("AnyOf(nil) did not panic")
		}
	}()
	AnyOf[*httphead.Request](nil)
}

// TestPathIsResolved checks that path rules see the path a server resolves,
// so that dot segments and repeated slashes cannot slip past them.
func TestPathIsResolved(t *testing.T) {
	tests := map[string]string{
		"/a/./b":             "/a/b",
		"/public/../admin/x": "/admin/x",
		"//admin//x":         "/admin/x",
		"/a%2Fb/c":           "/a/b/c",
		"/x;jsessionid=1":    "/x;jsessionid=1",
		"/../../etc":         "/etc",
		"/x/":                "/x/",
		"/":                  "/",
		"/a%20b?q=1":         "/a b",
	}
	for target, want := range tests {
		if got := parsedRequest(t, "h", target).Path; got != want {
			t.Errorf("%s: Path = %q, want %q", target, got, want)
		}
	}
	if req, res := parseHTTP([]byte("GET http://h.example HTTP/1.1\r\n\r\n")); res != Match || req.Path != "/" {
		t.Errorf("absolute form without a path: %+v, %v", req, res)
	}

	m := New()
	defer func() { _ = m.Close() }()
	if _, err := m.Add(RouteConfig{Name: "block", Priority: 10, Reject: true, Matchers: []Matcher{HTTP1(PathPrefix("/admin"))}}); err != nil {
		t.Fatal(err)
	}
	routes := map[string]*Route{"web": m.Match(HTTP1())}
	got := collect(routes)
	for _, target := range []string{"/public/../admin/", "//admin", "/./admin/x", "/%61dmin/x"} {
		data := "GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n"
		if name := routeOf(t, m, got, "192.0.2.1:1", data); name != ErrRefused.Error() {
			t.Errorf("%s slipped past the block: %s", target, name)
		}
	}
	if name := routeOf(t, m, got, "192.0.2.1:1", "GET /administrator HTTP/1.1\r\nHost: h\r\n\r\n"); name != "web" {
		t.Errorf("/administrator: %s", name)
	}
}

func TestPathPrefixSegments(t *testing.T) {
	tests := []struct {
		prefix, path string
		want         bool
	}{
		{"/api", "/api", true},
		{"/api", "/api/v1", true},
		{"/api", "/apis", false},
		{"/api/", "/api", false},
		{"/api/", "/api/v1", true},
		{"/", "/anything", true},
		{"", "/anything", true},
		{"/admin", "/admin;jsessionid=1", true}, // parameters, as Tomcat strips them
		{"/admin", "/admin;x/secret", true},
		{"/adm", "/admin;x", false},
	}
	for _, tt := range tests {
		if got := PathPrefix(tt.prefix).Match(parsedRequest(t, "h", tt.path)); got != tt.want {
			t.Errorf("PathPrefix(%q) on %q = %v", tt.prefix, tt.path, got)
		}
	}
}

func TestRegexpAndQueryFilters(t *testing.T) {
	req, res := parseHTTP([]byte("GET /v2/items/42?token=a%20b&debug HTTP/1.1\r\n" +
		"Host: API-12.Example.com:443\r\nUser-Agent: curl/8.4.0\r\n\r\n"))
	if res != Match {
		t.Fatal(res)
	}
	hello := &tlshello.Hello{ServerName: "Edge-3.example.com"}
	httpTests := []struct {
		filter HTTPFilter
		want   bool
	}{
		{HostRegexp(regexp.MustCompile(`^api-\d+\.example\.com$`)), true},
		{HostRegexp(regexp.MustCompile(`:443`)), false}, // the port is not part of the host
		{PathRegexp(regexp.MustCompile(`^/v\d+/items/\d+$`)), true},
		{HeaderRegexp("user-agent", regexp.MustCompile(`^curl/`)), true},
		{HeaderRegexp("X-Missing", regexp.MustCompile(``)), false},
		{Query("token", "a b"), true},
		{Query("token", "a%20b"), false},
		{Query("debug"), true},
		{Query("other"), false},
	}
	for _, tt := range httpTests {
		if got := tt.filter.Match(req); got != tt.want {
			t.Errorf("%s = %v, want %v", describe(tt.filter), got, tt.want)
		}
	}
	if !SNIRegexp(regexp.MustCompile(`^edge-\d+\.`)).Match(hello) || SNIRegexp(regexp.MustCompile(`.`)).Match(&tlshello.Hello{}) {
		t.Error("SNIRegexp")
	}
	if got := describe(HTTP1(HeaderRegexp("User-Agent", regexp.MustCompile(`^curl/`)), Query("debug"))); got != `HTTP1(HeaderRegexp("User-Agent", "^curl/"), Query("debug"))` {
		t.Errorf("description %s", got)
	}
	if got := req.Query().Get("token"); got != "a b" {
		t.Errorf("Query() = %q", got)
	}
	for name, fn := range map[string]func(){
		"HostRegexp": func() { HostRegexp(nil) },
		"SNIRegexp":  func() { SNIRegexp(nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s(nil) did not panic", name)
				}
			}()
			fn()
		}()
	}
}

func TestMinTLSVersion(t *testing.T) {
	modern := &tlshello.Hello{Version: tls.VersionTLS12, SupportedVersions: []uint16{0x7a7a, tls.VersionTLS13, tls.VersionTLS12}}
	legacy := &tlshello.Hello{Version: tls.VersionTLS11}
	if modern.MaxVersion() != tls.VersionTLS13 || legacy.MaxVersion() != tls.VersionTLS11 {
		t.Fatalf("MaxVersion %#x %#x", modern.MaxVersion(), legacy.MaxVersion())
	}
	f := MinTLSVersion(tls.VersionTLS12)
	if !f.Match(modern) || f.Match(legacy) || describe(f) != "MinTLSVersion(1.2)" {
		t.Fatalf("%s", describe(f))
	}
	raw := testutil.ClientHelloBytes(t, &tls.Config{ServerName: "x", MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	h, res := parseHello(raw)
	if res != Match {
		t.Fatalf("parse = %v", res)
	}
	if !MinTLSVersion(tls.VersionTLS13).Match(h) {
		t.Fatalf("crypto/tls hello offers %#x", h.MaxVersion())
	}
}
