# portmux

Serve multiple protocols on one port by sniffing the first bytes of each
connection — HTTP/1, h2c, TLS (SNI/ALPN/JA4), PROXY protocol, SSH, SOCKS,
databases and custom prefixes — and routing them to separate `net.Listener`s
or handlers.

Requires Go 1.25, and besides the standard library only
[netx](https://github.com/djylb/netx), whose `proxyproto` package parses and
builds PROXY protocol headers. The packages build on all major Go ports,
including Windows, the BSDs, js/wasm, wasip1 and Plan 9.

## Install

```bash
go get github.com/djylb/portmux
```

## Packages

| Package               | Contents                                                                      | Imports beyond the standard library                               |
|-----------------------|-------------------------------------------------------------------------------|-------------------------------------------------------------------|
| `portmux`             | Mux, routes, entries, matchers, filters, delivered connections, rules as text | `hostmatch`, `ipmatch`, `tlshello`, `httphead`, `netx/proxyproto` |
| `portmux/hostmatch`   | `Set` and `Map` of host name patterns, `Normalize`, `SplitHost`               | none                                                              |
| `portmux/ipmatch`     | `Set` of IP prefixes, for block lists and networks                            | none                                                              |
| `portmux/tlshello`    | `Parse` and `Scanner` for TLS ClientHellos                                    | `hostmatch`                                                       |
| `portmux/httphead`    | `Parse`, `ParseHTTP2` and scanners for HTTP/1.x and h2c request heads         | `hostmatch`                                                       |
| `portmux/fingerprint` | `JA4`, `JA3` and the `MatchJA4` and `MatchJA3` filters                        | `tlshello`, `crypto/sha256`, `crypto/md5`                         |

- A program carries only the packages it imports. The tool packages work
  without a Mux: `hostmatch`, `ipmatch`, `tlshello` and `httphead` add little
  more than the standard library's strings, sync and binary parsing.
- Only `fingerprint` imports hash functions, and nothing imports `net/http`
  or `crypto/tls`.

## Usage

```go
package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/djylb/portmux"
)

func main() {
	m := portmux.New()

	// Routes with equal priority are tried in the order they were added.
	agents := m.Match(portmux.Prefix("AGENT/1\n"))
	admin := m.Match(portmux.TLS(portmux.SNI("admin.example.com")))
	site := m.Match(portmux.TLS())
	web := m.Match(portmux.HTTP1())
	ssh := m.Match(portmux.SSH(), portmux.Silent(2*time.Second))

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	go forward(agents, "127.0.0.1:9000")
	go forward(ssh, "127.0.0.1:22")
	go http.Serve(tls.NewListener(admin, config), http.FileServer(http.Dir("admin")))
	go http.Serve(tls.NewListener(site, config), http.FileServer(http.Dir("www")))
	go http.Serve(web, http.RedirectHandler("https://example.com/", http.StatusMovedPermanently))

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(m.Serve(ln))
}

// forward proxies every connection of l to addr.
func forward(l net.Listener, addr string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			backend, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer backend.Close()
			go io.Copy(backend, c)
			io.Copy(c, backend)
		}()
	}
}
```

- Every route is a `*portmux.Route`, an ordinary `net.Listener`. Its `Accept`
  returns a `*portmux.Conn` that replays the sniffed bytes first, so servers see
  the stream from its first byte.
- Routes are tried by priority, highest first, and in the order they were added
  when priorities are equal. A route matches when any of its matchers returns
  `Match`.
- While a route still needs more bytes, the routes after it wait, so the order
  alone decides which route wins. A connection that no route accepts is closed.
- Routing happens once per connection: a keep-alive HTTP connection stays on the
  route chosen for its first request.

## Matchers

| Matcher                                       | Matches                                                           |
|-----------------------------------------------|-------------------------------------------------------------------|
| `Prefix(p...)`                                | Connections starting with one of the byte strings                 |
| `HTTP1(filters...)`                           | HTTP/1.x requests, once the request head is complete              |
| `HTTP2(filters...)`                           | Cleartext HTTP/2 (h2c), by the first request's header block       |
| `TLS(filters...)`                             | TLS ClientHellos, once the hello is complete, also across records |
| `Domain(patterns...)`                         | HTTP requests by Host and TLS ClientHellos by SNI, in one matcher |
| `HTTP2Preface()`                              | Cleartext HTTP/2 with prior knowledge (h2c)                       |
| `SSH()`                                       | SSH clients that send their identification first                  |
| `SOCKS4()`, `SOCKS5()`                        | SOCKS4/4a requests and SOCKS5 greetings                           |
| `PostgreSQL()`, `MQTT()`                      | PostgreSQL first messages and MQTT CONNECT packets                |
| `RDP()`, `OpenVPN()`                          | Remote Desktop connection requests and OpenVPN over TCP           |
| `XMPP()`, `DNS()`                             | XMPP stream headers and DNS queries over TCP                      |
| `Regexp(re, n)`                               | The first n bytes matching a regular expression                   |
| `Silent(d)`                                   | Clients that sent nothing for d after connecting                  |
| `RemoteIP(prefixes...)`                       | Client addresses                                                  |
| `LocalIP(prefixes...)`, `LocalPort(ports...)` | The address or listener the client connected to                   |
| `Any()`                                       | Any connection that sends at least one byte                       |
| `Always()`                                    | Every connection, before anything is read (see Entries)           |
| `And(m...)`, `Or(m...)`, `Not(m)`             | Combinations of other matchers, nested in any way                 |
| `MatcherFunc`, `Named(name, m)`               | Your own logic, and a description for it in `Snapshot`            |

- Filters narrow `HTTP1`, `HTTP2` and `TLS`; all filters given to one matcher must pass,
  and `AllOf`, `AnyOf` and `NoneOf` combine them (see Combining Conditions):

  | Protocol | Filters                                                                                                         |
    |----------|-----------------------------------------------------------------------------------------------------------------|
  | HTTP     | `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method`, `Header`, `HeaderRegexp`, `Query`, `WebSocket` |
  | TLS      | `SNI`, `SNIRegexp`, `ALPN`, `MinTLSVersion`, and `fingerprint.MatchJA4` and `MatchJA3`                          |
  | Your own | `HTTPFilterFunc`, `TLSFilterFunc`                                                                               |

- `Host`, `SNI` and `Domain` take exact names or patterns in which each `*`
  stands for one or more characters: `*.example.com` is any name below
  `example.com`, `api-*.example.com` any name starting with `api-` there, and
  `*` any name; `""` matches a request or ClientHello without a name. Names
  compare case-insensitively and without the port, and names with characters
  that no DNS name has, such as `@`, match nothing. Long lists of exact names
  are looked up in a map. The `Regexp` filters take compiled expressions and
  see the same lowercased name.
- Paths are decoded and resolved as servers resolve them: `.` and `..`
  segments and repeated slashes are removed, so `/public/../admin/` and
  `//admin/` are `/admin/` to `Path`, `PathPrefix` and `PathRegexp`, and a
  block on `/admin` cannot be walked around. `PathPrefix("/api")` matches
  `/api` and paths below it, not `/apis`.
- `Header` matches comma-separated tokens case-insensitively, and
  `HeaderRegexp` whole values. `Query` matches decoded query parameters.
  `MinTLSVersion` judges the highest version a client offers.
- `RemoteIP` and `LocalIP` accept IPv4 and IPv6 prefixes; long lists such as
  block lists are looked up by binary search.
- Every protocol is parsed once per connection, however many routes and
  filters look at it. Names are lowercased and checked once, so each route
  adds about ten nanoseconds; many names for one destination belong in one
  route, where they are looked up in a map.
- Matchers first run before any byte arrives, which lets the address matchers
  decide at once, and then again after every read.
- `HTTP1` accepts any method token, so a greeting that is a short run of
  letters keeps an `HTTP1` route waiting for a space. Give `Prefix` routes for
  such greetings a higher priority than `HTTP1`, or add them first.

### Custom matchers

```go
// acmeTLS matches TLS-ALPN-01 challenges of an ACME certificate authority.
var acmeTLS = portmux.MatcherFunc(func(in *portmux.Input) portmux.Result {
	hello, res := in.ClientHello()
	if res != portmux.Match {
		return res // NeedMore until the hello is complete, NoMatch for other protocols
	}
	if slices.Contains(hello.ALPN, "acme-tls/1") {
		return portmux.Match
	}
	return portmux.NoMatch
})
```

- An `Input` offers the bytes received so far, the client and local addresses,
  the PROXY header, and the parsed ClientHello and HTTP request head. Parses
  are incremental and shared by every matcher of the connection.
- Return `NeedMore` while the input is too short to decide, including when it
  is empty. Decisions are final: after `Match` or `NoMatch`, every longer input
  must get the same answer.
- Matchers run on many connections at once, must not block, and must not keep
  the `Input` or its bytes. A panicking matcher closes only the connection it
  was matching.

## Combining Conditions

```go
// domainRoutes restricts routes by domain with AND, OR and NOT inside one
// protocol.
func domainRoutes(m *portmux.Mux) {
	// OR: several names in one filter.
	m.Match(portmux.HTTP1(portmux.Host("example.com", "www.example.com")))
	// NOT: every subdomain except two, and nothing under /internal/.
	m.Match(portmux.HTTP1(
		portmux.Host("*.example.com"),
		portmux.NoneOf(portmux.Host("admin.example.com", "db.example.com"), portmux.PathPrefix("/internal/")),
	))
	// Groups: (api.example.com AND /v1/) OR status.example.com.
	m.Match(portmux.HTTP1(portmux.AnyOf(
		portmux.AllOf(portmux.Host("api.example.com"), portmux.PathPrefix("/v1/")),
		portmux.Host("status.example.com"),
	)))
	// The same for TLS: subdomains except admin, offering h2 or HTTP/1.1,
	// from clients that speak TLS 1.2 or newer.
	m.Match(portmux.TLS(
		portmux.SNI("*.example.com"),
		portmux.NoneOf(portmux.SNI("admin.example.com")),
		portmux.AnyOf(portmux.ALPN("h2"), portmux.ALPN("http/1.1")),
		portmux.MinTLSVersion(tls.VersionTLS12),
	))
	// Numbered hosts and versioned API paths, by regular expression.
	m.Match(portmux.HTTP1(
		portmux.HostRegexp(regexp.MustCompile(`^node-\d+\.example\.com$`)),
		portmux.PathRegexp(regexp.MustCompile(`^/v[0-9]+/`)),
	))
	// One site over HTTP and HTTPS.
	m.Match(portmux.Domain("shop.example.com", "*.shop.example.com"))
}
```

Conditions combine at three levels:

| Level                                           | OR                                   | AND                      | NOT      |
|-------------------------------------------------|--------------------------------------|--------------------------|----------|
| Values of one filter or address matcher         | `Host("a", "b")`, `RemoteIP(p1, p2)` |                          |          |
| Filters of one protocol, inside `HTTP1` / `TLS` | `AnyOf`                              | the filter list, `AllOf` | `NoneOf` |
| Any matchers: protocols, addresses, silence     | the route's matcher list, `Or`       | `And`                    | `Not`    |

- Each level nests in any way, and filter combinators only accept filters of
  their protocol, so mixing HTTP and TLS filters does not compile.
- Your own code fits at every level: `MatcherFunc`, `HTTPFilterFunc` and
  `TLSFilterFunc` decide yes or no inside any combination, and a `Resolve`
  route picks the route itself, ordered by priority among the other rules (see Deciding in Your Own Code).
- Exclude inside a protocol with `NoneOf`: `HTTP1(NoneOf(Host("admin.example.com")))`
  matches every HTTP request except those for the admin host. `Not(HTTP1(...))`
  instead also matches everything that is not HTTP.
- Address matchers decide at once, so `Not` works directly on them, as in
  `And(RemoteIP(office), Not(RemoteIP(guests)))`.
- Across routes, priorities give the order: an earlier route that matches takes
  the connection before later ones are asked.

## Routing Recipes

```go
// route combines a block list, an admin site for the office only, an API
// that needs HTTP/2, and a fallback. Priorities set the order of the checks.
func route(m *portmux.Mux, blocked []netip.Prefix, office netip.Prefix) error {
	admin := portmux.Or(
		portmux.TLS(portmux.SNI("admin.example.com")),
		portmux.HTTP1(portmux.Host("admin.example.com")),
	)
	routes := []portmux.RouteConfig{
		// Closed before a byte is read.
		{Name: "blocklist", Priority: 100, Reject: true, Matchers: []portmux.Matcher{portmux.RemoteIP(blocked...)}},
		{Name: "admin", Priority: 50, Matchers: []portmux.Matcher{portmux.And(portmux.RemoteIP(office), admin)}},
		{Name: "admin-elsewhere", Priority: 40, Reject: true, Matchers: []portmux.Matcher{admin}},
		{Name: "api", Matchers: []portmux.Matcher{portmux.TLS(portmux.SNI("api.example.com"), portmux.ALPN("h2"))}},
		{Name: "tls", Matchers: []portmux.Matcher{portmux.TLS()}},
		{Name: "http", Matchers: []portmux.Matcher{portmux.HTTP1()}},
		// Takes what no route matched, after all of them.
		{Name: "default", Fallback: true},
	}
	return m.Batch(func(b *portmux.Batch) error {
		for _, cfg := range routes {
			if _, err := b.Add(cfg); err != nil {
				return err
			}
		}
		return nil
	})
}
```

- Conditions on addresses, protocols, names and paths combine with `And`, `Or`
  and `Not` in any order. A route's own list of matchers is an `Or`.
- Priorities order the checks across routes: put block lists first, and add
  routes in between without touching the others.
- A route with `Reject` closes what it matches, reported with `ErrRefused`. With
  address matchers only, it decides before reading anything.
- A route with `Fallback` comes after every other route, whatever its priority.
  It takes the connections that every route ruled out, and those that sent
  bytes but stayed undecided until the sniff timeout. Clients that sent nothing
  are left to `Silent`. Of several fallback routes, the highest-priority one is
  used and the others stand by, so a replacement can be added before the old
  one is closed. Without a fallback route, an unmatched connection is closed at
  once and all it held is released.
- `Route.Matched` counts the connections each route matched, including those a
  reject route closed.

## Deciding in Your Own Code

```go
// tunnels binds host names to TCP tunnels. Each tunnel has a route without
// matchers, whose listener its server accepts from, and the name table sends
// TLS and HTTP connections there by their SNI or host.
type tunnels struct {
	m     *portmux.Mux
	hosts hostmatch.Map[*portmux.Route]
}

// newTunnels asks the name table after the block list and before the
// general HTTP and TLS routes.
func newTunnels(m *portmux.Mux) (*tunnels, error) {
	t := &tunnels{m: m}
	_, err := m.Add(portmux.RouteConfig{
		Name:     "tunnels",
		Priority: 10,
		Resolve:  portmux.ResolveDomain(&t.hosts),
	})
	return t, err
}

// add creates the route of a tunnel and binds a name pattern to it.
func (t *tunnels) add(pattern string) (*portmux.Route, error) {
	r, err := t.m.Add(portmux.RouteConfig{Name: "tunnel:" + pattern})
	if err != nil {
		return nil, err
	}
	t.hosts.Set(pattern, r)
	return r, nil
}

// site keeps an HTTPS and an HTTP target per name pattern.
type site struct{ https, http *portmux.Route }

// resolveSites falls back to a wider pattern when the most specific one has
// no target for the protocol: shop.example.com may serve HTTPS alone and
// leave HTTP to *.example.com.
func resolveSites(sites *hostmatch.Map[site]) portmux.ResolveFunc {
	return portmux.ResolveHosts(sites, func(in *portmux.Input, _ string, s site) (*portmux.Route, bool) {
		if _, res := in.ClientHello(); res == portmux.Match {
			return s.https, s.https != nil
		}
		return s.http, s.http != nil
	})
}

// byALPN decides in code of your own: it sends TLS connections to the route
// kept for their first ALPN protocol.
func byALPN(routes map[string]*portmux.Route) portmux.ResolveFunc {
	return func(in *portmux.Input) (*portmux.Route, portmux.Result) {
		hello, res := in.ClientHello()
		if res != portmux.Match {
			return nil, res // NeedMore until the hello is complete
		}
		if len(hello.ALPN) > 0 {
			if r, ok := routes[hello.ALPN[0]]; ok {
				return r, portmux.Match
			}
		}
		return nil, portmux.NoMatch // leave it to the next routes
	}
}
```

- A route with `Resolve` is one rule among the others: its priority places it
  before or after them, like any route, and `SetPriority` moves it. Its
  matchers, if any, are conditions checked first; the function is only asked
  when they match, so built-in filters and your own decision combine.
- The function chooses the route for the connection. It sees
  everything about the connection: the bytes, the entry, `RemoteAddr` and
  `LocalAddr`, `PeerAddr` (the TCP peer, which differs behind a PROXY header),
  the PROXY header, and the parsed ClientHello and HTTP/1 or h2c request.
- It returns the route that takes the connection, `NeedMore` to wait for bytes,
  or `NoMatch` to leave the connection to the later routes. Like a matcher, it
  runs before any byte arrives and after every read, and its decisions must be
  final.
- The target can be any route of the Mux: typically one without matchers,
  which the table never tries and which serves only as a target, or a reject
  route to close the connection, or `nil` for the resolver's own listener.
  A connection sent to a closed route is closed with `ErrRouteClosed`.
- `hostmatch.Map` maps name patterns to values and ranks the patterns that match a
  name by specificity, as virtual hosts are chosen: the exact name, then the
  patterns with the most literal characters (`*.api.example.com` before
  `*.example.com`), then `*`. `Lookup` returns the most specific pattern,
  `LookupFunc` the most specific one whose value a function accepts, and
  `Matches` all of them in order, so a policy of your own, such as a path or
  a certificate rule, can fall back to wider patterns. Lookups take no lock,
  allocate nothing and cost a few nanoseconds for any number of names, while
  `Set` and `Delete` change the map as connections are served.
- `ResolveHosts` routes by the name a connection asks for, the SNI or the
  HTTP/1 or h2c host, through a `hostmatch.Map` of values of your own: the
  first pattern whose value your function accepts decides. `ResolveDomain` is
  the case of a map of routes. `Input.RequestedName` and `hostmatch.Normalize`
  give the name as these compare it.
- Routing happens once per connection, so a host decides the service there;
  paths, which change from request to request on one connection, belong to
  the HTTP server behind it.
- `RouteInfo.Resolver` marks the route; `Matched` counts its decisions, and
  each target's `Matched` what it received.

## Changing Routes

```go
// addAdmin routes the admin site above every route with the default priority.
func addAdmin(m *portmux.Mux, host string) (web, secure *portmux.Route, err error) {
	web, err = m.Add(portmux.RouteConfig{
		Name:     "admin-http",
		Priority: 100,
		Matchers: []portmux.Matcher{portmux.HTTP1(portmux.Host(host))},
	})
	if err != nil {
		return nil, nil, err
	}
	secure, err = m.Add(portmux.RouteConfig{
		Name:     "admin-tls",
		Priority: 100,
		Matchers: []portmux.Matcher{portmux.TLS(portmux.SNI(host))},
	})
	return web, secure, err
}

// moveAdmin switches both admin routes to a new host at once. Their listeners,
// and the servers on them, keep running.
func moveAdmin(m *portmux.Mux, host string) error {
	return m.Batch(func(b *portmux.Batch) error {
		if err := b.SetMatchers(b.Route("admin-http"), portmux.HTTP1(portmux.Host(host))); err != nil {
			return err
		}
		return b.SetMatchers(b.Route("admin-tls"), portmux.TLS(portmux.SNI(host)))
	})
}

// updateBlocklist replaces the addresses of the block list.
func updateBlocklist(m *portmux.Mux, blocked []netip.Prefix) error {
	return m.Route("blocklist").SetMatchers(portmux.RemoteIP(blocked...))
}

// addBefore adds a route just ahead of another one, and checks the resulting
// order before it takes effect.
func addBefore(m *portmux.Mux, next string, cfg portmux.RouteConfig) error {
	return m.Batch(func(b *portmux.Batch) error {
		cfg.Priority = b.Route(next).Priority() + 1
		r, err := b.Add(cfg)
		if err != nil {
			return err
		}
		order := b.Routes()
		if i := slices.Index(order, r); i+1 >= len(order) || order[i+1].Name() != next {
			return errors.New("another route sits in between; pick other priorities")
		}
		return nil
	})
}
```

- Routes can be added, changed and removed at any time, including while
  connections are served. `Match` is short for an unnamed route with priority 0.
- A priority places a route without knowing the rest of the table; a negative
  one suits fallbacks. Names are optional and unique, and `Mux.Route` and
  `Batch.Route` look them up.
- `SetMatchers` and `SetPriority` keep the route's listener. A route without
  matchers is paused.
- `Batch` applies all of its changes at once, so a connection never sees half
  of them. When its function returns an error, nothing changes. The function
  holds no lock and may call other methods; its changes are applied on top of
  the routes as they are when it returns, and if one no longer applies, for
  example because another goroutine removed the route, nothing is applied.
- `Batch.Routes` previews the matching order with the batch's changes, so the
  priority of a new route can be checked before it takes effect.
- `Route.Close` removes the route at once: it stops matching, its name can be
  reused, its `Accept` returns `net.ErrClosed`, and connections that were
  matched to it but not accepted yet are matched again against the remaining
  routes. Nothing else of the route stays referenced by the Mux.
- Connections that are still undecided use the current routes for every
  decision. Delivered connections are never moved. `Mux.Routes` lists the
  routes in matching order.

## Rules as Text

```go
// loadRules applies routes kept as text, as in a configuration file or a
// database, all at once. A rule may name the matcher office of the program.
func loadRules(m *portmux.Mux, rules map[string]string, office portmux.Matcher) error {
	names := &portmux.Names{Matchers: map[string]portmux.Matcher{"office": office}}
	return m.Batch(func(b *portmux.Batch) error {
		for name, text := range rules {
			matcher, err := portmux.ParseMatcher(text, names)
			if err != nil {
				return err // a *portmux.ParseError with the offset of the problem
			}
			if r := b.Route(name); r != nil {
				if err := b.SetMatchers(r, matcher); err != nil {
					return err
				}
				continue
			}
			if _, err := b.Add(portmux.RouteConfig{Name: name, Matchers: []portmux.Matcher{matcher}}); err != nil {
				return err
			}
		}
		return nil
	})
}
```

- `ParseMatcher` reads the text that matchers print, as in
  `And(office, TLS(SNI("*.example.com"), MinTLSVersion(1.2)))`, so every
  built-in matcher and filter, and so every `RouteInfo.Matchers` entry, can be
  stored and parsed back into an equal matcher.
- Strings are Go string literals; prefixes, addresses, ports, durations and
  TLS versions are written bare: `RemoteIP(10.0.0.0/8, 2001:db8::1)`,
  `LocalPort(443)`, `Silent(2s)`.
- `Names` supplies matchers and HTTP and TLS filters of your own by name.
  They keep the name as description, so the parsed matcher prints the text
  again. Its `MatcherFuncs`, `HTTPFilterFuncs` and `TLSFilterFuncs` build
  calls with arguments, such as `Country("CN")` for a GeoIP matcher of your
  own or `JA4("...")` with `fingerprint.MatchJA4`.

## Live Status

```go
// printRoutes lists the routes in matching order with their state.
func printRoutes(m *portmux.Mux) {
	snap := m.Snapshot()
	for i, r := range snap.Routes {
		state := "active"
		switch {
		case r.Removed:
			state = "removed"
		case !r.Active:
			state = "inactive"
		case r.Accepting == 0 && !r.Reject && !r.Handler:
			state = "no server accepting"
		}
		fmt.Printf("%d %-12s prio=%-4d %-20s matched=%d queued=%d open=%d %s\n",
			i, r.Name, r.Priority, state, r.Matched, r.Queued, r.Open, strings.Join(r.Matchers, " | "))
	}
	for _, l := range snap.Listeners {
		fmt.Printf("%-8s %-21s accepted=%d delivered=%d rejected=%d pending=%d\n",
			l.Entry, l.Addr, l.Stats.Accepted, l.Stats.Delivered, l.Stats.Rejected, l.Stats.Pending)
	}
}
```

- `Mux.Snapshot` returns the listeners with their entries and counters, every
  route in matching order and the counters of the Mux, taken at one moment.
  `Route.Info` returns one route's state.
- Matchers describe themselves, as in
  `And(RemoteIP(10.0.0.0/8), TLS(SNI("admin.example.com")))`, in the text that
  `ParseMatcher` reads; `Named` labels your own.
- `Active` is false for a removed or paused route and for a fallback route on
  standby. `Accepting` counts `Accept` calls waiting: a route whose count stays
  at zero has no server taking its connections, which then time out, unless
  it passes them to a `Handler`.
- `Queued` counts matched connections waiting for `Accept`, `Matched` all
  connections the route matched, and `Open` those it has open: delivered, or
  waiting for `Accept`, and not closed yet. `RouteConfig.MaxConns` and
  `SetMaxConns` limit `Open`; connections over the limit are closed with
  `ErrRouteBusy`. Listeners and the Mux count `Open` too.
- `Mux.Bans` lists the banned clients and when their bans end.

## Server-First Protocols

```go
// addServerFirst routes clients that wait for the server to speak first.
func addServerFirst(m *portmux.Mux, office netip.Prefix) (ssh, database *portmux.Route) {
	// OpenSSH sends its banner at once; other SSH clients wait for the server.
	ssh = m.Match(portmux.SSH(), portmux.Silent(2*time.Second))
	// A client on the database port is routed before it sends anything.
	database = m.Match(portmux.And(portmux.LocalPort(3306), portmux.RemoteIP(office)))
	return ssh, database
}
```

- `Silent(d)` checks the connection d after it was accepted. The first route
  that accepts a silent connection gets it; routes that still wait for bytes do
  not hold it back. A client that sent anything never matches.
- `RemoteIP`, `LocalIP` and `LocalPort` decide before any byte arrives, so on
  their own they also route protocols in which the server speaks first.
- Silence checks extend the read deadline, which every connection from the net
  package supports.

## Listeners and Connections

```go
// serveDualStack serves the same routes on IPv4 and IPv6.
func serveDualStack(m *portmux.Mux) error {
	ln4, err := net.Listen("tcp4", ":443")
	if err != nil {
		return err
	}
	ln6, err := net.Listen("tcp6", ":443")
	if err != nil {
		ln4.Close()
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- m.Serve(ln4) }()
	go func() { errc <- m.Serve(ln6) }()
	return <-errc
}

// routeInsideTLS terminates TLS on a route and routes the decrypted streams
// with a second Mux.
func routeInsideTLS(secure net.Listener, config *tls.Config) *portmux.Mux {
	inner := portmux.New()
	go inner.Serve(tls.NewListener(secure, config))
	return inner
}

// serveTunnels serves each connection in the goroutine that matched it,
// without an accept loop.
func serveTunnels(m *portmux.Mux, backend string) (*portmux.Route, error) {
	return m.Add(portmux.RouteConfig{
		Name:     "tunnel",
		Matchers: []portmux.Matcher{portmux.Prefix("TUNNEL/1\n")},
		Handler: func(c *portmux.Conn) {
			defer c.Close()
			b, err := net.Dial("tcp", backend)
			if err != nil {
				return
			}
			defer b.Close()
			go io.Copy(b, c)
			io.Copy(c, b)
		},
	})
}

// shutdown stops taking connections and gives pending ones 5 seconds to be
// routed.
func shutdown(m *portmux.Mux) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.Shutdown(ctx)
}
```

- `Serve` can run for any number of listeners at once, and they share the
  routes. Closing a listener stops only its `Serve`. Entries, described next,
  or `LocalPort` tell the listeners apart.
- `ServeConn(c)` routes a connection obtained elsewhere, such as one received
  over a tunnel, in the calling goroutine.
- A route with a `Handler` passes each connection to it in the goroutine that
  matched it, once the connection no longer counts as pending. There is no
  accept loop, hand-over or queue, so dispatch timeouts and
  `WithMaxQueuedPerRoute` do not apply, and a server needs no goroutine of
  its own per connection. `ServeConn` calls the handler and returns when it
  returns.
- `Shutdown` closes the listeners and waits until every pending connection was
  delivered or rejected, or until its context ends. Routes keep accepting
  while it waits. `Close` stops at once; neither affects delivered
  connections, and neither waits for handlers.

## Entries

```go
// serveEntries keeps the listening ports apart from the services behind them:
// each listener serves an entry, and each service names the entries it is
// offered on.
func serveEntries(m *portmux.Mux, blocked []netip.Prefix) error {
	routes := []portmux.RouteConfig{
		// Without entries a route applies to every entry.
		{Name: "blocklist", Priority: 100, Reject: true, Matchers: []portmux.Matcher{portmux.RemoteIP(blocked...)}},
		{Name: "site", Entries: []string{"web"}, Matchers: []portmux.Matcher{portmux.Domain("www.example.com")}},
		{Name: "shop", Entries: []string{"web", "web-alt"}, Matchers: []portmux.Matcher{portmux.Domain("shop.example.com")}},
		{Name: "web-default", Entries: []string{"web", "web-alt"}, Fallback: true},
		// A dedicated port: each connection is handed over before any read.
		{Name: "tunnel-9000", Entries: []string{"tcp-9000"}, Matchers: []portmux.Matcher{portmux.Always()}},
	}
	err := m.Batch(func(b *portmux.Batch) error {
		for _, cfg := range routes {
			if _, err := b.Add(cfg); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	listeners := []struct{ entry, addr string }{
		{"web", ":80"}, {"web", ":443"}, {"web-alt", ":8443"}, {"tcp-9000", ":9000"},
	}
	errc := make(chan error, len(listeners))
	for _, l := range listeners {
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			return err
		}
		go func() { errc <- m.Entry(l.entry).Serve(ln) }()
	}
	return <-errc
}

// offerShopOn moves a service to other ports; the listeners stay as they are.
func offerShopOn(m *portmux.Mux, entries ...string) error {
	return m.Route("shop").SetEntries(entries...)
}
```

- An entry is a name for a group of listeners. `Mux.Entry(name)` returns its
  handle, whose `Serve` and `ServeConn` work as those of the Mux, which serve
  the entry with the empty name. Entries need no setup, and any number of
  listeners can serve one entry.
- `RouteConfig.Entries` limits a route to connections of those entries, and
  `Route.SetEntries` and `Batch.SetEntries` change them while serving. A route
  without entries applies to every entry, which suits block lists.
- So the listeners and the services form two tables that change apart: adding
  or closing a port touches no route, and moving a service to other ports
  touches no listener.
- Each entry has its own matching order and fallback, made of its own routes
  and those without entries. Routes of other entries are never asked, so
  entries cost each other nothing. A connection that no route of its entry
  takes is closed with `ErrNoMatch`.
- A route without entries that waits for bytes holds back the later routes of
  every entry. Give such a route entries, or put the routes of dedicated
  entries above it.
- `Always()` matches before anything is read. On a dedicated port it hands
  every connection over at once without taking a read buffer, for about half a
  microsecond, and the port keeps the Mux's limits, counters and status. A
  port that needs none of that can be served without a Mux.
- `Input.Entry` and `Conn.Entry` name the entry, so a resolver or a server can
  tell entries apart. Entries do not depend on addresses, so a PROXY header or
  a load balancer in front does not change them. `Snapshot.Listeners` lists
  every listener with its entry.

## Without a Mux

```go
// sniHandler reads the SNI of a connection the caller already accepted and
// passes the connection on with the ClientHello still to be read.
func sniHandler(c net.Conn, serve func(c net.Conn, name string)) {
	conn, err := portmux.Peek(c, portmux.TLS(), portmux.WithSniffTimeout(5*time.Second))
	if err != nil {
		_ = conn.Close()
		return
	}
	serve(conn, conn.ClientHello().ServerName)
}

// testAgentMatcher checks a custom matcher on chosen bytes and addresses.
func testAgentMatcher(m portmux.Matcher) bool {
	in := portmux.NewInput(&net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5000}, nil)
	in.SetBytes([]byte("AGENT/1\nhello"), false)
	return m.Match(in) == portmux.Match
}
```

| Function                                                        | Use                                                                                |
|-----------------------------------------------------------------|------------------------------------------------------------------------------------|
| `Peek(c, m, opts...)`                                           | Sniff one connection; returns a `Conn` that replays the bytes it read              |
| `Conn.Unread()`                                                 | The sniffed bytes not replayed yet, such as a raw ClientHello for your own parser  |
| `tlshello.Parse`, `httphead.Parse`, `httphead.ParseHTTP2`       | Parse the first bytes of a connection; `io.ErrUnexpectedEOF` while incomplete      |
| `tlshello.Scanner`, `httphead.Scanner`, `httphead.HTTP2Scanner` | Parse as bytes arrive, examining each byte once                                    |
| `fingerprint.JA4`, `fingerprint.JA3`                            | Fingerprint the TLS library of a client                                            |
| `ParseRDPCookie`                                                | The routing cookie of an RDP connection request                                    |
| `hostmatch.Map`, `hostmatch.Set`                                | Map host patterns to values, or match names, with the patterns of `Host` and `SNI` |
| `hostmatch.Normalize`, `hostmatch.SplitHost`                    | Prepare a host name, or remove the port of a Host value                            |
| `ipmatch.Set`                                                   | Look up IP addresses in prefix lists, as `RemoteIP` does                           |
| `ParseMatcher`                                                  | Read a matcher from the text matchers print                                        |
| `NewInput`, `Input.SetBytes`                                    | Run or test matchers on chosen bytes and addresses, parsing as bytes arrive        |
| Matchers and filters                                            | `m.Match(input)`, `SNI(...).Match(hello)` and the like work on their own too       |

- `Peek` never closes the connection and returns the `Conn` whatever the
  outcome: on `ErrNoMatch`, a timeout or `io.EOF`, the bytes read so far are
  still replayed, and parses that completed are attached.
- The `Parse` functions parse from the start on every call. For bytes that
  arrive in pieces, the scanners, `Peek` and `Input` continue where they
  stopped. Parsers return `io.ErrUnexpectedEOF` while the bytes are the start
  of what they parse and `ErrInvalid` when they are not, as
  `proxyproto.Parse` does.
- netx covers the rest: `netx.NewPrefixConn` puts bytes that your own code
  read back in front of a connection, `netx.Relay` copies between two
  connections, and `proxyproto.Parse` and `proxyproto.HeaderFromConn` read and
  write PROXY headers.
- Matchers, filters and the sets describe themselves through `String`, as
  `Snapshot` shows them.

## Delivered Connections

```go
// describe reports what a connection was routed by.
func describe(c *portmux.Conn) string {
	if hello := c.ClientHello(); hello != nil {
		return "tls " + hello.ServerName + " " + strings.Join(hello.ALPN, ",") + " " + fingerprint.JA4(hello)
	}
	if req := c.HTTPRequest(); req != nil {
		return req.Method + " " + req.Host + req.Path + " " + req.Header().Get("User-Agent")
	}
	return c.Route().Name() + " from " + c.RemoteAddr().String()
}
```

- `ClientHello` is always set for routes matched by `TLS`, and `HTTPRequest` for
  routes matched by `HTTP1` or `HTTP2`. Each is nil when it was not parsed; an
  h2c request has the `Proto` "HTTP/2.0" and its `:authority` as `Host`.
- `Close` ends the connection's count as open for its route, listener and Mux.
  Closing `NetConn` directly does not.
- A `tlshello.Hello` holds the SNI, ALPN, versions, cipher suites, extensions
  in their order, groups, signature schemes and point formats, GREASE values
  included. `fingerprint.JA4` fingerprints the client's TLS library whatever
  the order of its extensions; `fingerprint.JA3` is kept for older
  fingerprint lists.
- `httphead.Request.Header` builds a `textproto.MIMEHeader` on first use,
  which `http.Header(...)` converts where net/http is at hand. Like net/http,
  it leaves the Host field out; `Host` holds it. `Values` yields the values of
  one field without building the map.
- `ProxyHeader` returns the PROXY protocol header, and `RemoteAddr` and
  `LocalAddr` report its addresses.
- `NetConn` returns the connection from the listener. `Conn` also implements
  `CloseWrite`, `CloseRead`, `io.WriterTo` and `io.ReaderFrom`, so proxies keep
  half-close and the fast copy paths of the underlying connection.

## PROXY Protocol

```go
// behindLoadBalancer expects PROXY headers on the entry "lb", whose ports sit
// behind a load balancer, and from the balancer's subnet only.
func behindLoadBalancer(lb netip.Prefix) *portmux.Mux {
	return portmux.New(portmux.WithProxyProtocol(func(entry string, peer, _ net.Addr) proxyproto.Policy {
		if a, ok := peer.(*net.TCPAddr); ok && entry == "lb" && lb.Contains(a.AddrPort().Addr().Unmap()) {
			return proxyproto.Required
		}
		return proxyproto.Ignore
	}))
}
```

- Version 1 and 2 headers are parsed with `github.com/djylb/netx/proxyproto`
  and removed before matching, so the routes match the protocol behind the
  header. `Conn.ProxyHeader` returns the `proxyproto.Header`, TLVs included.
- The policy decides per entry, peer and local address. `proxyproto.Optional`
  accepts connections with and without a header. A missing required header
  is reported with `proxyproto.ErrNoHeader`, an invalid one with
  `proxyproto.ErrMalformed`.
- Address matchers and the delivered `Conn` see the header's addresses. Allow
  headers only from trusted peers: a header chooses the reported client
  address.
- Prefer this option to a `proxyproto.Listener` in front of the Mux: the
  header is then read within the sniff timeout and the pending limits, and
  the accept loop never waits for it. To send a header to a backend, use
  `proxyproto.HeaderFromConn`.

## Options

```go
// newPublicMux suits a port that is open to the internet, and logs the
// connections it routes.
func newPublicMux() *portmux.Mux {
	return portmux.New(
		portmux.WithSniffTimeout(5*time.Second),
		portmux.WithMaxPendingPerIP(32),
		portmux.WithRateLimitPerIP(20, 40),
		portmux.WithRateLimitPerListener(2000, 4000),
		portmux.WithBanPerIP(10, time.Minute, 10*time.Minute),
		portmux.WithObserver(func(ev portmux.Event) {
			if ev.Err == nil {
				log.Printf("%s %s -> %s in %v", ev.Entry, ev.Remote, ev.Route.Name(), ev.Elapsed)
			}
		}),
	)
}

// tighten lowers the limits of a running Mux, for example during an attack.
func tighten(m *portmux.Mux) {
	m.SetOptions(portmux.WithMaxPendingPerIP(4), portmux.WithRateLimitPerIP(2, 4))
}

// logRejections reports rejected connections without logging every one of
// them during an attack.
func logRejections(m *portmux.Mux) {
	for range time.Tick(time.Minute) {
		st := m.Stats()
		log.Printf("portmux: %d delivered, %d rejected (%d no match, %d timeouts, %d evicted, %d limited)",
			st.Delivered, st.Rejected, st.NoMatch, st.Timeouts, st.Evicted, st.Limited)
	}
}
```

| Option                           | Default | Effect                                                                                 |
|----------------------------------|---------|----------------------------------------------------------------------------------------|
| `WithSniffTimeout(d)`            | 10s     | Time from accept until a route matches                                                 |
| `WithDispatchTimeout(d)`         | 5s      | Time a matched connection waits for its route's `Accept`                               |
| `WithMaxSniffBytes(n)`           | 16 KiB  | Bytes buffered for matching, up to 16 MiB; undecided matchers then count as no match   |
| `WithMaxPending(n)`              | 4096    | Undelivered connections from `Serve`; at the limit the oldest undecided one is evicted |
| `WithMaxPendingPerIP(n)`         | none    | Undelivered connections per client; more are closed at once                            |
| `WithRateLimitPerIP(r, b)`       | none    | New connections per second per client, with bursts of b; more are closed at once       |
| `WithMaxQueuedPerRoute(n)`       | 1024    | Matched connections waiting for one route's `Accept`; more are closed                  |
| `WithRateLimitPerListener(r, b)` | none    | New connections per second per listener, whatever their clients                        |
| `WithBanPerIP(n, w, d)`          | none    | Bans for d a client with n failed connections within w                                 |
| `WithObserver(fn)`               | none    | Called with an `Event` for every connection delivered or closed, and for Accept errors |
| `WithProxyProtocol(policy)`      | none    | PROXY protocol v1/v2 per entry and peer                                                |

- `SetOptions` changes options while the Mux serves; options not given keep
  their values. Limits apply to connections accepted from then on, while
  connections being matched keep the timeouts they started with.
- A client is an IPv4 address or an IPv6 /64 network, taken from the TCP peer
  rather than from a PROXY header. The per-client limits apply to connections
  from `Serve`.
- Errors are `ErrNoMatch`, `ErrRefused`, `ErrSniffTimeout` (which also wraps the
  timeout), `ErrDispatchTimeout`, `ErrEvicted`, `ErrPendingLimit`,
  `ErrRateLimited`, `ErrBanned`, `ErrRouteBusy`, `ErrRouteClosed`, the
  `proxyproto` errors, read errors such as `io.EOF` for a client that closed
  without sending, and a description of a matcher panic.
- An `Event` names the entry, addresses, route or error, the time to the
  decision and the bytes sniffed. The observer runs synchronously, partly in
  the accept loop, so keep it cheap. `Stats` counts accepted, delivered,
  rejected, pending and open connections and breaks the rejected ones down by
  reason.
- `WithBanPerIP` counts connections that matched no route, timed out while
  sniffing, hit a reject route or sent an invalid PROXY header; connections
  closed without sending, as health checks are, do not count. `Mux.Ban` and
  `Unban` ban and lift by hand.
- `Serve` retries temporary `Accept` errors with a growing delay and returns
  the first permanent one, or `net.ErrClosed` after `Shutdown` or `Close`.

## Security

| Threat                                                 | Handling                                                                                              |
|--------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Port scans, clients that connect and close             | Closed at once with `io.EOF`                                                                          |
| Garbage and invalid packets                            | Each protocol is ruled out on the first byte that cannot belong to it; `ErrNoMatch`                   |
| Data too short to decide, then silence (slowloris)     | Sniff timeout; at the pending limit the oldest undecided connections are evicted                      |
| Floods of idle or slow connections from many addresses | The pending limit holds memory; eviction keeps accepting, and real clients decide within a round trip |
| Many connections from one client                       | `WithMaxPendingPerIP` and `WithRateLimitPerIP`, closed before reading                                 |
| Scanners that keep sending garbage or nothing          | `WithBanPerIP` refuses them for a while before reading; `Ban` for known sources                       |
| Floods of new connections from many addresses          | `WithRateLimitPerListener` caps each port's accept rate                                               |
| Floods of valid-looking connections (CC)               | `WithRateLimitPerIP`; reject routes for known sources; servers still see what they accept             |
| Heads sent in tiny pieces or many TLS records (CPU)    | Incremental parsing: cost grows linearly with the bytes                                               |
| Oversized heads                                        | `WithMaxSniffBytes`; `ErrNoMatch` unless a route matches without them                                 |
| Ambiguous requests                                     | Duplicate Host headers, folded headers, duplicate TLS extensions or SNI names: not matched            |
| HPACK bombs in h2c                                     | Decoded header lists are limited to 64 KiB; frames before the request to 16                           |
| Host or SNI names with characters such as `@` or NUL   | Never match a pattern, so they cannot reach a route meant for another name                            |
| Spoofed client addresses                               | PROXY headers are parsed only from peers the policy trusts                                            |
| A stalled server on one route                          | `WithMaxQueuedPerRoute` and the dispatch timeout keep it from taking the others' budget               |
| A faulty matcher                                       | Panics close only the connection being matched                                                        |
| Scanners and bots with a known TLS library             | A reject route with `TLS(fingerprint.MatchJA4(...))` closes them before the handshake                 |

- portmux sees established TCP connections only. SYN floods and bandwidth
  floods are for the kernel (SYN cookies) and the network.
- Delivered connections are no longer limited: servers keep their own
  timeouts and limits.
- Evicted and timed-out connections from a flood are counted in `Stats`; log
  aggregates rather than each connection.

## Resources

- **Release.** Every connection that is not delivered is closed as soon as it
  is decided, and gives back its goroutine, read buffer, pending slot and
  per-client count: no route matching, a reject route, a limit, a timeout, an
  eviction, or `Close`. Closing a route or the Mux releases what they hold, and
  the tests check that no goroutine outlives `Close`.
- **Memory.** An idle client holds about 7 KB on the server side, mostly the
  goroutine and the socket: on Linux, Android, macOS, iOS, the BSDs and Windows
  its read buffer is only taken when bytes arrive. A client that sends bytes
  holds a buffer of up to `WithMaxSniffBytes`. The worst case is therefore
  about `WithMaxPending` × (7 KB + `WithMaxSniffBytes`): 92 MB with the
  defaults, and less with lower limits. Rate limits and bans track at most
  65536 clients each.
- **Binary size.** A Mux with a few routes adds about 400 KB to a program
  that already serves TCP, mostly fmt and runtime type data, and one using
  most features about 950 KB. A program that only uses `hostmatch` or
  `tlshello` grows by a few kilobytes.
- **CPU.** Matching a connection takes well under a microsecond and a few
  allocations. Each route hands over several hundred thousand connections a
  second to its accept loop, and different routes hand over in parallel; a
  handler takes the connection without a hand-over at all. A route change
  rebuilds the matching table in time linear in the routes. Over
  loopback a whole TCP connection costs tens of microseconds, almost all of it
  in the kernel.
  Parsing is incremental, so heads sent in small pieces or split into many TLS
  records cost time proportional to their size. Run `go test -bench .` for
  numbers on your machine.
- **Integrity.** The sniffed bytes are replayed exactly, so servers read the
  stream unchanged from its first byte; only a PROXY header is removed, and its
  content is in `Conn.ProxyHeader`. portmux never writes to the client. It sets
  the read deadline while sniffing and clears it before delivery.
- **No hang.** The sniff timeout bounds how long a connection is read, the
  dispatch timeout and `WithMaxQueuedPerRoute` how long and how many wait for
  `Accept`, and the pending limits how many are held at once. Disabling a
  timeout lifts its bound; so do connections passed to `ServeConn` that do not
  support deadlines. Matchers and the observer run in portmux's
  goroutines and must not block.

## Limits

- Protocols in which the server speaks first can only be routed by `Silent`
  or by address. Likewise, h2c clients that wait for the server's SETTINGS
  before their first request can only be matched by `HTTP2Preface`.
- TLS traffic can only be told apart by its cleartext ClientHello, that is by
  SNI and ALPN. With Encrypted Client Hello, the SNI is the outer public name.
  Nest a second Mux to route by what is inside TLS.
- Datagram protocols such as UDP are out of scope.
