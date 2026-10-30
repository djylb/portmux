# portmux

Serve multiple protocols on one port by sniffing the first bytes of each
connection — HTTP/1, h2c, TLS (SNI/ALPN/JA4), PROXY protocol, SSH, SOCKS,
databases and custom prefixes — and routing them to separate `net.Listener`s
or handlers. Routes, limits and options change while serving.

Requires Go 1.26. Besides the standard library it uses only
[netx](https://github.com/djylb/netx) for PROXY protocol headers.

## Install

```bash
go get github.com/djylb/portmux
```

## Packages

| Package               | Contents                                                                   |
|-----------------------|----------------------------------------------------------------------------|
| `portmux`             | Mux, routes, entries, matchers, filters, delivered connections, text rules |
| `portmux/hostmatch`   | `Set` and `Map` of host name patterns such as `*.example.com`              |
| `portmux/ipmatch`     | `Set` of IP prefixes, for block lists and networks                         |
| `portmux/tlshello`    | TLS ClientHello parser                                                     |
| `portmux/httphead`    | HTTP/1.x and h2c request head parsers, with HPACK                          |
| `portmux/fingerprint` | JA4 and JA3 fingerprints of ClientHellos, and filters by them              |
| `portmux/httproute`   | HTTP request routing: reverse proxy, redirects, header rules, error pages  |

A program carries only the packages it imports: the tool packages work without
a Mux, only `fingerprint` imports hash functions, and only `httproute` imports
`net/http` and `crypto/tls`.

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
	agents := m.Listen(portmux.Prefix("AGENT/1\n"))
	admin := m.Listen(portmux.TLS(portmux.SNI("admin.example.com")))
	site := m.Listen(portmux.TLS())
	web := m.Listen(portmux.HTTP1())
	ssh := m.Listen(portmux.SSH(), portmux.Silent(2*time.Second))

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

- Every route is a `net.Listener`. Its `Accept` returns a `*portmux.Conn` that
  replays the sniffed bytes first, so servers see the stream from its first
  byte.
- Routes are tried by priority and then in the order they were added; while a
  route still needs bytes, the routes after it wait. A connection that no route
  takes is closed.
- Routing happens once per connection: a keep-alive HTTP connection stays on
  the route of its first request.

## Matchers

| Matcher                                       | Matches                                                    |
|-----------------------------------------------|------------------------------------------------------------|
| `Prefix(p...)`, `Regexp(re, n)`               | The first bytes                                            |
| `HTTP1(filters...)`, `HTTP2(filters...)`      | HTTP/1.x requests, and h2c by its first request            |
| `TLS(filters...)`                             | TLS ClientHellos, also across several records              |
| `Domain(patterns...)`                         | TLS by SNI, and HTTP/1.x and h2c by host, in one matcher   |
| `SSH()`, `SOCKS4()`, `SOCKS5()`               | SSH clients that speak first, SOCKS requests and greetings |
| `PostgreSQL()`, `MQTT()`, `RDP()`             | Database, MQTT and Remote Desktop clients                  |
| `OpenVPN()`, `XMPP()`, `DNS()`                | OpenVPN over TCP, XMPP streams, DNS over TCP               |
| `HTTP2Preface()`                              | The h2c connection preface alone                           |
| `Silent(d)`                                   | Clients that sent nothing for d, as server-first protocols |
| `RemoteIP(prefixes...)`, `RemoteIPFunc(fn)`   | Client addresses, from a fixed or a changing list          |
| `LocalIP(prefixes...)`, `LocalIPFunc(fn)`     | The address the client connected to                        |
| `LocalPort(ports...)`                         | The port the client connected to                           |
| `AnyBytes()`, `Always()`                      | Any client that sent a byte; every connection, unread      |
| `And`, `Or`, `Not`                            | Combinations, nested in any way                            |
| `MatcherFunc`, `Named(name, m)`               | Your own logic, with a description for `Snapshot`          |

| Filters of | Filters                                                                                                            |
|------------|--------------------------------------------------------------------------------------------------------------------|
| HTTP       | `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method`, `Header`, `HeaderRegexp`, `Query`, `WebSocket` |
| TLS        | `SNI`, `SNIRegexp`, `ALPN`, `MinTLSVersion`, `fingerprint.MatchJA4`, `fingerprint.MatchJA3`                        |

- Host patterns are those of nginx and Envoy: an exact name;
  `*.example.com`, any name below example.com at any depth (`a.b.example.com`
  too) but not example.com itself; `.example.com`, example.com and every
  name below it; `*`, any name; and `""`, a hello or request without a name.
  No other wildcards exist: `*a.example.com`, `api-*.example.com` and
  `a.*.com` are refused: `hostmatch.CheckPattern` reports them, and
  `Host`, `SNI`, `Domain`, `hostmatch.NewSet` and `hostmatch.Map.Set` panic
  on them, so check patterns from configurations first; `ParseMatcher`
  and `httproute.Build` return errors. Note that a wildcard
  certificate covers one level only: `*.example.com` routes `a.b.example.com`
  but a certificate for `*.example.com` does not cover it. Names compare
  case-insensitively and without a trailing dot, and names with bytes that
  no host name has, such as `@` or any non-ASCII byte, match nothing.
- Paths are decoded and resolved as servers resolve them, so `/public/../admin/`
  is `/admin/`, a path with a control character once decoded is ruled out, and `PathPrefix("/api")` matches `/api` and `/api/v1` but not
  `/apis`.
- Each protocol is parsed once per connection, incrementally, however many
  routes look at it.
- Address matchers and `Silent` decide without bytes, which routes protocols in
  which the server speaks first. A matcher of your own that waits for
  silence implements `Silencer` and reads `Input.Elapsed`.

A matcher of your own reads what is known about the connection from an
`Input`:

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

Matchers return `NeedMore` until they can decide, and their decisions must be
final: a longer input must get the same answer. They must not block. A parser
of your own can keep its state between calls on one connection with
`Input.SetValue` and `Input.Value`, as the built-in parsers do.

## Combining Conditions

```go
func combine(m *portmux.Mux, office netip.Prefix) {
	// Every subdomain except two, and nothing under /internal/.
	m.Listen(portmux.HTTP1(
		portmux.Host("*.example.com"),
		portmux.NoneOf(portmux.Host("admin.example.com", "db.example.com"), portmux.PathPrefix("/internal/")),
	))
	// (api.example.com AND /v1/) OR status.example.com.
	m.Listen(portmux.HTTP1(portmux.AnyOf(
		portmux.AllOf(portmux.Host("api.example.com"), portmux.PathPrefix("/v1/")),
		portmux.Host("status.example.com"),
	)))
	// The admin site over TLS 1.2 or newer, from the office only.
	m.Listen(portmux.And(
		portmux.RemoteIP(office),
		portmux.TLS(portmux.SNI("admin.example.com"), portmux.MinTLSVersion(tls.VersionTLS12)),
	))
}
```

| Level                                   | OR                                   | AND                      | NOT      |
|-----------------------------------------|--------------------------------------|--------------------------|----------|
| Values of one filter or address matcher | `Host("a", "b")`, `RemoteIP(p1, p2)` |                          |          |
| Filters of one protocol                 | `AnyOf`                              | the filter list, `AllOf` | `NoneOf` |
| Matchers of any kind                    | the route's matcher list, `Or`       | `And`                    | `Not`    |

`NoneOf` excludes within a protocol: `HTTP1(NoneOf(Host("a")))` matches HTTP
requests for other hosts, while `Not(HTTP1(Host("a")))` also matches
everything that is not HTTP.

## Routes

```go
// setup adds a block list, a route, a reject route and a fallback at once.
func setup(m *portmux.Mux, blocked []netip.Prefix) error {
	return m.Batch(func(b *portmux.Batch) error {
		for _, cfg := range []portmux.RouteConfig{
			{Name: "blocklist", Priority: 100, Reject: true, Matchers: []portmux.Matcher{portmux.RemoteIP(blocked...)}},
			{Name: "admin", Priority: 50, Matchers: []portmux.Matcher{portmux.Domain("admin.example.com")}},
			{Name: "web", Matchers: []portmux.Matcher{portmux.HTTP1(), portmux.TLS()}, MaxConns: 10000},
			{Name: "default", Fallback: true},
		} {
			if _, err := b.Add(cfg); err != nil {
				return err
			}
		}
		return nil
	})
}

// moveAdmin changes a route while serving; its listener keeps running.
func moveAdmin(m *portmux.Mux, host string) error {
	return m.Route("admin").SetMatchers(portmux.Domain(host))
}
```

- A `Reject` route closes what it matches; with address matchers it does so
  before reading. A `Fallback` route takes, after every other route, what they
  all ruled out and what stayed undecided until the sniff timeout.
- Matchers rule out what they cannot parse or find ambiguous, such as a
  request with two Host fields or a path that servers resolve differently, so
  a reject route does not see it and later routes may take it. Where reject
  routes guard the others, list what is allowed rather than what is not, and
  make the fallback a reject route too.
- `MaxConns` limits the connections a route has open at once, and
  `DispatchTimeout` and `MaxQueued` replace the entry's dispatch timeout and
  queue limit for a route whose server is slower to accept than the others.
- Routes can be added, changed with `SetMatchers`, `SetPriority`,
  `SetEntries`, `SetMaxConns`, `SetDispatchTimeout` and `SetMaxQueued`, and
  removed with `Close` at any time.
  `Batch` applies several changes at once, and `Batch.Routes` previews the
  order. Each change rebuilds the routing table, so make many changes, such
  as loading thousands of routes, in one `Batch`.
- Undecided connections use the current routes for every decision;
  connections waiting for a removed route's `Accept` are matched again.

## Entries

An entry names a group of listeners, so that ports and the services behind
them are set up apart: each listener serves an entry, and each route names the
entries it is offered on.

```go
func serveEntries(m *portmux.Mux) error {
	_, err := m.Add(portmux.RouteConfig{Name: "shop", Entries: []string{"web", "web-alt"},
		Matchers: []portmux.Matcher{portmux.Domain("shop.example.com")}})
	if err != nil {
		return err
	}
	// A dedicated port: each connection is handed over before any read.
	_, err = m.Add(portmux.RouteConfig{Name: "tunnel-9000", Entries: []string{"tcp-9000"},
		Matchers: []portmux.Matcher{portmux.Always()}})
	if err != nil {
		return err
	}
	// The public port gets stricter limits than the others.
	m.Entry("web").SetOptions(portmux.WithSniffTimeout(5*time.Second), portmux.WithBanPerClient(10, time.Minute, time.Hour))

	for entry, addr := range map[string]string{"web": ":443", "web-alt": ":8443", "tcp-9000": ":9000"} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go m.Entry(entry).Serve(ln)
	}
	return nil
}
```

- A route without entries applies to every entry, which suits block lists.
  Each entry has its own matching order and fallback; routes of other entries
  are never asked.
- `Route.SetEntries` moves a service to other ports without touching a
  listener, and closing a listener touches no route.
- `Entry.SetOptions` gives an entry options of its own on top of the Mux's,
  and `ResetOptions` drops them. An entry with its own per-client rate limit
  or ban rule counts its clients apart; a ban applies to every entry.
- `Input.Entry` and `Conn.Entry` name the entry, whatever a PROXY header says.

## Choosing Routes in Code

A resolver route picks the target route itself, as one rule ordered by
priority among the others:

```go
// tunnels binds host names to tunnel routes, which have no matchers and are
// reached only through the name table.
type tunnels struct {
	m     *portmux.Mux
	hosts hostmatch.Map[*portmux.Route]
}

func newTunnels(m *portmux.Mux) (*tunnels, error) {
	t := &tunnels{m: m}
	_, err := m.Add(portmux.RouteConfig{Name: "tunnels", Priority: 10, Resolve: portmux.ResolveDomain(&t.hosts)})
	return t, err
}

func (t *tunnels) add(pattern string) (*portmux.Route, error) {
	r, err := t.m.Add(portmux.RouteConfig{Name: "tunnel:" + pattern})
	if err == nil {
		t.hosts.Set(pattern, r)
	}
	return r, err
}

// resolveSites keeps an HTTPS and an HTTP route per name, and falls back to a
// wider pattern when a name has none for the protocol.
func resolveSites(sites *hostmatch.Map[[2]*portmux.Route]) portmux.ResolveFunc {
	return portmux.ResolveHosts(sites, func(in *portmux.Input, _ string, s [2]*portmux.Route) (*portmux.Route, bool) {
		if _, res := in.ClientHello(); res == portmux.Match {
			return s[0], s[0] != nil
		}
		return s[1], s[1] != nil
	})
}
```

- A `ResolveFunc` sees everything about the connection and returns a route,
  `NeedMore` or `NoMatch`. Its matchers, if any, are conditions checked first.
- `hostmatch.Map` looks a name up by the most specific pattern: the exact name,
  then `.name` for the name itself, then the wildcards by the length of
  their suffix (`*.` before `.` on a tie), then `*`. `LookupFunc`
  and `Matches` fall back to wider patterns for policies of your own. Lookups
  take no lock, and allocate nothing for lowercase names and those that
  `Input` prepared.
- `ResolveHosts` and `ResolveDomain` route TLS, HTTP/1.x and h2c by the name
  the client asks for, and protocols of your own by the name a matcher sets
  with `Input.SetRequestedName`. Paths are for the HTTP server behind the
  route.
- To replace the route of a name while serving, add the new route, point
  the name table to it, then close the old one: `ResolveHosts` passes closed
  routes over, so no connection reaches one.
- `Mux.Upsert` and `Batch.Upsert` add or change routes by name, keeping the
  listener of a route that stays, which suits reloading a configuration:
  upsert the routes it has, then remove the routes it no longer has.
  `SetHandler` and `SetResolve` change those of a route in place.

## Rules as Text

```go
// loadRule adds a route kept as text, as in a configuration file.
func loadRule(m *portmux.Mux, name, text string, office portmux.Matcher) error {
	names := &portmux.Names{Matchers: map[string]portmux.Matcher{"office": office}}
	matcher, err := portmux.ParseMatcher(text, names) // a *portmux.ParseError tells where it failed
	if err != nil {
		return err
	}
	_, err = m.Add(portmux.RouteConfig{Name: name, Matchers: []portmux.Matcher{matcher}})
	return err
}
```

`ParseMatcher` reads what matchers print, as in
`And(office, TLS(SNI("*.example.com"), MinTLSVersion(1.2)))`, so the matchers
of routes can be stored and read back, next to the other settings of their
`RouteConfig`. `Names` supplies your own matchers and filters, also with
arguments; `fpnames.Register` (package `fingerprint/fpnames`) adds `JA4("...")` and `JA3("...")`.

## Delivery

```go
// serveTunnel serves connections in the goroutine that matched them,
// without an accept loop.
func serveTunnel(m *portmux.Mux, backend string) (*portmux.Route, error) {
	return m.Add(portmux.RouteConfig{
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
```

- A route delivers to `Accept`, or to its `Handler`, which needs no accept loop
  and scales best for a busy route.
- A `Conn` carries what was parsed: `ClientHello`, `HTTPRequest`,
  `HTTP2Request`, `RequestedName`, `ProxyHeader`, the values that your
  matchers stored with `Input.SetValue` (`Conn.Value`), `Entry` and `Route`.
  It keeps half-close and the fast copy paths of the underlying connection.
- A panic in a matcher, resolver, PROXY policy or handler closes only its
  connection and is reported as a `*PanicError`.
- `Serve` runs for any number of listeners, and `ServeConn` routes a connection
  obtained elsewhere, without the admission of `Serve`: limits, bans and
  rates apply to connections that come through a `net.Listener` passed to
  `Serve`. `Shutdown` waits for pending connections to be routed; `Close`
  stops at once, after which `Add` and `Batch` return `net.ErrClosed`.
  Neither affects delivered connections.

A route is a `net.Listener`, so TLS can be terminated on it and what it
carries routed again by a second Mux, for example SOCKS and HTTP proxies
inside TLS on the same port as plain ones:

```go
// serveInsideTLS routes the plain connections of l, and those inside TLS
// with cert by the same routes.
func serveInsideTLS(l net.Listener, cert tls.Certificate, proxies func(*portmux.Mux)) error {
	outer, inner := portmux.New(), portmux.New()
	proxies(outer)
	proxies(inner)
	secure := outer.Listen(portmux.TLS())
	go inner.Serve(tls.NewListener(secure, &tls.Config{Certificates: []tls.Certificate{cert}}))
	return outer.Serve(l)
}
```

Connections of the inner Mux keep the client address of the outer one,
including one from a PROXY header. An `http.Server` behind the inner Mux
gets `*portmux.Conn`s rather than `*tls.Conn`s, so `Request.TLS` is nil; take
the state from the TLS connection under the Conn:

```go
type tlsStateKey struct{}

// tlsState puts the TLS state of a connection inside TLS in its requests'
// context, for handlers that need it, such as to set HSTS or Secure cookies.
func tlsState(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*portmux.Conn); ok {
		if tc, ok := pc.NetConn().(*tls.Conn); ok {
			return context.WithValue(ctx, tlsStateKey{}, tc.ConnectionState())
		}
	}
	return ctx
}

// Then: srv := &http.Server{Handler: h, ConnContext: tlsState}, and in h,
// state, isTLS := r.Context().Value(tlsStateKey{}).(tls.ConnectionState).
```

## PROXY Protocol

```go
// behindLoadBalancer expects PROXY headers on the entry "lb", from the
// balancer's subnet only; TrustPeers(lb) does it for every entry.
func behindLoadBalancer(lb netip.Prefix) *portmux.Mux {
	trusted := portmux.TrustPeers(lb)
	return portmux.New(portmux.WithProxyProtocol(func(entry string, peer, local net.Addr) proxyproto.Policy {
		if entry != "lb" {
			return proxyproto.Ignore
		}
		return trusted(entry, peer, local)
	}))
}
```

Headers of version 1 and 2 are removed before matching, and their addresses are
what address matchers and the `Conn` see. Allow them only from trusted peers.
Per-client limits and bans apply to the sources in the headers; a trusted
peer is not banned for its own connections without a valid header, so that a
misconfigured balancer is not banned with every client behind it.

## Options

```go
func newPublicMux() *portmux.Mux {
	return portmux.New(
		portmux.WithSniffTimeout(5*time.Second),
		portmux.WithMaxPendingPerClient(32),
		portmux.WithRateLimitPerClient(20, 40),
		portmux.WithBanPerClient(10, time.Minute, 10*time.Minute),
		portmux.WithObserver(func(ev portmux.Event) {
			if ev.Err != nil {
				log.Printf("%s %s: %v", ev.Entry, ev.Remote, ev.Err)
			}
		}),
	)
}

// tighten lowers the limits while serving and returns the new settings.
func tighten(m *portmux.Mux) portmux.Config {
	m.SetOptions(portmux.WithMaxPendingPerClient(4), portmux.WithRateLimitPerClient(2, 4))
	return m.Config()
}
```

| Option                           | Default | Effect                                                                    | Per entry |
|----------------------------------|---------|---------------------------------------------------------------------------|-----------|
| `WithSniffTimeout(d)`            | 10s     | Time until a route matches, not counting a wait for a pending slot        | yes       |
| `WithDispatchTimeout(d)`         | 5s      | Time a matched connection waits for `Accept`                              | yes       |
| `WithMaxSniffBytes(n)`           | 16 KiB  | Bytes buffered for matching                                               | yes       |
| `WithMaxPending(n)`              | 4096    | Connections being matched; at the limit the oldest undecided is evicted   |           |
| `WithMaxPendingPerClient(n)`         | none    | Undelivered connections per client                                        | yes       |
| `WithRateLimitPerClient(r, b)`       | none    | New connections per second per client                                     | yes       |
| `WithRateLimitPerListener(r, b)` | none    | New connections per second per listener                                   | yes       |
| `WithBanPerClient(n, w, d)`          | none    | Bans for d a client with n failed connections within w                    | yes       |
| `WithMaxQueued(n)`       | 1024    | Matched connections waiting for one route's `Accept`                      | yes       |
| `WithObserver(fn)`               | none    | Called with an `Event` for every connection delivered or closed           |           |
| `WithProxyProtocol(policy)`      | none    | PROXY protocol v1/v2 per entry and peer                                   |           |
| `WithClientPrefix(v4, v6)`       | 32, 64  | Networks counted as one client by the per-client limits and bans          |           |
| `WithCloseEvents(on)`            | off     | An `Event` when a delivered connection closes, with duration and bytes    |           |

- `SetOptions` changes options while serving; `Config` reads them back, and
  `Entry.Config` the settings of an entry.
- Clients are IPv4 addresses and IPv6 /64 networks, or the networks of
  `WithClientPrefix`, of the TCP peer, or of the source in the PROXY header of
  a peer that `WithProxyProtocol` lets send one, so that a load balancer is
  not limited or banned for its clients. Failed
  connections that count toward bans matched no route, timed out, hit a reject
  route or sent an invalid PROXY header or none where one is required;
  `Mux.Ban`, `BanPrefix`, `Unban` and `UnbanPrefix` act by hand; `Unban`
  lifts the bans of every network that holds the address, such as a /24
  banned under a shorter prefix.
- A matched connection waiting for `Accept` holds no pending slot: the queue
  of its route, `WithMaxQueued` and `RouteConfig.MaxQueued`, and the dispatch
  timeout bound those. In a `RouteConfig`, a zero `DispatchTimeout` or
  `MaxQueued` keeps the entry's setting and a negative one removes the limit,
  while a zero `MaxConns` means no limit.
- `Entry.ResetOptions` drops one or all of an entry's settings, `Mux.Entries`
  lists the entries in use, which catches a misspelt name, and
  `Config.Options` turns settings read back into options again.
- An `Event` carries the name the client asked for, what matchers parsed and
  stored (`Event.Value`) and the TCP peer, for logs and fingerprints, and
  reports with `Banned` the failure that banned its client. With
  `WithCloseEvents(true)` the observer also hears when a delivered connection
  is closed, how long it was open and how many bytes it carried.
- Rejected connections are reported with `ErrNoMatch`, `ErrRefused`,
  `ErrSniffTimeout`, `ErrDispatchTimeout`, `ErrEvicted`, `ErrPendingLimit`,
  `ErrRateLimited`, `ErrBanned`, `ErrQueueFull`, `ErrConnLimit`,
  `ErrRouteClosed`, `ErrEntryMismatch`, a `*PanicError`, the `proxyproto`
  errors or read errors. Route configurations that are not valid fail with
  errors that wrap `ErrInvalidRoute`.

## Status

```go
func printStatus(m *portmux.Mux) {
	snap := m.Snapshot()
	for _, r := range snap.Routes {
		fmt.Printf("%-12s prio=%-4d matched=%d open=%d %s\n", r.Name, r.Priority, r.Matched, r.Open, strings.Join(r.Matchers, " | "))
	}
	for _, l := range snap.Listeners {
		fmt.Printf("%-8s %s accepted=%d rejected=%d\n", l.Entry, l.Addr, l.Stats.Accepted, l.Stats.Rejected)
	}
}
```

`Snapshot` returns the routes in matching order, the listeners and the
counters at one moment, and `Stats` breaks rejected connections down by
reason. `Mux.Bans` lists the banned clients.

## Security

| Threat                                              | Handling                                                                                        |
|-----------------------------------------------------|-------------------------------------------------------------------------------------------------|
| Scans, garbage, data too short and then silence     | Ruled out at the first impossible byte; sniff timeout; bans                                     |
| Floods of idle or slow connections                  | The pending limit, evicting the oldest undecided connection                                     |
| Floods from one client or from many                 | Rate and pending limits per client, rate limit per listener                                     |
| Heads in tiny pieces, many TLS records, HPACK bombs | Incremental parsing; bounded head and header sizes                                              |
| Ambiguous requests and names                        | Duplicate Host headers or SNI names, folded headers, control characters and names with `@` fail |
| Spoofed client addresses                            | PROXY headers only from peers the policy trusts                                                 |
| A stalled server on one route                       | Queue limit and dispatch timeout per route                                                      |
| Known scanner TLS libraries                         | A reject route with `TLS(fingerprint.MatchJA4(...))`                                            |

portmux sees established TCP connections only: SYN floods are for the kernel,
and delivered connections are the servers' to limit.

## HTTP Routing

`httproute` routes the requests on the connections that routes hand over, as
a reverse proxy does: by host, path, method and header fields, to a backend
that your dial function reaches, to a redirect or to a fixed response.

```go
// serveSites routes the HTTP and HTTPS connections of m by request.
func serveSites(m *portmux.Mux, config *tls.Config, dial httproute.DialFunc) (*httproute.Router, error) {
	headers, err := httprewrite.ParseRules(`
X-Real-IP: ${remote_addr}
X-Forwarded-Proto: ${scheme}
`, httproute.Vars())
	if err != nil {
		return nil, err
	}
	table, err := httproute.Build(httproute.Config{
		Upstreams: []httproute.Upstream{{Name: "app", Dial: dial, ResponseHeaderTimeout: 30 * time.Second}},
		Routes: []httproute.Route{
			{Name: "api", Hosts: []string{"*.example.com"}, Path: "/api", RedirectHTTPS: &httproute.HTTPSRedirect{},
				Proxy: &httproute.Proxy{Upstream: "app", ReplacePath: "/"}, RequestHeaders: headers},
			{Name: "old", Path: "/old", Redirect: &httproute.Redirect{
				To: httprewrite.MustCompile("https://${host}/new${path_rest}", httproute.Vars()), Status: 301}},
			{Name: "health", Path: "/healthz", Respond: &httproute.Respond{Body: []byte("ok")}},
		},
		ErrorPages: map[int]httproute.ErrorPage{502: {Body: []byte("<h1>Backend down</h1>")}},
	})
	if err != nil {
		return nil, err
	}
	router := httproute.New(httproute.Options{})
	if err := router.Update(table); err != nil {
		return nil, err
	}
	_, err = m.Add(portmux.RouteConfig{Name: "https", Matchers: []portmux.Matcher{portmux.TLS()},
		Handler: func(c *portmux.Conn) { _ = router.ServeConn(tls.Server(c, config)) }})
	if err != nil {
		return nil, err
	}
	_, err = m.Add(portmux.RouteConfig{Name: "http", Matchers: []portmux.Matcher{portmux.HTTP1()},
		Handler: func(c *portmux.Conn) { _ = router.ServeConn(c) }})
	return router, err
}
```

Of the routes whose host patterns match the request, and whose `Methods` and
`Headers` fit it, the router takes:

1. a route whose `Exact` path is the request's path;
2. else the first route whose `PathRegexp` (Go `regexp`, linear time)
   matches it;
3. else the route with the longest `Path` prefix, by whole segments: `/api`
   takes `/api`, `/api/v1` and `/api;v=1` but not `/apix`; `/api/` takes
   only paths below it; `/api*` is a prefix of bytes and also takes `/apix`.

Within a level, the most specific host pattern wins, as `hostmatch.Map`
ranks them: the exact name, then the longer wildcard suffix
(`*.api.example.com` before `*.example.com`), then `*`; then the route
listed first. `Hosts: ["*"]` is the same as no `Hosts`: it takes requests
without a host too. `PathRegexp` is not anchored, as nginx's `~` is not:
`/admin` matches `/public/admin-ui`, so write `^/admin$` for whole paths.

| Routes                                                      | Request                | Route                      |
|-------------------------------------------------------------|------------------------|----------------------------|
| `a.example.com` `/`, `*.example.com` `/api`                 | `a.example.com/api/x`  | `*.example.com` `/api`     |
| `a.example.com` `/api`, `*.example.com` `/api`              | `a.example.com/api`    | `a.example.com` `/api`     |
| `.example.com` `/`, `*` `/`                                 | `example.com/`         | `.example.com` `/`         |
| `*.example.com` `= /login`, `a.example.com` `/login`        | `a.example.com/login`  | `*.example.com` `= /login` |
| `a.example.com` `~ ^/u/\d+$`, `*.example.com` `~ ^/u/`      | `a.example.com/u/x`    | `*.example.com` `~ ^/u/`   |
| `*` `/img*`, `*` `/`                                        | `x.org/img2/a.png`     | `*` `/img*`                |
| `a.example.com` `/` with `Methods: POST`, `*` `/`           | `GET a.example.com/`   | `*` `/`                    |

Paths are decoded and resolved as `httphead.CleanPath` does: requests
whose path servers read differently, or that holds a control character once
decoded, get 400, and so do hosts that are not ASCII host names. The
backend gets the path the route was chosen by, with the client's escapes
where they fit, unless `Proxy.SendRawPath` is set. `CaseInsensitivePath`
serves backends that ignore case. `TLS` filters on whether the request came
over TLS, by the connection or a trusted proxy alone. `Build` refuses
routes that match the same requests as one before them for a host, and
routes that one before them hides entirely.

- `Build` checks a `Config` and returns an immutable `Table`; `Update`
  replaces the table while serving, and requests keep the table they were
  matched with. Upstreams whose settings stay the same keep their idle
  connections.
- A `DialFunc` gets the request's context and a `DialInfo` with the route,
  host and client; it is where load balancing goes. A `*StatusError` it
  returns sets the status, such as 503 for a backend that is offline;
  other errors give 502 and timeouts 504. A connection serves later
  requests of the upstream unless `DisableKeepAlives` is set.
- Header rules, redirect targets, `Proxy.PathTemplate` and the `${...}` of
  error pages are `httprewrite` variables, its own and those of `Vars`:
  `route`, `route_path`, `path_rest`, `match_1` to `match_9` (the groups
  of a `PathRegexp`) and `request_id`. Error pages escape values for HTML.
  A rule on `Host` rewrites the host; without one the client's goes on.
  Forwarding fields that clients send are dropped; rules add them, with
  the client that `Config.Resolver` finds behind trusted proxies.
- `Upstream.Addr` alone is enough to dial a backend over TCP. With `TLS`,
  the server name is `ServerName`, else the name in `Addr`, else the
  outgoing Host. `HTTP2` speaks HTTP/2 by ALPN over TLS and h2c without it,
  upgrades staying on HTTP/1.1; `ProxyProtocol` sends a PROXY header of
  version 1 or 2 with the client's address on each connection.
- `Route.BasicAuth` checks Basic credentials against hashes from
  `HashPassword` (PBKDF2-HMAC-SHA256 in a self-describing form), or a
  `Verify` function of yours. Verified credentials are remembered for
  `CacheTTL`, at most `CacheSize` of them, the least recently used dropped
  first, until the table is replaced; at most one hash per CPU runs at a
  time.
- Upgrades are limited to `Route.Upgrades`, `websocket` by default; other
  Upgrade fields and `HTTP2-Settings` are removed, so that no h2c upgrade
  gets past the routes. Plain CONNECT gets 405; WebSockets over HTTP/2
  (extended CONNECT) are routed by their path and passed to the backend
  over HTTP/1.1. `net/http` accepts them when the program starts with
  `GODEBUG=http2xconnect=1`.
- `Config.AbortNoRoute` closes the connection, or resets the HTTP/2
  stream, instead of answering 404 when no route matches.
- `${request_id}` is the `X-Request-Id` of a trusted proxy, else random.
- `Route.UpgradeIdleTimeout` closes upgraded connections, such as
  WebSockets, that carry nothing for a while.
- Hop-by-hop fields are removed; upgrades such as WebSocket, trailers,
  `Expect: 100-continue` and streaming responses pass through. With "h2" in
  the TLS config's `NextProtos`, clients may use HTTP/2.
- `ServeConn` serves a connection that a route hands over, plain or as a
  `*tls.Conn`; `Serve` serves a listener such as a route; the Router is
  also an `http.Handler`. A connection that wraps a TLS connection and has
  a `NetConn` method, such as a `*portmux.Conn` of a nested Mux, gives its
  requests the TLS state. `Route.Wrap` adds authentication, limits or
  metrics of your own, and `Options.Observer` reports every request.
- `Shutdown` and `Close` end upgraded connections too and wait for the
  requests in progress to return.

## Without a Mux

| Function                                                        | Use                                                       |
|-----------------------------------------------------------------|-----------------------------------------------------------|
| `Peek(c, m, sniffOpts...)`, `PeekAny(c, ms, sniffOpts...)`      | Sniff one connection, and tell which matcher took it      |
| `tlshello.Parse`, `httphead.Parse`, `httphead.ParseHTTP2`       | Parse the first bytes of a connection                     |
| `httphead.CleanPath`, `httphead.HasPathPrefix`                  | Resolve request paths and compare them as routes do       |
| `tlshello.Scanner`, `httphead.Scanner`, `httphead.HTTP2Scanner` | Parse as bytes arrive                                     |
| `fingerprint.JA4`, `fingerprint.JA3`                            | Fingerprint a client's TLS library                        |
| `hostmatch.Set`, `hostmatch.Map`, `ipmatch.Set`                 | Match host names and IP addresses as the routes do        |
| `NewInput`, `ParseMatcher`                                      | Run matchers on bytes of your choice; read them from text |

Parsers return `io.ErrUnexpectedEOF` while the bytes are incomplete and
`ErrInvalid` when they are not of their protocol.

## Limits

- Protocols in which the server speaks first are routed by `Silent` or by
  address, and h2c clients that wait for the server's SETTINGS by
  `HTTP2Preface`.
- TLS is told apart only by its cleartext ClientHello; with Encrypted Client
  Hello the SNI is the outer name. Nest a second Mux to route inside TLS.
- UDP is out of scope.
