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

A program carries only the packages it imports: the tool packages work without
a Mux, only `fingerprint` imports hash functions, and nothing imports
`net/http` or `crypto/tls`.

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
| `RemoteIP(prefixes...)`                       | Client addresses                                           |
| `LocalIP(prefixes...)`, `LocalPort(ports...)` | The address or port the client connected to                |
| `Any()`, `Always()`                           | Any client that sent a byte; every connection, unread      |
| `And`, `Or`, `Not`                            | Combinations, nested in any way                            |
| `MatcherFunc`, `Named(name, m)`               | Your own logic, with a description for `Snapshot`          |

| Filters of | Filters                                                                                                            |
|------------|--------------------------------------------------------------------------------------------------------------------|
| HTTP       | `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method`, `Header`, `HeaderRegexp`, `Query`, `WebSocket` |
| TLS        | `SNI`, `SNIRegexp`, `ALPN`, `MinTLSVersion`, `fingerprint.MatchJA4`, `fingerprint.MatchJA3`                        |

- Host patterns are exact names or contain `*` for one or more characters:
  `*.example.com`, `api-*.example.com`, `*`; `""` matches a hello or request
  without a name. Names compare case-insensitively, and names with bytes that
  no host name has, such as `@`, match nothing.
- Paths are decoded and resolved as servers resolve them, so `/public/../admin/`
  is `/admin/`, and `PathPrefix("/api")` matches `/api` and `/api/v1` but not
  `/apis`.
- Each protocol is parsed once per connection, incrementally, however many
  routes look at it.
- Address matchers and `Silent` decide without bytes, which routes protocols in
  which the server speaks first.

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
final: a longer input must get the same answer. They must not block.

## Combining Conditions

```go
func combine(m *portmux.Mux, office netip.Prefix) {
	// Every subdomain except two, and nothing under /internal/.
	m.Match(portmux.HTTP1(
		portmux.Host("*.example.com"),
		portmux.NoneOf(portmux.Host("admin.example.com", "db.example.com"), portmux.PathPrefix("/internal/")),
	))
	// (api.example.com AND /v1/) OR status.example.com.
	m.Match(portmux.HTTP1(portmux.AnyOf(
		portmux.AllOf(portmux.Host("api.example.com"), portmux.PathPrefix("/v1/")),
		portmux.Host("status.example.com"),
	)))
	// The admin site over TLS 1.2 or newer, from the office only.
	m.Match(portmux.And(
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
- `MaxConns` limits the connections a route has open at once.
- Routes can be added, changed with `SetMatchers`, `SetPriority`,
  `SetEntries` and `SetMaxConns`, and removed with `Close` at any time.
  `Batch` applies several changes at once, and `Batch.Routes` previews the
  order.
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
	m.Entry("web").SetOptions(portmux.WithSniffTimeout(5*time.Second), portmux.WithBanPerIP(10, time.Minute, time.Hour))

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
  then the pattern with the most literal characters, then `*`. `LookupFunc`
  and `Matches` fall back to wider patterns for policies of your own. Lookups
  take no lock, and allocate nothing for lowercase names and those that
  `Input` prepared.
- `ResolveHosts` and `ResolveDomain` route TLS, HTTP/1.x and h2c by the name
  the client asks for. Paths are for the HTTP server behind the route.

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
`And(office, TLS(SNI("*.example.com"), MinTLSVersion(1.2)))`, so routes can be
stored and read back. `Names` supplies your own matchers and filters, also
with arguments, such as `JA4("...")` through `fingerprint.MatchJA4`.

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
  `ProxyHeader`, `Entry` and `Route`. It keeps half-close and the fast copy
  paths of the underlying connection.
- `Serve` runs for any number of listeners, and `ServeConn` routes a connection
  obtained elsewhere. `Shutdown` waits for pending connections to be routed;
  `Close` stops at once. Neither affects delivered connections.

## PROXY Protocol

```go
// behindLoadBalancer expects PROXY headers on the entry "lb", from the
// balancer's subnet only.
func behindLoadBalancer(lb netip.Prefix) *portmux.Mux {
	return portmux.New(portmux.WithProxyProtocol(func(entry string, peer, _ net.Addr) proxyproto.Policy {
		if a, ok := peer.(*net.TCPAddr); ok && entry == "lb" && lb.Contains(a.AddrPort().Addr().Unmap()) {
			return proxyproto.Required
		}
		return proxyproto.Ignore
	}))
}
```

Headers of version 1 and 2 are removed before matching, and their addresses are
what address matchers and the `Conn` see. Allow them only from trusted peers.

## Options

```go
func newPublicMux() *portmux.Mux {
	return portmux.New(
		portmux.WithSniffTimeout(5*time.Second),
		portmux.WithMaxPendingPerIP(32),
		portmux.WithRateLimitPerIP(20, 40),
		portmux.WithBanPerIP(10, time.Minute, 10*time.Minute),
		portmux.WithObserver(func(ev portmux.Event) {
			if ev.Err != nil {
				log.Printf("%s %s: %v", ev.Entry, ev.Remote, ev.Err)
			}
		}),
	)
}

// tighten lowers the limits while serving and returns the new settings.
func tighten(m *portmux.Mux) portmux.Config {
	m.SetOptions(portmux.WithMaxPendingPerIP(4), portmux.WithRateLimitPerIP(2, 4))
	return m.Config()
}
```

| Option                           | Default | Effect                                                                    | Per entry |
|----------------------------------|---------|---------------------------------------------------------------------------|-----------|
| `WithSniffTimeout(d)`            | 10s     | Time until a route matches, not counting a wait for a pending slot        | yes       |
| `WithDispatchTimeout(d)`         | 5s      | Time a matched connection waits for `Accept`                              | yes       |
| `WithMaxSniffBytes(n)`           | 16 KiB  | Bytes buffered for matching                                               | yes       |
| `WithMaxPending(n)`              | 4096    | Undelivered connections; at the limit the oldest undecided one is evicted |           |
| `WithMaxPendingPerIP(n)`         | none    | Undelivered connections per client                                        | yes       |
| `WithRateLimitPerIP(r, b)`       | none    | New connections per second per client                                     | yes       |
| `WithRateLimitPerListener(r, b)` | none    | New connections per second per listener                                   | yes       |
| `WithBanPerIP(n, w, d)`          | none    | Bans for d a client with n failed connections within w                    | yes       |
| `WithMaxQueuedPerRoute(n)`       | 1024    | Matched connections waiting for one route's `Accept`                      | yes       |
| `WithObserver(fn)`               | none    | Called with an `Event` for every connection delivered or closed           |           |
| `WithProxyProtocol(policy)`      | none    | PROXY protocol v1/v2 per entry and peer                                   |           |

- `SetOptions` changes options while serving; `Config` reads them back, and
  `Entry.Config` the settings of an entry.
- Clients are IPv4 addresses or IPv6 /64 networks of the TCP peer. Failed
  connections that count toward bans matched no route, timed out, hit a reject
  route or sent an invalid PROXY header or none where one is required;
  `Mux.Ban` and `Unban` act by hand.
- Rejected connections are reported with `ErrNoMatch`, `ErrRefused`,
  `ErrSniffTimeout`, `ErrDispatchTimeout`, `ErrEvicted`, `ErrPendingLimit`,
  `ErrRateLimited`, `ErrBanned`, `ErrRouteBusy`, `ErrRouteFull`,
  `ErrRouteClosed`, the `proxyproto` errors or read errors.

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

## Without a Mux

| Function                                                        | Use                                                       |
|-----------------------------------------------------------------|-----------------------------------------------------------|
| `Peek(c, m, opts...)`                                           | Sniff one connection; the `Conn` replays what was read    |
| `tlshello.Parse`, `httphead.Parse`, `httphead.ParseHTTP2`       | Parse the first bytes of a connection                     |
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
