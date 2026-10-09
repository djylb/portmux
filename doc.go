// Package portmux serves several protocols on one listening port by sniffing
// the first bytes of each connection and routing it to the listener or
// handler of a route.
//
// The package keeps four groups:
//
//   - Mux and routes: New creates a Mux, Serve runs it on any number of
//     listeners and ServeConn routes a connection obtained elsewhere. Every
//     route is a net.Listener whose Accept returns a *Conn, or passes its
//     connections to a Handler. Routes have a priority and an optional name,
//     and can be added, changed, paused and removed while serving, alone or
//     atomically with Batch. Entry names a group of listeners and
//     RouteConfig.Entries the entries a route serves, so ports and services
//     are set up apart. Reject routes close what they match, for block lists;
//     a fallback route takes what no route matched; a resolver route lets
//     your code choose the route from everything known about the connection,
//     and ResolveHosts and ResolveDomain do so by name through a
//     hostmatch.Map. MaxConns limits the open connections of a route.
//     Snapshot shows the listeners, routes and counters, Bans the banned
//     clients; SetOptions changes limits and timeouts while serving;
//     Shutdown and Close stop the Mux.
//   - Matchers: Prefix, Regexp, HTTP1, HTTP2, TLS, Domain, HTTP2Preface, SSH,
//     SOCKS4, SOCKS5, PostgreSQL, MQTT, RDP, OpenVPN, XMPP and DNS look at the
//     bytes; Silent routes clients that wait for the server and Always takes
//     every connection unread; RemoteIP, LocalIP and LocalPort look at the
//     addresses; And, Or and Not combine them in any nesting, and MatcherFunc
//     adds your own. HTTP1 and HTTP2 take the filters Host, HostRegexp, Path,
//     PathPrefix, PathRegexp, Method, Header, HeaderRegexp, Query and
//     WebSocket, and TLS takes SNI, SNIRegexp, ALPN and MinTLSVersion, and
//     the fingerprint filters of package fingerprint; AllOf, AnyOf and NoneOf
//     combine the filters of one protocol. Matchers and filters describe
//     themselves in the text that ParseMatcher reads, so routes can be kept
//     as text.
//   - Delivered connections: Conn replays the sniffed bytes and carries the
//     parsed ClientHello, HTTP/1 or h2c request and PROXY header, its entry
//     and the matching Route. Peek sniffs one connection without a Mux, and
//     NewInput runs matchers on bytes of your choice.
//   - Options: timeouts, buffer and pending limits with eviction of the
//     oldest undecided connection, rate limits per client and per listener,
//     bans of clients whose connections keep failing, a queue limit per
//     route, an observer of every connection, and a PROXY protocol v1/v2
//     policy per entry and peer. They can change while serving, most of them
//     can be set for one entry alone with Entry.SetOptions, and Config reads
//     them back.
//
// The parsers and sets work on their own in packages that import little:
// hostmatch matches host names, ipmatch IP addresses, tlshello parses TLS
// ClientHellos, httphead HTTP/1.x and h2c request heads, and fingerprint
// computes JA4 and JA3. PROXY protocol headers are parsed with
// github.com/djylb/netx/proxyproto.
//
// Routes are tried by priority and then in the order they were added; while
// a route needs more bytes, the routes after it wait. Matchers run before the
// first byte and after every read, share one incremental parse per
// connection, and return NeedMore until they can decide.
package portmux
