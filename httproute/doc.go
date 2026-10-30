// Package httproute routes HTTP requests by host, path, method and header
// fields to actions: a reverse proxy to a backend reached through the
// caller's dial function, a redirect, or a fixed response. Routes rewrite
// paths, hosts and header fields with templates of a fixed set of
// variables, answer errors with pages of their own and pass WebSocket and
// other upgrades on.
//
// A Router serves requests from its own http.Server, on listeners such as a
// portmux route (Serve) or on single connections handed over after TLS
// termination (ServeConn), and is itself an http.Handler for servers of the
// caller. Its routes are a Table, built once from a Config and replaced as a
// whole with Router.Update while requests are served; requests read it
// without a lock and keep the table they were matched with.
//
// Of the routes whose host patterns match a request, a route is chosen in
// this order:
//
//   - a route whose Exact path is the request's path;
//   - else a route whose PathRegexp matches the path;
//   - else the route with the longest Path that the path equals or lies
//     below, by whole segments: "/api" takes "/api" and "/api/v1" but not
//     "/apis".
//
// Path prefixes end at a segment boundary, '/' or ';', unless the Path ends
// with '*', which makes it a prefix of bytes. Within each level, the route
// of the most specific host pattern wins, as hostmatch.Map ranks them: the
// exact name, then the longer wildcard suffix ("*.example.com" takes names
// below example.com at any depth, ".example.com" also example.com itself),
// then "*"; then the route that comes first in the Config. So
// "*.example.com" with Path "/api" takes "a.example.com/api/x" from
// "a.example.com" with Path "/". Build refuses routes that a route before
// them hides for a host.
//
// Routes whose methods or header fields do not fit the request are skipped
// for the next one. Paths are decoded and resolved before matching as
// httphead.CleanPath resolves them, and requests whose path or host servers
// read differently are refused with 400 Bad Request rather than guessed at;
// backends get the path the route was chosen by.
//
// Load balancing, certificates and the choice between TLS termination and
// passthrough are the caller's: a backend is whatever the caller's DialFunc
// connects to, certificates come from the caller's tls.Config, and portmux
// routes connections before they reach a Router.
package httproute
