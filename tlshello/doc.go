// Package tlshello parses the TLS ClientHello that opens a TLS connection, as
// a sniffer sees it before any handshake: Parse reads it at once and Scanner
// as its bytes arrive, also when it spans several records. A Hello holds the
// server name, ALPN, versions, cipher suites, extensions in their order,
// groups, signature schemes and point formats, which routing and
// fingerprinting use.
//
// Malformed and ambiguous hellos, such as those with duplicate extensions or
// two server names, are invalid. The package uses only the standard library
// and hostmatch, and does not import crypto/tls.
package tlshello
