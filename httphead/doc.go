// Package httphead parses the head of the first HTTP request of a
// connection, as a sniffer sees it: Parse reads an HTTP/1.x request line and
// header fields, and ParseHTTP2 the first request of a cleartext HTTP/2
// connection with prior knowledge (h2c), whose header block it decodes with
// HPACK. Both return a Request with the decoded, resolved path and the host,
// and Scanner and HTTP2Scanner parse bytes as they arrive.
//
// Ambiguous requests, such as those with several Host headers or with fields
// that hide line breaks, are invalid. The package uses only the standard
// library and does not import net/http.
package httphead
