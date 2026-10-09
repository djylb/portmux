// Package hostmatch matches host names against patterns such as
// "*.example.com", as virtual hosts and TLS servers choose by name: Set
// tells whether a name matches any pattern, and Map maps patterns to values
// and looks names up by specificity, the exact name first and "*" last.
//
// Names compare case-insensitively and without a trailing dot, and names
// with bytes that no DNS name or IP address has match no pattern. Normalize
// prepares a name once for many matches, and SplitHost removes the port of an
// HTTP Host value. The package uses only the standard library.
package hostmatch
