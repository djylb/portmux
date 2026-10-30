// Package hostmatch matches host names against patterns such as
// "*.example.com" and ".example.com", as nginx and Envoy choose virtual
// hosts by name: Set
// tells whether a name matches any pattern, and Map maps patterns to values
// and looks names up by specificity, the exact name first and "*" last.
// CheckPattern refuses patterns of other forms.
//
// Names compare case-insensitively and without a trailing dot, and names
// with bytes that no DNS name or IP address has match no pattern. Normalize
// prepares a name once for many matches, NormalizeHost does so for an HTTP
// Host value, and SplitHost removes its port. The package uses only the
// standard library.
package hostmatch
