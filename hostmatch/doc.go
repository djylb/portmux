// Package hostmatch matches host names against patterns such as
// "*.example.com" and ".example.com". Set tests membership. Snapshot maps
// patterns to values and looks names up by specificity, the exact name first and "*"
// last. A Snapshot is immutable: With, Without and a MapBuilder make new
// ones that share all they leave alone, so changes cost little however many
// patterns there are. Map holds a Snapshot that Set, Delete and TryEdit
// replace while lookups run. CheckPattern refuses patterns of other forms.
// RewriteLegacyPattern migrates a leading star attached to a domain into
// separate patterns for the domain and its subdomains.
//
// Names compare case-insensitively and without a trailing dot, and names
// with bytes that no DNS name or IP address has match no pattern. Normalize
// prepares a name once for many matches, NormalizeHost does so for an HTTP
// Host value, and SplitHost removes its port. The package uses only the
// standard library.
package hostmatch
