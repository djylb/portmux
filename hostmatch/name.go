package hostmatch

import "strings"

// Name is a host name prepared for matching: lowercased, without one trailing
// dot, and checked for the bytes of a DNS name or IP address. Preparing a
// name once saves the work when it is matched against many sets.
type Name struct {
	name  string
	valid bool
}

// Normalize prepares host, a bare name or IP address without a port, for
// matching; see NormalizeHost for HTTP Host values. A host that is only a dot
// is invalid, rather than the empty name of a ClientHello or request without
// one.
func Normalize(host string) Name {
	if host == "." {
		return Name{}
	}
	host = strings.TrimSuffix(host, ".")
	valid := true
	upper := false
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 0x80 || !hostTable[c] {
			valid = false
			break
		}
		upper = upper || 'A' <= c && c <= 'Z'
	}
	if valid && upper {
		host = strings.ToLower(host)
	}
	return Name{name: host, valid: valid}
}

// String returns the name, lowercased and without a trailing dot.
func (n Name) String() string { return n.name }

// Valid reports whether the name has only bytes of DNS names and IP
// addresses: letters, digits, '-', '.', '_', ':' and '%'. Invalid names
// match no pattern, so that "user@admin.example.com" cannot reach what is
// meant for another name.
func (n Name) Valid() bool { return n.valid }

// hostTable holds the bytes of DNS names and IP addresses: letters, digits,
// '-', '.', '_', and ':' and '%' for IPv6 literals.
var hostTable = func() (t [128]bool) {
	for c := 'a'; c <= 'z'; c++ {
		t[c], t[c-'a'+'A'] = true, true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for _, c := range "-._:%" {
		t[c] = true
	}
	return t
}()

// glob reports whether name matches pattern, in which each '*' stands for one
// or more bytes.
func glob(pattern, name string) bool {
	pi, ni := 0, 0
	star, end := -1, 0 // the last star, and the end of the bytes it took
	for ni < len(name) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			star, end = pi, ni+1
			pi, ni = pi+1, ni+1
		case pi < len(pattern) && pattern[pi] == name[ni]:
			pi, ni = pi+1, ni+1
		case star >= 0:
			// Let the last star take one more byte.
			end++
			pi, ni = star+1, end
		default:
			return false
		}
	}
	return pi == len(pattern)
}

// NormalizeHost prepares an HTTP Host value or URL authority for matching:
// its name as SplitHost returns it, normalized. A value with a port or
// brackets but without a name, such as ":80" or "[]", is invalid, rather than
// the empty name of a request without a Host.
func NormalizeHost(host string) Name {
	name := SplitHost(host)
	if name == "" && host != "" {
		return Name{}
	}
	return Normalize(name)
}

// SplitHost returns the name of an HTTP Host value or URL authority, without
// its port and without the brackets around an IPv6 literal.
func SplitHost(host string) string {
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			return host[1:end]
		}
		return host
	}
	if i := strings.IndexByte(host, ':'); i >= 0 && strings.IndexByte(host[i+1:], ':') < 0 {
		return host[:i]
	}
	return host
}
