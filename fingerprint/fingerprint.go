package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/djylb/portmux/tlshello"
)

// JA4 returns the JA4 fingerprint of a ClientHello, as in
// "t13d1516h2_8daaf6152771_e5627efa2ab1", which identifies the TLS library
// of a client whatever the order of its extensions.
func JA4(h *tlshello.Hello) string {
	a := ja4A(h)
	var cipherBuf, extBuf, schemeBuf [64]uint16
	ciphers := appendWithoutGREASE(cipherBuf[:0], h.CipherSuites)
	slices.Sort(ciphers)
	exts := appendWithoutGREASE(extBuf[:0], h.Extensions)
	exts = slices.DeleteFunc(exts, func(t uint16) bool { return t == tlshello.ExtensionServerName || t == tlshello.ExtensionALPN })
	slices.Sort(exts)

	out := make([]byte, 0, len(a)+2*(1+ja4HashLen))
	out = append(append(out, a[:]...), '_')
	var in [512]byte
	out = appendJA4Hash(out, appendHexList(in[:0], ciphers))
	out = append(out, '_')
	if len(exts) == 0 {
		out = appendJA4Hash(out, nil)
	} else {
		b := appendHexList(in[:0], exts)
		if schemes := appendWithoutGREASE(schemeBuf[:0], h.SignatureSchemes); len(schemes) > 0 {
			b = appendHexList(append(b, '_'), schemes)
		}
		out = appendJA4Hash(out, b)
	}
	return string(out)
}

// ja4A returns the first part of JA4: the protocol, version, SNI flag,
// counts and ALPN, as in "t13d1516h2".
func ja4A(h *tlshello.Hello) [10]byte {
	a := [10]byte{'t', '0', '0', 'i'}
	switch v := h.MaxVersion(); v {
	case 0x0304, 0x0303, 0x0302, 0x0301:
		a[1], a[2] = '1', byte('0'+v-0x0301)
	case 0x0300:
		a[1], a[2] = 's', '3'
	case 0x0002:
		a[1], a[2] = 's', '2'
	}
	if slices.Contains(h.Extensions, tlshello.ExtensionServerName) {
		a[3] = 'd'
	}
	nc, ne := min(countWithoutGREASE(h.CipherSuites), 99), min(countWithoutGREASE(h.Extensions), 99)
	a[4], a[5], a[6], a[7] = byte('0'+nc/10), byte('0'+nc%10), byte('0'+ne/10), byte('0'+ne%10)
	a[8], a[9] = ja4ALPN(h.ALPN)
	return a
}

// ja4ALPN returns the first and last characters of the first protocol, or
// of its hex form when they are not alphanumeric.
func ja4ALPN(alpn []string) (byte, byte) {
	if len(alpn) == 0 || alpn[0] == "" {
		return '0', '0'
	}
	p := alpn[0]
	first, last := p[0], p[len(p)-1]
	if !isAlnum(first) || !isAlnum(last) {
		const digits = "0123456789abcdef"
		return digits[first>>4], digits[last&0xf]
	}
	return first, last
}

func isAlnum(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// ja4HashLen is the length of the truncated hashes of JA4.
const ja4HashLen = 12

// appendJA4Hash appends the first 12 hex digits of the SHA-256 of b, or zeros
// for nothing.
func appendJA4Hash(dst, b []byte) []byte {
	if len(b) == 0 {
		return append(dst, "000000000000"...)
	}
	sum := sha256.Sum256(b)
	return hex.AppendEncode(dst, sum[:ja4HashLen/2])
}

// appendHexList appends the values as four lowercase hex digits each,
// separated by commas.
func appendHexList(dst []byte, vs []uint16) []byte {
	for i, v := range vs {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = hex.AppendEncode(dst, []byte{byte(v >> 8), byte(v)})
	}
	return dst
}

// JA3 returns the JA3 fingerprint of a ClientHello, the MD5 hash of its
// version, cipher suites, extensions, groups and point formats without
// GREASE values. Clients that shuffle their extensions, as browsers do, get a
// new JA3 on every connection; JA4 does not depend on the order.
func JA3(h *tlshello.Hello) string {
	var buf [512]byte
	b := strconv.AppendUint(buf[:0], uint64(h.Version), 10)
	for _, list := range [...][]uint16{h.CipherSuites, h.Extensions, h.SupportedGroups} {
		b = append(b, ',')
		sep := false
		for _, v := range list {
			if !tlshello.IsGREASE(v) {
				if sep {
					b = append(b, '-')
				}
				b, sep = strconv.AppendUint(b, uint64(v), 10), true
			}
		}
	}
	b = append(b, ',')
	for i, f := range h.PointFormats {
		if i > 0 {
			b = append(b, '-')
		}
		b = strconv.AppendUint(b, uint64(f), 10)
	}
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func appendWithoutGREASE(dst, vs []uint16) []uint16 {
	for _, v := range vs {
		if !tlshello.IsGREASE(v) {
			dst = append(dst, v)
		}
	}
	return dst
}

func countWithoutGREASE(vs []uint16) int {
	n := 0
	for _, v := range vs {
		if !tlshello.IsGREASE(v) {
			n++
		}
	}
	return n
}

// Filter accepts ClientHellos by their fingerprint. It is a portmux.TLSFilter,
// as in portmux.TLS(fingerprint.MatchJA4("t13d1516h2_8daaf6152771_e5627efa2ab1")).
type Filter struct {
	name         string
	fingerprint  func(*tlshello.Hello) string
	fingerprints []string
	ja4          bool // whether the first part of JA4 rules hellos out cheaply
}

// MatchJA4 returns a filter that accepts ClientHellos whose JA4 fingerprint is
// one of fingerprints, for example to turn away the TLS library of a
// scanner. It describes itself as JA4("..."), the text that
// portmux.ParseMatcher reads when Names.TLSFilterFuncs supplies "JA4".
func MatchJA4(fingerprints ...string) Filter {
	return Filter{name: "JA4", fingerprint: JA4, fingerprints: slices.Clone(fingerprints), ja4: true}
}

// MatchJA3 returns a filter that accepts ClientHellos whose JA3 fingerprint is
// one of fingerprints; see MatchJA4.
func MatchJA3(fingerprints ...string) Filter {
	return Filter{name: "JA3", fingerprint: JA3, fingerprints: slices.Clone(fingerprints)}
}

// Match reports whether the fingerprint of h is one of the filter's. A JA4
// filter hashes the hello only when the first part of its fingerprint, which
// costs nothing to compute, is that of one of the filter's.
func (f Filter) Match(h *tlshello.Hello) bool {
	if f.ja4 {
		a := ja4A(h)
		found := false
		for _, fp := range f.fingerprints {
			if len(fp) >= len(a) && fp[:len(a)] == string(a[:]) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return slices.Contains(f.fingerprints, f.fingerprint(h))
}

// String describes the filter, as in JA4("t13d1516h2_8daaf6152771_e5627efa2ab1").
func (f Filter) String() string {
	quoted := make([]string, len(f.fingerprints))
	for i, fp := range f.fingerprints {
		quoted[i] = strconv.Quote(fp)
	}
	return f.name + "(" + strings.Join(quoted, ", ") + ")"
}
