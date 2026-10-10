package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/djylb/portmux/tlshello"
)

// JA4 returns the JA4 fingerprint of a ClientHello, as in
// "t13d1516h2_8daaf6152771_e5627efa2ab1", which identifies the TLS library
// of a client whatever the order of its extensions.
func JA4(h *tlshello.Hello) string {
	version := "00"
	switch v := h.MaxVersion(); v {
	case 0x0304, 0x0303, 0x0302, 0x0301:
		version = "1" + strconv.Itoa(int(v-0x0301))
	case 0x0300:
		version = "s3"
	case 0x0002:
		version = "s2"
	}
	sni := "i"
	if slices.Contains(h.Extensions, tlshello.ExtensionServerName) {
		sni = "d"
	}
	ciphers := withoutGREASE(h.CipherSuites)
	exts := withoutGREASE(h.Extensions)
	a := fmt.Sprintf("t%s%s%02d%02d%s", version, sni, min(len(ciphers), 99), min(len(exts), 99), ja4ALPN(h.ALPN))

	slices.Sort(ciphers)
	b := ja4Hash(hexList(ciphers))
	exts = slices.DeleteFunc(exts, func(t uint16) bool { return t == tlshello.ExtensionServerName || t == tlshello.ExtensionALPN })
	slices.Sort(exts)
	c := "000000000000"
	if len(exts) > 0 {
		in := hexList(exts)
		if schemes := withoutGREASE(h.SignatureSchemes); len(schemes) > 0 {
			in += "_" + hexList(schemes)
		}
		c = ja4Hash(in)
	}
	return a + "_" + b + "_" + c
}

// ja4ALPN returns the first and last characters of the first protocol, or
// of its hex form when they are not alphanumeric.
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	p := alpn[0]
	if !isAlnum(p[0]) || !isAlnum(p[len(p)-1]) {
		p = hex.EncodeToString([]byte(p))
	}
	return string([]byte{p[0], p[len(p)-1]})
}

func isAlnum(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// hexList joins the values as four lowercase hex digits each.
func hexList(vs []uint16) string {
	b := make([]byte, 0, 5*len(vs))
	for i, v := range vs {
		if i > 0 {
			b = append(b, ',')
		}
		b = hex.AppendEncode(b, []byte{byte(v >> 8), byte(v)})
	}
	return string(b)
}

// JA3 returns the JA3 fingerprint of a ClientHello, the MD5 hash of its
// version, cipher suites, extensions, groups and point formats without
// GREASE values. Clients that shuffle their extensions, as browsers do, get a
// new JA3 on every connection; JA4 does not depend on the order.
func JA3(h *tlshello.Hello) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(h.Version)))
	for _, list := range [][]uint16{h.CipherSuites, h.Extensions, h.SupportedGroups} {
		b.WriteByte(',')
		writeDecimals(&b, withoutGREASE(list))
	}
	b.WriteByte(',')
	formats := make([]uint16, len(h.PointFormats))
	for i, f := range h.PointFormats {
		formats[i] = uint16(f)
	}
	writeDecimals(&b, formats)
	sum := md5.Sum([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func writeDecimals(b *strings.Builder, vs []uint16) {
	for i, v := range vs {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
}

func withoutGREASE(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !tlshello.IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// Filter accepts ClientHellos by their fingerprint. It is a portmux.TLSFilter,
// as in portmux.TLS(fingerprint.MatchJA4("t13d1516h2_8daaf6152771_e5627efa2ab1")).
type Filter struct {
	name         string
	fingerprint  func(*tlshello.Hello) string
	fingerprints []string
}

// MatchJA4 returns a filter that accepts ClientHellos whose JA4 fingerprint is
// one of fingerprints, for example to turn away the TLS library of a
// scanner. It describes itself as JA4("..."), the text that
// portmux.ParseMatcher reads when Names.TLSFilterFuncs supplies "JA4".
func MatchJA4(fingerprints ...string) Filter {
	return Filter{name: "JA4", fingerprint: JA4, fingerprints: slices.Clone(fingerprints)}
}

// MatchJA3 returns a filter that accepts ClientHellos whose JA3 fingerprint is
// one of fingerprints; see MatchJA4.
func MatchJA3(fingerprints ...string) Filter {
	return Filter{name: "JA3", fingerprint: JA3, fingerprints: slices.Clone(fingerprints)}
}

// Match reports whether the fingerprint of h is one of the filter's.
func (f Filter) Match(h *tlshello.Hello) bool {
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
