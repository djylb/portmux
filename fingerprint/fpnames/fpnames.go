// Package fpnames lets portmux.ParseMatcher read the filters of package
// fingerprint. It is kept apart so that package fingerprint, which computes
// fingerprints, needs no portmux.
package fpnames

import (
	"errors"

	"github.com/djylb/portmux"
	"github.com/djylb/portmux/fingerprint"
)

// Register adds JA4 and JA3 to the TLS filters that portmux.ParseMatcher
// finds in names, so that rules kept as text can filter by fingerprint, as
// in TLS(JA4("t13d1516h2_8daaf6152771_e5627efa2ab1")); the matchers print as
// written. It replaces earlier functions of those names in names.
func Register(names *portmux.Names) {
	if names.TLSFilterFuncs == nil {
		names.TLSFilterFuncs = make(map[string]func(args ...string) (portmux.TLSFilter, error))
	}
	names.TLSFilterFuncs["JA4"] = func(args ...string) (portmux.TLSFilter, error) {
		if len(args) == 0 {
			return nil, errors.New("JA4 needs a fingerprint")
		}
		return fingerprint.MatchJA4(args...), nil
	}
	names.TLSFilterFuncs["JA3"] = func(args ...string) (portmux.TLSFilter, error) {
		if len(args) == 0 {
			return nil, errors.New("JA3 needs a fingerprint")
		}
		return fingerprint.MatchJA3(args...), nil
	}
}
