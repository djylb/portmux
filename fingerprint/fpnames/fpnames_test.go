package fpnames_test

import (
	"testing"

	"github.com/djylb/portmux"
	"github.com/djylb/portmux/fingerprint/fpnames"
	"github.com/djylb/portmux/internal/testutil"
)

func TestRegister(t *testing.T) {
	var names portmux.Names
	fpnames.Register(&names)
	const text = `TLS(JA4("t13d1516h2_8daaf6152771_e5627efa2ab1"), JA3("771,4865-4866,0-23,29,0"))`
	m, err := portmux.ParseMatcher(text, &names)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.(interface{ String() string }).String(); got != text {
		t.Fatalf("parsed matcher prints %s, want %s", got, text)
	}
	ja4, err := portmux.ParseMatcher(`TLS(JA4("t13d1516h2_8daaf6152771_e5627efa2ab1"))`, &names)
	if err != nil {
		t.Fatal(err)
	}
	in := portmux.NewInput(nil, nil)
	in.SetBytes(testutil.JA4Example(), false)
	if ja4.Match(in) != portmux.Match {
		t.Fatal("parsed JA4 filter does not match its ClientHello")
	}
	if _, err := portmux.ParseMatcher(`TLS(JA4())`, &names); err == nil {
		t.Fatal("JA4 without a fingerprint accepted")
	}
}
