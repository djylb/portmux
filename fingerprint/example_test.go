package fingerprint_test

import (
	"fmt"
	"log"

	"github.com/djylb/portmux"
	"github.com/djylb/portmux/fingerprint"
)

// Route a TLS library by its JA4 fingerprint, with the rule kept as text. The
// fingerprint, that of the example of the JA4 documentation, is Chrome's; to
// turn away a scanner, take its fingerprint from your logs and make the route
// a reject route.
func ExampleMatchJA4() {
	names := &portmux.Names{TLSFilterFuncs: map[string]func(args ...string) (portmux.TLSFilter, error){
		"JA4": func(args ...string) (portmux.TLSFilter, error) { return fingerprint.MatchJA4(args...), nil },
	}}
	chrome, err := portmux.ParseMatcher(`TLS(JA4("t13d1516h2_8daaf6152771_e5627efa2ab1"))`, names)
	if err != nil {
		log.Fatal(err)
	}
	m := portmux.New()
	defer func() { _ = m.Close() }()
	if _, err := m.Add(portmux.RouteConfig{Name: "chrome", Priority: 100, Matchers: []portmux.Matcher{chrome}}); err != nil {
		log.Fatal(err)
	}
	fmt.Println(m.Route("chrome").Matchers()[0])
	// Output: TLS(JA4("t13d1516h2_8daaf6152771_e5627efa2ab1"))
}
