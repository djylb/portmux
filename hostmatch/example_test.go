package hostmatch_test

import (
	"fmt"

	"github.com/djylb/portmux/hostmatch"
)

// Match names against patterns, case-insensitively and turning away names
// with bytes that no host name has.
func ExampleSet() {
	hosts := hostmatch.NewSet("*.example.com", "example.com")
	fmt.Println(hosts.Match("WWW.example.com."), hosts.Match("evil@www.example.com"), hosts.Match("example.org"))
	fmt.Println(hostmatch.SplitHost("[2001:db8::1]:443"), hostmatch.Normalize("API.Example.com."))
	// Output:
	// true false false
	// 2001:db8::1 api.example.com
}

// Look host names up by the most specific pattern.
func ExampleMap() {
	var sites hostmatch.Map[string]
	sites.Set("*.example.com", "wildcard")
	sites.Set("*.api.example.com", "api")
	sites.Set("www.example.com", "www")
	for _, host := range []string{"www.example.com", "v1.api.example.com", "blog.example.com", "example.org"} {
		site, pattern, ok := sites.Lookup(host)
		fmt.Println(host, site, pattern, ok)
	}
	// Output:
	// www.example.com www www.example.com true
	// v1.api.example.com api *.api.example.com true
	// blog.example.com wildcard *.example.com true
	// example.org   false
}

// Fall back to a wider pattern when the value of a narrower one does not
// apply, here the paths that each pattern serves.
func ExampleMap_LookupFunc() {
	var sites hostmatch.Map[[]string]
	sites.Set("www.example.com", []string{"/api"})
	sites.Set("*.example.com", []string{"/", "/static"})
	serves := func(path string) func(string, []string) bool {
		return func(_ string, paths []string) bool {
			for _, p := range paths {
				if p == path {
					return true
				}
			}
			return false
		}
	}
	_, pattern, _ := sites.LookupFunc("www.example.com", serves("/api"))
	fmt.Println(pattern)
	_, pattern, _ = sites.LookupFunc("www.example.com", serves("/static"))
	fmt.Println(pattern)
	// Output:
	// www.example.com
	// *.example.com
}
