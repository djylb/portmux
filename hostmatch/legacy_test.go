package hostmatch_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/djylb/portmux/hostmatch"
)

func TestRewriteLegacyPattern(t *testing.T) {
	const (
		domain   = "example.com"
		wildcard = "*." + domain
		legacy   = "*" + domain
		partial  = "api-*." + domain
	)
	if err := hostmatch.CheckPattern(legacy); !errors.Is(err, hostmatch.ErrPattern) ||
		!strings.Contains(err.Error(), fmt.Sprintf("%q and %q", domain, wildcard)) {
		t.Fatalf("legacy diagnostic: %v", err)
	}
	patterns, err := hostmatch.RewriteLegacyPattern(legacy)
	if err != nil || !slices.Equal(patterns, []string{domain, wildcard}) {
		t.Fatalf("rewrite: %q, %v", patterns, err)
	}
	set := hostmatch.NewSet(patterns...)
	if !set.Match(domain) || !set.Match("a.b."+domain) || set.Match("foo"+domain) {
		t.Fatalf("unexpected match for %s", set)
	}
	for _, pattern := range []string{domain, wildcard, "." + domain, "", "*"} {
		want := []string{pattern}
		if got, err := hostmatch.RewriteLegacyPattern(pattern); err != nil || !slices.Equal(got, want) {
			t.Errorf("rewrite %q = %q, %v", pattern, got, err)
		}
	}
	for _, pattern := range []string{partial, "*com", "a.*.example.com", "**" + domain, "*a..example.com", "*a.example.com:80"} {
		if got, err := hostmatch.RewriteLegacyPattern(pattern); got != nil || !errors.Is(err, hostmatch.ErrInvalid) || !errors.Is(err, hostmatch.ErrPattern) {
			t.Errorf("rewrite %q = %q, %v", pattern, got, err)
		}
	}
	if err := hostmatch.CheckPattern(partial); !errors.Is(err, hostmatch.ErrPattern) ||
		!strings.Contains(err.Error(), "list exact host names") {
		t.Fatalf("partial diagnostic: %v", err)
	}
}

func ExampleRewriteLegacyPattern() {
	patterns, err := hostmatch.RewriteLegacyPattern("*example.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(patterns)
	// Output: [example.com *.example.com]
}
