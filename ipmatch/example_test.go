package ipmatch_test

import (
	"fmt"
	"net/netip"

	"github.com/djylb/portmux/ipmatch"
)

// Look addresses up in an office network list.
func ExampleSet() {
	internal := ipmatch.NewSet(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8"))
	fmt.Println(internal.Contains(netip.MustParseAddr("::ffff:10.0.0.1")), internal.Contains(netip.MustParseAddr("192.0.2.1")), internal)
	// Output: true false Set(10.0.0.0/8, fd00::/8)
}
