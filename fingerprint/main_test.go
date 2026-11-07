package fingerprint_test

import (
	"testing"

	"github.com/djylb/portmux/internal/leakcheck"
)

func TestMain(m *testing.M) { leakcheck.VerifyTestMain(m) }
