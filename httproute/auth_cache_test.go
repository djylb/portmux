package httproute

import (
	"errors"
	"testing"
)

// A zero CacheSize remembers 1024 credentials, DisableCache none, and a
// negative size is invalid.
func TestBasicAuthCacheSize(t *testing.T) {
	hash, err := HashPassword("pw", 1)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]string{"u": hash}
	b, err := compileAuth(&BasicAuth{Users: users})
	if err != nil || b.cache == nil || b.cache.size != 1024 {
		t.Fatalf("zero: %+v, %v", b, err)
	}
	if b, err = compileAuth(&BasicAuth{Users: users, DisableCache: true}); err != nil || b.cache != nil {
		t.Fatalf("disabled: %+v, %v", b, err)
	}
	if _, err = compileAuth(&BasicAuth{Users: users, CacheSize: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative: %v", err)
	}
}
