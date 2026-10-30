package httproute

import (
	"cmp"
	"container/list"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultIterations is the PBKDF2 iteration count of HashPassword when it
// is given none.
const DefaultIterations = 600_000

// ErrHash reports a password hash that does not parse.
var ErrHash = errors.New("httproute: invalid password hash")

const hashPrefix = "$pbkdf2-sha256$i="

var b64 = base64.RawStdEncoding

// HashPassword hashes a password for BasicAuth.Users with PBKDF2-HMAC-SHA256,
// a random 16-byte salt and iterations rounds (DefaultIterations when 0), in
// the self-describing form "$pbkdf2-sha256$i=ROUNDS$SALT$KEY" with SALT and
// KEY in unpadded standard base64.
func HashPassword(password string, iterations int) (string, error) {
	if iterations <= 0 {
		iterations = DefaultIterations
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	return hashPrefix + strconv.Itoa(iterations) + "$" + b64.EncodeToString(salt) + "$" + b64.EncodeToString(key), nil
}

// VerifyPassword reports whether password has the hash, which
// HashPassword returned. It returns ErrHash for a hash that does not parse.
func VerifyPassword(hash, password string) (bool, error) {
	h, err := parseHash(hash)
	if err != nil {
		return false, err
	}
	return h.verify(password), nil
}

type passwordHash struct {
	iterations int
	salt, key  []byte
}

func parseHash(s string) (*passwordHash, error) {
	rest, ok := strings.CutPrefix(s, hashPrefix)
	if !ok {
		return nil, ErrHash
	}
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return nil, ErrHash
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n <= 0 {
		return nil, ErrHash
	}
	salt, err1 := b64.DecodeString(parts[1])
	key, err2 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || len(salt) == 0 || len(key) == 0 {
		return nil, ErrHash
	}
	return &passwordHash{iterations: n, salt: salt, key: key}, nil
}

func (h *passwordHash) verify(password string) bool {
	key, err := pbkdf2.Key(sha256.New, password, h.salt, h.iterations, len(h.key))
	return err == nil && subtle.ConstantTimeCompare(key, h.key) == 1
}

// basicAuth is a BasicAuth as a Table holds it. Hashing is slow by design,
// and clients send their credentials with every request, so credentials
// once verified are remembered for a while by an HMAC of them under a key
// of the table, the least recently used dropped first; and at most one hash
// per CPU is computed at a time, so that wrong passwords cannot take every
// CPU. A new table remembers nothing of the old one.
type basicAuth struct {
	challenge string
	users     map[string]*passwordHash
	dummy     *passwordHash // for unknown users, which cost as much as known ones
	verify    func(r *http.Request, user, password string) bool
	macKey    [32]byte
	cache     *authCache // nil when caching is off
	slots     chan struct{}
}

func compileAuth(a *BasicAuth) (*basicAuth, error) {
	realm := a.Realm
	if realm == "" {
		realm = "restricted"
	}
	for i := 0; i < len(realm); i++ {
		if c := realm[i]; c < ' ' && c != '\t' || c == 0x7f {
			return nil, invalid("realm %q has a control character", realm)
		}
	}
	realm = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(realm)
	b := &basicAuth{challenge: `Basic realm="` + realm + `", charset="UTF-8"`, verify: a.Verify,
		slots: make(chan struct{}, runtime.GOMAXPROCS(0))}
	if a.Verify != nil {
		return b, nil
	}
	if len(a.Users) == 0 {
		return nil, invalid("basic auth without users or Verify")
	}
	b.users = make(map[string]*passwordHash, len(a.Users))
	most := 1
	for user, hash := range a.Users {
		if strings.IndexByte(user, ':') >= 0 {
			return nil, invalid("user name %q has a colon", user)
		}
		h, err := parseHash(hash)
		if err != nil {
			return nil, invalid("hash of user %q does not parse", user)
		}
		b.users[user] = h
		most = max(most, h.iterations)
	}
	b.dummy = &passwordHash{iterations: most, salt: make([]byte, 16), key: make([]byte, sha256.Size)}
	if a.CacheTTL < 0 {
		return nil, invalid("negative CacheTTL")
	}
	if a.CacheSize >= 0 {
		b.cache = &authCache{size: cmp.Or(a.CacheSize, 1024), ttl: cmp.Or(a.CacheTTL, 5*time.Minute),
			index: map[[32]byte]*list.Element{}, order: list.New()}
	}
	_, _ = rand.Read(b.macKey[:])
	return b, nil
}

// check reports whether the request has valid credentials; it returns
// false also when the request's context ends while it waits for a slot.
func (b *basicAuth) check(r *http.Request) bool {
	user, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if b.verify != nil {
		return b.verify(r, user, password)
	}
	mac := hmac.New(sha256.New, b.macKey[:])
	mac.Write([]byte(user))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	var id [32]byte
	mac.Sum(id[:0])
	if b.cache.has(id) {
		return true
	}
	select {
	case b.slots <- struct{}{}:
	case <-r.Context().Done():
		return false
	}
	h, known := b.users[user]
	if !known {
		h = b.dummy
	}
	ok = h.verify(password) && known
	// Every check costs the rounds of the slowest hash, so that the time
	// of a check tells nothing about the user.
	if extra := b.dummy.iterations - h.iterations; extra > 0 {
		_, _ = pbkdf2.Key(sha256.New, password, b.dummy.salt, extra, sha256.Size)
	}
	<-b.slots
	if ok {
		b.cache.add(id)
	}
	return ok
}

// authCache remembers verified credentials, at most size of them, each for
// ttl, dropping the least recently used when full.
type authCache struct {
	size  int
	ttl   time.Duration
	mu    sync.Mutex
	index map[[32]byte]*list.Element
	order *list.List // of *cached, most recently used first
}

type cached struct {
	id      [32]byte
	expires time.Time
}

func (c *authCache) has(id [32]byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.index[id]
	if e == nil {
		return false
	}
	if time.Now().After(e.Value.(*cached).expires) {
		c.order.Remove(e)
		delete(c.index, id)
		return false
	}
	c.order.MoveToFront(e)
	return true
}

func (c *authCache) add(id [32]byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	expires := time.Now().Add(c.ttl)
	if e := c.index[id]; e != nil {
		e.Value.(*cached).expires = expires
		c.order.MoveToFront(e)
		return
	}
	c.index[id] = c.order.PushFront(&cached{id: id, expires: expires})
	for c.order.Len() > c.size {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.index, last.Value.(*cached).id)
	}
}

// authHandler runs the route's authentication before next.
type authHandler struct {
	auth *basicAuth
	next http.Handler
}

func (a authHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if a.auth.check(req) {
		a.next.ServeHTTP(w, req)
		return
	}
	w.Header().Set("Www-Authenticate", a.auth.challenge)
	if rs := stateOf(req.Context()); rs != nil {
		writeError(w, req, rs, http.StatusUnauthorized)
	} else {
		writePlainError(w, req, http.StatusUnauthorized)
	}
}
