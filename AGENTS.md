# AGENTS.md

- Before you finish, `gofmt -l .` must print nothing and `go vet ./...`,
  `go test -race ./...` and the js/wasm tests
  (`GOOS=js GOARCH=wasm go test ./...` with `$(go env GOROOT)/lib/wasm` on
  `PATH`) must pass.
- The only dependencies are github.com/djylb/netx and
  github.com/djylb/timeshim; add no other, also not for tests.
- The per-connection path adds no allocation, lock or atomic operation:
  compare `BenchmarkLoopback`, `BenchmarkDelivery` and
  `BenchmarkServeConnHandler` before and after a change.
- Treat everything a client sends as untrusted: sniffing is bounded by the
  sniff byte limit and timeout, and every parser rejects what it cannot
  read instead of guessing.
- User code (handlers, matchers, resolvers, policies, observers) never runs
  under a lock, and its panics become a `*PanicError`.
- Every exit path of a connection gives back what it holds: its pending
  slot, its client's pending count and its route's open count. Every event
  of a connection is built by the same constructors, so all carry the same
  fields.
- A connection keeps the settings it was accepted with.
- A matcher's `String` must parse back with `ParseMatcher` to an equal
  matcher.
- Tests must not leak goroutines, sockets or timers, and must not rely on OS
  socket buffer sizes.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
