package portmux

import "github.com/djylb/portmux/hostmatch"

// Domain matches connections whose requested name, as Input.RequestedName
// returns it, matches one of the patterns: TLS ClientHellos by their SNI and
// HTTP/1.x and h2c requests by their host, so that one matcher routes a
// site's HTTPS and HTTP traffic. Patterns work as in hostmatch.Set; it is short for
// Or(TLS(SNI(patterns...)), HTTP1(Host(patterns...)),
// HTTP2(Host(patterns...))). It panics on a pattern that
// hostmatch.CheckPattern refuses.
func Domain(patterns ...string) Matcher {
	return domainMatcher{set: hostSet(patterns)}
}

// hostSet returns the set of patterns, which must pass
// hostmatch.CheckPattern; ParseMatcher checks them before.
func hostSet(patterns []string) *hostmatch.Set {
	for _, p := range patterns {
		if err := hostmatch.CheckPattern(p); err != nil {
			panic("portmux: " + err.Error())
		}
	}
	return hostmatch.NewSet(patterns...)
}

type domainMatcher struct {
	set *hostmatch.Set
}

func (d domainMatcher) Match(in *Input) Result {
	n, res := in.requestedName()
	if res != Match {
		return res
	}
	return matchIf(d.set.MatchName(n))
}

func (d domainMatcher) String() string { return call("Domain", d.set.Patterns(), quote) }

// RequestedName returns the host name the connection asks for, normalized
// as hostmatch.Normalize does: the name set with SetRequestedName, or else the
// SNI of a TLS ClientHello, or the host of an HTTP/1.x or h2c request without
// its port. The name is empty for a
// ClientHello or request without one. It returns NoMatch when the
// connection is none of these or its name is not a valid host name, and
// NeedMore until it can tell.
func (in *Input) RequestedName() (string, Result) {
	n, res := in.requestedName()
	switch {
	case res != Match:
		return "", res
	case !n.Valid():
		return "", NoMatch
	}
	return n.String(), Match
}

func (in *Input) requestedName() (hostmatch.Name, Result) {
	if in.named {
		return in.name, Match
	}
	hello, tlsRes := in.ClientHello()
	if tlsRes == Match {
		return hello.Name(), Match
	}
	req, httpRes := in.HTTPRequest()
	if httpRes == Match {
		return req.Name(), Match
	}
	req, h2Res := in.HTTP2Request()
	if h2Res == Match {
		return req.Name(), Match
	}
	if tlsRes == NeedMore || httpRes == NeedMore || h2Res == NeedMore {
		return hostmatch.Name{}, NeedMore
	}
	return hostmatch.Name{}, NoMatch
}

// ResolveHosts returns a resolver that routes connections by the name they
// ask for, as Input.RequestedName returns it, through hosts: pick is called with
// the patterns that match the name, most specific first, and their values,
// and the first route it accepts takes the connection. A nil route sends the
// connection to the resolver route itself. A route that is closed is passed
// over as pick not accepting it, so that replacing a route, by adding the
// new one, pointing hosts to it and closing the old one, sends no
// connection to the closed one. When pick accepts no pattern, the
// connection is left to the next routes.
//
// pick sees the Input too, so that a value can hold several targets, for
// example one for TLS and one for HTTP. Like a resolver, it must not block.
// Changes to hosts apply to the next decisions.
func ResolveHosts[V any](hosts *hostmatch.Map[V], pick func(in *Input, pattern string, v V) (*Route, bool)) ResolveFunc {
	if hosts == nil || pick == nil {
		panic("portmux: ResolveHosts needs a hostmatch.Map and a pick function")
	}
	return func(in *Input) (*Route, Result) {
		n, res := in.requestedName()
		if res != Match {
			return nil, res
		}
		var target *Route
		_, _, found := hosts.LookupNameFunc(n, func(pattern string, v V) bool {
			var ok bool
			target, ok = pick(in, pattern, v)
			// A closed route, such as one replaced while hosts still names
			// it, passes the name on to the next pattern.
			return ok && (target == nil || !target.isClosed())
		})
		if !found {
			return nil, NoMatch
		}
		return target, Match
	}
}

// ResolveDomain returns a resolver that routes connections by the name they
// ask for to the route of the most specific pattern of hosts; see
// ResolveHosts. A pattern whose route is nil sends the connection to the
// resolver route itself.
func ResolveDomain(hosts *hostmatch.Map[*Route]) ResolveFunc {
	return ResolveHosts(hosts, func(_ *Input, _ string, r *Route) (*Route, bool) { return r, true })
}
