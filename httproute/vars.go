package httproute

import (
	"math/rand/v2"
	"strconv"

	"github.com/djylb/netx/httprewrite"
)

// Vars returns the variables that templates of routes may use besides the
// built-in ones of httprewrite, for compiling rules and redirect targets:
//
//	route        the name of the route
//	route_path   the route's Path
//	path_rest    the decoded path after the route's Path, such as "/v1"
//	             for "/api/v1" under "/api"; the whole path for a
//	             PathRegexp route
//	match_1 ...  the groups of a PathRegexp's match, up to match_9
//	request_id   the X-Request-Id of a trusted proxy (Config.Resolver),
//	             else 16 random hexadecimal digits; the same for every
//	             template of one request
//
// They are empty in templates expanded by others than a Router.
func Vars() httprewrite.Vars {
	v := httprewrite.Vars{
		"request_id": func(dst []byte, c *httprewrite.Context) []byte {
			if rs, ok := c.Data.(*reqState); ok {
				dst = append(dst, rs.requestID()...)
			}
			return dst
		},
		"route": func(dst []byte, c *httprewrite.Context) []byte {
			if rs, ok := c.Data.(*reqState); ok && rs.route != nil {
				dst = append(dst, rs.route.name...)
			}
			return dst
		},
		"route_path": func(dst []byte, c *httprewrite.Context) []byte {
			if rs, ok := c.Data.(*reqState); ok && rs.route != nil {
				dst = append(dst, rs.route.path...)
			}
			return dst
		},
		"path_rest": func(dst []byte, c *httprewrite.Context) []byte {
			if rs, ok := c.Data.(*reqState); ok && rs.route != nil && len(rs.path) >= len(rs.route.path) {
				dst = append(dst, rs.path[len(rs.route.path):]...)
			}
			return dst
		},
	}
	for i := 1; i <= 9; i++ {
		v["match_"+strconv.Itoa(i)] = func(dst []byte, c *httprewrite.Context) []byte {
			if rs, ok := c.Data.(*reqState); ok && 2*i+1 < len(rs.groups) && rs.groups[2*i] >= 0 {
				dst = append(dst, rs.path[rs.groups[2*i]:rs.groups[2*i+1]]...)
			}
			return dst
		}
	}
	return v
}

// requestID returns the request's id, made when first asked for.
func (rs *reqState) requestID() string {
	if rs.id == "" && rs.inboundID != "" {
		rs.id = rs.inboundID
	}
	if rs.id == "" {
		const digits = "0123456789abcdef"
		var b [16]byte
		x := rand.Uint64()
		for i := range b {
			b[i] = digits[x>>(4*i)&0xf]
		}
		rs.id = string(b[:])
	}
	return rs.id
}

// validRequestID returns id when it is 1 to 128 visible ASCII characters,
// else "".
func validRequestID(id string) string {
	if len(id) == 0 || len(id) > 128 {
		return ""
	}
	for i := 0; i < len(id); i++ {
		if id[i] <= ' ' || id[i] >= 0x7f {
			return ""
		}
	}
	return id
}
