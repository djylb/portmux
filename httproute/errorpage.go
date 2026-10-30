package httproute

import (
	"bytes"
	"html"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/djylb/netx/httprewrite"
)

// page is an ErrorPage as a Table holds it: literal text and variables.
type page struct {
	contentType string
	html        bool
	parts       []pagePart
	size        int // of the literal text
}

type pagePart struct {
	text []byte
	v    *httprewrite.Template // a single variable, or nil
}

// compilePage splits the body at ${name}, compiling each variable as a
// template of its own, so that pages are not bound to what field values
// may hold.
func compilePage(p ErrorPage, vars httprewrite.Vars) (*page, error) {
	pg := &page{contentType: p.ContentType}
	if pg.contentType == "" {
		pg.contentType = "text/html; charset=utf-8"
	}
	if mt, _, err := mime.ParseMediaType(pg.contentType); err == nil {
		pg.html = mt == "text/html" || strings.HasSuffix(mt, "+xml") || mt == "application/xhtml+xml"
	}
	body := p.Body
	var text []byte
	for len(body) > 0 {
		i := bytes.IndexByte(body, '$')
		if i < 0 || i+1 == len(body) {
			text = append(text, body...)
			break
		}
		text = append(text, body[:i]...)
		switch body[i+1] {
		case '$':
			text = append(text, '$')
			body = body[i+2:]
		case '{':
			end := bytes.IndexByte(body[i:], '}')
			if end < 0 {
				return nil, invalid("error page: unclosed ${")
			}
			t, err := httprewrite.Compile(string(body[i:i+end+1]), vars)
			if err != nil {
				return nil, invalid("error page: %v", err)
			}
			pg.parts = append(pg.parts, pagePart{text: text}, pagePart{v: t})
			pg.size += len(text)
			text = nil
			body = body[i+end+1:]
		default:
			text = append(text, '$')
			body = body[i+1:]
		}
	}
	pg.parts = append(pg.parts, pagePart{text: text})
	pg.size += len(text)
	return pg, nil
}

// render returns the page for c; variables that fail to expand are left
// empty.
func (pg *page) render(c *httprewrite.Context) []byte {
	out := make([]byte, 0, pg.size+64)
	for _, part := range pg.parts {
		out = append(out, part.text...)
		if part.v == nil {
			continue
		}
		v, err := part.v.Expand(c)
		if err != nil {
			continue
		}
		if pg.html {
			v = html.EscapeString(v)
		}
		out = append(out, v...)
	}
	return out
}

func compilePages(pages map[int]ErrorPage) (map[int]*page, error) {
	if len(pages) == 0 {
		return nil, nil
	}
	out := make(map[int]*page, len(pages))
	vars := Vars()
	for status, p := range pages {
		if status < 400 || status > 599 {
			return nil, invalid("error page for status %d, not 400 to 599", status)
		}
		pg, err := compilePage(p, vars)
		if err != nil {
			return nil, err
		}
		out[status] = pg
	}
	return out, nil
}

// writeError answers with status and the error page for it: the route's,
// the table's or a line of text.
func writeError(w http.ResponseWriter, req *http.Request, rs *reqState, status int) {
	pg := rs.errorPage(status)
	if pg == nil {
		writePlainError(w, req, status)
		return
	}
	h := w.Header()
	writeBody(w, req, status, pg.contentType, pg.render(rs.context(req, status, h)))
}

// writePlainError answers with status and a line of text, for requests
// without a table to take a page from.
func writePlainError(w http.ResponseWriter, req *http.Request, status int) {
	writeBody(w, req, status, "text/plain; charset=utf-8", []byte(strconv.Itoa(status)+" "+http.StatusText(status)+"\n"))
}

func writeBody(w http.ResponseWriter, req *http.Request, status int, contentType string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Del("Content-Encoding")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if req.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// errorPage returns the page for status: the route's, then the table's.
func (rs *reqState) errorPage(status int) *page {
	if rs.table == nil {
		return nil
	}
	if rs.route != nil {
		if p := rs.route.pages[status]; p != nil {
			return p
		}
	}
	return rs.table.errorPages[status]
}

// context returns what variables read for a response with status.
func (rs *reqState) context(req *http.Request, status int, h http.Header) *httprewrite.Context {
	return &httprewrite.Context{Request: req, Client: rs.client, Data: rs,
		Response: &http.Response{StatusCode: status, Header: h, Request: req}}
}
