package mitm

import (
	"io"
	"net/http"
	"strings"
)

// applyRequestHeader applies request-header rewrite rules to a request in
// place. A rule's Arg is the header name and Arg2 the new value; a header name
// prefixed with "-" is removed instead.
func (s *Set) applyRequestHeader(req *http.Request) {
	for _, r := range s.HeaderRules(TargetRequest) {
		name := r.Arg
		if strings.HasPrefix(name, "-") {
			req.Header.Del(name[1:])
			continue
		}
		if strings.HasPrefix(r.Arg2, "-") {
			req.Header.Del(name)
			continue
		}
		req.Header.Set(name, r.Arg2)
	}
}

// applyResponseHeader applies response-header rewrite rules in place.
func (s *Set) applyResponseHeader(resp *http.Response) {
	for _, r := range s.HeaderRules(TargetResponse) {
		name := r.Arg
		if strings.HasPrefix(name, "-") {
			resp.Header.Del(name[1:])
			continue
		}
		if strings.HasPrefix(r.Arg2, "-") {
			resp.Header.Del(name)
			continue
		}
		resp.Header.Set(name, r.Arg2)
	}
}

// evaluate returns a synthetic response for a matched non-header rule, or nil
// when the request should continue upstream.
func evaluate(rule *Rule, url string) *http.Response {
	switch rule.Action {
	case ActionReject:
		return &http.Response{
			StatusCode: 404,
			Status:     "Not Found",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Length": []string{"0"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}
	case ActionReject200:
		return &http.Response{
			StatusCode: 200,
			Status:     "OK",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Length": []string{"0"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}
	case ActionRejectImg:
		body := "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
		return &http.Response{
			StatusCode: 200,
			Status:     "OK",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"image/gif"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}
	case ActionRejectDict:
		body := rule.Arg
		if body == "" {
			body = "{}"
		}
		return jsonResponse(body)
	case ActionRejectArray:
		return jsonResponse("[]")
	case ActionRedirect:
		return &http.Response{
			StatusCode: 302,
			Status:     "Found",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Location": []string{rule.Arg}},
			Body:       io.NopCloser(strings.NewReader("")),
		}
	}
	return nil
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Status:     "OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
