package mitm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/itchyny/gojq"
	"github.com/metacubex/mihomo/constant"
)

// maxRewriteBody bounds how much of a body is held in memory while a rewrite
// or a script runs. Anything larger is forwarded untouched: a video stream is
// not something a rewrite rule can meaningfully edit, and buffering it would
// cost the connection.
const maxRewriteBody = 8 << 20

// ScriptRunner executes the script a rule references. A nil runner means
// script rules are skipped, which is how the fixed-action handler behaves when
// no engine is installed.
type ScriptRunner interface {
	RunScript(rule *Rule, req *http.Request, resp *http.Response) (*ScriptResult, error)
}

// RewriteRequest walks the rules in order and applies the request-side ones,
// returning a synthetic response when a rule answers the request itself.
//
// Quantumult X semantics are kept: every matching header or body rule applies,
// in file order, and a terminal rule stops the walk.
func (s *Set) RewriteRequest(req *http.Request, scripts ScriptRunner) *http.Response {
	if req == nil || req.URL == nil {
		return nil
	}
	rules := s.snapshotRules()
	if len(rules) == 0 {
		return nil
	}

	// Every rule is matched against the URL the client asked for, exactly as
	// Quantumult X does: a rule that rewrites the path does not change what the
	// following rules are compared against.
	url := req.URL.String()
	head := newHeadCache(func() string { return requestHead(req) })
	body := newBodyCache(req)

	for _, rule := range rules {
		if !rule.requestSide() {
			continue
		}
		if !matchesRule(rule, url, head) {
			continue
		}
		// A rule is reported once it actually runs: one whose script never
		// arrived, or whose body is too large to hold, is skipped below and
		// has not touched the exchange.
		switch rule.Action {
		case ActionHeader:
			recordHit(req.Context(), rule)
			applyHeader(req.Header, rule.Arg, rule.Arg2)
			head.invalidate()
		case ActionHeaderRewrite:
			recordHit(req.Context(), rule)
			if applyRequestHeaderRewrite(req, rule) {
				head.invalidate()
			}
		case ActionBodyRewrite, ActionJSONQuery:
			data, ok := body.get()
			if !ok {
				continue
			}
			recordHit(req.Context(), rule)
			if updated, changed := rule.rewriteBody(data); changed {
				body.set(updated)
				head.invalidate()
			}
		case ActionScriptRequest:
			if scripts == nil {
				continue
			}
			result, err := scripts.RunScript(rule, req, nil)
			if err != nil || result == nil {
				continue
			}
			recordHit(req.Context(), rule)
			if rule.Stage == StageEcho {
				if resp := doneToResponse(result.Done); resp != nil {
					return resp
				}
				continue
			}
			applyDoneToRequest(req, result.Done)
			head.invalidate()
			body.reload()
		default:
			recordHit(req.Context(), rule)
			if resp := evaluate(rule, url); resp != nil {
				return resp
			}
		}
	}
	return nil
}

// RewriteResponse walks the rules in order and applies the response-side ones
// in place.
func (s *Set) RewriteResponse(resp *http.Response, scripts ScriptRunner) {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return
	}
	rules := s.snapshotRules()
	if len(rules) == 0 {
		return
	}

	url := resp.Request.URL.String()
	// A body that cannot exist must not be invented: a 204, a 304 and the
	// answer to a HEAD all carry no payload, and reading one would block until
	// the connection times out.
	hasBody := resp.StatusCode != http.StatusNoContent &&
		resp.StatusCode != http.StatusNotModified &&
		resp.Request.Method != http.MethodHead

	head := newHeadCache(func() string { return responseHead(resp) })
	body := newResponseBodyCache(resp)

	for _, rule := range rules {
		if !rule.responseSide() {
			continue
		}
		if !matchesRule(rule, url, head) {
			continue
		}
		switch rule.Action {
		case ActionHeader:
			recordHit(resp.Request.Context(), rule)
			applyHeader(resp.Header, rule.Arg, rule.Arg2)
			head.invalidate()
		case ActionHeaderRewrite:
			recordHit(resp.Request.Context(), rule)
			if applyResponseHeaderRewrite(resp, rule) {
				head.invalidate()
			}
		case ActionBodyRewrite, ActionJSONQuery:
			if !hasBody {
				continue
			}
			data, ok := body.get()
			if !ok {
				continue
			}
			recordHit(resp.Request.Context(), rule)
			if updated, changed := rule.rewriteBody(data); changed {
				body.set(updated)
				head.invalidate()
			}
		case ActionScriptResponse:
			if scripts == nil || !hasBody {
				continue
			}
			result, err := scripts.RunScript(rule, resp.Request, resp)
			if err != nil || result == nil {
				continue
			}
			recordHit(resp.Request.Context(), rule)
			applyDoneToResponse(resp, result.Done)
			head.invalidate()
			body.reload()
		}
	}
}

// Matches reports whether the rule's URL pattern matches.
func (s *Set) snapshotRules() []*Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rules
}

// matchesRule reports whether a rule applies, rendering the header block only
// when the rule actually needs it.
func matchesRule(rule *Rule, url string, head *headCache) bool {
	if rule.HeaderPattern == nil {
		return rule.Pattern.MatchString(url)
	}
	if !rule.Pattern.MatchString(url) {
		return false
	}
	return rule.HeaderPattern.MatchString(head.get())
}

// headCache renders the raw head of an exchange at most once per rule that
// needs it, and again after a rule changed it.
type headCache struct {
	render func() string
	value  string
	valid  bool
}

func newHeadCache(render func() string) *headCache {
	return &headCache{render: render}
}

func (c *headCache) get() string {
	if !c.valid {
		c.value = c.render()
		c.valid = true
	}
	return c.value
}

func (c *headCache) invalidate() {
	c.valid = false
	c.value = ""
}

// bodyCache holds a body in memory once a rule needs it, and keeps the
// exchange re-readable afterwards. Reading is lazy: a message whose rules never
// touch the body is streamed through untouched.
type bodyCache struct {
	source  func() io.ReadCloser
	apply   func([]byte)
	restore func(io.ReadCloser)
	data    []byte
	ok      bool
	read    bool
}

func newBodyCache(req *http.Request) *bodyCache {
	return &bodyCache{
		source:  func() io.ReadCloser { return req.Body },
		apply:   func(data []byte) { setRequestBody(req, data) },
		restore: func(body io.ReadCloser) { req.Body = body },
	}
}

func newResponseBodyCache(resp *http.Response) *bodyCache {
	return &bodyCache{
		source:  func() io.ReadCloser { return resp.Body },
		apply:   func(data []byte) { setResponseBody(resp, data) },
		restore: func(body io.ReadCloser) { resp.Body = body },
	}
}

func (c *bodyCache) get() ([]byte, bool) {
	if c.read {
		return c.data, c.ok
	}
	c.read = true
	data, restored, ok := bufferBody(c.source())
	c.data, c.ok = data, ok
	if ok {
		c.apply(data)
	} else if restored != nil {
		// Too large to rewrite: put the stream back together so the exchange
		// continues untouched instead of being cut short.
		c.restore(restored)
	}
	return c.data, c.ok
}

// reload forgets the cached body after a script replaced it, so a following
// rule reads what the script produced instead of the original stream.
func (c *bodyCache) reload() {
	if !c.read {
		return
	}
	c.read, c.data, c.ok = false, nil, false
}

func (c *bodyCache) set(data []byte) {
	c.data, c.ok, c.read = data, true, true
	c.apply(data)
}

// applyHeader applies a name/value header rule. A header name prefixed with
// "-" is removed; so is a value that is just "-".
func applyHeader(h http.Header, name, value string) {
	if strings.HasPrefix(name, "-") {
		h.Del(name[1:])
		return
	}
	if value == "-" {
		h.Del(name)
		return
	}
	h.Set(name, value)
}

// requestHead renders the request line and headers the way a Quantumult X
// header rewrite sees them, so patterns written against
// "\r\nHeader: value\r\n" work unchanged.
func requestHead(req *http.Request) string {
	var b strings.Builder
	target := "/"
	if req.URL != nil {
		if uri := req.URL.RequestURI(); uri != "" {
			target = uri
		}
	}
	b.WriteString(req.Method + " " + target + " HTTP/1.1\r\n")
	if req.Host != "" {
		b.WriteString("Host: " + req.Host + "\r\n")
	}
	writeHeaderLines(&b, req.Header, req.ContentLength)
	b.WriteString("\r\n")
	return b.String()
}

// responseHead renders a status line plus headers in the same shape.
func responseHead(resp *http.Response) string {
	var b strings.Builder
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	b.WriteString(proto + " " + status + "\r\n")
	writeHeaderLines(&b, resp.Header, resp.ContentLength)
	b.WriteString("\r\n")
	return b.String()
}

// writeHeaderLines renders headers in a stable order. Go maps iterate at
// random, and a rewrite pattern that spans two headers would otherwise behave
// differently from one request to the next.
func writeHeaderLines(b *strings.Builder, h http.Header, contentLength int64) {
	names := make([]string, 0, len(h))
	for name := range h {
		if strings.EqualFold(name, "Content-Length") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range h[name] {
			b.WriteString(name + ": " + value + "\r\n")
		}
	}
	// Content-Length lives on the request or response struct, not in the
	// header map, so it is rendered last to stay visible to patterns.
	if contentLength > 0 {
		b.WriteString("Content-Length: " + strconv.FormatInt(contentLength, 10) + "\r\n")
	}
}

// applyRequestHeaderRewrite runs a regular expression over the request head and
// parses the result back, so a rule can change the request line ("GET /old" to
// "GET /api") as well as any header. It reports whether the head changed.
func applyRequestHeaderRewrite(req *http.Request, rule *Rule) bool {
	before := requestHead(req)
	after := rule.Match.ReplaceAllString(before, rule.Replace)
	if after == before {
		return false
	}
	parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(after)))
	if err != nil {
		return false
	}
	req.Method = parsed.Method
	req.Host = parsed.Host
	req.Header = parsed.Header
	if parsed.URL != nil {
		if parsed.URL.IsAbs() {
			req.URL.Scheme = parsed.URL.Scheme
			req.URL.Host = parsed.URL.Host
			req.Host = parsed.URL.Host
		}
		if parsed.URL.Path != "" {
			req.URL.Path = parsed.URL.Path
		}
		req.URL.RawPath = parsed.URL.RawPath
		req.URL.RawQuery = parsed.URL.RawQuery
	}
	return true
}

// applyResponseHeaderRewrite runs a regular expression over the status line and
// headers, then parses the result back. It reports whether the head changed.
func applyResponseHeaderRewrite(resp *http.Response, rule *Rule) bool {
	before := responseHead(resp)
	after := rule.Match.ReplaceAllString(before, rule.Replace)
	if after == before {
		return false
	}
	parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(after)), resp.Request)
	if err != nil {
		return false
	}
	resp.StatusCode = parsed.StatusCode
	resp.Status = parsed.Status
	resp.Header = parsed.Header
	// The payload was not touched, so the length stays authoritative even if a
	// rule rewrote the header; keeping them in sync avoids a broken frame.
	if resp.ContentLength >= 0 {
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	return true
}

// readBody reads a body into memory and closes it, reporting false when it is
// too large to rewrite or cannot be read. Callers that keep the exchange alive
// use bufferBody instead.
func readBody(body io.ReadCloser) ([]byte, bool) {
	if body == nil || body == http.NoBody {
		return nil, true
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxRewriteBody+1))
	if err != nil || len(data) > maxRewriteBody {
		return nil, false
	}
	return data, true
}

// bufferBody reads a body into memory. When the body is too large to rewrite it
// hands back a reader that replays what was consumed and continues with the
// rest of the stream, so the exchange can carry on untouched.
func bufferBody(body io.ReadCloser) (data []byte, restored io.ReadCloser, ok bool) {
	if body == nil || body == http.NoBody {
		return nil, http.NoBody, true
	}
	data, err := io.ReadAll(io.LimitReader(body, maxRewriteBody+1))
	if err != nil {
		return nil, body, false
	}
	if len(data) > maxRewriteBody {
		return nil, &prefixedBody{Reader: io.MultiReader(bytes.NewReader(data), body), Closer: body}, false
	}
	_ = body.Close()
	return data, bodyCloserBytes(data), true
}

// setRequestBody installs a body a rule or script produced, keeping the request
// consistent for the upstream round trip.
func setRequestBody(req *http.Request, body []byte) {
	// A body read off the wire may have been chunked; after buffering it is
	// sent with a plain length, otherwise two framings would be announced.
	req.TransferEncoding = nil
	if len(body) == 0 {
		req.Body = http.NoBody
		req.ContentLength = 0
		req.Header.Del("Content-Length")
		return
	}
	req.Body = bodyCloserBytes(body)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

// setResponseBody installs a body a rule or script produced.
func setResponseBody(resp *http.Response, body []byte) {
	resp.Body = bodyCloserBytes(body)
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	// The replacement is plain bytes, whatever the origin had encoded.
	resp.Header.Del("Content-Encoding")
	resp.Uncompressed = false
}

// evaluate returns a synthetic response for a matched terminal rule, or nil
// when the request should continue upstream.
func evaluate(rule *Rule, url string) *http.Response {
	switch rule.Action {
	case ActionReject:
		return syntheticResponse(http.StatusNotFound, nil, "", "Not Found")
	case ActionReject200:
		return syntheticResponse(http.StatusOK, nil, "", "OK")
	case ActionRejectImg:
		const transparentGif = "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
		return syntheticResponse(http.StatusOK, http.Header{"Content-Type": {"image/gif"}}, transparentGif, "OK")
	case ActionRejectDict:
		body := rule.Arg
		if body == "" {
			body = "{}"
		}
		return jsonResponse(body)
	case ActionRejectArray:
		return jsonResponse("[]")
	case ActionRedirect:
		status := rule.Status
		if status == 0 {
			status = http.StatusFound
		}
		return syntheticResponse(status, http.Header{"Location": {rule.Arg}}, "", "")
	case ActionEcho:
		return echoResponse(rule)
	}
	return nil
}

func syntheticResponse(status int, header http.Header, body string, reason string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	if reason == "" {
		reason = http.StatusText(status)
	}
	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + reason,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		ContentLength: int64(len(body)),
		Body:          bodyCloser(body),
	}
}

func jsonResponse(body string) *http.Response {
	return syntheticResponse(
		http.StatusOK,
		http.Header{"Content-Type": {"application/json; charset=utf-8"}},
		body,
		"OK",
	)
}

// echoDirectory is where echo-response looks for its body file, mirroring
// Quantumult X's script and resource folder.
func echoDirectory() string {
	if constant.Path != nil {
		return filepath.Join(constant.Path.HomeDir(), "mitm", "rewrite")
	}
	return "mitm-rewrite"
}

// echoResponse answers a request with a local file. The rule's Arg is the
// content type, optionally followed by extra header lines, and Replace is the
// file name.
func echoResponse(rule *Rule) *http.Response {
	name := strings.TrimSpace(rule.Replace)
	if name == "" {
		return syntheticResponse(http.StatusNotFound, nil, "", "")
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(echoDirectory(), filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return syntheticResponse(http.StatusNotFound, nil, "", "")
	}

	header := http.Header{}
	lines := strings.Split(rule.Arg, `\r\n`)
	contentType := strings.TrimSpace(lines[0])
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	header.Set("Content-Type", contentType)
	for _, line := range lines[1:] {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return syntheticResponse(http.StatusOK, header, string(data), "OK")
}

// runJSONQuery evaluates a jq expression against a JSON body and returns the
// encoded result, which is what Quantumult X's jsonjq rewrites put back in
// place of the original payload.
func runJSONQuery(data []byte, query *gojq.Query) ([]byte, error) {
	var input interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, err
	}
	iter := query.Run(input)
	value, ok := iter.Next()
	if !ok {
		return nil, fmt.Errorf("mitm: jq expression produced no value")
	}
	if err, isErr := value.(error); isErr {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// bodyCloserBytes returns a body reader over a byte slice.
func bodyCloserBytes(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}

// prefixedBody replays bytes already read from a stream before continuing with
// the rest of it.
type prefixedBody struct {
	io.Reader
	io.Closer
}
