package mitm

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// ScriptHandler adapts a *Set plus a *ScriptEngine into a Handler, executing
// Quantumult X rewrite scripts in addition to the fixed rewrite actions.
// Scripts referenced by rule.Arg or rule.Script are resolved through a
// ScriptLoader.
type ScriptHandler struct {
	Set    *Set
	Engine *ScriptEngine
	// Loader resolves a script reference (URL or path) to its JavaScript source.
	Loader ScriptLoader
	// cache memoizes loaded script source by reference.
	mu    sync.Mutex
	cache map[string]string
}

// ScriptLoader returns the JavaScript source for a script reference (the Arg
// of a script rule), or an empty string if it cannot be loaded.
type ScriptLoader func(ref string) string

// scriptFor returns the cached source for a rule's script reference.
func (h *ScriptHandler) scriptFor(ref string) string {
	if ref == "" {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cache == nil {
		h.cache = make(map[string]string)
	}
	if s, ok := h.cache[ref]; ok {
		return s
	}
	var s string
	if h.Loader != nil {
		s = h.Loader(ref)
	}
	h.cache[ref] = s
	return s
}

// RunScript implements ScriptRunner, resolving and executing the script a rule
// references. A rule with inline source runs that instead.
func (h *ScriptHandler) RunScript(rule *Rule, req *http.Request, resp *http.Response) (*ScriptResult, error) {
	if h.Engine == nil || rule == nil {
		return nil, nil
	}
	src := rule.Script
	if src == "" {
		src = h.scriptFor(rule.Arg)
	}
	if src == "" {
		return nil, nil
	}
	return h.Engine.RunScript(src, req, resp)
}

// ServeMITM implements Handler. The rule walk decides when scripts run, so a
// request-header script observes the headers a preceding rule already set.
func (h *ScriptHandler) ServeMITM(req *http.Request) *http.Response {
	if h.Set == nil {
		return nil
	}
	return h.Set.RewriteRequest(req, h)
}

// OnResponse implements Handler, running response-side scripts then applying
// response-side rewrites, both in rule order.
func (h *ScriptHandler) OnResponse(resp *http.Response) *http.Response {
	if h.Set != nil {
		h.Set.RewriteResponse(resp, h)
	}
	return resp
}

// doneToResponse converts a $done object that asks to answer the request into a
// synthetic *http.Response, or nil when the script only edited the request.
func doneToResponse(done map[string]interface{}) *http.Response {
	if done == nil {
		return nil
	}
	// Only an explicit status asks for a reply; a script that just rewrites
	// headers or a body leaves the exchange to the origin.
	rawStatus, hasStatus := done["status"]
	if !hasStatus {
		return nil
	}
	status := 200
	if n, ok := statusFrom(rawStatus); ok {
		status = n
	}
	body := ""
	if v, ok := done["body"]; ok {
		body = toString(v)
	}
	headers := http.Header{}
	if v, ok := done["headers"]; ok {
		applyHeaders(headers, v)
	}
	resp := syntheticResponse(status, headers, body, "")
	return resp
}

// statusFrom reads a status from either a number or a Quantumult X status line
// such as "HTTP/1.1 200 OK".
func statusFrom(value interface{}) (int, bool) {
	if n, ok := toInt(value); ok {
		return n, true
	}
	text, ok := value.(string)
	if !ok {
		return 0, false
	}
	for _, field := range strings.Fields(text) {
		if n, err := strconv.Atoi(field); err == nil && n >= 100 && n <= 599 {
			return n, true
		}
	}
	return 0, false
}

// applyDoneToRequest applies $done url, header and body rewrites to a request
// in place.
func applyDoneToRequest(req *http.Request, done map[string]interface{}) {
	if done == nil || req == nil {
		return
	}
	if v, ok := done["url"]; ok {
		if s, isString := v.(string); isString && s != "" {
			if u, err := req.URL.Parse(s); err == nil {
				req.URL = u
				if u.Host != "" {
					req.Host = u.Host
				}
			}
		}
	}
	if v, ok := done["headers"]; ok {
		applyHeaders(req.Header, v)
	}
	if v, ok := done["body"]; ok {
		setRequestBody(req, []byte(toString(v)))
	}
}

// applyDoneToResponse applies $done status, header and body rewrites to a
// response.
func applyDoneToResponse(resp *http.Response, done map[string]interface{}) {
	if done == nil || resp == nil {
		return
	}
	if v, ok := done["status"]; ok {
		if n, isNumber := statusFrom(v); isNumber {
			resp.StatusCode = n
			resp.Status = strconv.Itoa(n) + " " + http.StatusText(n)
		}
	}
	if v, ok := done["headers"]; ok {
		applyHeaders(resp.Header, v)
	}
	if v, ok := done["body"]; ok {
		setResponseBody(resp, []byte(toString(v)))
	}
}

// applyHeaders merges a script's header map into h, treating a value that
// starts with "-" as a removal, which is how Quantumult X scripts delete a
// header.
func applyHeaders(h http.Header, v interface{}) {
	switch m := v.(type) {
	case map[string]string:
		for k, val := range m {
			if strings.HasPrefix(val, "-") {
				h.Del(k)
			} else {
				h.Set(k, val)
			}
		}
	case map[string]interface{}:
		for k, val := range m {
			s := toString(val)
			if strings.HasPrefix(s, "-") {
				h.Del(k)
			} else {
				h.Set(k, s)
			}
		}
	}
}

func toString(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	case nil:
		return ""
	default:
		if s, ok := v.(interface{ String() string }); ok {
			return s.String()
		}
		return ""
	}
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case int32:
		return int(n), true
	}
	return 0, false
}
