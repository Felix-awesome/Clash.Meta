package mitm

import (
	"net/http"
	"strings"
	"sync"
)

// ScriptHandler adapts a *Set plus a *ScriptEngine into a Handler, executing
// Quantumult X rewrite scripts in addition to the fixed rewrite actions.
// Scripts referenced by rule.Arg are resolved through a ScriptLoader.
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
	if h.cache == nil {
		h.cache = make(map[string]string)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
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

// requestScripts returns the script rules that match the request URL.
func (h *ScriptHandler) requestScripts(url string) []*Rule {
	if h.Set == nil {
		return nil
	}
	h.Set.mu.RLock()
	defer h.Set.mu.RUnlock()
	var out []*Rule
	for _, r := range h.Set.rules {
		if r.Action == ActionScriptRequest && r.Matches(url) {
			out = append(out, r)
		}
	}
	return out
}

// responseScripts returns the script rules that match the request URL.
func (h *ScriptHandler) responseScripts(url string) []*Rule {
	if h.Set == nil {
		return nil
	}
	h.Set.mu.RLock()
	defer h.Set.mu.RUnlock()
	var out []*Rule
	for _, r := range h.Set.rules {
		if r.Action == ActionScriptResponse && r.Matches(url) {
			out = append(out, r)
		}
	}
	return out
}

// ServeMITM implements Handler. It applies request-header rewrites, then
// request-side scripts, then the fixed short-circuit actions.
func (h *ScriptHandler) ServeMITM(req *http.Request) *http.Response {
	if h.Set == nil {
		return nil
	}

	h.Set.applyRequestHeader(req)

	url := req.URL.String()

	// Request-side scripts run before the fixed rules so a script's $done can
	// short-circuit the exchange.
	if h.Engine != nil {
		for _, r := range h.requestScripts(url) {
			src := h.scriptFor(r.Arg)
			if src == "" {
				continue
			}
			res, err := h.Engine.RunScript(src, req, nil)
			if err != nil || res == nil || res.Done == nil {
				continue
			}
			if resp := doneToResponse(res.Done); resp != nil {
				return resp
			}
			// Otherwise apply header/body rewrites from $done.
			applyDoneToRequest(req, res.Done)
		}
	}

	if rule := h.Set.Match(url); rule != nil {
		return evaluate(rule, url)
	}
	return nil
}

// OnResponse implements Handler, running response-side scripts then applying
// response-header rewrites.
func (h *ScriptHandler) OnResponse(resp *http.Response) *http.Response {
	if h.Set == nil || resp == nil || resp.Request == nil {
		return resp
	}

	url := resp.Request.URL.String()

	if h.Engine != nil {
		for _, r := range h.responseScripts(url) {
			src := h.scriptFor(r.Arg)
			if src == "" {
				continue
			}
			res, err := h.Engine.RunScript(src, resp.Request, resp)
			if err != nil || res == nil || res.Done == nil {
				continue
			}
			applyDoneToResponse(resp, res.Done)
		}
	}

	h.Set.applyResponseHeader(resp)
	return resp
}

// doneToResponse converts a $done object that asks to short-circuit (contains
// a "response" or status key) into a synthetic *http.Response, or nil.
func doneToResponse(done map[string]interface{}) *http.Response {
	status := 200
	if v, ok := done["status"]; ok {
		if n, ok := toInt(v); ok {
			status = n
		}
	}
	body := ""
	if v, ok := done["body"]; ok {
		if s, ok := v.(string); ok {
			body = s
		}
	}
	headers := http.Header{}
	if v, ok := done["headers"]; ok {
		if m, ok := v.(map[string]string); ok {
			for k, val := range m {
				headers.Set(k, val)
			}
		} else if m, ok := v.(map[string]interface{}); ok {
			for k, val := range m {
				headers.Set(k, toString(val))
			}
		}
	}
	// Only short-circuit when the script explicitly returned a response object.
	if _, hasStatus := done["status"]; hasStatus {
		resp := &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     headers,
			Body:       bodyCloser(body),
		}
		return resp
	}
	return nil
}

// applyDoneToRequest applies $done header/body rewrites to a request in place.
func applyDoneToRequest(req *http.Request, done map[string]interface{}) {
	if v, ok := done["url"]; ok {
		if s, ok := v.(string); ok && s != "" {
			if u, err := req.URL.Parse(s); err == nil {
				req.URL = u
			}
		}
	}
	if v, ok := done["headers"]; ok {
		applyHeaders(req.Header, v)
	}
	if v, ok := done["body"]; ok {
		if s, ok := v.(string); ok {
			req.Body = bodyCloser(s)
			req.ContentLength = int64(len(s))
		}
	}
}

// applyDoneToResponse applies $done header/body rewrites to a response.
func applyDoneToResponse(resp *http.Response, done map[string]interface{}) {
	if v, ok := done["status"]; ok {
		if n, ok := toInt(v); ok {
			resp.StatusCode = n
			resp.Status = http.StatusText(n)
		}
	}
	if v, ok := done["headers"]; ok {
		applyHeaders(resp.Header, v)
	}
	if v, ok := done["body"]; ok {
		if s, ok := v.(string); ok {
			resp.Body = bodyCloser(s)
			resp.ContentLength = int64(len(s))
		}
	}
}

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
