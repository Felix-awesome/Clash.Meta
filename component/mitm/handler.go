package mitm

import (
	"net/http"
)

// RewriteHandler adapts a *Set into a Handler, applying rewrite rules to each
// decrypted request. It is the concrete bridge between the Interceptor and a
// compiled rule set.
type RewriteHandler struct {
	Set *Set
}

// ServeMITM implements Handler. It applies request-header rules, then checks
// for a short-circuit rule match. Header rules for the response are applied
// by the caller after the upstream responds, which is handled in
// interceptor.go.
func (h *RewriteHandler) ServeMITM(req *http.Request) *http.Response {
	if h.Set == nil {
		return nil
	}

	h.Set.applyRequestHeader(req)

	url := req.URL.String()
	if rule := h.Set.Match(url); rule != nil {
		return evaluate(rule, url)
	}
	return nil
}

// ApplyResponseHeader applies response-header rules to an upstream response.
// The interceptor calls this after a successful upstream round-trip.
func (h *RewriteHandler) ApplyResponseHeader(resp *http.Response) {
	if h.Set != nil {
		h.Set.applyResponseHeader(resp)
	}
}

// OnResponse implements Handler, applying response-header rules in place and
// returning the same response.
func (h *RewriteHandler) OnResponse(resp *http.Response) *http.Response {
	h.ApplyResponseHeader(resp)
	return resp
}
