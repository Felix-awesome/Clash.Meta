package mitm

import (
	"net/http"
)

// RewriteHandler adapts a *Set into a Handler using only the fixed rewrite
// actions. It is the path taken when no script engine is installed.
type RewriteHandler struct {
	Set *Set
}

// ServeMITM implements Handler.
func (h *RewriteHandler) ServeMITM(req *http.Request) *http.Response {
	if h.Set == nil {
		return nil
	}
	return h.Set.RewriteRequest(req, nil)
}

// ApplyResponseHeader applies response-side rules to an upstream response.
func (h *RewriteHandler) ApplyResponseHeader(resp *http.Response) {
	if h.Set != nil {
		h.Set.RewriteResponse(resp, nil)
	}
}

// OnResponse implements Handler.
func (h *RewriteHandler) OnResponse(resp *http.Response) *http.Response {
	h.ApplyResponseHeader(resp)
	return resp
}
