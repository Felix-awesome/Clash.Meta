package mitm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScriptHandlerEndToEnd wires a full rule set + script through the
// ScriptHandler and asserts a response-side body rewrite is applied.
func TestScriptHandlerEndToEnd(t *testing.T) {
	rules, errs := ParseRules("^https://example\\.com/.*$ url script-response-body my-script")
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	set := NewSet()
	set.Replace(rules)

	engine := &ScriptEngine{}
	loader := func(ref string) string {
		if ref == "my-script" {
			return `$done({body: $response.body.replace(/foo/g, "bar")});`
		}
		return ""
	}

	h := &ScriptHandler{Set: set, Engine: engine, Loader: loader}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       bodyCloser("foo foo foo"),
		Request:    httptest.NewRequest("GET", "https://example.com/api", nil),
	}

	out := h.OnResponse(resp)
	if out == nil {
		t.Fatal("OnResponse returned nil")
	}
	b, _ := readAll(out.Body)
	if string(b) != "bar bar bar" {
		t.Fatalf("expected rewritten body, got %q", string(b))
	}
}

// TestFetchRemote verifies remote subscription fetching over a local server.
func TestFetchRemote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("^https://example\\.com/.*$ reject\n"))
	}))
	defer srv.Close()

	body, err := FetchRemote(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchRemote failed: %v", err)
	}
	if !strings.Contains(body, "reject") {
		t.Fatalf("unexpected body: %q", body)
	}
}

// TestFetchRemoteNon200 verifies a non-200 status is surfaced as an error.
func TestFetchRemoteNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := FetchRemote(context.Background(), srv.URL); err == nil {
		t.Fatal("expected an error for a 404 response")
	}
}

// readAll is a tiny helper mirroring io.ReadAll for the test.
func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out, err
		}
	}
}
