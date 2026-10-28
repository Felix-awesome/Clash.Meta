package mitm

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScriptEngineResponseBodyRewrite verifies a Quantumult X style
// script-response-body script can rewrite the response body via $done.
func TestScriptEngineResponseBodyRewrite(t *testing.T) {
	engine := &ScriptEngine{}

	script := `
var body = $response.body;
body = body.replace(/hello/g, "HELLO");
$done({body: body});
`

	resp := &http.Response{
		StatusCode: 200,
		Status:     "OK",
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("hello world, hello again")),
	}

	res, err := engine.RunScript(script, nil, resp)
	if err != nil {
		t.Fatalf("RunScript failed: %v", err)
	}
	if res == nil || res.Done == nil {
		t.Fatal("expected a $done result")
	}
	body, _ := res.Done["body"].(string)
	if body != "HELLO world, HELLO again" {
		t.Fatalf("unexpected rewritten body: %q", body)
	}
}

// TestScriptEngineRequestHeaders verifies $request exposes headers and $done
// can short-circuit with a synthetic response.
func TestScriptEngineRequestShortCircuit(t *testing.T) {
	engine := &ScriptEngine{}

	script := `
if ($request.url.indexOf("example.com") >= 0) {
  $done({status: 200, body: "blocked", headers: {"X-Blocked": "yes"}});
}
`

	req := httptest.NewRequest("GET", "https://example.com/api", nil)

	res, err := engine.RunScript(script, req, nil)
	if err != nil {
		t.Fatalf("RunScript failed: %v", err)
	}
	if res == nil || res.Done == nil {
		t.Fatal("expected a $done result")
	}
	status, ok := toInt(res.Done["status"])
	if !ok || status != 200 {
		t.Fatalf("expected status 200, got %v", res.Done["status"])
	}
}

// TestScriptEnginePersistentStore verifies $persistentStore read/write.
func TestScriptEnginePersistentStore(t *testing.T) {
	store := &mapStore{data: map[string]string{}}
	engine := &ScriptEngine{PersistentStore: store}

	script := `
$persistentStore.write("key", "value123");
$done({stored: $persistentStore.read("key")});
`

	res, err := engine.RunScript(script, nil, nil)
	if err != nil {
		t.Fatalf("RunScript failed: %v", err)
	}
	if res.Done["stored"] != "value123" {
		t.Fatalf("expected stored value, got %v", res.Done["stored"])
	}
}

// TestParseRuleScriptActions verifies the parser accepts script actions.
func TestParseRuleScriptActions(t *testing.T) {
	rules, errs := ParseRules(`
^https://example\.com/api url script-response-body https://cdn/x.js
^https://example\.com/login url script-request-header https://cdn/y.js
`)
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Action != ActionScriptResponse {
		t.Fatalf("expected script-response, got %s", rules[0].Action)
	}
	if rules[0].Arg != "https://cdn/x.js" {
		t.Fatalf("unexpected arg: %s", rules[0].Arg)
	}
	if rules[1].Action != ActionScriptRequest {
		t.Fatalf("expected script-request, got %s", rules[1].Action)
	}
}

type mapStore struct {
	data map[string]string
}

func (m *mapStore) Read(key string) (string, bool) {
	v, ok := m.data[key]
	return v, ok
}

func (m *mapStore) Write(key, value string) {
	m.data[key] = value
}
