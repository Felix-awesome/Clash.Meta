package mitm

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// qxSampleRewrites is the "[rewrite_local]" block of the Quantumult X sample
// configuration with the leading comment markers removed. Every rule in it must
// parse, because it is the reference for the syntax this package targets.
const qxSampleRewrites = `
[rewrite_local]
^http://example\.com/resource1/1/ url reject
^http://example\.com/resource1/2/ url reject-img
^http://example\.com/resource1/3/ url reject-200
^http://example\.com/resource1/4/ url reject-dict
^http://example\.com/resource1/5/ url reject-array
^http://example\.com/resource2/ url 302 http://example.com/new-resource2/
^http://example\.com/resource3/ url 307 http://example.com/new-resource3/
^http://example\.com/resource4/ url jsonjq-response-body '.[0]'
^http://example\.com/resource4/ url request-header ^GET /resource4/ HTTP/1\.1(\r\n) request-header GET /api/ HTTP/1.1$1
^http://example\.com/resource4/ url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36$2
^http://example\.com/resource5/ url request-body "info":\[.+\],"others" request-body "info":[],"others"
^http://example\.com/resource5/ url response-body "info":\[.+\],"others" response-body "info":[],"others"
^http://example\.com/resource5/ url echo-response text/html echo-response index.html
^http://example\.com/resource5/ url echo-response text/html\r\nHeader-1: value1\r\nHeader-2: value2 echo-response index.html
^http://example\.com/resource6/ url script-response-body response-body.js
^http://example\.com/resource7/ url script-echo-response script-echo.js
^http://example\.com/resource8/ url script-response-header response-header.js
^http://example\.com/resource9/ url script-request-header request-header.js
^http://example\.com/resource10/ url script-request-body request-body.js
^http://example\.com/resource1/1/ \r\nUser-Agent: example-agent url-and-header reject
^http://example\.com/resource1/1/ ^POST url-and-header reject
`

// TestParseQuantumultXSample checks that the reference syntax parses without a
// single complaint and that the actions land where they should.
func TestParseQuantumultXSample(t *testing.T) {
	parsed, errs := Parse(qxSampleRewrites)
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(parsed.Rules) != 21 {
		t.Fatalf("got %d rules, want 21", len(parsed.Rules))
	}

	byAction := map[Action]int{}
	for _, rule := range parsed.Rules {
		byAction[rule.Action]++
	}
	want := map[Action]int{
		ActionReject:         3, // two plain rejects and the url-and-header one
		ActionRejectImg:      1,
		ActionReject200:      1,
		ActionRejectDict:     1,
		ActionRejectArray:    1,
		ActionRedirect:       2,
		ActionJSONQuery:      1,
		ActionHeaderRewrite:  2,
		ActionBodyRewrite:    2,
		ActionEcho:           2,
		ActionScriptRequest:  3, // two request scripts and the echo script
		ActionScriptResponse: 2,
	}
	for action, count := range want {
		if byAction[action] != count {
			t.Errorf("action %s: got %d rules, want %d", action, byAction[action], count)
		}
	}
}

// TestParseRedirectStatusKeepsTheCode covers 307, which the first version
// parsed as a 302.
func TestParseRedirectStatusKeepsTheCode(t *testing.T) {
	rule, err := ParseRule(`^http://x/$ url 307 https://y/`)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Status != 307 || rule.Arg != "https://y/" {
		t.Fatalf("got status %d target %q, want 307 https://y/", rule.Status, rule.Arg)
	}
}

// TestParseSemicolonCommentAndSections covers the Quantumult X comment marker
// and the section headers a pasted configuration carries.
func TestParseSemicolonCommentAndSections(t *testing.T) {
	text := `
; a comment
[general]
network_check_url = http://example.com
[filter_local]
host, example.com, direct
[rewrite_local]
;^http://example.com/off/ url reject
^http://example.com/on/ url reject
`
	parsed, errs := Parse(text)
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(parsed.Rules) != 1 {
		t.Fatalf("got %d rules, want 1: %+v", len(parsed.Rules), parsed.Rules)
	}
}

// TestParseHostnameAllowList covers the "[mitm]" section.
func TestParseHostnameAllowList(t *testing.T) {
	parsed, errs := Parse("[mitm]\npassphrase = secret\nhostname = *.example.com, api.test.io\n")
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(parsed.Hostnames) != 2 {
		t.Fatalf("got %v, want two hostnames", parsed.Hostnames)
	}

	set := NewSet()
	set.Replace(parsed.Rules)
	set.SetHostnames(parsed.Hostnames)

	if !set.ReferencesHost("www.example.com") {
		t.Error("expected www.example.com to be intercepted")
	}
	if !set.ReferencesHost("api.test.io") {
		t.Error("expected api.test.io to be intercepted")
	}
	if set.ReferencesHost("example.org") {
		t.Error("expected example.org to be left alone")
	}
}

// TestRewriteRequestHeaderRegexp covers the Quantumult X request-header form,
// where a regular expression rewrites the raw request head.
func TestRewriteRequestHeaderRegexp(t *testing.T) {
	set := mustSet(t, qxSampleRewrites)
	req := httptest.NewRequest("GET", "http://example.com/resource4/", nil)
	req.Header.Set("User-Agent", "old-agent/1.0")

	if resp := set.RewriteRequest(req, nil); resp != nil {
		t.Fatalf("unexpected terminal response: %+v", resp)
	}
	if req.URL.Path != "/api/" {
		t.Errorf("path = %q, want /api/", req.URL.Path)
	}
	if got := req.Header.Get("User-Agent"); got !=
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36" {
		t.Errorf("User-Agent = %q", got)
	}
}

// TestRewriteRequestBodyRegexp covers request-body and response-body.
func TestRewriteRequestBodyRegexp(t *testing.T) {
	set := mustSet(t, `
^http://example.com/api/ request-body "info":\[.+\],"others" request-body "info":[],"others"
^http://example.com/api/ response-body "info":\[.+\],"others" response-body "info":[],"others"
`)

	req := httptest.NewRequest("POST", "http://example.com/api/x", bodyCloser(`{"info":[1,2],"others":true}`))
	if resp := set.RewriteRequest(req, nil); resp != nil {
		t.Fatalf("unexpected terminal response: %+v", resp)
	}
	sent, ok := readBody(req.Body)
	if !ok {
		t.Fatal("request body unreadable after the rewrite")
	}
	if string(sent) != `{"info":[],"others":true}` {
		t.Errorf("request body = %s", sent)
	}

	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          bodyCloser(`{"info":[3],"others":false}`),
		ContentLength: int64(len(`{"info":[3],"others":false}`)),
		Request:       req,
	}
	set.RewriteResponse(resp, nil)
	received, _ := readBody(resp.Body)
	if string(received) != `{"info":[],"others":false}` {
		t.Errorf("response body = %s", received)
	}
}

// TestRewriteJSONQuery covers jsonjq-response-body.
func TestRewriteJSONQuery(t *testing.T) {
	set := mustSet(t, `^http://example.com/list url jsonjq-response-body '.[0]'`)

	req := httptest.NewRequest("GET", "http://example.com/list", nil)
	payload := `[{"id":1},{"id":2}]`
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{},
		Body:          bodyCloser(payload),
		ContentLength: int64(len(payload)),
		Request:       req,
	}
	set.RewriteResponse(resp, nil)

	got, _ := readBody(resp.Body)
	if string(got) != `{"id":1}` {
		t.Errorf("body = %s, want {\"id\":1}", got)
	}
}

// TestRewriteEchoResponse covers echo-response, including the extra header
// lines that may follow the content type.
func TestRewriteEchoResponse(t *testing.T) {
	dir := t.TempDir()
	page := filepath.Join(dir, "index.html")
	if err := os.WriteFile(page, []byte("<h1>local</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}

	set := mustSet(t, "^http://example.com/page url echo-response text/html\\r\\nX-Local: yes echo-response "+page)
	req := httptest.NewRequest("GET", "http://example.com/page", nil)

	resp := set.RewriteRequest(req, nil)
	if resp == nil {
		t.Fatal("echo-response did not answer the request")
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/html" {
		t.Fatalf("status %d content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Local") != "yes" {
		t.Errorf("extra header missing: %v", resp.Header)
	}
	body, _ := readBody(resp.Body)
	if string(body) != "<h1>local</h1>" {
		t.Errorf("body = %q", body)
	}
}

// TestRewriteEchoResponseMissingFileKeepsTheTunnel covers a rule pointing at a
// file that is not there: the request must fail locally, not hang.
func TestRewriteEchoResponseMissingFileKeepsTheTunnel(t *testing.T) {
	set := mustSet(t, "^http://example.com/page url echo-response text/html echo-response gone.html")
	req := httptest.NewRequest("GET", "http://example.com/page", nil)
	resp := set.RewriteRequest(req, nil)
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("response = %+v, want 404", resp)
	}
}

// TestRewriteURLAndHeader covers the url-and-header form, which only applies
// when the URL and the header block both match.
func TestRewriteURLAndHeader(t *testing.T) {
	set := mustSet(t, `
^http://example.com/a/ \r\nUser-Agent: blocked url-and-header reject
^http://example.com/b/ ^POST url-and-header reject
`)

	blocked := httptest.NewRequest("GET", "http://example.com/a/x", nil)
	blocked.Header.Set("User-Agent", "blocked")
	if resp := set.RewriteRequest(blocked, nil); resp == nil || resp.StatusCode != 404 {
		t.Fatalf("expected the url-and-header rule to answer, got %+v", resp)
	}

	allowed := httptest.NewRequest("GET", "http://example.com/a/x", nil)
	allowed.Header.Set("User-Agent", "fine")
	if resp := set.RewriteRequest(allowed, nil); resp != nil {
		t.Fatalf("expected the header mismatch to skip the rule, got %+v", resp)
	}

	post := httptest.NewRequest("POST", "http://example.com/b/x", nil)
	if resp := set.RewriteRequest(post, nil); resp == nil {
		t.Fatal("expected the method rule to answer")
	}
}

// TestRewriteResponseHeaderRegexp covers the response-header form.
func TestRewriteResponseHeaderRegexp(t *testing.T) {
	set := mustSet(t, `^http://example.com/ response-header (\r\n)Set-Cookie: .+ response-header $1`)

	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Set-Cookie": {"session=secret"}},
		Body:          bodyCloser(""),
		ContentLength: 0,
		Request:       req,
	}
	set.RewriteResponse(resp, nil)

	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Errorf("Set-Cookie = %q, want it removed", got)
	}
}

// TestScriptEchoResponseAnswersLocally covers script-echo-response and the
// Quantumult X status line a script may return.
func TestScriptEchoResponseAnswersLocally(t *testing.T) {
	set := mustSet(t, `^http://example.com/echo$ url script-echo-response echo.js`)
	handler := &ScriptHandler{
		Set:    set,
		Engine: &ScriptEngine{},
		Loader: func(ref string) string {
			return `$done({status: "HTTP/1.1 204 No Content", headers: {"X-Echo": "1"}, body: ""});`
		},
	}

	req := httptest.NewRequest("GET", "http://example.com/echo", nil)
	resp := set.RewriteRequest(req, handler)
	if resp == nil {
		t.Fatal("the echo script did not answer")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("X-Echo") != "1" {
		t.Errorf("headers = %v", resp.Header)
	}
}

// TestScriptAppliesInPlaceRequestEdits covers the common Quantumult X pattern of
// editing $request.headers and then calling $done() with nothing.
func TestScriptAppliesInPlaceRequestEdits(t *testing.T) {
	engine := &ScriptEngine{}
	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req.Header.Set("User-Agent", "old")

	result, err := engine.RunScript(`
$request.headers['User-Agent'] = 'QX/1.0';
delete $request.headers['Accept-Language'];
$done();
`, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Done == nil {
		t.Fatal("expected the edit to be reported")
	}
	headers, ok := result.Done["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers = %#v", result.Done["headers"])
	}
	if headers["User-Agent"] != "QX/1.0" {
		t.Errorf("User-Agent edit = %v", headers["User-Agent"])
	}
}

// TestScriptPrefsAlias covers $prefs, whose argument order differs from
// $persistentStore.
func TestScriptPrefsAlias(t *testing.T) {
	store := &mapStore{data: map[string]string{}}
	engine := &ScriptEngine{PersistentStore: store}

	result, err := engine.RunScript(`
$prefs.setValueForKey("v1", "k1");
$done({read: $prefs.valueForKey("k1")});
`, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Done["read"] != "v1" {
		t.Fatalf("read = %v", result.Done["read"])
	}
	if store.data["k1"] != "v1" {
		t.Fatalf("store = %v", store.data)
	}
}

// TestScriptResponseStatusCode covers the statusCode name Quantumult X uses on
// $response, alongside console.log.
func TestScriptResponseStatusCode(t *testing.T) {
	engine := &ScriptEngine{}
	resp := &http.Response{
		StatusCode: 403,
		Header:     http.Header{},
		Body:       bodyCloser("nope"),
	}
	result, err := engine.RunScript(`
console.log('status is ' + $response.statusCode);
$done({});
`, nil, resp)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Done != nil {
		if _, changed := result.Done["status"]; changed {
			t.Errorf("nothing was edited, but status was reported: %v", result.Done)
		}
	}
}

// TestScriptTaskFetch covers $task.fetch, which resolves with statusCode,
// headers and body.
func TestScriptTaskFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("remote-body"))
	}))
	defer srv.Close()

	engine := &ScriptEngine{HTTPClient: srv.Client()}
	result, err := engine.RunScript(`
$task.fetch({url: "`+srv.URL+`", method: "GET"}).then(
  function (resp) { $done({status: resp.statusCode, body: resp.body}); },
  function (err) { $done({status: 500, body: String(err)}); }
);
`, httptest.NewRequest("GET", "http://example.com/x", nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Done == nil {
		t.Fatal("expected $task.fetch to answer")
	}
	if result.Done["body"] != "remote-body" {
		t.Fatalf("body = %v", result.Done["body"])
	}
}

// TestScriptSetTimeout covers setTimeout, which scripts use to answer after a
// short delay.
func TestScriptSetTimeout(t *testing.T) {
	engine := &ScriptEngine{}
	result, err := engine.RunScript(`
setTimeout(function () { $done({status: 200, body: "late"}); }, 1);
`, httptest.NewRequest("GET", "http://example.com/x", nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Done == nil || result.Done["body"] != "late" {
		t.Fatalf("timed-out result = %#v", result)
	}
}

// mustSet compiles a rule set and fails the test on any syntax error.
func mustSet(t *testing.T, text string) *Set {
	t.Helper()
	parsed, errs := Parse(text)
	for _, err := range errs {
		t.Fatalf("parse: %v", err)
	}
	set := NewSet()
	set.Replace(parsed.Rules)
	set.SetHostnames(parsed.Hostnames)
	return set
}
