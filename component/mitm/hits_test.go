package mitm

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// observeHits installs a hit observer for one test and returns the channel it
// reports on.
func observeHits(t *testing.T) <-chan Hit {
	t.Helper()
	hits := make(chan Hit, 8)
	SetHitObserver(func(hit Hit) { hits <- hit })
	t.Cleanup(func() { SetHitObserver(nil) })
	return hits
}

// expectHit waits for one reported exchange.
func expectHit(t *testing.T, hits <-chan Hit) Hit {
	t.Helper()
	select {
	case hit := <-hits:
		return hit
	case <-time.After(3 * time.Second):
		t.Fatal("no exchange was reported")
		return Hit{}
	}
}

// interceptedExchange sends one request through a fresh interceptor over a
// real TLS connection, the way a client behind the tunnel would, and returns
// the response it read.
func interceptedExchange(
	t *testing.T,
	handler Handler,
	dial func(network, addr string) (net.Conn, error),
	request string,
) *http.Response {
	t.Helper()

	ca, err := NewCA()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		interceptor := &Interceptor{
			CA:           ca,
			Handler:      handler,
			DialUpstream: dial,
		}
		interceptor.Hijack(conn, "example.com:443")
	}()

	client, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial interceptor: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestInterceptorReportsAMatchedExchange walks a rejected request through the
// interceptor and checks the report carries the request line, the rule as it
// was written and the status the client was answered with.
func TestInterceptorReportsAMatchedExchange(t *testing.T) {
	hits := observeHits(t)

	const line = `^https://example\.com/ad/.*$ reject`
	set := NewSet()
	rules, errs := ParseRules(line)
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	set.Replace(rules)

	resp := interceptedExchange(
		t,
		&RewriteHandler{Set: set},
		func(network, addr string) (net.Conn, error) {
			return nil, io.ErrUnexpectedEOF
		},
		"GET /ad/banner HTTP/1.1\r\nHost: example.com\r\n\r\n",
	)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}

	hit := expectHit(t, hits)
	if hit.Method != http.MethodGet {
		t.Errorf("method = %q, want GET", hit.Method)
	}
	if hit.URL != "https://example.com/ad/banner" {
		t.Errorf("url = %q, want https://example.com/ad/banner", hit.URL)
	}
	if len(hit.Rules) != 1 || hit.Rules[0] != line {
		t.Errorf("rules = %v, want [%s]", hit.Rules, line)
	}
	if hit.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", hit.Status)
	}
	if hit.Download <= 0 {
		t.Errorf("download = %d, want the answered bytes", hit.Download)
	}
}

// TestInterceptorKeepsQuietWithoutAHit makes sure an intercepted request that
// no rule matches is not logged: the log is there to show rewrite hits.
func TestInterceptorKeepsQuietWithoutAHit(t *testing.T) {
	hits := observeHits(t)

	set := NewSet()
	rules, _ := ParseRules(`^https://example\.com/ad/.*$ reject`)
	set.Replace(rules)

	resp := interceptedExchange(
		t,
		&RewriteHandler{Set: set},
		func(network, addr string) (net.Conn, error) {
			return nil, io.ErrUnexpectedEOF
		},
		"GET /home HTTP/1.1\r\nHost: example.com\r\n\r\n",
	)
	// Without an upstream the exchange ends in a gateway error, which is the
	// point: a request no rule touched must not reach the log.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	select {
	case hit := <-hits:
		t.Fatalf("unexpected report: %+v", hit)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestRequestWalkRecordsItsHit checks the request-side walk reports the rule
// that answered the request.
func TestRequestWalkRecordsItsHit(t *testing.T) {
	const line = `^https://example\.com/config$ reject-dict {"ok":true}`
	set := NewSet()
	rules, _ := ParseRules(line)
	set.Replace(rules)

	req, hits := withHitLog(httptest.NewRequest(http.MethodGet, "https://example.com/config", nil))
	if resp := set.RewriteRequest(req, nil); resp == nil {
		t.Fatal("expected the rule to answer the request")
	}
	if got := hits.list(); len(got) != 1 || got[0] != line {
		t.Errorf("rules = %v, want [%s]", got, line)
	}
}

// TestResponseWalkRecordsItsHit checks a response-side rule is reported too, so
// a rule set that only rewrites bodies still shows up in the request log.
func TestResponseWalkRecordsItsHit(t *testing.T) {
	const line = `^https://example\.com/api/.*$ url response-body "foo" response-body "bar"`
	set := NewSet()
	rules, _ := ParseRules(line)
	set.Replace(rules)

	req, hits := withHitLog(httptest.NewRequest(http.MethodGet, "https://example.com/api/list", nil))
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          bodyCloser(`{"ad":"foo"}`),
		ContentLength: int64(len(`{"ad":"foo"}`)),
		Request:       req,
	}
	set.RewriteResponse(resp, nil)

	if got := hits.list(); len(got) != 1 || got[0] != line {
		t.Errorf("rules = %v, want [%s]", got, line)
	}
	body, _ := readAll(resp.Body)
	if string(body) != `{"ad":"bar"}` {
		t.Errorf("body = %q, want the rewritten body", string(body))
	}
}

// TestRuleThatCannotRunIsNotRecorded keeps the report honest: a script rule
// whose script never arrived did not rewrite anything, so it is not a hit.
func TestRuleThatCannotRunIsNotRecorded(t *testing.T) {
	set := NewSet()
	rules, _ := ParseRules(`^https://example\.com/.*$ url script-response-body missing.js`)
	set.Replace(rules)

	req, hits := withHitLog(httptest.NewRequest(http.MethodGet, "https://example.com/api/list", nil))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       bodyCloser("{}"),
		Request:    req,
	}
	set.RewriteResponse(resp, nil)

	if got := hits.list(); len(got) != 0 {
		t.Errorf("rules = %v, want none", got)
	}
}

// TestHitKeepsTheLineAsWritten checks the report carries the directive the user
// pasted, not just the pattern.
func TestHitKeepsTheLineAsWritten(t *testing.T) {
	const line = `^https://example\.com/.*  url  script-response-body  https://cdn.example.com/a.js`
	rule, err := ParseRule(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Contains(rule.Raw, "script") {
		t.Fatalf("Raw should hold the pattern only, got %q", rule.Raw)
	}
	if rule.Line != line {
		t.Errorf("Line = %q, want %q", rule.Line, line)
	}
}
