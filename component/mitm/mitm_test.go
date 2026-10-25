package mitm

import (
	"strings"
	"testing"
)

func TestParseRuleActions(t *testing.T) {
	cases := []struct {
		line   string
		action Action
	}{
		{"^https://example\\.com/ad/.*$ reject", ActionReject},
		{"^https://example\\.com/api/.*$ reject-200", ActionReject200},
		{"^https://example\\.com/.*\\.(jpg|png)$ reject-img", ActionRejectImg},
		{"^https://example\\.com/config$ reject-dict {\"ok\":true}", ActionRejectDict},
		{"^https://example\\.com/old$ 302 https://example.com/new", ActionRedirect},
		{"^https://example\\.com/.*$ request-header User-Agent FlClash/1.0", ActionHeader},
	}

	for _, c := range cases {
		rule, err := ParseRule(c.line)
		if err != nil {
			t.Fatalf("ParseRule(%q) error: %v", c.line, err)
		}
		if rule.Action != c.action {
			t.Errorf("ParseRule(%q) action = %v, want %v", c.line, rule.Action, c.action)
		}
	}
}

func TestParseRuleCommentsAndBlank(t *testing.T) {
	for _, line := range []string{"", "   ", "# comment", "// comment"} {
		rule, err := ParseRule(line)
		if err != nil {
			t.Fatalf("ParseRule(%q) unexpected error: %v", line, err)
		}
		if rule != nil {
			t.Errorf("ParseRule(%q) expected nil rule, got %+v", line, rule)
		}
	}
}

func TestParseRuleMalformed(t *testing.T) {
	if _, err := ParseRule("reject"); err == nil {
		t.Error("expected error for single-field rule")
	}
	if _, err := ParseRule("([ invalid reject"); err == nil {
		t.Error("expected error for invalid regex")
	}
	if _, err := ParseRule("^https://x$ unknown"); err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestRuleMatches(t *testing.T) {
	rule, _ := ParseRule("^https://example\\.com/ad/.*$ reject")
	if !rule.Matches("https://example.com/ad/banner?id=1") {
		t.Error("expected match for ad URL")
	}
	if rule.Matches("https://example.com/home") {
		t.Error("unexpected match for non-ad URL")
	}
}

func TestHeaderRuleRemoval(t *testing.T) {
	rule, err := ParseRule("^https://example\\.com/.*$ request-header -X-Ad-Token -")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Arg != "-X-Ad-Token" {
		t.Errorf("Arg = %q, want -X-Ad-Token", rule.Arg)
	}
}

func TestParseRulesMulti(t *testing.T) {
	text := strings.Join([]string{
		"# ad block",
		"^https://example\\.com/ad/.*$ reject",
		"",
		"^https://example\\.com/api/.*$ reject-200",
		"([ broken reject",
	}, "\n")

	rules, errs := ParseRules(text)
	if len(rules) != 2 {
		t.Errorf("got %d rules, want 2", len(rules))
	}
	if len(errs) != 1 {
		t.Errorf("got %d errors, want 1", len(errs))
	}
}

func TestCANewAndLoad(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.CertificatePEM()) == 0 {
		t.Error("empty certificate PEM")
	}

	// A loaded CA should sign certs for hosts.
	cert, key, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || key == nil {
		t.Fatal("nil leaf certificate or key")
	}
	if cert.DNSNames[0] != "example.com" {
		t.Errorf("leaf DNSNames = %v, want example.com", cert.DNSNames)
	}

	// Caching should return the same certificate.
	cert2, _, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert2 != cert {
		t.Error("expected cached certificate, got a new one")
	}
}

func TestSetMatchAndReplace(t *testing.T) {
	set := NewSet()
	rules, _ := ParseRules("^https://a\\.com/x$ reject\n^https://a\\.com/y$ reject-200")
	set.Replace(rules)

	if set.Match("https://a.com/x") == nil {
		t.Error("expected match for a.com/x")
	}
	if set.Match("https://a.com/z") != nil {
		t.Error("unexpected match for a.com/z")
	}

	if len(set.HeaderRules(TargetRequest)) != 0 {
		t.Error("expected no header rules")
	}
}

func TestEvaluateReject(t *testing.T) {
	rule, _ := ParseRule("^https://x$ reject")
	resp := evaluate(rule, "https://x")
	if resp == nil || resp.StatusCode != 404 {
		t.Errorf("reject response = %+v, want 404", resp)
	}

	rule, _ = ParseRule("^https://x$ 302 https://y")
	resp = evaluate(rule, "https://x")
	if resp == nil || resp.StatusCode != 302 || resp.Header.Get("Location") != "https://y" {
		t.Errorf("redirect response = %+v", resp)
	}
}
