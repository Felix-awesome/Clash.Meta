package mitm

import (
	"net/http/httptest"
	"testing"
)

// A rule set copied from the community repositories looks like this: the
// "[mitm]" header is gone and only a bare "hostname =" line survives, patterns
// escape their slashes, and several rules point at hosts the list never
// mentions. Every part of it has to work, because this is what users paste.
const pastedRuleSet = `hostname = mp.weixin.qq.com, api.zhihu.com, vip1.kuwo.cn, *.prod.ftl.netflix.com

# 去微信公众号广告
^https?:\/\/mp\.weixin\.qq\.com\/mp\/getappmsgad url script-response-body https://example.com/Wechat.js

# 知乎去广告
https://api.zhihu.com/(ad|drama|fringe|commercial) url reject-200

# 哔哩哔哩动画去广告（主机不在 hostname 列表里）
https://app.bilibili.com/x/v2/(splash|search/square) url reject-200

# Netflix 评分
^https?://ios[-\w]*\.prod\.ftl\.netflix\.com/iosui/user/.+path=%5B%22videos%22%2C%\d+ url script-request-header https://example.com/nf.js
`

// TestPastedRuleSetParses covers the shapes a real rule set uses: a bare
// hostname line without a section header, escaped slashes, and patterns that
// start without a caret.
func TestPastedRuleSetParses(t *testing.T) {
	parsed, errs := Parse(pastedRuleSet)
	if len(errs) > 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(parsed.Rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(parsed.Rules))
	}
	if len(parsed.Hostnames) != 4 {
		t.Fatalf("got %d hostnames, want 4: %v", len(parsed.Hostnames), parsed.Hostnames)
	}
}

// TestPastedRuleSetInterceptsHosts covers the regression this guards: the
// hostname list must not veto a rule. A host is decrypted when the list or a
// rule mentions it, which is also how Quantumult X keeps its generated list in
// sync with the rules.
func TestPastedRuleSetInterceptsHosts(t *testing.T) {
	parsed, _ := Parse(pastedRuleSet)
	set := NewSet()
	set.Replace(parsed.Rules)
	set.SetHostnames(parsed.Hostnames)

	cases := map[string]bool{
		"mp.weixin.qq.com":         true,
		"api.zhihu.com":            true,
		"app.bilibili.com":         true, // not in the list, but a rule needs it
		"ios.prod.ftl.netflix.com": true,
		"unrelated.example.com":    false,
		"api.bilibili.com":         false, // no rule and not listed
	}
	for host, want := range cases {
		if got := set.ReferencesHost(host); got != want {
			t.Errorf("ReferencesHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestPastedRuleSetRejectsOnAPathRule proves the path rule still fires end to
// end once the tunnel is selected by host.
func TestPastedRuleSetRejectsOnAPathRule(t *testing.T) {
	parsed, _ := Parse(pastedRuleSet)
	set := NewSet()
	set.Replace(parsed.Rules)
	set.SetHostnames(parsed.Hostnames)

	req := httptest.NewRequest("GET", "https://app.bilibili.com/x/v2/splash", nil)
	resp := set.RewriteRequest(req, nil)
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("reject-200 rule did not answer, got %v", resp)
	}
}
