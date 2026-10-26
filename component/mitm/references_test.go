package mitm

import "testing"

func TestReferencesHostPathRule(t *testing.T) {
	set := NewSet()
	rules, errs := ParseRules("baidu.com/mitmtest reject-200\nbaidu.com/mitmredirect 302 https://example.com/\n233t")
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 parse error (the lone token line), got %d", len(errs))
	}
	set.Replace(rules)
	cases := map[string]bool{
		"www.baidu.com": true,
		"baidu.com":     true,
		"example.com":   false,
		"qq.com":        false,
	}
	for host, want := range cases {
		if got := set.ReferencesHost(host); got != want {
			t.Errorf("ReferencesHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestInterceptGate(t *testing.T) {
	set := NewSet()
	rules, _ := ParseRules("baidu.com/mitmtest reject-200")
	set.Replace(rules)
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	Enable(true, ca, set)
	if _, ok := Intercept("www.baidu.com:443"); !ok {
		t.Fatal("expected interception for www.baidu.com:443")
	}
	if _, ok := Intercept("www.qq.com:443"); ok {
		t.Fatal("expected no interception for www.qq.com:443")
	}
	Enable(false, nil, nil)
	if _, ok := Intercept("www.baidu.com:443"); ok {
		t.Fatal("expected no interception when disabled")
	}
}
