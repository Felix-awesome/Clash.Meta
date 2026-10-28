package mitm

import (
	"regexp"
	"strings"
)

// Action is the effect a rewrite rule applies to a matched request or
// response.
type Action string

const (
	// Reject drops the request and returns a 404 to the client.
	ActionReject Action = "reject"
	// Reject200 drops the request and returns an empty 200.
	ActionReject200 Action = "reject-200"
	// RejectImg drops the request and returns a transparent 1x1 gif.
	ActionRejectImg Action = "reject-img"
	// RejectDict returns a small fixed JSON body with status 200.
	ActionRejectDict Action = "reject-dict"
	// RejectArray returns a small fixed JSON array with status 200.
	ActionRejectArray Action = "reject-array"
	// Redirect replies with a 302 to the target URL.
	ActionRedirect Action = "302"
	// Header adds, removes or replaces a header value.
	ActionHeader Action = "header"
	// ScriptRequest runs a Quantumult X script against the request.
	ActionScriptRequest Action = "script-request"
	// ScriptResponse runs a Quantumult X script against the response.
	ActionScriptResponse Action = "script-response"
)

// Target is which side of the exchange a header rule applies to.
type Target string

const (
	TargetRequest  Target = "request"
	TargetResponse Target = "response"
)

// Rule is a single rewrite directive, mirroring Quantumult X's rewrite
// syntax as closely as practical:
//
//	<pattern> <action> [<args>]
//
// Patterns are regular expressions matched against the full request URL
// (scheme://host/path?query).
type Rule struct {
	// Pattern is the compiled URL regular expression.
	Pattern *regexp.Regexp
	// Raw is the original pattern text, kept for diagnostics.
	Raw string
	// Action is the effect to apply on a match.
	Action Action
	// Target applies only to ActionHeader; otherwise empty.
	Target Target
	// Arg carries action-specific data: the redirect target for 302, the
	// header name/value for header rules, or the literal body for reject-dict.
	Arg string
	// Arg2 is the replacement value for header rules (arg is the header name).
	Arg2 string
	// Script is the JavaScript source to run for script-request/script-response
	// rules. It may be set directly (inline script) or loaded by the caller.
	Script string
}

// ParseRule compiles a single rewrite line into a Rule. It returns an error
// for malformed input so a bad subscription line can be skipped rather than
// breaking the whole set.
func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil, nil
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, &parseError{line, "expected at least a pattern and an action"}
	}

	pattern, err := regexp.Compile(fields[0])
	if err != nil {
		return nil, &parseError{line, "invalid pattern: " + err.Error()}
	}

	rule := &Rule{Pattern: pattern, Raw: fields[0]}

	// Quantumult X writes script rewrites as "<pattern> url <action> <args>";
	// accept and drop the optional "url" marker so both the native FlClash
	// form ("<pattern> <action> <args>") and QX form parse identically.
	if fields[1] == "url" {
		fields = fields[1:]
	}

	switch fields[1] {
	case "reject":
		rule.Action = ActionReject
	case "reject-200":
		rule.Action = ActionReject200
	case "reject-img":
		rule.Action = ActionRejectImg
	case "reject-dict":
		rule.Action = ActionRejectDict
		if len(fields) >= 3 {
			rule.Arg = fields[2]
		}
	case "reject-array":
		rule.Action = ActionRejectArray
	case "302":
		rule.Action = ActionRedirect
		if len(fields) < 3 {
			return nil, &parseError{line, "302 requires a redirect target"}
		}
		rule.Arg = fields[2]
	case "script-request-header", "script-request-body":
		rule.Action = ActionScriptRequest
		if len(fields) >= 3 {
			rule.Arg = fields[2]
		}
	case "script-response-header", "script-response-body":
		rule.Action = ActionScriptResponse
		if len(fields) >= 3 {
			rule.Arg = fields[2]
		}
	case "request-header", "response-header":
		rule.Action = ActionHeader
		if fields[1] == "request-header" {
			rule.Target = TargetRequest
		} else {
			rule.Target = TargetResponse
		}
		if len(fields) < 4 {
			return nil, &parseError{line, "header rule requires a name and a value"}
		}
		rule.Arg = fields[2]
		rule.Arg2 = fields[3]
	default:
		return nil, &parseError{line, "unknown action " + fields[1]}
	}

	return rule, nil
}

// Matches reports whether the rule's pattern matches the URL.
func (r *Rule) Matches(url string) bool {
	return r.Pattern.MatchString(url)
}

type parseError struct {
	line string
	msg  string
}

func (e *parseError) Error() string {
	return "mitm: bad rewrite rule \"" + e.line + "\": " + e.msg
}

// ParseRules compiles a multi-line rule set, dropping blank lines and
// comments and returning every valid rule alongside any parse errors.
func ParseRules(text string) ([]*Rule, []error) {
	var rules []*Rule
	var errs []error
	for _, line := range strings.Split(text, "\n") {
		rule, err := ParseRule(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	return rules, errs
}
