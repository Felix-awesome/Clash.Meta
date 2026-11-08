package mitm

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/itchyny/gojq"
)

// Action is the effect a rewrite rule applies to a matched request or
// response. The values that coincide with a Quantumult X keyword are spelled
// the same way, which keeps diagnostics readable next to the source rule set.
type Action string

const (
	// ActionReject drops the request and returns a 404 to the client.
	ActionReject Action = "reject"
	// ActionReject200 drops the request and returns an empty 200.
	ActionReject200 Action = "reject-200"
	// ActionRejectImg drops the request and returns a transparent 1x1 gif.
	ActionRejectImg Action = "reject-img"
	// ActionRejectDict returns a small JSON body with status 200.
	ActionRejectDict Action = "reject-dict"
	// ActionRejectArray returns a small JSON array with status 200.
	ActionRejectArray Action = "reject-array"
	// ActionRedirect replies with a redirect to the target URL.
	ActionRedirect Action = "302"
	// ActionHeader adds, replaces or removes a header addressed by name.
	ActionHeader Action = "header"
	// ActionHeaderRewrite replaces a regular expression inside the raw request
	// or response head, which is how Quantumult X writes request-header and
	// response-header.
	ActionHeaderRewrite Action = "header-rewrite"
	// ActionBodyRewrite replaces a regular expression inside the body.
	ActionBodyRewrite Action = "body-rewrite"
	// ActionJSONQuery rewrites a JSON body by evaluating a jq expression
	// against it, which is Quantumult X's jsonjq-request-body and
	// jsonjq-response-body.
	ActionJSONQuery Action = "jsonjq"
	// ActionEcho answers with a local file instead of going upstream.
	ActionEcho Action = "echo-response"
	// ActionScriptRequest runs a Quantumult X script before the request is
	// sent.
	ActionScriptRequest Action = "script-request"
	// ActionScriptResponse runs a Quantumult X script after the response is
	// received.
	ActionScriptResponse Action = "script-response"
)

// Target is which side of the exchange a rule applies to.
type Target string

const (
	TargetRequest  Target = "request"
	TargetResponse Target = "response"
)

// Script stages. A Quantumult X rule set spells them out as separate actions;
// they describe when a script runs relative to the body, and the echo stages
// are the ones that answer the request themselves.
const (
	StageHeader = "header"
	StageBody   = "body"
	StageEcho   = "echo"
)

// Rule is a single rewrite directive. It covers the whole Quantumult X syntax:
//
//	<url> <action> <args>
//	<url> url <action> <args>
//	<url> <headers> url-and-header <action> <args>
//
// The optional "url" marker is accepted so that the Quantumult X form and the
// plain "<url> <action>" form parse the same way.
type Rule struct {
	// Pattern is the compiled URL regular expression.
	Pattern *regexp.Regexp
	// Raw is the original pattern text, kept for diagnostics and for deciding
	// whether a host is worth intercepting at all.
	Raw string
	// HeaderPattern is the header block expression of a url-and-header rule,
	// or nil when the rule only matches on the URL.
	HeaderPattern *regexp.Regexp
	// Action is the effect to apply on a match.
	Action Action
	// Target is the side a header, body or script rule applies to.
	Target Target
	// Arg carries the action's primary payload: the redirect target, the
	// header name of a name/value header rule, the content type of an
	// echo-response rule, the jq expression of a jsonjq rule, or the script
	// reference of a script rule.
	Arg string
	// Arg2 is the header value of a name/value header rule.
	Arg2 string
	// Match is the expression a header or body rewrite replaces.
	Match *regexp.Regexp
	// Replace is the replacement of a header or body rewrite, or the file name
	// of an echo-response rule. "$1" style group references are passed to Go's
	// regexp, which understands them.
	Replace string
	// Query is the compiled jq expression of a jsonjq rule.
	Query *gojq.Query
	// Status is the redirect status code, 302 or 307.
	Status int
	// Stage records which Quantumult X script action produced the rule.
	Stage string
	// Script is the JavaScript source to run for script rules. It may be set
	// directly (inline script) or left empty for the caller to load.
	Script string
}

// IsTerminal reports whether the rule answers the request itself instead of
// only adjusting what is forwarded.
func (r *Rule) IsTerminal() bool {
	switch r.Action {
	case ActionReject, ActionReject200, ActionRejectImg,
		ActionRejectDict, ActionRejectArray, ActionRedirect, ActionEcho:
		return true
	}
	return false
}

// requestSide reports whether the rule takes part in the request walk.
func (r *Rule) requestSide() bool {
	switch r.Action {
	case ActionScriptResponse:
		return false
	case ActionScriptRequest:
		return true
	case ActionHeader, ActionHeaderRewrite, ActionBodyRewrite, ActionJSONQuery:
		return r.Target == TargetRequest
	}
	return true
}

// responseSide reports whether the rule takes part in the response walk.
func (r *Rule) responseSide() bool {
	switch r.Action {
	case ActionScriptResponse:
		return true
	case ActionScriptRequest:
		return false
	case ActionHeader, ActionHeaderRewrite, ActionBodyRewrite, ActionJSONQuery:
		return r.Target == TargetResponse
	}
	return false
}

// Parsed is a compiled rewrite configuration: the rules in file order, plus
// the "[mitm]" options that came along with them.
type Parsed struct {
	// Rules are the rewrite rules, in the order they were written. The first
	// matching rule wins for terminal actions and every matching rule applies
	// to header and body adjustments.
	Rules []*Rule
	// Hostnames is the interception allow-list from a "[mitm]" section. An
	// empty list means "decide from the rules", which is what an ordinary
	// FlClash rule set relies on.
	Hostnames []string
}

// ParseRule compiles a single rewrite line into a Rule. It returns an error for
// malformed input so a bad subscription line can be skipped rather than
// breaking the whole set.
func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || isComment(line) {
		return nil, nil
	}

	patternText, rest := cutToken(line)
	if patternText == "" {
		return nil, &parseError{line, "expected at least a pattern and an action"}
	}
	pattern, err := regexp.Compile(patternText)
	if err != nil {
		return nil, &parseError{line, "invalid pattern: " + err.Error()}
	}

	rule := &Rule{Pattern: pattern, Raw: patternText}

	rest = strings.TrimSpace(rest)
	// The "url" marker of "<url> url <action>" comes first: it is a bare token
	// and never collides with the header expression of a url-and-header rule.
	if token, after := cutToken(rest); token == "url" {
		rest = strings.TrimSpace(after)
	}
	if loc := urlAndHeaderMarker.FindStringIndex(rest); loc != nil {
		// Quantumult X writes "<url> <headers> url-and-header <action> <args>".
		// The header expression may contain spaces, so the marker is what
		// separates it from the action rather than field counting.
		headerText := strings.TrimSpace(rest[:loc[0]])
		if headerText == "" {
			return nil, &parseError{line, "url-and-header requires a header pattern"}
		}
		rule.HeaderPattern, err = regexp.Compile(headerText)
		if err != nil {
			return nil, &parseError{line, "invalid header pattern: " + err.Error()}
		}
		rest = strings.TrimSpace(rest[loc[1]:])
	}

	action, args := cutToken(rest)
	args = strings.TrimSpace(args)

	switch action {
	case "":
		return nil, &parseError{line, "expected an action"}
	case "reject":
		rule.Action = ActionReject
	case "reject-200":
		rule.Action = ActionReject200
	case "reject-img":
		rule.Action = ActionRejectImg
	case "reject-dict":
		rule.Action = ActionRejectDict
		// FlClash's own extension: an optional literal body.
		rule.Arg = args
	case "reject-array":
		rule.Action = ActionRejectArray
	case "302", "307":
		rule.Action = ActionRedirect
		rule.Status = 302
		if action == "307" {
			rule.Status = 307
		}
		if args == "" {
			return nil, &parseError{line, action + " requires a redirect target"}
		}
		rule.Arg = args
	case "request-header", "response-header":
		rule.Target = TargetRequest
		if action == "response-header" {
			rule.Target = TargetResponse
		}
		// Quantumult X: "<match> request-header <replacement>", where the
		// action keyword is repeated between the two halves because either
		// half may contain spaces. Anything else is the name/value form this
		// app used first.
		match, replace, repeated := cutRepeatedAction(args, action)
		if repeated {
			rule.Action = ActionHeaderRewrite
			if rule.Match, err = compileRewrite(line, match); err != nil {
				return nil, err
			}
			rule.Replace = expandGroupRefs(replace)
			break
		}
		fields := strings.Fields(args)
		if len(fields) < 2 {
			return nil, &parseError{line, "header rule requires a name and a value"}
		}
		rule.Action = ActionHeader
		rule.Arg = fields[0]
		rule.Arg2 = strings.Join(fields[1:], " ")
	case "request-body", "response-body":
		rule.Target = TargetRequest
		if action == "response-body" {
			rule.Target = TargetResponse
		}
		match, replace, repeated := cutRepeatedAction(args, action)
		if !repeated {
			return nil, &parseError{line, action + " requires a match and a replacement"}
		}
		rule.Action = ActionBodyRewrite
		if rule.Match, err = compileRewrite(line, match); err != nil {
			return nil, err
		}
		rule.Replace = expandGroupRefs(replace)
	case "jsonjq-request-body", "jsonjq-response-body":
		rule.Target = TargetRequest
		if action == "jsonjq-response-body" {
			rule.Target = TargetResponse
		}
		rule.Action = ActionJSONQuery
		rule.Arg = unquote(args)
		if rule.Query, err = compileJSONQuery(line, rule.Arg); err != nil {
			return nil, err
		}
	case "echo-response":
		rule.Action = ActionEcho
		meta, file, repeated := cutRepeatedAction(args, action)
		if !repeated {
			return nil, &parseError{line, "echo-response requires a content type and a file"}
		}
		rule.Arg = meta
		rule.Replace = file
	case "script-request-header", "script-request-body":
		rule.Action = ActionScriptRequest
		rule.Target = TargetRequest
		rule.Stage = StageHeader
		if action == "script-request-body" {
			rule.Stage = StageBody
		}
		rule.Arg = args
	case "script-response-header", "script-response-body":
		rule.Action = ActionScriptResponse
		rule.Target = TargetResponse
		rule.Stage = StageHeader
		if action == "script-response-body" {
			rule.Stage = StageBody
		}
		rule.Arg = args
	case "script-echo-response", "script-analyze-echo-response":
		// The script answers instead of the origin, so it runs before the
		// request is forwarded. "analyze" is the variant that also wants the
		// request body, which this implementation always reads anyway.
		rule.Action = ActionScriptRequest
		rule.Target = TargetRequest
		rule.Stage = StageEcho
		rule.Arg = args
	default:
		return nil, &parseError{line, "unknown action " + action}
	}

	return rule, nil
}

// Matches reports whether the rule's URL pattern matches.
func (r *Rule) Matches(url string) bool {
	return r.Pattern.MatchString(url)
}

// MatchesRequest reports whether the rule applies to a request, taking the
// url-and-header header expression into account. The header block is only
// evaluated when the URL matched first, exactly as Quantumult X does it.
func (r *Rule) MatchesRequest(url, headerBlock string) bool {
	if !r.Pattern.MatchString(url) {
		return false
	}
	if r.HeaderPattern == nil {
		return true
	}
	return r.HeaderPattern.MatchString(headerBlock)
}

// rewriteBody applies a body rewrite or a jq query to a body, reporting
// whether the result differs from the input.
func (r *Rule) rewriteBody(data []byte) ([]byte, bool) {
	switch r.Action {
	case ActionBodyRewrite:
		if r.Match == nil {
			return nil, false
		}
		updated := r.Match.ReplaceAll(data, []byte(r.Replace))
		if bytes.Equal(updated, data) {
			return nil, false
		}
		return updated, true
	case ActionJSONQuery:
		if r.Query == nil {
			return nil, false
		}
		updated, err := runJSONQuery(data, r.Query)
		if err != nil || bytes.Equal(updated, data) {
			return nil, false
		}
		return updated, true
	}
	return nil, false
}

// ParseRules compiles a multi-line rule set, dropping blank lines and comments
// and returning every valid rule alongside any parse errors.
func ParseRules(text string) ([]*Rule, []error) {
	parsed, errs := Parse(text)
	return parsed.Rules, errs
}

// Parse compiles a multi-line configuration. Besides rewrite rules it
// understands the "[mitm]" section a Quantumult X configuration carries, so a
// rule set can be pasted over without hand-editing. Other sections of such a
// configuration are ignored rather than reported as syntax errors.
func Parse(text string) (Parsed, []error) {
	var parsed Parsed
	var errs []error
	section := ""

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if name, ok := sectionHeader(line); ok {
			section = name
			continue
		}
		if isComment(line) {
			continue
		}
		switch section {
		case "mitm":
			errs = append(errs, parsed.parseMitmLine(line)...)
		case "", "rewrite", "rewrite_local", "rewrite_remote":
			rule, err := ParseRule(line)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if rule != nil {
				parsed.Rules = append(parsed.Rules, rule)
			}
		default:
			// A Quantumult X configuration carries many sections this app does
			// not implement; skipping them keeps a pasted file usable.
		}
	}
	return parsed, errs
}

// parseMitmLine reads one "key = value" line of a "[mitm]" section. Only the
// hostname allow-list changes behaviour: the certificate settings describe a
// p12 this app does not use, and the skip_* filters are accepted for
// compatibility but have no effect on a tunnel that is already selective.
func (p *Parsed) parseMitmLine(line string) []error {
	key, value, found := strings.Cut(line, "=")
	if !found {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "hostname":
		for _, host := range strings.Split(value, ",") {
			if host = strings.TrimSpace(host); host != "" {
				p.Hostnames = append(p.Hostnames, host)
			}
		}
	}
	return nil
}

// cutRepeatedAction splits "<match> <action> <replacement>" on the second
// occurrence of the action keyword. Quantumult X repeats the keyword between
// the two halves because either half may contain spaces.
func cutRepeatedAction(args, action string) (match, replacement string, ok bool) {
	marker := regexp.MustCompile(`\s+` + regexp.QuoteMeta(action) + `\s+`)
	loc := marker.FindStringIndex(args)
	if loc == nil {
		return "", "", false
	}
	return strings.TrimSpace(args[:loc[0]]), strings.TrimSpace(args[loc[1]:]), true
}

// compileRewrite compiles the match half of a header or body rewrite.
func compileRewrite(line, expression string) (*regexp.Regexp, error) {
	if expression == "" {
		return nil, &parseError{line, "empty rewrite expression"}
	}
	compiled, err := regexp.Compile(expression)
	if err != nil {
		return nil, &parseError{line, "invalid rewrite expression: " + err.Error()}
	}
	return compiled, nil
}

// compileJSONQuery compiles the jq half of a jsonjq rewrite.
func compileJSONQuery(line, expression string) (*gojq.Query, error) {
	if expression == "" {
		return nil, &parseError{line, "jsonjq requires an expression"}
	}
	query, err := gojq.Parse(expression)
	if err != nil {
		return nil, &parseError{line, "invalid jq expression: " + err.Error()}
	}
	return query, nil
}

// urlAndHeaderMarker finds the "url-and-header" keyword as a whole token.
var urlAndHeaderMarker = regexp.MustCompile(`(?:^|\s)url-and-header(?:\s|$)`)

// isComment reports whether a line is a comment in any of the syntaxes this
// app accepts. Quantumult X uses ";", other rule sets use "#" or "//", and a
// pasted snippet may carry a "[rewrite_local]" section header as well.
func isComment(line string) bool {
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, ";") {
		return true
	}
	_, ok := sectionHeader(line)
	return ok
}

// sectionHeader reports whether the line is a "[name]" header and returns the
// lower-cased name.
func sectionHeader(line string) (string, bool) {
	if len(line) < 2 || !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(line[1 : len(line)-1])), true
}

// cutToken splits off the first whitespace-delimited token.
func cutToken(s string) (token, rest string) {
	s = strings.TrimLeft(s, " \t\r\n")
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// unquote strips the matching quotes a Quantumult X rule set wraps a jq
// expression in.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') ||
			(s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// expandGroupRefs rewrites "$1" into "${1}" so a replacement can put a letter
// right after a group reference.
//
// Quantumult X borrows JavaScript's replacement syntax, where "$1User-Agent"
// means group 1 followed by "User-Agent". Go reads "$1User" as the name of a
// group, finds none, and expands it to nothing, so the reference has to be
// braced before it reaches regexp.
func expandGroupRefs(replacement string) string {
	if !strings.Contains(replacement, "$") {
		return replacement
	}
	var b strings.Builder
	for i := 0; i < len(replacement); i++ {
		if replacement[i] != '$' {
			b.WriteByte(replacement[i])
			continue
		}
		// "$$" is a literal dollar and "${1}" is already braced; both are left
		// exactly as written.
		if i+1 < len(replacement) && replacement[i+1] == '$' {
			b.WriteString("$$")
			i++
			continue
		}
		if i+1 < len(replacement) && replacement[i+1] == '{' {
			b.WriteByte('$')
			continue
		}
		end := i + 1
		for end < len(replacement) && replacement[end] >= '0' && replacement[end] <= '9' {
			end++
		}
		if end == i+1 {
			b.WriteByte('$')
			continue
		}
		b.WriteString("${" + replacement[i+1:end] + "}")
		i = end - 1
	}
	return b.String()
}

type parseError struct {
	line string
	msg  string
}

func (e *parseError) Error() string {
	return "mitm: bad rewrite rule \"" + e.line + "\": " + e.msg
}
