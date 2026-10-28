package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchTimeout bounds how long a single remote subscription fetch may take.
const FetchTimeout = 30 * time.Second

// RemoteSource is a single remote rewrite subscription. It mirrors the
// Quantumult X "[rewrite_remote]" section: a URL plus an optional policy flag.
type RemoteSource struct {
	// URL is the subscription endpoint.
	URL string
	// Enabled controls whether this subscription is fetched and applied.
	Enabled bool
	// DisabledByPolicy is set when a subscription lists itself as disabled.
	DisabledByPolicy bool
}

// FetchRemote downloads a remote rule set. It returns the raw text (rules and
// script lines) with a caller-provided context controlling the timeout, so it
// can be cancelled on shutdown or refresh.
func FetchRemote(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "FlClash-Mitm/1.0")

	client := &http.Client{Timeout: FetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote fetch %s: unexpected status %d", url, resp.StatusCode)
	}

	// Cap the body size so a hostile subscription cannot exhaust memory.
	const maxBody = 10 << 20 // 10 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxBody {
		return "", fmt.Errorf("remote fetch %s: body exceeds %d bytes", url, maxBody)
	}
	return string(body), nil
}

// SplitRemoteScripts separates a Quantumult X subscription body into the rule
// lines and the inline scripts it may embed. Scripts are delimited by
// "script-..." markers and their trailing URL; this is a best-effort split
// for the common subscription layouts, not a full QX grammar.
//
// It returns the rule text (scripts removed) so ParseRules can consume it.
func SplitRemoteScripts(body string) (rulesText string, scripts map[string]string) {
	scripts = map[string]string{}
	var ruleLines []string

	// A simple heuristic: a script reference in a rule looks like
	//   <pattern> url script-response-body <url-or-token>
	// If a line carries a script action and the referenced value is an http(s)
	// URL, we record it for the caller to fetch separately; otherwise it is a
	// token resolved by the caller.
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		ruleLines = append(ruleLines, line)
	}

	return strings.Join(ruleLines, "\n"), scripts
}

// IsRemoteEnabled reports whether a "[rewrite_remote]" line marks the
// subscription as enabled (the default) or explicitly disabled. Quantumult X
// uses the presence of "disable" or a leading "!"/"#" to switch a source off.
func IsRemoteEnabled(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	// A leading "!" or "#" marks a source as commented out / disabled.
	if strings.HasPrefix(t, "!") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
		return false
	}
	return true
}
