package mitm

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Hit is one intercepted exchange that a rewrite rule acted on. It is what the
// app's request log shows for a MITM'd request: an intercepted request never
// travels through the tunnel, so nothing else would record it, and a rule that
// silently misses would look exactly like one that works.
type Hit struct {
	// Start is when the request was read off the tunnel.
	Start time.Time
	// Method and URL are the request line the client sent, before any rule
	// rewrote it.
	Method string
	URL    string
	// Rules are the rule lines that matched, in the order they were applied.
	Rules []string
	// Status is the status code the client was answered with.
	Status int
	// Upload and Download are the bytes the exchange carried.
	Upload   int64
	Download int64
}

// HitObserver receives an exchange a rewrite rule acted on. A nil observer
// turns the report off, which is the default: only a core with a request log
// to feed installs one.
type HitObserver func(Hit)

// SetHitObserver installs the observer told about matched exchanges.
func SetHitObserver(observer HitObserver) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.hit = observer
}

// hitObserver returns the installed observer, if any.
func hitObserver() HitObserver {
	global.mu.RLock()
	defer global.mu.RUnlock()
	return global.hit
}

// hitLog collects the rules one exchange matched. It travels in the request
// context because the request walk and the response walk are separate calls
// and both have to append to the same list.
type hitLog struct {
	mu    sync.Mutex
	rules []string
}

// hitLogKey is the context key the exchange's log is stored under.
type hitLogKey struct{}

// withHitLog attaches an empty log to the request and returns it, so the rules
// the request and the response walks match can be collected for one report.
func withHitLog(req *http.Request) (*http.Request, *hitLog) {
	collected := &hitLog{}
	ctx := context.WithValue(req.Context(), hitLogKey{}, collected)
	return req.WithContext(ctx), collected
}

// recordHit notes a rule that took effect. It reports the rule as it was
// written, because that is what the user has to recognise in the log.
func recordHit(ctx context.Context, rule *Rule) {
	collected, _ := ctx.Value(hitLogKey{}).(*hitLog)
	if collected == nil {
		return
	}
	collected.add(rule)
}

func (l *hitLog) add(rule *Rule) {
	line := rule.Line
	if line == "" {
		line = rule.Raw
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rules = append(l.rules, line)
}

// list returns the rules collected so far, in the order they were applied.
func (l *hitLog) list() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.rules...)
}

// reportHit hands a finished exchange to the installed observer when a rule
// acted on it. The upload is what the client sent and the download is what it
// was answered with, both counted over the exchange itself.
func reportHit(
	hits *hitLog,
	start time.Time,
	method string,
	url string,
	resp *http.Response,
	upload int64,
	download int64,
) {
	rules := hits.list()
	if len(rules) == 0 || resp == nil {
		return
	}
	observer := hitObserver()
	if observer == nil {
		return
	}
	observer(Hit{
		Start:    start,
		Method:   method,
		URL:      url,
		Rules:    rules,
		Status:   resp.StatusCode,
		Upload:   upload,
		Download: download,
	})
}
