package mitm

import (
	"net"
	"sync"
)

// global holds the process-wide MITM configuration. It mirrors the pattern
// used by listener/auth (authStore.Default): a single shared instance that the
// HTTP listener consults for every CONNECT without needing the config plumbed
// through every call.
var global = struct {
	mu      sync.RWMutex
	enabled bool
	ca      *CA
	set     *Set
}{}

// Enable turns interception on or off and installs the CA and rule set the
// listener should use. Passing a nil set disables rewriting while keeping the
// CA for future use.
func Enable(enabled bool, ca *CA, set *Set) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.enabled = enabled
	if ca != nil {
		global.ca = ca
	}
	if set != nil {
		global.set = set
	}
}

// SetRules swaps the active rule set without touching the CA or enabled flag.
func SetRules(set *Set) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.set = set
}

// Intercept reports whether a CONNECT to hostPort should be MITM'd, and if so
// returns the interceptor to run. It returns (nil, false) when interception is
// disabled, no CA is installed, or the host is excluded.
func Intercept(hostPort string) (*Interceptor, bool) {
	global.mu.RLock()
	defer global.mu.RUnlock()

	if !global.enabled || global.ca == nil {
		return nil, false
	}

	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	// Only hijack tunnels whose host is referenced by at least one rewrite
	// rule; every other connection continues through the tunnel untouched,
	// keeping certificates and privacy intact for unrelated apps.
	if global.set == nil || !global.set.ReferencesHost(host) {
		return nil, false
	}

	return &Interceptor{
		CA:      global.ca,
		Handler: &RewriteHandler{Set: global.set},
	}, true
}

// IsEnabled reports whether MITM is currently active.
func IsEnabled() bool {
	global.mu.RLock()
	defer global.mu.RUnlock()
	return global.enabled
}
