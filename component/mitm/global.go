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
	engine  *ScriptEngine
	loader  ScriptLoader
	dial    func(network, addr string) (net.Conn, error)
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

// SetScriptEngine installs the JS engine and script loader used to execute
// Quantumult X rewrite scripts. It is optional: without an engine, only the
// fixed rewrite actions run.
func SetScriptEngine(engine *ScriptEngine, loader ScriptLoader) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.engine = engine
	global.loader = loader
}

// snapshot returns the pieces needed to build an interceptor. It reports false
// when interception is off or has no CA or rule set yet, so both the CONNECT
// path and the transparent (TUN) path agree on when to stay out of the way.
func snapshot() (
	ca *CA,
	set *Set,
	engine *ScriptEngine,
	loader ScriptLoader,
	dial func(network, addr string) (net.Conn, error),
	ok bool,
) {
	global.mu.RLock()
	defer global.mu.RUnlock()
	if !global.enabled || global.ca == nil || global.set == nil {
		return nil, nil, nil, nil, nil, false
	}
	return global.ca, global.set, global.engine, global.loader, global.dial, true
}

// newInterceptor wires the rule set, the script engine and the upstream dialer
// into a per-connection interceptor. Each connection gets its own, because the
// interceptor carries the destination it was created for.
func newInterceptor(
	ca *CA,
	set *Set,
	engine *ScriptEngine,
	loader ScriptLoader,
	dial func(network, addr string) (net.Conn, error),
) *Interceptor {
	var handler Handler = &RewriteHandler{Set: set}
	if engine != nil {
		handler = &ScriptHandler{Set: set, Engine: engine, Loader: loader}
	}
	if dial == nil {
		dial = defaultUpstreamDial
	}
	return &Interceptor{CA: ca, Handler: handler, DialUpstream: dial}
}

// Intercept reports whether a CONNECT to hostPort should be MITM'd, and if so
// returns the interceptor to run. It returns (nil, false) when interception is
// disabled, no CA is installed, or the host is excluded.
func Intercept(hostPort string) (*Interceptor, bool) {
	ca, set, engine, loader, dial, ok := snapshot()
	if !ok {
		return nil, false
	}

	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	// Only hijack tunnels whose host is referenced by at least one rewrite
	// rule; every other connection continues through the tunnel untouched,
	// keeping certificates and privacy intact for unrelated apps.
	if !set.ReferencesHost(host) {
		return nil, false
	}

	return newInterceptor(ca, set, engine, loader, dial), true
}

// IsEnabled reports whether MITM is currently active.
func IsEnabled() bool {
	global.mu.RLock()
	defer global.mu.RUnlock()
	return global.enabled
}
