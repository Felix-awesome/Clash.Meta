//go:build ios

package dns

import "github.com/metacubex/mihomo/component/resolver"

// On iOS the system DNS is driven by the NetworkExtension's NEDNSSettings,
// not by mutating a system-wide resolver, so these are no-ops. They exist so
// the shared core (lib.go) can call them unconditionally.
func FlushCacheWithDefaultResolver() {
	resolver.ClearCache()
	resolver.ResetConnection()
}

// UpdateSystemDNS is a no-op on iOS: DNS servers are applied through the
// tunnel's NEDNSSettings instead.
func UpdateSystemDNS(addr []string) {}
