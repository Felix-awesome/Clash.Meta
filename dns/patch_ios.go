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

// iosUpstreamDNS are the plain-UDP upstreams the system resolver uses on iOS.
// The NetworkExtension tunnel process has no usable /etc/resolv.conf:
// NEDNSSettings points the device at the fake-IP gateway (198.18.0.1), so the
// generic !android dnsReadConfig() either finds nothing or finds the gateway
// itself and the resolver dead-loops. A static, real upstream keeps the
// outbound dialer able to resolve proxy-server hostnames (and any other name
// the main fake-IP resolver is not asked for) - the same job UpdateSystemDNS
// does on Android and desktop.
var iosUpstreamDNS = []NameServer{
	{Addr: "223.5.5.5:53", Net: "udp"},
	{Addr: "119.29.29.29:53", Net: "udp"},
	{Addr: "1.1.1.1:53", Net: "udp"},
	{Addr: "8.8.8.8:53", Net: "udp"},
}

// getDnsClients overrides the generic system_common.go implementation: instead
// of reading /etc/resolv.conf (unusable inside the tunnel process), it returns
// a fixed set of public upstreams. UpdateSystemDNS stays a no-op, so the app
// never has to feed the device DNS through the tunnel.
func (c *systemClient) getDnsClients() ([]dnsClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.dnsClients) == 0 {
		clients := transform(iosUpstreamDNS, nil)
		for i, client := range clients {
			c.dnsClients[iosUpstreamDNS[i].Addr] = &systemDnsClient{
				disableTimes: 0,
				dnsClient:    client,
			}
		}
	}

	dnsClients := make([]dnsClient, 0, len(c.dnsClients))
	for _, sdc := range c.dnsClients {
		dnsClients = append(dnsClients, sdc.dnsClient)
	}
	return dnsClients, nil
}

func (c *systemClient) ResetConnection() {}
