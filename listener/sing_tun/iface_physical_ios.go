//go:build ios

package sing_tun

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// physicalInterfaceName reports the interface that actually carries traffic on
// iOS: en0 for Wi-Fi, en1 on a few models, pdp_ip0 for cellular.
//
// Neither source the rest of the stack uses can answer here. The tunnel
// installs two /1 routes that own the whole IPv4 space, so the BSD RIB reports
// the TUN as the default route, and a connect() to any address leaves from the
// TUN's own address. The interface list is the one thing the tunnel never
// rewrites, so the physical NIC is picked from it.
func physicalInterfaceName() string {
	physicalMu.Lock()
	defer physicalMu.Unlock()
	if time.Since(physicalCheckedAt) < physicalCacheTTL {
		return physicalName
	}
	name := detectPhysicalInterface()
	if name != physicalName {
		if name == "" {
			log.Warnln("[TUN] no physical interface carries traffic; outbound stays on the tunnel")
		} else {
			log.Infoln("[TUN] physical interface for outbound: %s", name)
		}
	}
	physicalName = name
	physicalCheckedAt = time.Now()
	return name
}

var (
	physicalMu        sync.Mutex
	physicalName      string
	physicalCheckedAt time.Time
)

// Cached for a short while rather than for the life of the process: this is
// consulted once per dial, and enumerating interfaces is a syscall. Three
// seconds is short enough that a Wi-Fi to cellular handover is picked up
// before the user notices, and long enough that a burst of dials costs one
// enumeration.
const physicalCacheTTL = 3 * time.Second

func detectPhysicalInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var bestName string
	bestRank := 0
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		rank := physicalInterfaceRank(iface.Name)
		if rank <= bestRank {
			continue
		}
		if !hasIPv4Address(iface) {
			continue
		}
		bestName, bestRank = iface.Name, rank
	}
	return bestName
}

// physicalInterfaceRank orders candidates by how much the tunnel should prefer
// them and rejects everything that never carries internet traffic: utun (the
// tunnel itself), awdl0/llw0 (peer to peer), bridge/ap (hotspot), gif/stf
// (transition tunnels), lo0 (loopback).
func physicalInterfaceRank(name string) int {
	switch {
	case name == "en0":
		return 100
	case strings.HasPrefix(name, "en"):
		return 90
	case strings.HasPrefix(name, "pdp_ip"):
		// Cellular is the fallback: it is only primary while Wi-Fi is down.
		return 60
	default:
		return 0
	}
}

// hasIPv4Address is the difference between "up" and "usable": an interface
// with no address cannot source a socket, and a link-local one cannot reach
// beyond its own segment.
func hasIPv4Address(iface net.Interface) bool {
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		addr := prefix.Addr()
		if !addr.Is4() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		return true
	}
	return false
}
