//go:build !ios

package sing_tun

// physicalInterfaceName is only meaningful on iOS, where the tunnel owns the
// route table and leaves no other way to find the NIC that carries traffic.
// Everywhere else the platform's own default-interface detection is correct,
// so this reports nothing and callers fall through to it.
func physicalInterfaceName() string {
	return ""
}
