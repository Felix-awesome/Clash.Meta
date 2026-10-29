package mitm

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/sniffer"
)

const (
	// tlsRecordTypeHandshake is the content type of a TLS handshake record,
	// which is always the first byte of a ClientHello.
	tlsRecordTypeHandshake byte = 0x16
	// tlsRecordHeaderLen is the fixed size of a TLS record header.
	tlsRecordHeaderLen = 5
	// maxClientHello bounds how much of the stream is buffered while looking
	// for the SNI. A ClientHello that does not fit is left alone.
	maxClientHello = 16 << 10
	// peekTimeout bounds how long the SNI peek may block, so a client that
	// opens a connection and then stalls cannot hold the goroutine.
	peekTimeout = 3 * time.Second
	// upstreamDialTimeout bounds a single re-originated request.
	upstreamDialTimeout = 15 * time.Second
)

// defaultUpstreamDial dials the real destination for an intercepted request.
// It goes through mihomo's dialer instead of net.Dial: under TUN a plain dial
// would be captured by the tunnel itself and loop back into the proxy.
func defaultUpstreamDial(network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), upstreamDialTimeout)
	defer cancel()
	return dialer.DialContext(ctx, network, addr)
}

// SetUpstreamDialer replaces how an intercepted request reaches its origin,
// which lets the caller route re-originated traffic through a proxy instead of
// dialing directly. Passing nil restores the default dialer.
func SetUpstreamDialer(fn func(network, addr string) (net.Conn, error)) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.dial = fn
}

// peekedConn replays the bytes buffered by Peek and then reads from the
// underlying connection, so a connection that turns out not to need
// interception continues to the tunnel unchanged.
type peekedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// InterceptTunnel sniffs the TLS ClientHello of an opaque connection (a TUN or
// redirect inbound), and when the SNI it carries is referenced by a rewrite
// rule, takes over the connection to decrypt and rewrite it.
//
// hostPort is the destination the client connected to; only its port is used,
// because the certificate must be issued for the name in the ClientHello, not
// for the address. It returns the connection the caller should keep using and
// whether it was handled: when handled is true the interceptor owns the
// connection and it must not be touched again, otherwise the returned
// connection replays whatever the peek consumed.
func InterceptTunnel(conn net.Conn, hostPort string) (net.Conn, bool) {
	ca, set, engine, loader, dial, ok := snapshot()
	if !ok {
		return conn, false
	}

	reader := bufio.NewReaderSize(conn, maxClientHello)
	wrapped := &peekedConn{Conn: conn, reader: reader}

	host, ok := sniffSNI(conn, reader)
	if !ok || !set.ReferencesHost(host) {
		return wrapped, false
	}

	port := "443"
	if _, p, err := net.SplitHostPort(hostPort); err == nil && p != "" {
		port = p
	}
	newInterceptor(ca, set, engine, loader, dial).Hijack(wrapped, net.JoinHostPort(host, port))
	return nil, true
}

// sniffSNI walks the handshake records at the head of the stream until the
// ClientHello is complete and returns the server name it advertises.
func sniffSNI(conn net.Conn, reader *bufio.Reader) (string, bool) {
	// Bound the peek first: a silent peer would otherwise block the goroutine
	// forever waiting for a ClientHello that never arrives.
	if err := conn.SetReadDeadline(time.Now().Add(peekTimeout)); err == nil {
		defer conn.SetReadDeadline(time.Time{})
	}

	// The first byte decides cheaply: anything but a handshake record is not
	// TLS, and the connection is left untouched.
	first, err := reader.Peek(1)
	if err != nil || first[0] != tlsRecordTypeHandshake {
		return "", false
	}

	offset := 0
	for offset+tlsRecordHeaderLen <= maxClientHello {
		// A short peek means the peer closed or stalled; the length check
		// below is what decides, so the error itself is not needed.
		header, _ := reader.Peek(offset + tlsRecordHeaderLen)
		if len(header) < offset+tlsRecordHeaderLen {
			return "", false
		}
		if header[offset] != tlsRecordTypeHandshake ||
			!validTLSVersion(header[offset+1], header[offset+2]) {
			return "", false
		}
		recordLen := int(binary.BigEndian.Uint16(header[offset+3 : offset+tlsRecordHeaderLen]))
		if recordLen == 0 || offset+tlsRecordHeaderLen+recordLen > maxClientHello {
			return "", false
		}
		total := offset + tlsRecordHeaderLen + recordLen
		buf, _ := reader.Peek(total)
		if len(buf) < total {
			return "", false
		}
		if host, sniffErr := sniffer.SniffTLS(buf); sniffErr == nil {
			if host != nil && *host != "" {
				return *host, true
			}
			return "", false
		}
		// A ClientHello larger than one record continues in the next one.
		offset = total
	}
	return "", false
}

// validTLSVersion reports whether the record version is a TLS handshake
// version a ClientHello can carry: SSL 3.0 through TLS 1.2 on the wire, with
// TLS 1.3 still announcing 1.2 (0x0303) for compatibility.
func validTLSVersion(major, minor byte) bool {
	return major == 3 && minor <= 4
}
