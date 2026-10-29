package mitm

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// clientHelloBytes captures a real ClientHello for the given server name, so
// the sniffer is exercised against bytes a client would actually send.
func clientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	go func() {
		// The handshake blocks once the ClientHello is written; only the first
		// flight is needed here, so the error is irrelevant.
		_ = tls.Client(clientConn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		}).Handshake()
	}()
	serverConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	header := make([]byte, tlsRecordHeaderLen)
	if _, err := io.ReadFull(serverConn, header); err != nil {
		t.Fatalf("read record header: %v", err)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
	if _, err := io.ReadFull(serverConn, body); err != nil {
		t.Fatalf("read record body: %v", err)
	}
	return append(header, body...)
}

func TestSniffSNIReadsServerName(t *testing.T) {
	hello := clientHelloBytes(t, "rewrite.example.com")

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	go func() {
		_, _ = clientConn.Write(hello)
	}()

	host, ok := sniffSNI(serverConn, bufio.NewReaderSize(serverConn, maxClientHello))
	if !ok {
		t.Fatal("expected the ClientHello to be sniffed")
	}
	if host != "rewrite.example.com" {
		t.Fatalf("expected rewrite.example.com, got %q", host)
	}
}

func TestSniffSNILeavesPlainHTTPAlone(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	go func() {
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	if host, ok := sniffSNI(serverConn, bufio.NewReaderSize(serverConn, maxClientHello)); ok {
		t.Fatalf("plain HTTP must not yield a host, got %q", host)
	}
}

func TestPeekedConnReplaysBufferedBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	go func() {
		_, _ = clientConn.Write([]byte("hello"))
	}()

	reader := bufio.NewReaderSize(serverConn, maxClientHello)
	if _, err := reader.Peek(2); err != nil {
		t.Fatalf("peek: %v", err)
	}

	conn := &peekedConn{Conn: serverConn, reader: reader}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("expected the peeked bytes to be replayed, got %q", got)
	}
}

func TestInterceptTunnelDisabledPassesThrough(t *testing.T) {
	Enable(false, nil, nil)
	t.Cleanup(func() { Enable(false, nil, nil) })

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	next, handled := InterceptTunnel(serverConn, "example.com:443")
	if handled {
		t.Fatal("interception must stay off while disabled")
	}
	if next != serverConn {
		t.Fatal("expected the original connection back when disabled")
	}
}
