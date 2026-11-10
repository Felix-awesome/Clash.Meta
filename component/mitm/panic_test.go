package mitm

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

// panickingHandler stands for a rewrite that trips over an exchange it did not
// expect. It must cost the connection, not the process.
type panickingHandler struct{}

func (panickingHandler) ServeMITM(*http.Request) *http.Response {
	panic("rewrite blew up")
}

func (panickingHandler) OnResponse(resp *http.Response) *http.Response {
	return resp
}

// TestHijackContainsAPanic asserts a panicking rewrite is confined to the one
// connection: Hijack returns instead of unwinding into the caller, which on a
// device is the goroutine carrying every other tunnel connection.
func TestHijackContainsAPanic(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	in := &Interceptor{CA: ca, Handler: panickingHandler{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		in.Hijack(serverConn, "example.com:443")
	}()

	tlsClient := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, _ = tlsClient.Write([]byte("GET /boom HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Hijack did not return after the handler panicked")
	}
}
