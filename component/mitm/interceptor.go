package mitm

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Handler receives the decrypted HTTP request for an intercepted connection
// and returns the response to send back to the client, or nil to fall through
// to normal proxying. It is the seam through which rewrite rules are applied.
type Handler interface {
	// ServeMITM returns a response to short-circuit the request, or nil when
	// the request should continue to the real upstream.
	ServeMITM(req *http.Request) *http.Response

	// OnResponse is called after an upstream response is received but before it
	// is written to the client, letting a handler rewrite response headers or
	// body. It returns the (possibly replaced) response to send.
	OnResponse(resp *http.Response) *http.Response
}

// Interceptor terminates TLS for a single CONNECT tunnel and re-originates the
// plaintext stream, applying rules via its Handler.
type Interceptor struct {
	CA      *CA
	Handler Handler
	// DialUpstream dials the real destination. Defaults to net.DialTimeout.
	DialUpstream func(network, addr string) (net.Conn, error)
}

// Hijack takes an established CONNECT tunnel (the raw client connection after
// a "200 Connection established" response has been sent) and the destination
// host:port, and runs the MITM interception. The caller should have already
// written the 200 status to the client.
func (in *Interceptor) Hijack(clientConn net.Conn, hostPort string) {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	cert, key, err := in.CA.leafFor(host)
	if err != nil {
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
			Leaf:        cert,
		}},
		MinVersion: tls.VersionTLS12,
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return
	}

	in.serveHTTP(tlsConn, hostPort)
}

func (in *Interceptor) serveHTTP(conn net.Conn, hostPort string) {
	defer conn.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				if in.DialUpstream != nil {
					return in.DialUpstream(network, addr)
				}
				return net.DialTimeout(network, addr, 15*time.Second)
			},
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		// Reconstruct the absolute URL from the Host header, since a decrypted
		// origin-form request has no scheme or host in its RequestURI.
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		req.RequestURI = ""

		if in.Handler != nil {
			if resp := in.Handler.ServeMITM(req); resp != nil {
				writeResponse(conn, resp)
				if resp.Close || !reqIsKeepAlive(req) {
					return
				}
				continue
			}
		}

		// Re-originate upstream.
		upstreamReq := req.Clone(req.Context())
		resp, err := client.Do(upstreamReq)
		if err != nil {
			writeResponse(conn, errorResponse(http.StatusBadGateway))
			return
		}

		if in.Handler != nil {
			resp = in.Handler.OnResponse(resp)
		}

		writeResponse(conn, resp)
		if resp.Close || !reqIsKeepAlive(req) {
			return
		}
	}
}

func reqIsKeepAlive(req *http.Request) bool {
	return !strings.EqualFold(req.Header.Get("Connection"), "close")
}

func writeResponse(w io.Writer, resp *http.Response) {
	_ = resp.Write(w)
}

func errorResponse(code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Status:     http.StatusText(code),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

// Set is a concurrency-safe collection of compiled rules plus the CA that
// signs certificates for intercepted connections.
type Set struct {
	mu       sync.RWMutex
	rules    []*Rule
	byTarget map[Target][]*Rule
}

// NewSet builds an empty rule set.
func NewSet() *Set {
	return &Set{byTarget: make(map[Target][]*Rule)}
}

// Replace atomically swaps in a freshly compiled rule list.
func (s *Set) Replace(rules []*Rule) {
	byTarget := make(map[Target][]*Rule)
	for _, r := range rules {
		if r.Action == ActionHeader {
			byTarget[r.Target] = append(byTarget[r.Target], r)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = rules
	s.byTarget = byTarget
}

// HeaderRules returns the header rules for a side, or nil.
func (s *Set) HeaderRules(target Target) []*Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byTarget[target]
}

// Match returns the first rule whose pattern matches url, or nil.
func (s *Set) Match(url string) *Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if r.Action == ActionHeader {
			continue
		}
		if r.Matches(url) {
			return r
		}
	}
	return nil
}
