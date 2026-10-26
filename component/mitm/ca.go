// Package mitm implements a man-in-the-middle TLS proxy that lets FlClash
// intercept and rewrite HTTPS traffic, in the style of Quantumult X's
// [rewrite] rules. It terminates the client's TLS connection with a
// per-hostname certificate signed by a local CA, inspects the plaintext HTTP
// stream, applies rewrite rules, and re-originates the request upstream.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA holds the root certificate authority used to sign per-host certificates
// for TLS interception. A single CA is shared by the whole process so that a
// device only has to trust one root certificate.
type CA struct {
	mu          sync.Mutex
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	certPEM     []byte
	certCache   map[string]*x509.Certificate
	keyCache    map[string]*ecdsa.PrivateKey
	leafValidity time.Duration
}

// NewCA generates a fresh root CA on first use. The caller is expected to
// persist the returned certificate and private key and pass them to
// LoadCA on later runs, so a device's installed root stays valid.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "FlClashPlus MITM CA",
			Organization: []string{"FlClashPlus"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:         cert,
		key:          key,
		certPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		certCache:    make(map[string]*x509.Certificate),
		keyCache:     make(map[string]*ecdsa.PrivateKey),
		leafValidity: 24 * time.Hour * 30,
	}, nil
}

// LoadCA restores a previously generated CA from its PEM-encoded certificate
// and private key.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errBadPEM("certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errBadPEM("private key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:         cert,
		key:          key,
		certPEM:      certPEM,
		certCache:    make(map[string]*x509.Certificate),
		keyCache:     make(map[string]*ecdsa.PrivateKey),
		leafValidity: 24 * time.Hour * 30,
	}, nil
}

// CertificatePEM returns the PEM-encoded root certificate, which the user must
// install and trust on their device for interception to be transparent.
func (ca *CA) CertificatePEM() []byte {
	return ca.certPEM
}

// PrivateKeyPEM returns the PEM-encoded (SEC1) private key of the root CA so
// the caller can persist the full CA and restore it with LoadCA on later runs.
func (ca *CA) PrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// leafFor returns a cached per-host certificate, generating and signing one on
// first use. The host must be a bare hostname (no port), since it is embedded
// as a DNSName SAN.
func (ca *CA) leafFor(host string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cert, ok := ca.certCache[host]; ok {
		return cert, ca.keyCache[host], nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ca.leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	ca.certCache[host] = leaf
	ca.keyCache[host] = key
	return leaf, key, nil
}

type pemError struct{ kind string }

func (e *pemError) Error() string { return "mitm: invalid PEM " + e.kind }

func errBadPEM(kind string) error { return &pemError{kind: kind} }
