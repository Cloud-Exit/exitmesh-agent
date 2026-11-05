package nodeapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type testCA struct {
	pem  []byte
	leaf tls.Certificate
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "coordinator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leaf: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

// writeCA swaps the file the way a ConfigMap volume does: a new file renamed over the old one.
func writeCA(t *testing.T, path string, data []byte, at time.Time) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, at, at); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestClientReloadsRotatedCA(t *testing.T) {
	oldCA := newTestCA(t, "old-ca")
	newCA := newTestCA(t, "new-ca")
	var serving atomic.Pointer[tls.Certificate]
	serving.Store(&oldCA.leaf)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Listener = tls.NewListener(srv.Listener, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return serving.Load(), nil
		},
	})
	srv.Start()
	defer srv.Close()
	baseURL := "https://" + srv.Listener.Addr().String()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	tokenFile := filepath.Join(dir, "token")
	start := time.Now().Add(-time.Minute)
	writeCA(t, caFile, oldCA.pem, start)
	if err := os.WriteFile(tokenFile, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientOptions{BaseURL: baseURL, CAFile: caFile, TokenFile: tokenFile, Node: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.WaitTasks(ctx); err != nil {
		t.Fatalf("old CA: %v", err)
	}

	serving.Store(&newCA.leaf)
	srv.CloseClientConnections()
	if _, err := c.WaitTasks(ctx); err == nil || !IsRetryable(err) {
		t.Fatalf("a certificate from an unknown CA must fail and be retried, got %v", err)
	}

	writeCA(t, caFile, newCA.pem, start.Add(time.Second))
	if _, err := c.WaitTasks(ctx); err != nil {
		t.Fatalf("the rotated CA file must be picked up without a restart: %v", err)
	}

	writeCA(t, caFile, []byte("not a certificate"), start.Add(2*time.Second))
	srv.CloseClientConnections()
	if _, err := c.WaitTasks(ctx); err != nil {
		t.Fatalf("an unreadable CA file must keep the last good one: %v", err)
	}
}
