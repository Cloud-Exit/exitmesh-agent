// Command exitmesh-refcp serves the reference control plane over TLS with a generated self-signed CA for local testing.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol/refcp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "exitmesh-refcp:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("exitmesh-refcp", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", "127.0.0.1:8443", "TLS listen address")
	var clusters, hosts countFlag
	fs.Var(&clusters, "create-cluster", "create a cluster target and print its enrollment token (repeat or =N for more)")
	fs.Var(&hosts, "create-host", "create a host target and print its enrollment token (repeat or =N for more)")
	certDir := fs.String("cert-dir", "", "directory for the generated CA certificate (default: a new temporary directory)")
	names := fs.String("hostnames", "", "additional comma-separated DNS names or IP addresses for the certificate")
	trustDir := fs.String("trust-dir", "", "generate a deployment trust root and write roots.txt (a trust.roots entry) and roots.json there")
	bundleK8s := fs.String("bundle-kubernetes", "", "build, sign, and publish the kubernetes rule bundle in this directory (needs -trust-dir)")
	bundleHost := fs.String("bundle-host", "", "build, sign, and publish the host rule bundle in this directory (needs -trust-dir)")
	status := fs.Bool("status", false, "serve a JSON progress report of the created targets at "+StatusPath+" (development only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if (*bundleK8s != "" || *bundleHost != "") && *trustDir == "" {
		return errors.New("-bundle-kubernetes and -bundle-host need -trust-dir")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	cert, certPEM, err := selfSigned(certNames(ln.Addr().String(), *names))
	if err != nil {
		return err
	}
	dir := *certDir
	if dir == "" {
		if dir, err = os.MkdirTemp("", "exitmesh-refcp-"); err != nil {
			return err
		}
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		return err
	}
	log := slog.New(redact.NewHandler(slog.NewTextHandler(errOut, nil), redact.Default()))
	cp := refcp.New(refcp.Options{Logger: log})
	st := &statusHandler{cp: cp}
	fmt.Fprintf(out, "ca %s\nendpoint %s\n", caPath, ln.Addr())
	for _, kind := range []string{protocol.TargetKubernetes, protocol.TargetHost} {
		n := map[string]int{protocol.TargetKubernetes: int(clusters), protocol.TargetHost: int(hosts)}[kind]
		for i := 0; i < n; i++ {
			id, tok, err := cp.CreateTarget(kind)
			if err != nil {
				return err
			}
			st.add(id, kind)
			fmt.Fprintf(out, "target %s %s token %s\n", kind, id, tok)
		}
	}
	if *trustDir != "" {
		tr, err := newTrust(*trustDir, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "roots %s\n", filepath.Join(*trustDir, "roots.txt"))
		for kind, dir := range map[string]string{protocol.TargetKubernetes: *bundleK8s, protocol.TargetHost: *bundleHost} {
			if dir == "" {
				continue
			}
			v, err := tr.publish(cp, kind, dir)
			if err != nil {
				return fmt.Errorf("bundle %s: %w", kind, err)
			}
			fmt.Fprintf(out, "bundle %s %s\n", kind, v)
		}
	}
	var handler http.Handler = cp
	if *status {
		handler = withStatus(cp, st)
	}
	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		cp.Close()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err = srv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

// countFlag counts bare occurrences and also accepts an explicit count.
type countFlag int

func (c *countFlag) String() string   { return strconv.Itoa(int(*c)) }
func (c *countFlag) IsBoolFlag() bool { return true }

func (c *countFlag) Set(v string) error {
	if v == "true" {
		*c++
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid count %q", v)
	}
	*c = countFlag(n)
	return nil
}

func certNames(addr, extra string) []string {
	names := []string{"localhost", "127.0.0.1", "::1"}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
			names = append(names, host)
		} else if h, err := os.Hostname(); err == nil {
			names = append(names, h)
		}
	}
	for _, n := range strings.Split(extra, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	return names
}

func selfSigned(names []string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "exitmesh-refcp"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pemBytes, nil
}
