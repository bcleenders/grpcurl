package grpcurl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	. "github.com/fullstorydev/grpcurl"
	grpcurl_testing "github.com/fullstorydev/grpcurl/internal/testing"
)

// spiffeTestPKI holds the in-memory PKI material needed for SPIFFE TLS tests.
type spiffeTestPKI struct {
	caCertFile string // path to a temp file containing the CA certificate PEM
	serverTLS  tls.Certificate
}

// newSpiffeTestPKI creates a minimal CA + server certificate with the given URI SAN.
// Pass an empty spiffeURI to create a cert with no URI SANs.
// The CA cert is written to a temporary file cleaned up by t.Cleanup.
func newSpiffeTestPKI(t *testing.T, spiffeURI string) spiffeTestPKI {
	t.Helper()

	// Generate CA key and self-signed cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// Generate server key and cert signed by the CA.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "spiffe-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if spiffeURI != "" {
		u, err := url.Parse(spiffeURI)
		if err != nil {
			t.Fatalf("parse SPIFFE URI %q: %v", spiffeURI, err)
		}
		srvTemplate.URIs = []*url.URL{u}
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	// Write the CA PEM to a temp file so tests can pass it as a file path.
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCertFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caCertFile, caPEM, 0600); err != nil {
		t.Fatalf("write CA cert file: %v", err)
	}

	// Build a tls.Certificate for the server.
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	tlsCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("create TLS cert pair: %v", err)
	}

	return spiffeTestPKI{
		caCertFile: caCertFile,
		serverTLS:  tlsCert,
	}
}

func TestPlainText(t *testing.T) {
	e, err := createTestServerAndClient(nil, nil)
	if err != nil {
		t.Fatalf("failed to setup server and client: %v", err)
	}
	defer e.Close()

	simpleTest(t, e.cc)
}

func TestBasicTLS(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "", "")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err != nil {
		t.Fatalf("failed to setup server and client: %v", err)
	}
	defer e.Close()

	simpleTest(t, e.cc)
}

func TestInsecureClientTLS(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(true, "", "", "")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err != nil {
		t.Fatalf("failed to setup server and client: %v", err)
	}
	defer e.Close()

	simpleTest(t, e.cc)
}

func TestClientCertTLS(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("internal/testing/tls/ca.crt", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "internal/testing/tls/client.crt", "internal/testing/tls/client.key")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err != nil {
		t.Fatalf("failed to setup server and client: %v", err)
	}
	defer e.Close()

	simpleTest(t, e.cc)
}

func TestRequireClientCertTLS(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("internal/testing/tls/ca.crt", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", true)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "internal/testing/tls/client.crt", "internal/testing/tls/client.key")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err != nil {
		t.Fatalf("failed to setup server and client: %v", err)
	}
	defer e.Close()

	simpleTest(t, e.cc)
}

func TestBrokenTLS_ClientPlainText(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	// client connection (usually) succeeds since client is not waiting for TLS handshake
	// (we try several times, but if we never get a connection and the error message is
	// a known/expected possibility, we'll just bail)
	var e testEnv
	failCount := 0
	for {
		e, err = createTestServerAndClient(serverCreds, nil)
		if err == nil {
			// success!
			defer e.Close()
			break
		}

		if strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "use of closed network connection") {
			// It is possible that the connection never becomes healthy:
			//   1) grpc connects successfully
			//   2) grpc client tries to send HTTP/2 preface and settings frame
			//   3) server, expecting handshake, closes the connection
			//   4) in the client, the write fails, so the connection never
			//      becomes ready
			// The client will attempt to reconnect on transient errors, so
			// may eventually bump into the connect time limit. This used to
			// result in a "deadline exceeded" error, but more recent versions
			// of the grpc library report any underlying I/O error instead, so
			// we also check for "use of closed network connection".
			failCount++
			if failCount > 5 {
				return // bail...
			}
			// we'll try again

		} else {
			// some other error occurred, so we'll consider that a test failure
			t.Fatalf("failed to setup server and client: %v", err)
		}
	}

	// but request fails because server closes connection upon seeing request
	// bytes that are not a TLS handshake
	cl := grpcurl_testing.NewTestServiceClient(e.cc)
	_, err = cl.UnaryCall(context.Background(), &grpcurl_testing.SimpleRequest{})
	if err == nil {
		t.Fatal("expecting failure")
	}
	// various errors possible when server closes connection
	if !strings.Contains(err.Error(), "transport is closing") &&
		!strings.Contains(err.Error(), "connection is unavailable") &&
		!strings.Contains(err.Error(), "use of closed network connection") &&
		!strings.Contains(err.Error(), "all SubConns are in TransientFailure") {

		t.Fatalf("expecting transport failure, got: %v", err)
	}
}

func TestBrokenTLS_ServerPlainText(t *testing.T) {
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "", "")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(nil, clientCreds)
	if err == nil {
		e.Close()
		t.Fatal("expecting TLS failure setting up server and client")
	}
	if !strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
		t.Fatalf("expecting TLS handshake failure, got: %v", err)
	}
}

func TestBrokenTLS_ServerUsesWrongCert(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("", "internal/testing/tls/other.crt", "internal/testing/tls/other.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "", "")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err == nil {
		e.Close()
		t.Fatal("expecting TLS failure setting up server and client")
	}
	if !strings.Contains(err.Error(), "certificate is valid for") {
		t.Fatalf("expecting TLS certificate error, got: %v", err)
	}
}

func TestBrokenTLS_ClientHasExpiredCert(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("internal/testing/tls/ca.crt", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "internal/testing/tls/expired.crt", "internal/testing/tls/expired.key")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err == nil {
		e.Close()
		t.Fatal("expecting TLS failure setting up server and client")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expecting TLS certificate error, got: %v", err)
	}
}

func TestBrokenTLS_ServerHasExpiredCert(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("", "internal/testing/tls/expired.crt", "internal/testing/tls/expired.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "", "")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err == nil {
		e.Close()
		t.Fatal("expecting TLS failure setting up server and client")
	}
	if !strings.Contains(err.Error(), "certificate has expired or is not yet valid") {
		t.Fatalf("expecting TLS certificate expired, got: %v", err)
	}
}

func TestBrokenTLS_ClientNotTrusted(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("internal/testing/tls/ca.crt", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", true)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "internal/testing/tls/wrong-client.crt", "internal/testing/tls/wrong-client.key")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err == nil {
		e.Close()
		t.Fatal("expecting TLS failure setting up server and client")
	}
	// Check for either the old error (Go <=1.24) or the new one (Go 1.25+)
	// Go 1.24: "bad certificate"
	// Go 1.25: "handshake failure"
	errMsg := err.Error()
	if !strings.Contains(errMsg, "bad certificate") && !strings.Contains(errMsg, "handshake failure") {
		t.Fatalf("expecting a specific TLS certificate or handshake error, got: %v", err)
	}
}

func TestBrokenTLS_ServerNotTrusted(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", false)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "", "internal/testing/tls/client.crt", "internal/testing/tls/client.key")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err == nil {
		e.Close()
		t.Fatal("expecting TLS failure setting up server and client")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expecting TLS certificate error, got: %v", err)
	}
}

func TestBrokenTLS_RequireClientCertButNonePresented(t *testing.T) {
	serverCreds, err := ServerTransportCredentials("internal/testing/tls/ca.crt", "internal/testing/tls/server.crt", "internal/testing/tls/server.key", true)
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}
	clientCreds, err := ClientTransportCredentials(false, "internal/testing/tls/ca.crt", "", "")
	if err != nil {
		t.Fatalf("failed to create server creds: %v", err)
	}

	e, err := createTestServerAndClient(serverCreds, clientCreds)
	if err == nil {
		e.Close()
		t.Fatal("expecting TLS failure setting up server and client")
	}
	// Check for either the old error (Go <=1.24) or the new one (Go 1.25+)
	// Go 1.24: "bad certificate"
	// Go 1.25: "handshake failure"
	errMsg := err.Error()
	if !strings.Contains(errMsg, "bad certificate") && !strings.Contains(errMsg, "handshake failure") {
		t.Fatalf("expecting a specific TLS certificate or handshake error, got: %v", err)
	}
}

// createSPIFFETestServerAndClient starts a gRPC server using the provided TLS cert,
// then dials it with the given client credentials.
func createSPIFFETestServerAndClient(t *testing.T, serverTLS tls.Certificate, clientCreds credentials.TransportCredentials) (*grpc.ClientConn, func()) {
	t.Helper()
	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverTLS},
		// TLS 1.3 is fine here; we override min version only to keep parity with ServerTransportCredentials.
		MaxVersion: tls.VersionTLS13,
	}
	serverCreds := credentials.NewTLS(serverTLSConf)
	svr := grpc.NewServer(grpc.Creds(serverCreds))
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go svr.Serve(l) //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addr := fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)
	cc, err := BlockingDial(ctx, "tcp", addr, clientCreds)
	cleanup := func() {
		if cc != nil {
			cc.Close()
		}
		svr.GracefulStop()
	}
	if err != nil {
		cleanup()
		t.Fatalf("dial: %v", err)
	}
	return cc, cleanup
}

func TestSPIFFETLS_Valid(t *testing.T) {
	const spiffeURI = "spiffe://example.org/myservice"
	pki := newSpiffeTestPKI(t, spiffeURI)

	tlsConf, err := ClientTLSConfigForSPIFFE(spiffeURI, pki.caCertFile, "", "")
	if err != nil {
		t.Fatalf("create SPIFFE TLS config: %v", err)
	}
	clientCreds := credentials.NewTLS(tlsConf)

	cc, cleanup := createSPIFFETestServerAndClient(t, pki.serverTLS, clientCreds)
	defer cleanup()
	simpleTest(t, cc)
}

func TestSPIFFETLS_WrongID(t *testing.T) {
	const serverURI = "spiffe://example.org/myservice"
	const clientExpectedURI = "spiffe://example.org/wrong"
	pki := newSpiffeTestPKI(t, serverURI)

	// Use the same CA so chain verification passes; only the ID check should fail.
	tlsConf, err := ClientTLSConfigForSPIFFE(clientExpectedURI, pki.caCertFile, "", "")
	if err != nil {
		t.Fatalf("create SPIFFE TLS config: %v", err)
	}
	clientCreds := credentials.NewTLS(tlsConf)

	svr := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pki.serverTLS},
	})))
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go svr.Serve(l) //nolint:errcheck
	defer svr.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)
	_, dialErr := BlockingDial(ctx, "tcp", addr, clientCreds)
	if dialErr == nil {
		t.Fatal("expected dial to fail due to SPIFFE ID mismatch")
	}
	if !strings.Contains(dialErr.Error(), "SPIFFE ID mismatch") {
		t.Fatalf("expected SPIFFE ID mismatch error, got: %v", dialErr)
	}
}

func TestSPIFFETLS_NoURISAN(t *testing.T) {
	// Server cert has no URI SAN at all.
	pki := newSpiffeTestPKI(t, "")

	tlsConf, err := ClientTLSConfigForSPIFFE("spiffe://example.org/myservice", pki.caCertFile, "", "")
	if err != nil {
		t.Fatalf("create SPIFFE TLS config: %v", err)
	}
	clientCreds := credentials.NewTLS(tlsConf)

	svr := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pki.serverTLS},
	})))
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go svr.Serve(l) //nolint:errcheck
	defer svr.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)
	_, dialErr := BlockingDial(ctx, "tcp", addr, clientCreds)
	if dialErr == nil {
		t.Fatal("expected dial to fail because server cert has no URI SAN")
	}
	if !strings.Contains(dialErr.Error(), "SPIFFE verification failed") {
		t.Fatalf("expected SPIFFE verification error, got: %v", dialErr)
	}
}

func TestSPIFFETLS_UntrustedCA(t *testing.T) {
	const spiffeURI = "spiffe://example.org/myservice"
	serverPKI := newSpiffeTestPKI(t, spiffeURI)
	// Build a different CA for the client; chain verification should fail.
	wrongPKI := newSpiffeTestPKI(t, spiffeURI)

	// Use the wrong CA's cert file so chain verification fails.
	tlsConf, err := ClientTLSConfigForSPIFFE(spiffeURI, wrongPKI.caCertFile, "", "")
	if err != nil {
		t.Fatalf("create SPIFFE TLS config: %v", err)
	}
	clientCreds := credentials.NewTLS(tlsConf)

	svr := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverPKI.serverTLS},
	})))
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go svr.Serve(l) //nolint:errcheck
	defer svr.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)
	_, dialErr := BlockingDial(ctx, "tcp", addr, clientCreds)
	if dialErr == nil {
		t.Fatal("expected dial to fail due to untrusted CA")
	}
	if !strings.Contains(dialErr.Error(), "SPIFFE verification failed") {
		t.Fatalf("expected SPIFFE verification error, got: %v", dialErr)
	}
}

func simpleTest(t *testing.T, cc *grpc.ClientConn) {
	cl := grpcurl_testing.NewTestServiceClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := cl.UnaryCall(ctx, &grpcurl_testing.SimpleRequest{}, grpc.WaitForReady(true))
	if err != nil {
		t.Errorf("simple RPC failed: %v", err)
	}
}

func createTestServerAndClient(serverCreds, clientCreds credentials.TransportCredentials) (testEnv, error) {
	var e testEnv
	completed := false
	defer func() {
		if !completed {
			e.Close()
		}
	}()

	var svrOpts []grpc.ServerOption
	if serverCreds != nil {
		svrOpts = []grpc.ServerOption{grpc.Creds(serverCreds)}
	}
	svr := grpc.NewServer(svrOpts...)
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return e, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	go svr.Serve(l)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cc, err := BlockingDial(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port), clientCreds)
	if err != nil {
		return e, err
	}

	e.svr = svr
	e.cc = cc
	completed = true
	return e, nil
}

type testEnv struct {
	svr *grpc.Server
	cc  *grpc.ClientConn
}

func (e *testEnv) Close() {
	if e.cc != nil {
		e.cc.Close()
		e.cc = nil
	}
	if e.svr != nil {
		e.svr.GracefulStop()
		e.svr = nil
	}
}
