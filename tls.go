package grpcurl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/credentials"
)

// ClientTransportCredentials is a helper function that constructs a TLS config with
// the given properties (see ClientTLSConfig) and then constructs and returns gRPC
// transport credentials using that config.
//
// Deprecated: Use grpcurl.ClientTLSConfig and credentials.NewTLS instead.
func ClientTransportCredentials(insecureSkipVerify bool, cacertFile, clientCertFile, clientKeyFile string) (credentials.TransportCredentials, error) {
	tlsConf, err := ClientTLSConfig(insecureSkipVerify, cacertFile, clientCertFile, clientKeyFile)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(tlsConf), nil
}

// ClientTLSConfig builds transport-layer config for a gRPC client using the
// given properties. If cacertFile is blank, only standard trusted certs are used to
// verify the server certs. If clientCertFile is blank, the client will not use a client
// certificate. If clientCertFile is not blank then clientKeyFile must not be blank.
func ClientTLSConfig(insecureSkipVerify bool, cacertFile, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	var tlsConf tls.Config

	if clientCertFile != "" {
		// Load the client certificates from disk
		certificate, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("could not load client key pair: %v", err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
	}

	if insecureSkipVerify {
		tlsConf.InsecureSkipVerify = true
	} else if cacertFile != "" {
		// Create a certificate pool from the certificate authority
		certPool := x509.NewCertPool()
		ca, err := os.ReadFile(cacertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ca certificate: %v", err)
		}

		// Append the certificates from the CA
		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("failed to append ca certs")
		}

		tlsConf.RootCAs = certPool
	}

	return &tlsConf, nil
}

// SpiffeConfigFromCAFiles builds a TLS config that validates the server using SPIFFE ID
// matching on SAN.URI instead of hostname verification.
//
// cacertFile must not be blank: SPIFFE verification requires explicit trust
// anchors. Use SpiffeConfigFromBundleMap or SpiffeConfigFromWorkloadAPI
// for other trust models.
// If clientCertFile is blank, the client will not use a client certificate. If clientCertFile
// is not blank then clientKeyFile must not be blank.
func SpiffeConfigFromCAFiles(expectedID, cacertFile, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	id, err := spiffeid.FromString(expectedID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", expectedID, err)
	}
	if cacertFile == "" {
		return nil, errors.New("cacert is required for SPIFFE verification (or use a SPIFFE bundle / Workload API)")
	}

	caCerts, err := parsePEMCertificatesFromFile(cacertFile)
	if err != nil {
		return nil, err
	}
	bundle := x509bundle.FromX509Authorities(id.TrustDomain(), caCerts)
	tlsConf := tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeID(id))

	if clientCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("could not load client key pair: %v", err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
	}

	return tlsConf, nil
}

func parsePEMCertificatesFromFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read certificate file %q: %v", path, err)
	}
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %q", path)
	}
	return certs, nil
}

// SpiffeConfigFromBundleMap builds a TLS config that validates the server using
// SPIFFE ID matching, with the trust anchors loaded from a SPIFFE trust bundle file.
//
// The bundle file may be either:
// - a single SPIFFE bundle (JWKS JSON with a top-level "keys" array), or;
// - a SPIFFE Bundle Map (with a top-level "trust_domains" object and bundles
//   nested as keys), as described in: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
//
// If clientCertFile is blank, the client will not use a client certificate. If clientCertFile
// is not blank then clientKeyFile must not be blank.
func SpiffeConfigFromBundleMap(expectedID, bundleFile, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	id, err := spiffeid.FromString(expectedID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", expectedID, err)
	}

	bundleBytes, err := os.ReadFile(bundleFile)
	if err != nil {
		return nil, fmt.Errorf("could not read SPIFFE bundle file: %w", err)
	}

	// Support both a single SPIFFE bundle (JWKS with top-level "keys") and a
	// SPIFFE Bundle Map (top-level "trust_domains" object keyed by trust domain).
	var bundleMap struct {
		TrustDomains map[string]json.RawMessage `json:"trust_domains"`
	}
	if err := json.Unmarshal(bundleBytes, &bundleMap); err == nil && bundleMap.TrustDomains != nil {
		tdName := id.TrustDomain().String()
		tdBytes, ok := bundleMap.TrustDomains[tdName]
		if !ok {
			return nil, fmt.Errorf("SPIFFE bundle map does not contain an entry for trust domain %q", tdName)
		}
		bundleBytes = tdBytes
	}

	bundle, err := spiffebundle.Parse(id.TrustDomain(), bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("could not load SPIFFE bundle: %w", err)
	}

	tlsConf := tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeID(id))

	if clientCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("could not load client key pair: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{certificate}
	}

	return tlsConf, nil
}

// SpiffeConfigFromWorkloadAPI builds a TLS config by fetching the client's X.509 SVID
// and trust bundles from the SPIFFE Workload API.
//
// The SVID provides the client certificate and key (enabling mTLS), and the bundles
// provide the trust anchors for validating the server certificate.
//
// socketPath is the gRPC address of the Workload API endpoint (e.g.
// "unix:///run/spire/sockets/agent.sock"). If empty, the SPIFFE_ENDPOINT_SOCKET
// environment variable is used.
func SpiffeConfigFromWorkloadAPI(ctx context.Context, expectedID, socketPath string) (*tls.Config, error) {
	id, err := spiffeid.FromString(expectedID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", expectedID, err)
	}

	var opts []workloadapi.ClientOption
	if socketPath != "" {
		opts = append(opts, workloadapi.WithAddr(socketPath))
	}

	x509Ctx, err := workloadapi.FetchX509Context(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("could not fetch X.509 context from SPIFFE Workload API: %w", err)
	}
	if len(x509Ctx.SVIDs) == 0 {
		return nil, errors.New("SPIFFE Workload API returned no X.509 SVIDs")
	}

	return tlsconfig.MTLSClientConfig(x509Ctx.SVIDs[0], x509Ctx.Bundles, tlsconfig.AuthorizeID(id)), nil
}

// ServerTransportCredentials builds transport credentials for a gRPC server using the
// given properties. If cacertFile is blank, the server will not request client certs
// unless requireClientCerts is true. When requireClientCerts is false and cacertFile is
// not blank, the server will verify client certs when presented, but will not require
// client certs. The serverCertFile and serverKeyFile must both not be blank.
func ServerTransportCredentials(cacertFile, serverCertFile, serverKeyFile string, requireClientCerts bool) (credentials.TransportCredentials, error) {
	var tlsConf tls.Config
	// TODO(jh): Remove this line once https://github.com/golang/go/issues/28779 is fixed
	// in Go tip. Until then, the recently merged TLS 1.3 support breaks the TLS tests.
	tlsConf.MaxVersion = tls.VersionTLS12

	// Load the server certificates from disk
	certificate, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load key pair: %v", err)
	}
	tlsConf.Certificates = []tls.Certificate{certificate}

	if cacertFile != "" {
		// Create a certificate pool from the certificate authority
		certPool := x509.NewCertPool()
		ca, err := os.ReadFile(cacertFile)
		if err != nil {
			return nil, fmt.Errorf("could not read ca certificate: %v", err)
		}

		// Append the certificates from the CA
		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("failed to append ca certs")
		}

		tlsConf.ClientCAs = certPool
	}

	if requireClientCerts {
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	} else if cacertFile != "" {
		tlsConf.ClientAuth = tls.VerifyClientCertIfGiven
	} else {
		tlsConf.ClientAuth = tls.NoClientCert
	}

	return credentials.NewTLS(&tlsConf), nil
}
