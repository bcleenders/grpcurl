package grpcurl_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	gcplog "github.com/envoyproxy/go-control-plane/pkg/log"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/xds" // register the xds:// resolver and balancers
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	. "github.com/fullstorydev/grpcurl"
	grpcurl_testing "github.com/fullstorydev/grpcurl/internal/testing"
)

const xdsTestNodeID = "grpcurl-xds-test-node"

func mustAny(t *testing.T, m proto.Message) *anypb.Any {
	t.Helper()
	a, err := anypb.New(m)
	if err != nil {
		t.Fatalf("marshal %T to Any: %v", m, err)
	}
	return a
}

// xdsResourcesForTarget builds the LDS/CDS/EDS resources for one xds:/// target:
// a client listener with an inline route config pointing at an EDS cluster whose
// UpstreamTlsContext requires the server to present expectedSAN, verified against
// the "default" certificate provider instance from the bootstrap file (gRFC A29).
func xdsResourcesForTarget(t *testing.T, targetName, expectedSAN, backendHost string, backendPort uint32) (*listenerv3.Listener, *clusterv3.Cluster, *endpointv3.ClusterLoadAssignment) {
	t.Helper()
	clusterName := targetName + "-cluster"

	hcm := &hcmv3.HttpConnectionManager{
		RouteSpecifier: &hcmv3.HttpConnectionManager_RouteConfig{
			RouteConfig: &routev3.RouteConfiguration{
				Name: targetName + "-route",
				VirtualHosts: []*routev3.VirtualHost{{
					Name:    targetName + "-vh",
					Domains: []string{"*"},
					Routes: []*routev3.Route{{
						Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: ""}},
						Action: &routev3.Route_Route{Route: &routev3.RouteAction{
							ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: clusterName},
						}},
					}},
				}},
			},
		},
		HttpFilters: []*hcmv3.HttpFilter{{
			Name:       "router",
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(t, &routerv3.Router{})},
		}},
	}
	listener := &listenerv3.Listener{
		Name:        targetName,
		ApiListener: &listenerv3.ApiListener{ApiListener: mustAny(t, hcm)},
	}

	tlsCtx := &tlsv3.UpstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
				ValidationContext: &tlsv3.CertificateValidationContext{
					CaCertificateProviderInstance: &tlsv3.CertificateProviderPluginInstance{
						InstanceName: "default",
					},
					MatchSubjectAltNames: []*matcherv3.StringMatcher{{
						MatchPattern: &matcherv3.StringMatcher_Exact{Exact: expectedSAN},
					}},
				},
			},
		},
	}
	cluster := &clusterv3.Cluster{
		Name:                 clusterName,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
		EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
			EdsConfig: &corev3.ConfigSource{
				ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
			},
		},
		LbPolicy: clusterv3.Cluster_ROUND_ROBIN,
		TransportSocket: &corev3.TransportSocket{
			Name:       "envoy.transport_sockets.tls",
			ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(t, tlsCtx)},
		},
	}

	endpoints := &endpointv3.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpointv3.LocalityLbEndpoints{{
			Locality:            &corev3.Locality{Region: "region1"},
			LoadBalancingWeight: wrapperspb.UInt32(1),
			LbEndpoints: []*endpointv3.LbEndpoint{{
				HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
					Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
						Address:       backendHost,
						PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: backendPort},
					}}},
				}},
			}},
		}},
	}

	return listener, cluster, endpoints
}

// startXDSManagementServer starts a stub xDS (ADS) management server serving the
// given snapshot resources, and returns its address.
func startXDSManagementServer(t *testing.T, resources map[resourcev3.Type][]cachetypes.Resource) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := gcplog.LoggerFuncs{
		DebugFunc: t.Logf,
		InfoFunc:  t.Logf,
		WarnFunc:  t.Logf,
		ErrorFunc: t.Logf,
	}
	// ads=false: in ADS mode the cache refuses to answer requests that do not
	// subscribe to every resource of a type in the snapshot, and our client
	// subscribes to one target's resources at a time.
	snapCache := cachev3.NewSnapshotCache(false, cachev3.IDHash{}, logger)
	snap, err := cachev3.NewSnapshot("1", resources)
	if err != nil {
		t.Fatalf("create xDS snapshot: %v", err)
	}
	if err := snapCache.SetSnapshot(ctx, xdsTestNodeID, snap); err != nil {
		t.Fatalf("set xDS snapshot: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for xDS management server: %v", err)
	}
	gs := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, serverv3.NewServer(ctx, snapCache, nil))
	go gs.Serve(l) //nolint:errcheck
	t.Cleanup(gs.Stop)
	return l.Addr().String()
}

// writeXDSBootstrap writes a gRPC xDS bootstrap file pointing at the given
// management server, with a file_watcher certificate provider ("default") that
// trusts the test CA, and returns its path.
func writeXDSBootstrap(t *testing.T, mgmtAddr string) string {
	t.Helper()
	caPath, err := filepath.Abs("internal/testing/tls/ca.crt")
	if err != nil {
		t.Fatalf("resolve ca.crt path: %v", err)
	}
	bootstrap := map[string]interface{}{
		"xds_servers": []interface{}{map[string]interface{}{
			"server_uri":      mgmtAddr,
			"channel_creds":   []interface{}{map[string]interface{}{"type": "insecure"}},
			"server_features": []interface{}{"xds_v3"},
		}},
		"node": map[string]interface{}{"id": xdsTestNodeID},
		"certificate_providers": map[string]interface{}{
			"default": map[string]interface{}{
				"plugin_name": "file_watcher",
				"config": map[string]interface{}{
					"ca_certificate_file": caPath,
					"refresh_interval":    "600s",
				},
			},
		},
	}
	data, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatalf("marshal bootstrap: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write bootstrap file: %v", err)
	}
	return path
}

// startTLSServer starts a TLS gRPC test server with the given certificate and
// returns its address and a stop function.
func startTLSServer(t *testing.T, serverCert tls.Certificate) (string, func()) {
	t.Helper()
	svr := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
	})))
	grpcurl_testing.RegisterTestServiceServer(svr, grpcurl_testing.TestServer{})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go svr.Serve(l) //nolint:errcheck
	return fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port), svr.GracefulStop
}

// TestXDS_ServerIdentityFromControlPlane verifies gRFC A29 end to end: the
// expected server identity (SPIFFE ID) is not specified by the client at all;
// it is delivered by the xDS control plane as a SAN matcher in the cluster's
// UpstreamTlsContext, and trust anchors come from the bootstrap's certificate
// provider. A matching identity must connect; a mismatched one must be
// rejected during TLS verification.
//
// grpc-go captures GRPC_XDS_BOOTSTRAP at package init, so the env var cannot
// be set from within a running process. The test therefore re-executes itself:
// the parent starts the backend and the stub management server and writes the
// bootstrap file; the subprocess (with the env var set at launch) performs the
// dials.
func TestXDS_ServerIdentityFromControlPlane(t *testing.T) {
	const serverID = "spiffe://example.org/myservice" // URI SAN of spiffe-server.crt

	if os.Getenv("GRPCURL_XDS_TEST_SUBPROCESS") == "1" {
		// Subprocess: the bootstrap env var was set at launch by the parent.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cc, err := BlockingDial(ctx, "", "xds:///xds-good", nil)
		if err != nil {
			t.Fatalf("dial via xDS with control-plane-provided identity: %v", err)
		}
		defer cc.Close()
		simpleTest(t, cc)

		ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel2()
		_, dialErr := BlockingDial(ctx2, "", "xds:///xds-bad", nil)
		if dialErr == nil {
			t.Fatal("expected dial to fail: control-plane identity does not match server certificate")
		}
		if !strings.Contains(dialErr.Error(), "SAN") {
			t.Fatalf("expected SAN mismatch error, got: %v", dialErr)
		}
		return
	}

	srvCert, err := tls.LoadX509KeyPair("internal/testing/tls/spiffe-server.crt", "internal/testing/tls/spiffe-server.key")
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	backendAddr, stop := startTLSServer(t, srvCert)
	defer stop()
	backendHost, portStr, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("split backend address: %v", err)
	}
	backendPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	goodLis, goodCluster, goodEndpoints := xdsResourcesForTarget(t, "xds-good", serverID, backendHost, uint32(backendPort))
	badLis, badCluster, badEndpoints := xdsResourcesForTarget(t, "xds-bad", "spiffe://example.org/other", backendHost, uint32(backendPort))

	mgmtAddr := startXDSManagementServer(t, map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ListenerType: {goodLis, badLis},
		resourcev3.ClusterType:  {goodCluster, badCluster},
		resourcev3.EndpointType: {goodEndpoints, badEndpoints},
	})
	bootstrapPath := writeXDSBootstrap(t, mgmtAddr)

	cmd := exec.Command(os.Args[0], "-test.run=^TestXDS_ServerIdentityFromControlPlane$", "-test.v")
	cmd.Env = append(os.Environ(),
		"GRPCURL_XDS_TEST_SUBPROCESS=1",
		"GRPC_XDS_BOOTSTRAP="+bootstrapPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xDS subprocess failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("xDS subprocess did not pass:\n%s", out)
	}
}
