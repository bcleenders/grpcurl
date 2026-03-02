#!/bin/bash

set -e

cd "$(dirname $0)"

# Run this script to generate files used by tests.

echo "Creating protosets..."
protoc testing/test.proto \
	--include_imports \
	--descriptor_set_out=testing/test.protoset

protoc testing/example.proto \
	--include_imports \
	--descriptor_set_out=testing/example.protoset

protoc testing/jsonpb_test_proto/test_objects.proto \
	--go_out=paths=source_relative:.

echo "Creating certs for TLS testing..."
if ! hash certstrap 2>/dev/null; then
  # certstrap not found: try to install it
  go install github.com/square/certstrap@latest
fi

function cs() {
	certstrap --depot-path testing/tls "$@" --passphrase ""
}

rm -rf testing/tls

# Create CA
cs init --years 10 --common-name ca

# Create client cert
cs request-cert --common-name client
cs sign client --years 10 --CA ca

# Create server cert
cs request-cert --common-name server --ip 127.0.0.1 --domain localhost
cs sign server --years 10 --CA ca

# Create another server cert for error testing
cs request-cert --common-name other --ip 1.2.3.4 --domain foobar.com
cs sign other --years 10 --CA ca

# Create another CA and client cert for more
# error testing
cs init --years 10 --common-name wrong-ca
cs request-cert --common-name wrong-client
cs sign wrong-client --years 10 --CA wrong-ca

# Create expired cert.
# certstrap doesn't support backdating, so we use openssl to produce a cert
# whose validity window is entirely in the past.
EXPIRED_EXT=$(mktemp)
cat > "$EXPIRED_EXT" << 'EOF'
[expired_ext]
subjectAltName = IP:127.0.0.1, DNS:localhost
EOF
openssl genrsa -out internal/testing/tls/expired.key 2048
openssl req -new \
    -key internal/testing/tls/expired.key \
    -subj "/CN=expired" \
    -out internal/testing/tls/expired.csr
openssl x509 -req \
    -in internal/testing/tls/expired.csr \
    -CA internal/testing/tls/ca.crt \
    -CAkey internal/testing/tls/ca.key \
    -set_serial 2 \
    -not_before 20200101000000Z \
    -not_after 20210101000000Z \
    -out internal/testing/tls/expired.crt \
    -extfile "$EXPIRED_EXT" \
    -extensions expired_ext
rm internal/testing/tls/expired.csr "$EXPIRED_EXT"

# Create a server cert with a SPIFFE URI SAN.
# certstrap doesn't support URI SANs, so we use openssl and sign with the
# certstrap-generated CA above.
echo "Creating SPIFFE cert with URI SAN..."
SPIFFE_EXT=$(mktemp)
cat > "$SPIFFE_EXT" << 'EOF'
[spiffe_ext]
subjectAltName = URI:spiffe://example.org/myservice
EOF

openssl genrsa -out internal/testing/tls/spiffe-server.key 2048
openssl req -new \
    -key internal/testing/tls/spiffe-server.key \
    -subj "/CN=spiffe-server" \
    -out internal/testing/tls/spiffe-server.csr
openssl x509 -req \
    -in internal/testing/tls/spiffe-server.csr \
    -CA internal/testing/tls/ca.crt \
    -CAkey internal/testing/tls/ca.key \
    -set_serial 1 \
    -out internal/testing/tls/spiffe-server.crt \
    -days 3650 \
    -extfile "$SPIFFE_EXT" \
    -extensions spiffe_ext
rm internal/testing/tls/spiffe-server.csr "$SPIFFE_EXT"
