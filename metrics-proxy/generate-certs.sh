#!/bin/bash

# Generate test certificates for metrics proxy
# This script creates a CA, server certificate, and client certificate for testing

set -e

CERT_DIR="certs"
mkdir -p "$CERT_DIR"

# Generate CA private key
openssl genrsa -out "$CERT_DIR/ca.key" 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=CA/L=San Francisco/O=Test CA/CN=Test CA"

# Generate server private key
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate server certificate signing request
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=CA/L=San Francisco/O=Test Server/CN=localhost"

# Generate server certificate
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 \
    -extensions v3_req -extfile <(cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF
)

# Generate client private key
openssl genrsa -out "$CERT_DIR/client.key" 2048

# Generate client certificate signing request
openssl req -new -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" \
    -subj "/C=US/ST=CA/L=San Francisco/O=Test Client/CN=test-client"

# Generate client certificate
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client.crt" -days 365 \
    -extensions v3_req -extfile <(cat <<EOF
[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF
)

# Create CA bundle (same as CA cert for this example)
cp "$CERT_DIR/ca.crt" "$CERT_DIR/ca-bundle.pem"

# Clean up CSR files
rm "$CERT_DIR/server.csr" "$CERT_DIR/client.csr"

# Create sample token file
echo "sample-bearer-token-12345" > "$CERT_DIR/token.txt"

echo "Certificates generated in $CERT_DIR directory:"
echo "  - ca.crt: CA certificate"
echo "  - ca-bundle.pem: CA bundle for client validation"
echo "  - server.crt/server.key: Server certificate and key"
echo "  - client.crt/client.key: Client certificate and key"
echo "  - token.txt: Sample bearer token file"
echo ""
echo "To run the metrics proxy:"
echo "  ../../bin/control-plane-operator metrics-proxy \\"
echo "    --listen-addr=:8443 \\"
echo "    --backend-url=https://your-backend.com \\"
echo "    --bearer-token-file=$CERT_DIR/token.txt \\"
echo "    --ca-bundle=$CERT_DIR/ca-bundle.pem \\"
echo "    --server-cert=$CERT_DIR/server.crt \\"
echo "    --server-key=$CERT_DIR/server.key \\"
echo "    --token-refresh-interval=30"
echo ""
echo "To test with curl:"
echo "  curl --cert $CERT_DIR/client.crt --key $CERT_DIR/client.key --cacert $CERT_DIR/ca.crt https://localhost:8443/metrics"
