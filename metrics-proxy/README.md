# Metrics Proxy Server

A secure HTTP proxy server that authenticates clients via mTLS and forwards requests to a backend service with bearer token authentication.

## Features

- **mTLS Authentication**: Validates client certificates against a provided CA bundle
- **File-based Token Management**: Reads bearer tokens from files with automatic rotation support
- **Bearer Token Forwarding**: Automatically adds bearer token authentication to backend requests
- **Request/Response Forwarding**: Transparently forwards HTTP requests and responses
- **TLS Security**: Uses TLS 1.2+ for secure communication
- **Structured Logging**: Comprehensive logging with structured output

## Usage

### Command Line Options

```bash
./bin/control-plane-operator metrics-proxy \
  --listen-addr=:8443 \
  --backend-url=https://backend.example.com \
  --bearer-token-file=/path/to/token.txt \
  --ca-bundle=/path/to/ca-bundle.pem \
  --server-cert=/path/to/server.crt \
  --server-key=/path/to/server.key \
  --token-refresh-interval=30
```

### Required Flags

- `--backend-url`: URL of the backend service to proxy requests to
- `--bearer-token-file`: Path to file containing bearer token for backend authentication
- `--ca-bundle`: Path to CA bundle for client certificate validation
- `--server-cert`: Path to server certificate
- `--server-key`: Path to server private key

### Optional Flags

- `--listen-addr`: Address to listen on (default: `:8443`)
- `--token-refresh-interval`: Interval in seconds to refresh the bearer token from file (default: `30`)

## Building

The metrics-proxy is built as part of the control-plane-operator:

```bash
# Build all components including control-plane-operator
make build

# Build only control-plane-operator (which includes metrics-proxy)
make control-plane-operator
```

The binary will be created in the `bin/` directory as `bin/control-plane-operator`.

## Testing

```bash
# Run tests for metrics-proxy
go test ./metrics-proxy/...

# Run all project tests
make test
```

## Architecture

The metrics proxy server works as follows:

1. **Client Connection**: Clients connect using mTLS with valid client certificates
2. **Certificate Validation**: Server validates client certificates against the provided CA bundle
3. **Token Management**: Server reads bearer tokens from files and automatically refreshes them
4. **Request Forwarding**: Valid requests are forwarded to the backend with current bearer token authentication
5. **Response Forwarding**: Backend responses are returned to the client

### Token Rotation

The proxy supports automatic token rotation by:

- Reading bearer tokens from files specified by `--bearer-token-file`
- Periodically refreshing tokens at the interval specified by `--token-refresh-interval`
- Handling token file updates without service interruption
- Logging token refresh events for monitoring

This is particularly useful in Kubernetes environments where service account tokens are automatically rotated.

## Security Considerations

- Client certificates must be signed by a CA in the provided CA bundle
- Server uses TLS 1.2+ for secure communication
- Bearer tokens are securely handled and not logged
- Request/response bodies are not logged for security

## Example Configuration

### Server Certificate and Key

The server requires a TLS certificate and private key for HTTPS operation:

```bash
# Generate server certificate and key
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

### CA Bundle

The CA bundle should contain the root and intermediate certificates that signed the client certificates:

```bash
# Combine CA certificates into a bundle
cat root-ca.crt intermediate-ca.crt > ca-bundle.pem
```

### Client Certificates

Client certificates must be signed by a CA in the provided CA bundle:

```bash
# Generate client certificate
openssl req -newkey rsa:2048 -keyout client.key -out client.csr
openssl x509 -req -in client.csr -CA ca-bundle.pem -CAkey ca-key.pem -out client.crt -days 365
```

## Logging

The server uses structured logging with the following log levels:

- **Info**: Request processing, successful operations
- **Error**: Authentication failures, backend errors
- **Debug**: Detailed request/response information (when enabled)

## Error Handling

The server handles various error conditions:

- **401 Unauthorized**: Invalid or missing client certificate
- **502 Bad Gateway**: Backend service unavailable
- **500 Internal Server Error**: Server configuration or processing errors
