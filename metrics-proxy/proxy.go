package metricsproxy

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// MetricsProxy handles HTTP requests by authenticating clients via mTLS
// and forwarding requests to a backend with bearer token authentication.
type MetricsProxy struct {
	backendURL   string
	tokenManager *TokenManager
	caCertPool   *x509.CertPool
	client       *http.Client
	logger       logr.Logger
}

// NewMetricsProxy creates a new metrics proxy instance.
func NewMetricsProxy(backendURL string, tokenManager *TokenManager, caCertPool *x509.CertPool, logger logr.Logger) *MetricsProxy {
	return &MetricsProxy{
		backendURL:   backendURL,
		tokenManager: tokenManager,
		caCertPool:   caCertPool,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// ServeHTTP implements the http.Handler interface.
func (p *MetricsProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request
	p.logger.Info("Processing request", "method", r.Method, "path", r.URL.Path, "remote-addr", r.RemoteAddr)

	// Verify client certificate
	if err := p.verifyClientCert(r); err != nil {
		p.logger.Error(err, "Client certificate verification failed", "remote-addr", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Create backend request
	backendReq, err := p.createBackendRequest(r)
	if err != nil {
		p.logger.Error(err, "Failed to create backend request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Forward request to backend
	resp, err := p.client.Do(backendReq)
	if err != nil {
		p.logger.Error(err, "Failed to forward request to backend")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set response status
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		p.logger.Error(err, "Failed to copy response body")
		return
	}

	p.logger.Info("Request completed", "status", resp.StatusCode, "method", r.Method, "path", r.URL.Path)
}

// verifyClientCert verifies that the client certificate is valid according to the CA bundle.
func (p *MetricsProxy) verifyClientCert(r *http.Request) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	// Get the client certificate
	clientCert := r.TLS.PeerCertificates[0]

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots: p.caCertPool,
	}

	_, err := clientCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("client certificate verification failed: %w", err)
	}

	p.logger.V(1).Info("Client certificate verified", "subject", clientCert.Subject.String())
	return nil
}

// createBackendRequest creates a new HTTP request to forward to the backend.
func (p *MetricsProxy) createBackendRequest(r *http.Request) (*http.Request, error) {
	// Build backend URL
	backendURL := strings.TrimSuffix(p.backendURL, "/") + r.URL.Path
	if r.URL.RawQuery != "" {
		backendURL += "?" + r.URL.RawQuery
	}

	// Create new request
	backendReq, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL, r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend request: %w", err)
	}

	// Copy relevant headers (excluding host and authorization)
	for key, values := range r.Header {
		keyLower := strings.ToLower(key)
		if keyLower != "host" && keyLower != "authorization" {
			for _, value := range values {
				backendReq.Header.Add(key, value)
			}
		}
	}

	// Set authorization header with bearer token
	backendReq.Header.Set("Authorization", "Bearer "+p.tokenManager.GetToken())

	// Set content length if present
	if r.ContentLength > 0 {
		backendReq.ContentLength = r.ContentLength
	}

	return backendReq, nil
}
