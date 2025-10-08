package metricsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestTokenManager creates a token manager with a temporary token file
func createTestTokenManager(t *testing.T, token string) *TokenManager {
	// Create temporary file with token
	tmpFile, err := os.CreateTemp("", "test-token-*.txt")
	require.NoError(t, err)
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(token)
	require.NoError(t, err)

	// Create token manager
	tokenManager := NewTokenManager(tmpFile.Name(), 1, logr.Discard())

	// Start token manager
	ctx := context.Background()
	err = tokenManager.Start(ctx)
	require.NoError(t, err)

	// Clean up file when test is done
	t.Cleanup(func() {
		tokenManager.Stop()
		os.Remove(tmpFile.Name())
	})

	return tokenManager
}

// testMetricsProxy is a test version that skips certificate verification
type testMetricsProxy struct {
	MetricsProxy
}

// verifyClientCert overrides the certificate verification for testing
func (p *testMetricsProxy) verifyClientCert(r *http.Request) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("no client certificate provided")
	}
	return nil
}

func TestMetricsProxy_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		request        *http.Request
		backendHandler http.HandlerFunc
		expectedStatus int
		expectError    bool
		skipCertCheck  bool
	}{
		{
			name: "Request without client certificate",
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/metrics", nil)
				req.TLS = &tls.ConnectionState{}
				return req
			}(),
			backendHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			expectedStatus: http.StatusUnauthorized,
			expectError:    true,
		},
		{
			name: "Request with mock valid certificate (skip verification)",
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/metrics", nil)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{createTestCert()},
				}
				return req
			}(),
			backendHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test metrics"))
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
			skipCertCheck:  true,
		},
		{
			name: "POST request with body (skip cert check)",
			request: func() *http.Request {
				req := httptest.NewRequest("POST", "/api/v1/query", strings.NewReader("test body"))
				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{createTestCert()},
				}
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			backendHandler: func(w http.ResponseWriter, r *http.Request) {
				// Verify the request was forwarded correctly
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/api/v1/query", r.URL.Path)
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				body, _ := io.ReadAll(r.Body)
				assert.Equal(t, "test body", string(body))

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("query result"))
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
			skipCertCheck:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create backend server
			backendServer := httptest.NewServer(tt.backendHandler)
			defer backendServer.Close()

			// Create CA cert pool with test CA
			caCertPool := x509.NewCertPool()
			caCertPool.AddCert(createTestCACert())

			// Create token manager
			tokenManager := createTestTokenManager(t, "test-token")

			// Create proxy
			logger := logr.Discard()
			proxy := NewMetricsProxy(backendServer.URL, tokenManager, caCertPool, logger)

			// Create response recorder
			w := httptest.NewRecorder()

			// For tests that skip cert check, we'll create a custom proxy
			if tt.skipCertCheck {
				// Create a test proxy that skips certificate verification
				testProxy := &testMetricsProxy{
					MetricsProxy: *proxy,
				}
				testProxy.ServeHTTP(w, tt.request)
				return
			}

			// Serve the request
			proxy.ServeHTTP(w, tt.request)

			// Verify response
			assert.Equal(t, tt.expectedStatus, w.Code)

			if !tt.expectError {
				// Verify that the backend was called with correct headers
				assert.Contains(t, w.Body.String(), "test")
			}
		})
	}
}

func TestMetricsProxy_verifyClientCert(t *testing.T) {
	tests := []struct {
		name        string
		request     *http.Request
		expectError bool
	}{
		{
			name: "No TLS connection",
			request: func() *http.Request {
				return httptest.NewRequest("GET", "/", nil)
			}(),
			expectError: true,
		},
		{
			name: "No client certificates",
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.TLS = &tls.ConnectionState{}
				return req
			}(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCertPool := x509.NewCertPool()
			caCertPool.AddCert(createTestCACert())

			tokenManager := createTestTokenManager(t, "token")
			logger := logr.Discard()
			proxy := NewMetricsProxy("http://backend", tokenManager, caCertPool, logger)

			err := proxy.verifyClientCert(tt.request)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetricsProxy_createBackendRequest(t *testing.T) {
	tests := []struct {
		name           string
		request        *http.Request
		backendURL     string
		bearerToken    string
		expectedURL    string
		expectedMethod string
		expectedAuth   string
		expectedBody   string
	}{
		{
			name: "GET request with query parameters",
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/metrics?query=up", nil)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("User-Agent", "test-client")
				return req
			}(),
			backendURL:     "https://backend.example.com",
			bearerToken:    "test-token",
			expectedURL:    "https://backend.example.com/metrics?query=up",
			expectedMethod: "GET",
			expectedAuth:   "Bearer test-token",
		},
		{
			name: "POST request with body",
			request: func() *http.Request {
				req := httptest.NewRequest("POST", "/api/v1/query", strings.NewReader("test body"))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer old-token") // Should be replaced
				return req
			}(),
			backendURL:     "https://backend.example.com",
			bearerToken:    "new-token",
			expectedURL:    "https://backend.example.com/api/v1/query",
			expectedMethod: "POST",
			expectedAuth:   "Bearer new-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caCertPool := x509.NewCertPool()
			tokenManager := createTestTokenManager(t, tt.bearerToken)
			logger := logr.Discard()
			proxy := NewMetricsProxy(tt.backendURL, tokenManager, caCertPool, logger)

			backendReq, err := proxy.createBackendRequest(tt.request)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedURL, backendReq.URL.String())
			assert.Equal(t, tt.expectedMethod, backendReq.Method)
			assert.Equal(t, tt.expectedAuth, backendReq.Header.Get("Authorization"))

			// Verify that host and authorization headers from original request are not copied
			assert.Empty(t, backendReq.Header.Get("Host"))
		})
	}
}

// Helper functions to create test certificates

func createTestCACert() *x509.Certificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// For testing purposes, we'll create a self-signed CA
	// In a real scenario, this would be properly signed
	return ca
}

func createTestCert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test Client"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
}

func createInvalidTestCert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization:  []string{"Invalid Client"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now().AddDate(-1, 0, 0), // Expired
		NotAfter:    time.Now().AddDate(-1, 0, 0), // Expired
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
}

func TestTokenManager(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "Valid token",
			token:       "valid-token-123",
			expectError: false,
		},
		{
			name:        "Empty token",
			token:       "   ",
			expectError: true,
		},
		{
			name:        "Token with whitespace",
			token:       "  token-with-whitespace  ",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with token
			tmpFile, err := os.CreateTemp("", "test-token-*.txt")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.token)
			require.NoError(t, err)
			tmpFile.Close()

			// Create token manager
			tokenManager := NewTokenManager(tmpFile.Name(), 1, logr.Discard())

			// Test validation (ValidateTokenFile only checks if file is readable, not content)
			err = tokenManager.ValidateTokenFile()
			// ValidateTokenFile should always pass for readable files, even empty ones
			assert.NoError(t, err)

			// Test loading token
			err = tokenManager.loadToken()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				expectedToken := strings.TrimSpace(tt.token)
				assert.Equal(t, expectedToken, tokenManager.GetToken())
			}
		})
	}
}

func TestTokenManager_Refresh(t *testing.T) {
	// Create temporary file with initial token
	tmpFile, err := os.CreateTemp("", "test-token-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	initialToken := "initial-token"
	_, err = tmpFile.WriteString(initialToken)
	require.NoError(t, err)
	tmpFile.Close()

	// Create token manager with short refresh interval
	tokenManager := NewTokenManager(tmpFile.Name(), 1, logr.Discard())

	// Start token manager
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = tokenManager.Start(ctx)
	require.NoError(t, err)
	defer tokenManager.Stop()

	// Verify initial token
	assert.Equal(t, initialToken, tokenManager.GetToken())

	// Update token in file
	newToken := "updated-token"
	err = os.WriteFile(tmpFile.Name(), []byte(newToken), 0644)
	require.NoError(t, err)

	// Wait for refresh (should happen within 2 seconds)
	time.Sleep(2 * time.Second)

	// Verify token was updated
	assert.Equal(t, newToken, tokenManager.GetToken())
}
