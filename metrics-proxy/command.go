package metricsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

type options struct {
	listenAddr      string
	backendURL      string
	bearerTokenFile string
	caBundlePath    string
	serverCertPath  string
	serverKeyPath   string
	tokenRefreshSec int
}

func NewStartCommand() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "metrics-proxy",
		Short: "A secure HTTP proxy server that authenticates clients via mTLS and forwards requests to a backend service with bearer token authentication.",
		Long: `A secure HTTP proxy server that authenticates clients via mTLS and forwards requests to a backend service with bearer token authentication.

The metrics proxy server works as follows:
1. Clients connect using mTLS with valid client certificates
2. Server validates client certificates against the provided CA bundle
3. Server reads bearer tokens from files and automatically refreshes them
4. Valid requests are forwarded to the backend with current bearer token authentication
5. Backend responses are returned to the client

This is particularly useful in Kubernetes environments where service account tokens are automatically rotated.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMetricsProxy(opts)
		},
	}

	cmd.Flags().StringVar(&opts.listenAddr, "listen-addr", ":8443", "Address to listen on")
	cmd.Flags().StringVar(&opts.backendURL, "backend-url", "", "Backend URL to proxy requests to (required)")
	cmd.Flags().StringVar(&opts.bearerTokenFile, "bearer-token-file", "", "Path to file containing bearer token for backend authentication (required)")
	cmd.Flags().StringVar(&opts.caBundlePath, "ca-bundle", "", "Path to CA bundle for client certificate validation (required)")
	cmd.Flags().StringVar(&opts.serverCertPath, "server-cert", "", "Path to server certificate (required)")
	cmd.Flags().StringVar(&opts.serverKeyPath, "server-key", "", "Path to server private key (required)")
	cmd.Flags().IntVar(&opts.tokenRefreshSec, "token-refresh-interval", 30, "Interval in seconds to refresh the bearer token from file")

	cmd.MarkFlagRequired("backend-url")
	cmd.MarkFlagRequired("bearer-token-file")
	cmd.MarkFlagRequired("ca-bundle")
	cmd.MarkFlagRequired("server-cert")
	cmd.MarkFlagRequired("server-key")

	return cmd
}

func runMetricsProxy(opts *options) error {
	// Setup logging
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerologr.NameFieldName = "logger"
	zerologr.NameSeparator = "/"

	zlog := zerolog.New(os.Stderr).With().Timestamp().Logger()
	logger := zerologr.New(&zlog).WithName("metrics-proxy")

	// Load CA bundle for client certificate validation
	caBundle, err := os.ReadFile(opts.caBundlePath)
	if err != nil {
		return fmt.Errorf("failed to read CA bundle: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caBundle) {
		return fmt.Errorf("failed to parse CA bundle")
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(opts.serverCertPath, opts.serverKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Create token manager
	tokenManager := NewTokenManager(opts.bearerTokenFile, opts.tokenRefreshSec, logger)

	// Validate token file before starting
	if err := tokenManager.ValidateTokenFile(); err != nil {
		return fmt.Errorf("failed to validate token file: %w", err)
	}

	// Start token manager
	ctx := context.Background()
	if err := tokenManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start token manager: %w", err)
	}
	defer tokenManager.Stop()

	// Create proxy server
	proxy := NewMetricsProxy(opts.backendURL, tokenManager, caCertPool, logger)

	// Configure TLS server
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      opts.listenAddr,
		Handler:   proxy,
		TLSConfig: tlsConfig,
	}

	logger.Info("Starting metrics proxy server", "listen-addr", opts.listenAddr, "backend-url", opts.backendURL)

	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}
