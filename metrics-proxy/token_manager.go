package metricsproxy

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// TokenManager handles reading and refreshing bearer tokens from a file.
type TokenManager struct {
	tokenFile    string
	refreshSec   int
	currentToken string
	mutex        sync.RWMutex
	logger       logr.Logger
	stopCh       chan struct{}
}

// NewTokenManager creates a new token manager.
func NewTokenManager(tokenFile string, refreshSec int, logger logr.Logger) *TokenManager {
	return &TokenManager{
		tokenFile:  tokenFile,
		refreshSec: refreshSec,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}
}

// Start begins the token refresh goroutine.
func (tm *TokenManager) Start(ctx context.Context) error {
	// Load initial token
	if err := tm.loadToken(); err != nil {
		return fmt.Errorf("failed to load initial token: %w", err)
	}

	// Start refresh goroutine
	go tm.refreshLoop(ctx)
	return nil
}

// Stop stops the token refresh goroutine.
func (tm *TokenManager) Stop() {
	close(tm.stopCh)
}

// GetToken returns the current bearer token.
func (tm *TokenManager) GetToken() string {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	return tm.currentToken
}

// loadToken reads the token from the file and updates the current token.
func (tm *TokenManager) loadToken() error {
	file, err := os.Open(tm.tokenFile)
	if err != nil {
		return fmt.Errorf("failed to open token file %s: %w", tm.tokenFile, err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read token file %s: %w", tm.tokenFile, err)
	}

	token := strings.TrimSpace(string(content))
	if token == "" {
		return fmt.Errorf("token file %s is empty or contains only whitespace", tm.tokenFile)
	}

	tm.mutex.Lock()
	oldToken := tm.currentToken
	tm.currentToken = token
	tm.mutex.Unlock()

	// Log token change (without logging the actual token for security)
	if oldToken != "" && oldToken != token {
		tm.logger.Info("Bearer token refreshed from file", "file", tm.tokenFile)
	} else if oldToken == "" {
		tm.logger.Info("Bearer token loaded from file", "file", tm.tokenFile)
	}

	return nil
}

// refreshLoop periodically refreshes the token from the file.
func (tm *TokenManager) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(tm.refreshSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			tm.logger.Info("Token refresh loop stopped due to context cancellation")
			return
		case <-tm.stopCh:
			tm.logger.Info("Token refresh loop stopped")
			return
		case <-ticker.C:
			if err := tm.loadToken(); err != nil {
				tm.logger.Error(err, "Failed to refresh token from file", "file", tm.tokenFile)
				// Continue with the old token rather than failing completely
			}
		}
	}
}

// ValidateTokenFile checks if the token file exists and is readable.
func (tm *TokenManager) ValidateTokenFile() error {
	file, err := os.Open(tm.tokenFile)
	if err != nil {
		return fmt.Errorf("failed to open token file %s: %w", tm.tokenFile, err)
	}
	defer file.Close()

	// Try to read a small amount to verify the file is readable
	buffer := make([]byte, 1)
	_, err = file.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read token file %s: %w", tm.tokenFile, err)
	}

	return nil
}
