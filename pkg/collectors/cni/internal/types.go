package internal

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/yairfalse/tapio/pkg/domain"
)

// Logger interface for consistent logging across monitors
type Logger interface {
	Info(msg string, fields map[string]interface{})
	Warn(msg string, fields map[string]interface{})
	Error(msg string, fields map[string]interface{})
	Debug(msg string, fields map[string]interface{})
}

// StandardLogger provides a basic logger implementation
type StandardLogger struct{}

func (l *StandardLogger) Info(msg string, fields map[string]interface{}) {
	fmt.Printf("[INFO] %s %v\n", msg, fields)
}

func (l *StandardLogger) Warn(msg string, fields map[string]interface{}) {
	fmt.Printf("[WARN] %s %v\n", msg, fields)
}

func (l *StandardLogger) Error(msg string, fields map[string]interface{}) {
	fmt.Printf("[ERROR] %s %v\n", msg, fields)
}

func (l *StandardLogger) Debug(msg string, fields map[string]interface{}) {
	fmt.Printf("[DEBUG] %s %v\n", msg, fields)
}

// Monitor interface that all CNI monitors must implement
type Monitor interface {
	Start(ctx context.Context, events chan<- domain.UnifiedEvent) error
	Stop() error
}

// generateEventID generates a unique event ID
func generateEventID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("cni_%x_%d", b, time.Now().UnixNano())
}
