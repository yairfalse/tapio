package cni

import (
	"crypto/rand"
	"fmt"
	"time"
)

// Logger interface for consistent logging
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

// generateEventID generates a unique event ID
func generateEventID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("cni_corr_%x_%d", b, time.Now().UnixNano())
}

// contains checks if a string slice contains a value
func contains(item string, slice []string) bool {
	for _, s := range slice {
		if item == s {
			return true
		}
	}
	return false
}
