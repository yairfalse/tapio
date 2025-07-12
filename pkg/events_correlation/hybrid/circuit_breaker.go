package hybrid

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState represents the state of the circuit breaker
type CircuitState int32

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

// String returns the string representation of the circuit state
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker protects V2 engine from cascading failures
type CircuitBreaker struct {
	config CircuitConfig
	
	state           atomic.Int32
	failures        atomic.Int32
	successes       atomic.Int32
	lastFailureTime atomic.Int64
	lastStateChange atomic.Int64
	
	halfOpenMutex sync.Mutex
}

// CircuitConfig configures the circuit breaker
type CircuitConfig struct {
	FailureThreshold int           // Number of failures before opening
	SuccessThreshold int           // Number of successes in half-open before closing
	Timeout          time.Duration // Timeout for each call
	ResetTimeout     time.Duration // Time before attempting reset
}

// Errors
var (
	ErrCircuitOpen = errors.New("circuit breaker is open")
	ErrTimeout     = errors.New("operation timed out")
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitConfig) *CircuitBreaker {
	cb := &CircuitBreaker{
		config: config,
	}
	cb.state.Store(int32(StateClosed))
	return cb
}

// Call executes the given function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	state := cb.State()
	
	switch state {
	case StateOpen:
		// Check if we should transition to half-open
		if cb.shouldAttemptReset() {
			cb.transitionToHalfOpen()
			return cb.callInHalfOpen(fn)
		}
		return ErrCircuitOpen
		
	case StateHalfOpen:
		return cb.callInHalfOpen(fn)
		
	case StateClosed:
		return cb.callInClosed(fn)
		
	default:
		return ErrCircuitOpen
	}
}

// callInClosed executes the function when circuit is closed
func (cb *CircuitBreaker) callInClosed(fn func() error) error {
	// Execute with timeout
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()
	
	select {
	case err := <-done:
		if err != nil {
			cb.recordFailure()
			
			// Check if we should open the circuit
			if cb.failures.Load() >= int32(cb.config.FailureThreshold) {
				cb.transitionToOpen()
			}
			
			return err
		}
		
		cb.recordSuccess()
		return nil
		
	case <-time.After(cb.config.Timeout):
		cb.recordFailure()
		
		// Check if we should open the circuit
		if cb.failures.Load() >= int32(cb.config.FailureThreshold) {
			cb.transitionToOpen()
		}
		
		return ErrTimeout
	}
}

// callInHalfOpen executes the function when circuit is half-open
func (cb *CircuitBreaker) callInHalfOpen(fn func() error) error {
	// Only allow one call at a time in half-open state
	cb.halfOpenMutex.Lock()
	defer cb.halfOpenMutex.Unlock()
	
	// Re-check state as it might have changed while waiting for lock
	if cb.State() != StateHalfOpen {
		return cb.Call(fn)
	}
	
	// Execute with timeout
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()
	
	select {
	case err := <-done:
		if err != nil {
			cb.transitionToOpen()
			return err
		}
		
		cb.recordSuccess()
		
		// Check if we should close the circuit
		if cb.successes.Load() >= int32(cb.config.SuccessThreshold) {
			cb.transitionToClosed()
		}
		
		return nil
		
	case <-time.After(cb.config.Timeout):
		cb.transitionToOpen()
		return ErrTimeout
	}
}

// State returns the current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// shouldAttemptReset checks if enough time has passed to attempt reset
func (cb *CircuitBreaker) shouldAttemptReset() bool {
	lastFailure := time.Unix(0, cb.lastFailureTime.Load())
	return time.Since(lastFailure) >= cb.config.ResetTimeout
}

// recordFailure records a failure
func (cb *CircuitBreaker) recordFailure() {
	cb.failures.Add(1)
	cb.lastFailureTime.Store(time.Now().UnixNano())
}

// recordSuccess records a success
func (cb *CircuitBreaker) recordSuccess() {
	cb.successes.Add(1)
	// Reset failure count on success in closed state
	if cb.State() == StateClosed {
		cb.failures.Store(0)
	}
}

// transitionToOpen transitions the circuit to open state
func (cb *CircuitBreaker) transitionToOpen() {
	cb.state.Store(int32(StateOpen))
	cb.lastStateChange.Store(time.Now().UnixNano())
	cb.failures.Store(0)
	cb.successes.Store(0)
}

// transitionToHalfOpen transitions the circuit to half-open state
func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.state.Store(int32(StateHalfOpen))
	cb.lastStateChange.Store(time.Now().UnixNano())
	cb.failures.Store(0)
	cb.successes.Store(0)
}

// transitionToClosed transitions the circuit to closed state
func (cb *CircuitBreaker) transitionToClosed() {
	cb.state.Store(int32(StateClosed))
	cb.lastStateChange.Store(time.Now().UnixNano())
	cb.failures.Store(0)
	cb.successes.Store(0)
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	lastStateChange := time.Unix(0, cb.lastStateChange.Load())
	lastFailure := time.Unix(0, cb.lastFailureTime.Load())
	
	return CircuitBreakerStats{
		State:           cb.State(),
		Failures:        cb.failures.Load(),
		Successes:       cb.successes.Load(),
		LastStateChange: lastStateChange,
		LastFailureTime: lastFailure,
		TimeInState:     time.Since(lastStateChange),
	}
}

// CircuitBreakerStats contains circuit breaker statistics
type CircuitBreakerStats struct {
	State           CircuitState
	Failures        int32
	Successes       int32
	LastStateChange time.Time
	LastFailureTime time.Time
	TimeInState     time.Duration
}