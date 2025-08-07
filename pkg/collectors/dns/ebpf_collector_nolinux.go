//go:build !linux
// +build !linux

package dns

import "fmt"

// DNSEvent represents a DNS event (stub for non-Linux platforms)
type DNSEvent struct {
	Timestamp       uint64
	ProcessID       uint32
	ThreadID        uint32
	EventType       uint8
	Protocol        uint8
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Opcode          uint8
	ResponseCode    uint8
	Flags           uint16
	QueryName       string
	RawData         []byte
}

// startEBPF is not supported on non-Linux platforms
func (c *Collector) startEBPF() error {
	return fmt.Errorf("eBPF DNS monitoring is only supported on Linux")
}

// stopEBPF is a no-op on non-Linux platforms
func (c *Collector) stopEBPF() {
	// No-op
}
