//go:build linux
// +build linux

package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yairfalse/tapio/pkg/collectors/dns/bpf"
)

// BPF generation is handled in bpf/generate.go

// DNSEvent represents a DNS event from eBPF
type DNSEvent struct {
	Timestamp       uint64
	ProcessID       uint32
	ThreadID        uint32
	EventType       uint8 // 1=query, 2=response, 3=error
	Protocol        uint8 // 6=TCP, 17=UDP
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

// rawDNSEvent represents the raw DNS event structure from eBPF (must match C struct)
type rawDNSEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	EventType uint8
	Protocol  uint8
	_         [2]byte // padding
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	DNSOpcode uint8
	DNSRCode  uint8
	DNSFlags  uint16
	DataLen   uint32
	QueryName [64]byte
	Data      [256]byte
}

// eBPF components
type ebpfState struct {
	objs   *bpf.DnsMonitorObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// startEBPF initializes eBPF monitoring for DNS
func (c *Collector) startEBPF() error {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load eBPF objects
	objs := &bpf.DnsMonitorObjects{}
	if err := bpf.LoadDnsMonitor(objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Create eBPF state
	state := &ebpfState{
		objs:  objs,
		links: make([]link.Link, 0),
	}

	// For now, we'll use tracepoint-based monitoring as TC requires more setup
	// In production, you'd want to use TC (traffic control) for better network monitoring

	// Attach to socket system calls for DNS monitoring
	// Note: This is a simplified approach - full DNS monitoring would need TC hooks
	if err := c.attachSocketTracepoints(state); err != nil {
		state.cleanup()
		return fmt.Errorf("failed to attach tracepoints: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		state.cleanup()
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	state.reader = reader

	// Store state and start reading events
	c.ebpfState = state
	go c.readEBPFEvents()

	return nil
}

// attachSocketTracepoints attaches to socket-related tracepoints
func (c *Collector) attachSocketTracepoints(state *ebpfState) error {
	// Attach to sendto syscall (outgoing DNS queries)
	l1, err := link.Tracepoint("syscalls", "sys_enter_sendto", state.objs.TraceDnsQuery, nil)
	if err != nil {
		return fmt.Errorf("attaching sendto tracepoint: %w", err)
	}
	state.links = append(state.links, l1)

	// Attach to recvfrom syscall (incoming DNS responses)
	l2, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", state.objs.TraceDnsResponse, nil)
	if err != nil {
		return fmt.Errorf("attaching recvfrom tracepoint: %w", err)
	}
	state.links = append(state.links, l2)

	return nil
}

// stopEBPF cleans up eBPF resources
func (c *Collector) stopEBPF() {
	if state, ok := c.ebpfState.(*ebpfState); ok && state != nil {
		state.cleanup()
		c.ebpfState = nil
	}
}

// cleanup releases all eBPF resources
func (s *ebpfState) cleanup() {
	if s.reader != nil {
		s.reader.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	if s.objs != nil {
		s.objs.Close()
	}
}

// readEBPFEvents reads events from eBPF ring buffer
func (c *Collector) readEBPFEvents() {
	state, ok := c.ebpfState.(*ebpfState)
	if !ok || state == nil {
		return
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			record, err := state.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				// Log error and continue
				continue
			}

			// Parse the raw event
			var rawEvent rawDNSEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
				continue
			}

			// Convert to high-level DNS event
			dnsEvent := c.convertRawEvent(&rawEvent)

			// Process the DNS event based on type
			switch dnsEvent.EventType {
			case 1: // DNS_TYPE_QUERY
				c.processDNSQuery(dnsEvent)
			case 2: // DNS_TYPE_RESPONSE
				c.processDNSResponse(dnsEvent)
			case 3: // DNS_TYPE_ERROR
				c.processDNSFailure(dnsEvent)
			}
		}
	}
}

// convertRawEvent converts raw eBPF event to high-level DNS event
func (c *Collector) convertRawEvent(raw *rawDNSEvent) *DNSEvent {
	event := &DNSEvent{
		Timestamp:       raw.Timestamp,
		ProcessID:       raw.PID,
		ThreadID:        raw.TID,
		EventType:       raw.EventType,
		Protocol:        raw.Protocol,
		SourcePort:      raw.SrcPort,
		DestinationPort: raw.DstPort,
		Opcode:          raw.DNSOpcode,
		ResponseCode:    raw.DNSRCode,
		Flags:           raw.DNSFlags,
	}

	// Convert IP addresses from uint32 to string
	event.SourceIP = fmt.Sprintf("%d.%d.%d.%d",
		byte(raw.SrcIP), byte(raw.SrcIP>>8),
		byte(raw.SrcIP>>16), byte(raw.SrcIP>>24))
	event.DestinationIP = fmt.Sprintf("%d.%d.%d.%d",
		byte(raw.DstIP), byte(raw.DstIP>>8),
		byte(raw.DstIP>>16), byte(raw.DstIP>>24))

	// Extract query name (null-terminated string)
	queryNameBytes := raw.QueryName[:]
	for i, b := range queryNameBytes {
		if b == 0 {
			queryNameBytes = queryNameBytes[:i]
			break
		}
	}
	event.QueryName = string(queryNameBytes)

	// Copy raw data
	if raw.DataLen > 0 && raw.DataLen <= 256 {
		event.RawData = make([]byte, raw.DataLen)
		copy(event.RawData, raw.Data[:raw.DataLen])
	}

	return event
}

// processDNSQuery processes a DNS query event
func (c *Collector) processDNSQuery(dnsEvent *DNSEvent) {
	c.mu.Lock()
	c.stats.QueriesTracked++
	c.stats.LastEventTime = time.Now()
	c.mu.Unlock()

	// Store pending query for correlation
	queryKey := c.createQueryKey(dnsEvent)
	pendingQuery := &PendingQuery{
		TransactionID: uint16(dnsEvent.Flags), // Simplified - would extract actual transaction ID
		QueryName:     dnsEvent.QueryName,
		QueryType:     "A", // Simplified - would extract actual query type
		SourceIP:      dnsEvent.SourceIP,
		DestinationIP: dnsEvent.DestinationIP,
		Port:          dnsEvent.DestinationPort,
		Timestamp:     time.Unix(0, int64(dnsEvent.Timestamp)),
		ProcessID:     dnsEvent.ProcessID,
		ThreadID:      dnsEvent.ThreadID,
	}

	c.pendingQueriesMu.Lock()
	c.pendingQueries[queryKey] = pendingQuery
	c.pendingQueriesMu.Unlock()
}

// processDNSResponse processes a DNS response event
func (c *Collector) processDNSResponse(dnsEvent *DNSEvent) {
	c.mu.Lock()
	c.stats.ResponsesTracked++
	c.stats.LastEventTime = time.Now()
	c.mu.Unlock()

	// Try to correlate with pending query
	queryKey := c.createQueryKey(dnsEvent)
	c.pendingQueriesMu.Lock()
	if pendingQuery, exists := c.pendingQueries[queryKey]; exists {
		delete(c.pendingQueries, queryKey)
		c.pendingQueriesMu.Unlock()

		// Calculate response time
		responseTime := time.Unix(0, int64(dnsEvent.Timestamp)).Sub(pendingQuery.Timestamp)

		// Check for slow responses
		if responseTime > time.Duration(c.config.FailureThreshold.ResponseTimeMs)*time.Millisecond {
			c.processSlowDNSResponse(dnsEvent, pendingQuery, responseTime)
		}
	} else {
		c.pendingQueriesMu.Unlock()
	}

	// Update failure tracking for successful responses
	if dnsEvent.ResponseCode == 0 { // NOERROR
		c.updateFailureStats(dnsEvent)
	}
}

// processSlowDNSResponse processes slow DNS responses
func (c *Collector) processSlowDNSResponse(dnsEvent *DNSEvent, pendingQuery *PendingQuery, responseTime time.Duration) {
	// Create slow response event
	// Similar to processDNSTimeout but for slow responses
	// Implementation would be similar to other event creation methods
}

// createQueryKey creates a unique key for query correlation
func (c *Collector) createQueryKey(dnsEvent *DNSEvent) string {
	return fmt.Sprintf("%s:%s:%d:%d",
		dnsEvent.SourceIP, dnsEvent.QueryName,
		dnsEvent.SourcePort, dnsEvent.ProcessID)
}

// Helper method to check if domain should be monitored
func (c *Collector) shouldMonitorDomain(domain string) bool {
	// If no specific domains configured, monitor all
	if len(c.config.Filters.Domains) == 0 {
		return true
	}

	// Check if domain matches configured filters
	for _, filterDomain := range c.config.Filters.Domains {
		if domain == filterDomain {
			return true
		}
		// Could add wildcard matching here
	}

	return false
}

// Helper method to check if we should ignore local queries
func (c *Collector) shouldIgnoreLocal(ip string) bool {
	if !c.config.Filters.IgnoreLocal {
		return false
	}

	// Check for localhost and private IP ranges
	return ip == "127.0.0.1" || ip == "::1" ||
		(len(ip) > 7 && ip[:7] == "192.168") ||
		(len(ip) > 3 && ip[:3] == "10.") ||
		(len(ip) > 7 && ip[:7] == "172.16")
}
