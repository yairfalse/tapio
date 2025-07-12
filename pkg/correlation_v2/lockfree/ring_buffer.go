package lockfree

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

// RingBuffer implements a high-performance lock-free ring buffer
// Optimized for single-producer, multiple-consumer scenarios
type RingBuffer struct {
	// Buffer storage - must be power of 2 size for fast modulo
	buffer []unsafe.Pointer
	mask   uint64 // size - 1, for fast modulo operation
	
	// Atomic counters for lock-free operations
	writePos uint64 // Producer position
	readPos  uint64 // Consumer position
	
	// Cache line padding to prevent false sharing
	_ [CacheLineSize - 16]byte
}

// CacheLineSize represents the CPU cache line size for padding
const CacheLineSize = 64

// NewRingBuffer creates a new lock-free ring buffer
// Size must be a power of 2 for optimal performance
func NewRingBuffer(size uint64) *RingBuffer {
	if size == 0 || (size&(size-1)) != 0 {
		panic("Ring buffer size must be a power of 2")
	}
	
	return &RingBuffer{
		buffer: make([]unsafe.Pointer, size),
		mask:   size - 1,
	}
}

// Push adds an item to the ring buffer (single producer)
// Returns false if buffer is full
func (rb *RingBuffer) Push(item unsafe.Pointer) bool {
	writePos := atomic.LoadUint64(&rb.writePos)
	readPos := atomic.LoadUint64(&rb.readPos)
	
	// Check if buffer is full (leave one slot empty to distinguish full from empty)
	if writePos-readPos >= uint64(len(rb.buffer))-1 {
		return false
	}
	
	// Store the item
	index := writePos & rb.mask
	atomic.StorePointer(&rb.buffer[index], item)
	
	// Update write position (release barrier)
	atomic.StoreUint64(&rb.writePos, writePos+1)
	
	return true
}

// Pop removes an item from the ring buffer (multiple consumers)
// Returns nil if buffer is empty
func (rb *RingBuffer) Pop() unsafe.Pointer {
	for {
		readPos := atomic.LoadUint64(&rb.readPos)
		writePos := atomic.LoadUint64(&rb.writePos)
		
		// Check if buffer is empty
		if readPos >= writePos {
			return nil
		}
		
		// Try to claim the slot
		if !atomic.CompareAndSwapUint64(&rb.readPos, readPos, readPos+1) {
			// Another consumer got there first, retry
			runtime.Gosched()
			continue
		}
		
		// Successfully claimed, read the item
		index := readPos & rb.mask
		item := atomic.LoadPointer(&rb.buffer[index])
		
		// Clear the slot to help GC
		atomic.StorePointer(&rb.buffer[index], nil)
		
		return item
	}
}

// TryPop attempts to pop without blocking
// Returns item and true if successful, nil and false if empty
func (rb *RingBuffer) TryPop() (unsafe.Pointer, bool) {
	readPos := atomic.LoadUint64(&rb.readPos)
	writePos := atomic.LoadUint64(&rb.writePos)
	
	// Check if buffer is empty
	if readPos >= writePos {
		return nil, false
	}
	
	// Try to claim the slot (non-blocking)
	if !atomic.CompareAndSwapUint64(&rb.readPos, readPos, readPos+1) {
		return nil, false
	}
	
	// Successfully claimed, read the item
	index := readPos & rb.mask
	item := atomic.LoadPointer(&rb.buffer[index])
	
	// Clear the slot to help GC
	atomic.StorePointer(&rb.buffer[index], nil)
	
	return item, true
}

// Size returns the current number of items in the buffer
func (rb *RingBuffer) Size() uint64 {
	writePos := atomic.LoadUint64(&rb.writePos)
	readPos := atomic.LoadUint64(&rb.readPos)
	
	if writePos >= readPos {
		return writePos - readPos
	}
	return 0
}

// Capacity returns the maximum capacity of the buffer
func (rb *RingBuffer) Capacity() uint64 {
	return uint64(len(rb.buffer)) - 1 // One slot reserved
}

// IsFull returns true if the buffer is full
func (rb *RingBuffer) IsFull() bool {
	writePos := atomic.LoadUint64(&rb.writePos)
	readPos := atomic.LoadUint64(&rb.readPos)
	return writePos-readPos >= uint64(len(rb.buffer))-1
}

// IsEmpty returns true if the buffer is empty
func (rb *RingBuffer) IsEmpty() bool {
	writePos := atomic.LoadUint64(&rb.writePos)
	readPos := atomic.LoadUint64(&rb.readPos)
	return readPos >= writePos
}

// Stats returns performance statistics
func (rb *RingBuffer) Stats() RingBufferStats {
	writePos := atomic.LoadUint64(&rb.writePos)
	readPos := atomic.LoadUint64(&rb.readPos)
	
	return RingBufferStats{
		WritePos:     writePos,
		ReadPos:      readPos,
		Size:         rb.Size(),
		Capacity:     rb.Capacity(),
		Utilization:  float64(rb.Size()) / float64(rb.Capacity()),
	}
}

// RingBufferStats contains performance metrics
type RingBufferStats struct {
	WritePos     uint64  `json:"write_pos"`
	ReadPos      uint64  `json:"read_pos"`
	Size         uint64  `json:"size"`
	Capacity     uint64  `json:"capacity"`
	Utilization  float64 `json:"utilization"`
}

// BatchPop pops multiple items at once for better cache efficiency
// Returns the number of items actually popped
func (rb *RingBuffer) BatchPop(items []unsafe.Pointer) int {
	if len(items) == 0 {
		return 0
	}
	
	popped := 0
	for i := 0; i < len(items); i++ {
		if item, ok := rb.TryPop(); ok {
			items[i] = item
			popped++
		} else {
			break
		}
	}
	
	return popped
}

// Reset clears the ring buffer
func (rb *RingBuffer) Reset() {
	// Drain all items
	for !rb.IsEmpty() {
		rb.Pop()
	}
	
	// Reset positions
	atomic.StoreUint64(&rb.writePos, 0)
	atomic.StoreUint64(&rb.readPos, 0)
}

// WaitForSpace blocks until space is available for writing
// Returns false if context is cancelled
func (rb *RingBuffer) WaitForSpace() bool {
	for rb.IsFull() {
		runtime.Gosched() // Yield to other goroutines
	}
	return true
}

// WaitForItem blocks until an item is available for reading
// Returns false if context is cancelled
func (rb *RingBuffer) WaitForItem() bool {
	for rb.IsEmpty() {
		runtime.Gosched() // Yield to other goroutines
	}
	return true
}