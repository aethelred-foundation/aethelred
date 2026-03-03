// Package runtime provides the high-performance runtime engine for Aethelred SDK.
//
// Features:
//   - Hardware Abstraction Layer (HAL) for CPUs, GPUs, TEEs
//   - Lock-free memory pool with size-class bucketing
//   - Async execution streams with dependency graphs
//   - Comprehensive profiling with Chrome Trace export
//   - JIT compilation support
package runtime

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// ============ Device Types ============

// DeviceType represents the type of compute device
type DeviceType int

const (
	// DeviceCPU device
	DeviceCPU DeviceType = iota
	// DeviceGPU GPU accelerator
	DeviceGPU
	// DeviceROCm AMD GPU
	DeviceROCm
	// DeviceMetal Apple GPU
	DeviceMetal
	// DeviceVulkan cross-platform GPU
	DeviceVulkan
	// DeviceIntelSGX Intel SGX enclave
	DeviceIntelSGX
	// DeviceAMDSEV AMD SEV enclave
	DeviceAMDSEV
	// DeviceAWSNitro AWS Nitro enclave
	DeviceAWSNitro
	// DeviceARMTrustZone ARM TrustZone
	DeviceARMTrustZone
)

// String returns the string representation of DeviceType
func (dt DeviceType) String() string {
	switch dt {
	case DeviceCPU:
		return "CPU"
	case DeviceGPU:
		return "GPU"
	case DeviceROCm:
		return "ROCm"
	case DeviceMetal:
		return "Metal"
	case DeviceVulkan:
		return "Vulkan"
	case DeviceIntelSGX:
		return "Intel SGX"
	case DeviceAMDSEV:
		return "AMD SEV"
	case DeviceAWSNitro:
		return "AWS Nitro"
	case DeviceARMTrustZone:
		return "ARM TrustZone"
	default:
		return "Unknown"
	}
}

// ============ Device Capabilities ============

// DeviceCapabilities represents the capabilities of a compute device
type DeviceCapabilities struct {
	ComputeCapability         [2]int
	TotalMemory               uint64
	MaxThreadsPerBlock        int
	MaxSharedMemoryPerBlock   int
	WarpSize                  int
	MultiProcessorCount       int
	SupportsFP16              bool
	SupportsBF16              bool
	SupportsFP8               bool
	SupportsInt8              bool
	SupportsInt4              bool
	SupportsTensorCores       bool
	SupportsAsyncCopy         bool
	SupportsCooperativeGroups bool
	MaxRegistersPerBlock      int
	ClockRateKHz              uint32
	MemoryClockRateKHz        uint32
	MemoryBusWidth            uint32
	L2CacheSize               uint64
}

// DefaultCPUCapabilities returns default capabilities for DeviceCPU
func DefaultCPUCapabilities() DeviceCapabilities {
	return DeviceCapabilities{
		ComputeCapability:       [2]int{0, 0},
		TotalMemory:             getSystemMemory(),
		MaxThreadsPerBlock:      runtime.NumCPU(),
		MaxSharedMemoryPerBlock: 0,
		WarpSize:                1,
		MultiProcessorCount:     runtime.NumCPU(),
		SupportsFP16:            true,
		SupportsBF16:            true,
		SupportsFP8:             false,
		SupportsInt8:            true,
		SupportsInt4:            false,
		SupportsTensorCores:     false,
		SupportsAsyncCopy:       true,
		MaxRegistersPerBlock:    0,
		ClockRateKHz:            3000000,
		MemoryClockRateKHz:      3200000,
		MemoryBusWidth:          64,
		L2CacheSize:             8 * 1024 * 1024,
	}
}

func getSystemMemory() uint64 {
	// Simplified - would use syscall in production
	return 16 * 1024 * 1024 * 1024 // 16GB default
}

// ============ Device ============

// Device represents a compute device
type Device struct {
	ID            int
	Type          DeviceType
	Name          string
	Capabilities  DeviceCapabilities
	IsAvailable   bool
	NativeBackend bool
	BackendName   string
	memoryPool    *MemoryPool
	mu            sync.RWMutex
}

// NewCPUDevice creates a new DeviceCPU device
func NewCPUDevice() *Device {
	numCPU := runtime.NumCPU()
	caps := DefaultCPUCapabilities()

	pool := NewMemoryPool(caps.TotalMemory / 2)

	return &Device{
		ID:            0,
		Type:          DeviceCPU,
		Name:          fmt.Sprintf("CPU (%d cores)", numCPU),
		Capabilities:  caps,
		IsAvailable:   true,
		NativeBackend: true,
		BackendName:   "cpu",
		memoryPool:    pool,
	}
}

// Allocate allocates memory on this device
func (d *Device) Allocate(size uint64) (*MemoryBlock, error) {
	if d == nil {
		return nil, fmt.Errorf("device is nil")
	}
	if !d.IsAvailable {
		return nil, ErrDeviceUnavailable
	}
	if d.Type != DeviceCPU && !d.NativeBackend && !AllowSimulatedGPU() {
		return nil, ErrNativeBackendRequired
	}
	return d.memoryPool.Allocate(size)
}

// Free frees memory on this device
func (d *Device) Free(block *MemoryBlock) error {
	return d.memoryPool.Free(block)
}

// Synchronize waits for all operations on this device to complete
func (d *Device) Synchronize() error {
	// DeviceCPU is always synchronized
	return nil
}

// String returns string representation
func (d *Device) String() string {
	return fmt.Sprintf("Device{ID: %d, Type: %s, Name: %s, Available: %v}",
		d.ID, d.Type, d.Name, d.IsAvailable)
}

// ============ Memory Management ============

// MemoryBlock represents an allocated memory block
type MemoryBlock struct {
	Ptr        unsafe.Pointer
	Size       uint64
	DeviceType DeviceType
	PoolID     uint64
	inUse      int32
}

// AsSlice returns the memory as a byte slice
func (m *MemoryBlock) AsSlice() []byte {
	return unsafe.Slice((*byte)(m.Ptr), m.Size)
}

// AsFloat32Slice returns the memory as a float32 slice
func (m *MemoryBlock) AsFloat32Slice() []float32 {
	return unsafe.Slice((*float32)(m.Ptr), m.Size/4)
}

// AsFloat64Slice returns the memory as a float64 slice
func (m *MemoryBlock) AsFloat64Slice() []float64 {
	return unsafe.Slice((*float64)(m.Ptr), m.Size/8)
}

// CopyFromHost copies data from host memory
func (m *MemoryBlock) CopyFromHost(data []byte) error {
	if uint64(len(data)) > m.Size {
		return ErrInsufficientSize
	}
	copy(m.AsSlice(), data)
	return nil
}

// CopyToHost copies data to host memory
func (m *MemoryBlock) CopyToHost(data []byte) error {
	if uint64(len(data)) > m.Size {
		return ErrInsufficientSize
	}
	copy(data, m.AsSlice())
	return nil
}

// MemoryError represents a memory operation error
type MemoryError struct {
	Op  string
	Err error
}

func (e *MemoryError) Error() string {
	return fmt.Sprintf("memory %s: %v", e.Op, e.Err)
}

var (
	// ErrAllocationFailed indicates memory allocation failed
	ErrAllocationFailed = fmt.Errorf("allocation failed")
	// ErrInsufficientSize indicates insufficient memory size
	ErrInsufficientSize = fmt.Errorf("insufficient size")
	// ErrPoolExhausted indicates the memory pool is exhausted
	ErrPoolExhausted = fmt.Errorf("pool exhausted")
	// ErrDoubleFree indicates a double free attempt
	ErrDoubleFree = fmt.Errorf("double free")
	// ErrInvalidPointer indicates an invalid pointer
	ErrInvalidPointer = fmt.Errorf("invalid pointer")
	// ErrDeviceUnavailable indicates the selected device cannot execute workloads.
	ErrDeviceUnavailable = fmt.Errorf("device unavailable")
	// ErrNativeBackendRequired indicates non-CPU execution requires native backend.
	ErrNativeBackendRequired = fmt.Errorf("native accelerator backend required")
)

// Size classes for memory pool buckets
var sizeClasses = []uint64{
	64,      // 64 bytes
	128,     // 128 bytes
	256,     // 256 bytes
	512,     // 512 bytes
	1024,    // 1 KB
	2048,    // 2 KB
	4096,    // 4 KB
	8192,    // 8 KB
	16384,   // 16 KB
	32768,   // 32 KB
	65536,   // 64 KB
	131072,  // 128 KB
	262144,  // 256 KB
	524288,  // 512 KB
	1048576, // 1 MB
	2097152, // 2 MB
}

// MemoryPool is a lock-free memory pool with size-class bucketing
type MemoryPool struct {
	maxSize   uint64
	allocated uint64
	poolID    uint64
	buckets   [16]sync.Pool
	mu        sync.Mutex
}

var poolCounter uint64

// NewMemoryPool creates a new memory pool
func NewMemoryPool(maxSize uint64) *MemoryPool {
	pool := &MemoryPool{
		maxSize: maxSize,
		poolID:  atomic.AddUint64(&poolCounter, 1),
	}

	// Initialize pools for each size class
	for i := range pool.buckets {
		size := sizeClasses[i]
		pool.buckets[i] = sync.Pool{
			New: func() interface{} {
				data := make([]byte, size)
				return &MemoryBlock{
					Ptr:        unsafe.Pointer(&data[0]),
					Size:       size,
					DeviceType: DeviceCPU,
					PoolID:     pool.poolID,
				}
			},
		}
	}

	return pool
}

// getSizeClass returns the size class index for a given size
func getSizeClass(size uint64) int {
	for i, classSize := range sizeClasses {
		if classSize >= size {
			return i
		}
	}
	return -1
}

// Allocate allocates memory from the pool
func (p *MemoryPool) Allocate(size uint64) (*MemoryBlock, error) {
	classIdx := getSizeClass(size)

	if classIdx >= 0 {
		// Get from pool
		block := p.buckets[classIdx].Get().(*MemoryBlock)
		atomic.StoreInt32(&block.inUse, 1)
		atomic.AddUint64(&p.allocated, sizeClasses[classIdx])
		return block, nil
	}

	// Size too large for pools, allocate directly
	current := atomic.LoadUint64(&p.allocated)
	if current+size > p.maxSize {
		return nil, ErrPoolExhausted
	}

	data := make([]byte, size)
	atomic.AddUint64(&p.allocated, size)

	return &MemoryBlock{
		Ptr:        unsafe.Pointer(&data[0]),
		Size:       size,
		DeviceType: DeviceCPU,
		PoolID:     p.poolID,
	}, nil
}

// Free returns memory to the pool
func (p *MemoryPool) Free(block *MemoryBlock) error {
	if block.PoolID != p.poolID {
		return ErrInvalidPointer
	}

	if !atomic.CompareAndSwapInt32(&block.inUse, 1, 0) {
		return ErrDoubleFree
	}

	classIdx := getSizeClass(block.Size)
	if classIdx >= 0 && sizeClasses[classIdx] == block.Size {
		// Return to pool
		p.buckets[classIdx].Put(block)
	} else {
		// Deallocate
		atomic.AddUint64(&p.allocated, ^(block.Size - 1))
	}

	return nil
}

// Stats returns pool statistics
func (p *MemoryPool) Stats() PoolStats {
	return PoolStats{
		MaxSize:   p.maxSize,
		Allocated: atomic.LoadUint64(&p.allocated),
	}
}

// PoolStats contains memory pool statistics
type PoolStats struct {
	MaxSize   uint64
	Allocated uint64
}

// ============ Execution Streams ============

// StreamState represents the state of an execution stream
type StreamState int32

const (
	// StreamIdle indicates the stream is idle
	StreamIdle StreamState = iota
	// StreamRunning indicates the stream is running
	StreamRunning
	// StreamCompleted indicates the stream has completed
	StreamCompleted
	// StreamError indicates the stream has an error
	StreamError
)

// Stream represents an async execution stream
type Stream struct {
	id           uint64
	device       *Device
	state        int32
	pendingOps   []func()
	dependencies []*Event
	mu           sync.Mutex
	wg           sync.WaitGroup
}

var streamCounter uint64

// NewStream creates a new stream on the given device
func NewStream(device *Device) *Stream {
	return &Stream{
		id:           atomic.AddUint64(&streamCounter, 1),
		device:       device,
		state:        int32(StreamIdle),
		pendingOps:   make([]func(), 0),
		dependencies: make([]*Event, 0),
	}
}

// ID returns the stream ID
func (s *Stream) ID() uint64 {
	return s.id
}

// State returns the current stream state
func (s *Stream) State() StreamState {
	return StreamState(atomic.LoadInt32(&s.state))
}

// Enqueue adds an operation to the stream
func (s *Stream) Enqueue(op func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingOps = append(s.pendingOps, op)
}

// WaitFor adds a dependency on an event
func (s *Stream) WaitFor(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dependencies = append(s.dependencies, event)
}

// Execute runs all pending operations
func (s *Stream) Execute() {
	// Wait for dependencies
	s.mu.Lock()
	deps := s.dependencies
	s.dependencies = make([]*Event, 0)
	s.mu.Unlock()

	for _, event := range deps {
		event.Wait()
	}

	atomic.StoreInt32(&s.state, int32(StreamRunning))

	// Execute operations
	for {
		s.mu.Lock()
		if len(s.pendingOps) == 0 {
			s.mu.Unlock()
			break
		}
		op := s.pendingOps[0]
		s.pendingOps = s.pendingOps[1:]
		s.mu.Unlock()

		op()
	}

	atomic.StoreInt32(&s.state, int32(StreamCompleted))
}

// ExecuteAsync runs operations asynchronously
func (s *Stream) ExecuteAsync() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.Execute()
	}()
}

// Synchronize waits for all operations to complete
func (s *Stream) Synchronize() {
	s.wg.Wait()
	for s.State() == StreamRunning {
		runtime.Gosched()
	}
}

// RecordEvent creates an event at the current point
func (s *Stream) RecordEvent() *Event {
	event := NewEvent()
	s.Enqueue(func() {
		event.Record()
	})
	return event
}

// ============ Events ============

// Event represents a synchronization event
type Event struct {
	id        uint64
	completed int32
	timestamp time.Time
	mu        sync.Mutex
	cond      *sync.Cond
}

var eventCounter uint64

// NewEvent creates a new event
func NewEvent() *Event {
	e := &Event{
		id: atomic.AddUint64(&eventCounter, 1),
	}
	e.cond = sync.NewCond(&e.mu)
	return e
}

// ID returns the event ID
func (e *Event) ID() uint64 {
	return e.id
}

// IsCompleted checks if the event is completed
func (e *Event) IsCompleted() bool {
	return atomic.LoadInt32(&e.completed) == 1
}

// Wait waits for the event to complete
func (e *Event) Wait() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for !e.IsCompleted() {
		e.cond.Wait()
	}
}

// WaitTimeout waits with a timeout
func (e *Event) WaitTimeout(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		e.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Record marks the event as completed
func (e *Event) Record() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.timestamp = time.Now()
	atomic.StoreInt32(&e.completed, 1)
	e.cond.Broadcast()
}

// ElapsedSince returns the time elapsed since another event
func (e *Event) ElapsedSince(other *Event) time.Duration {
	if !e.IsCompleted() || !other.IsCompleted() {
		return 0
	}
	return e.timestamp.Sub(other.timestamp)
}

// ============ Profiling ============

// ProfileEventType represents the type of profile event
type ProfileEventType int

const (
	// ProfileKernelLaunch is a kernel launch event
	ProfileKernelLaunch ProfileEventType = iota
	// ProfileMemoryCopy is a memory copy event
	ProfileMemoryCopy
	// ProfileMemoryAlloc is a memory allocation event
	ProfileMemoryAlloc
	// ProfileMemoryFree is a memory free event
	ProfileMemoryFree
	// ProfileSynchronize is a synchronization event
	ProfileSynchronize
	// ProfileCustom is a custom event
	ProfileCustom
)

// ProfileEvent represents a profiling event
type ProfileEvent struct {
	Name      string
	Type      ProfileEventType
	StartTime time.Time
	Duration  time.Duration
	DeviceID  int
	StreamID  uint64
	Metadata  map[string]string
}

// Profiler is a performance profiler
type Profiler struct {
	enabled   int32
	events    []ProfileEvent
	startTime time.Time
	mu        sync.Mutex
}

// NewProfiler creates a new profiler
func NewProfiler() *Profiler {
	return &Profiler{
		events:    make([]ProfileEvent, 0),
		startTime: time.Now(),
	}
}

// Enable enables profiling
func (p *Profiler) Enable() {
	atomic.StoreInt32(&p.enabled, 1)
}

// Disable disables profiling
func (p *Profiler) Disable() {
	atomic.StoreInt32(&p.enabled, 0)
}

// IsEnabled checks if profiling is enabled
func (p *Profiler) IsEnabled() bool {
	return atomic.LoadInt32(&p.enabled) == 1
}

// Record records a profile event
func (p *Profiler) Record(event ProfileEvent) {
	if !p.IsEnabled() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
}

// Scope creates a profiling scope
func (p *Profiler) Scope(name string, eventType ProfileEventType) *ProfileScope {
	return &ProfileScope{
		profiler:  p,
		name:      name,
		eventType: eventType,
		startTime: time.Now(),
	}
}

// GetEvents returns all recorded events
func (p *Profiler) GetEvents() []ProfileEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	events := make([]ProfileEvent, len(p.events))
	copy(events, p.events)
	return events
}

// Clear clears all events
func (p *Profiler) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = make([]ProfileEvent, 0)
}

// ExportChromeTrace exports to Chrome Trace format
func (p *Profiler) ExportChromeTrace() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var traceEvents []string
	for _, event := range p.events {
		startUs := event.StartTime.Sub(p.startTime).Microseconds()
		durUs := event.Duration.Microseconds()
		traceEvents = append(traceEvents, fmt.Sprintf(
			`{"name":"%s","cat":"%d","ph":"X","ts":%d,"dur":%d,"pid":0,"tid":%d}`,
			event.Name, event.Type, startUs, durUs, event.StreamID,
		))
	}

	result := `{"traceEvents":[`
	for i, e := range traceEvents {
		if i > 0 {
			result += ","
		}
		result += e
	}
	result += `]}`
	return result
}

// Summary returns a summary of profiling data
func (p *Profiler) Summary() ProfileSummary {
	p.mu.Lock()
	defer p.mu.Unlock()

	summary := ProfileSummary{
		TotalEvents: len(p.events),
		ByName:      make(map[string]*EventStats),
	}

	for _, event := range p.events {
		summary.TotalTime += event.Duration

		stats, ok := summary.ByName[event.Name]
		if !ok {
			stats = &EventStats{
				MinTime: event.Duration,
				MaxTime: event.Duration,
			}
			summary.ByName[event.Name] = stats
		}

		stats.Count++
		stats.TotalTime += event.Duration
		if event.Duration < stats.MinTime {
			stats.MinTime = event.Duration
		}
		if event.Duration > stats.MaxTime {
			stats.MaxTime = event.Duration
		}
	}

	return summary
}

// ProfileScope is a scoped profiling helper
type ProfileScope struct {
	profiler  *Profiler
	name      string
	eventType ProfileEventType
	startTime time.Time
}

// End ends the profiling scope
func (s *ProfileScope) End() {
	s.profiler.Record(ProfileEvent{
		Name:      s.name,
		Type:      s.eventType,
		StartTime: s.startTime,
		Duration:  time.Since(s.startTime),
	})
}

// ProfileSummary contains profiling summary data
type ProfileSummary struct {
	TotalEvents int
	TotalTime   time.Duration
	ByName      map[string]*EventStats
}

// EventStats contains statistics for a specific event type
type EventStats struct {
	Count     int
	TotalTime time.Duration
	MinTime   time.Duration
	MaxTime   time.Duration
}

// AvgTime returns the average time
func (s *EventStats) AvgTime() time.Duration {
	if s.Count == 0 {
		return 0
	}
	return s.TotalTime / time.Duration(s.Count)
}

// ============ Runtime ============

// Runtime is the global runtime instance
type Runtime struct {
	devices       []*Device
	defaultDevice *Device
	profiler      *Profiler
	initialized   int32
	mu            sync.RWMutex
}

var (
	globalRuntime *Runtime
	runtimeOnce   sync.Once
)

// Instance returns the global runtime instance
func Instance() *Runtime {
	runtimeOnce.Do(func() {
		globalRuntime = &Runtime{
			devices:  make([]*Device, 0),
			profiler: NewProfiler(),
		}
	})
	return globalRuntime
}

// Initialize initializes the runtime
func (r *Runtime) Initialize() error {
	if !atomic.CompareAndSwapInt32(&r.initialized, 0, 1) {
		return nil // Already initialized
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Add CPU device
	cpu := NewCPUDevice()
	r.devices = append(r.devices, cpu)
	r.defaultDevice = cpu

	// Detect physical GPU devices for visibility. These are only executable
	// when a native backend is enabled (or simulation is explicitly allowed).
	r.devices = append(r.devices, detectGPUDevices()...)

	return nil
}

// Devices returns all available devices
func (r *Runtime) Devices() []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	devices := make([]*Device, len(r.devices))
	copy(devices, r.devices)
	return devices
}

// DefaultDevice returns the default device
func (r *Runtime) DefaultDevice() *Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultDevice
}

// SetDefaultDevice sets the default device
func (r *Runtime) SetDefaultDevice(device *Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultDevice = device
}

// Profiler returns the profiler
func (r *Runtime) Profiler() *Profiler {
	return r.profiler
}

// EnableProfiling enables profiling
func (r *Runtime) EnableProfiling() {
	r.profiler.Enable()
}

// DisableProfiling disables profiling
func (r *Runtime) DisableProfiling() {
	r.profiler.Disable()
}

// IsInitialized checks if runtime is initialized
func (r *Runtime) IsInitialized() bool {
	return atomic.LoadInt32(&r.initialized) == 1
}
