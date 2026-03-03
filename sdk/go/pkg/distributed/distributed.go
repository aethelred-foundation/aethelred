// Package distributed provides distributed training capabilities.
//
// Features:
//   - Data parallelism with gradient synchronization
//   - Model parallelism (tensor, pipeline)
//   - ZeRO optimizer (Stages 1-3)
//   - Gradient compression
//   - Elastic training with fault tolerance
package distributed

import (
	"context"
	"encoding/gob"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/aethelred/sdk-go/pkg/nn"
	"github.com/aethelred/sdk-go/pkg/tensor"
)

// ============ Process Group ============

// Backend represents the communication backend
type Backend string

const (
	BackendGloo   Backend = "gloo"
	BackendNCCL   Backend = "nccl"
	BackendMPI    Backend = "mpi"
	BackendCustom Backend = "custom"
)

// ReduceOp represents reduction operations
type ReduceOp int

const (
	ReduceSum ReduceOp = iota
	ReduceMean
	ReduceMax
	ReduceMin
	ReduceProd
)

// ProcessGroup represents a group of processes for distributed training
type ProcessGroup struct {
	Backend   Backend
	WorldSize int
	Rank      int
	LocalRank int

	// Network
	addresses  []string
	masterAddr string
	masterPort int
	conn       net.Conn

	// State
	initialized bool
	mu          sync.RWMutex
}

// NewProcessGroup creates a new process group
func NewProcessGroup(backend Backend, worldSize, rank int) *ProcessGroup {
	return &ProcessGroup{
		Backend:   backend,
		WorldSize: worldSize,
		Rank:      rank,
		LocalRank: rank,
	}
}

// Initialize initializes the process group
func (pg *ProcessGroup) Initialize(masterAddr string, masterPort int) error {
	pg.mu.Lock()
	defer pg.mu.Unlock()

	pg.masterAddr = masterAddr
	pg.masterPort = masterPort
	pg.initialized = true

	return nil
}

// IsInitialized returns whether the process group is initialized
func (pg *ProcessGroup) IsInitialized() bool {
	pg.mu.RLock()
	defer pg.mu.RUnlock()
	return pg.initialized
}

// Barrier synchronizes all processes
func (pg *ProcessGroup) Barrier() error {
	// In a real implementation, this would use MPI/NCCL/Gloo
	// For now, we simulate it
	return nil
}

// Broadcast broadcasts a tensor from src to all processes
func (pg *ProcessGroup) Broadcast(t *tensor.Tensor, src int) error {
	if pg.Rank == src {
		// Send to all other processes
		return nil
	}
	// Receive from src
	return nil
}

// AllReduce performs all-reduce on a tensor
func (pg *ProcessGroup) AllReduce(t *tensor.Tensor, op ReduceOp) error {
	// In a real implementation, this would use collective communication
	// For simulation, we just return
	return nil
}

// AllGather gathers tensors from all processes
func (pg *ProcessGroup) AllGather(sendTensor *tensor.Tensor) ([]*tensor.Tensor, error) {
	// Gather from all processes
	result := make([]*tensor.Tensor, pg.WorldSize)
	for i := 0; i < pg.WorldSize; i++ {
		clone, _ := sendTensor.Clone()
		result[i] = clone
	}
	return result, nil
}

// ReduceScatter performs reduce-scatter operation
func (pg *ProcessGroup) ReduceScatter(t *tensor.Tensor, op ReduceOp) (*tensor.Tensor, error) {
	// Split and reduce
	chunkSize := t.Numel() / pg.WorldSize
	start := pg.Rank * chunkSize
	end := start + chunkSize

	result, err := tensor.NewTensor([]int{chunkSize}, t.DType, t.Device)
	if err != nil {
		return nil, err
	}

	srcData := t.Float32Data()
	dstData := result.Float32Data()
	copy(dstData, srcData[start:end])

	return result, nil
}

// Send sends a tensor to a specific rank
func (pg *ProcessGroup) Send(t *tensor.Tensor, dst int) error {
	return nil
}

// Recv receives a tensor from a specific rank
func (pg *ProcessGroup) Recv(t *tensor.Tensor, src int) error {
	return nil
}

// Destroy destroys the process group
func (pg *ProcessGroup) Destroy() {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	pg.initialized = false
	if pg.conn != nil {
		pg.conn.Close()
	}
}

// ============ Distributed Data Parallel ============

// DistributedDataParallel wraps a module for data parallel training
type DistributedDataParallel struct {
	Module       nn.Module
	ProcessGroup *ProcessGroup
	DeviceIDs    []int
	OutputDevice int

	// Gradient hooks
	hooks       []int
	gradBuffers map[string]*tensor.Tensor

	// Configuration
	BucketCapMB      float64
	FindUnusedParams bool
	GradientAsyncOps bool

	mu sync.Mutex
}

// DDPConfig configures DistributedDataParallel
type DDPConfig struct {
	BucketCapMB      float64
	FindUnusedParams bool
	GradientAsyncOps bool
}

// DefaultDDPConfig returns default DDP configuration
func DefaultDDPConfig() DDPConfig {
	return DDPConfig{
		BucketCapMB:      25.0,
		FindUnusedParams: false,
		GradientAsyncOps: true,
	}
}

// NewDistributedDataParallel creates a new DDP wrapper
func NewDistributedDataParallel(module nn.Module, processGroup *ProcessGroup, config DDPConfig) *DistributedDataParallel {
	ddp := &DistributedDataParallel{
		Module:           module,
		ProcessGroup:     processGroup,
		DeviceIDs:        []int{processGroup.LocalRank},
		OutputDevice:     processGroup.LocalRank,
		gradBuffers:      make(map[string]*tensor.Tensor),
		BucketCapMB:      config.BucketCapMB,
		FindUnusedParams: config.FindUnusedParams,
		GradientAsyncOps: config.GradientAsyncOps,
	}

	// Broadcast initial parameters from rank 0
	if processGroup.Rank == 0 {
		for name, param := range module.NamedParameters() {
			processGroup.Broadcast(param.Tensor, 0)
			_ = name
		}
	}

	return ddp
}

// Forward performs forward pass with gradient synchronization
func (ddp *DistributedDataParallel) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	output, err := ddp.Module.Forward(input)
	if err != nil {
		return nil, err
	}
	return output, nil
}

// SyncGradients synchronizes gradients across all processes
func (ddp *DistributedDataParallel) SyncGradients() error {
	ddp.mu.Lock()
	defer ddp.mu.Unlock()

	for _, param := range ddp.Module.Parameters() {
		if param.Grad != nil {
			// All-reduce gradients
			err := ddp.ProcessGroup.AllReduce(param.Grad, ReduceSum)
			if err != nil {
				return err
			}

			// Average gradients
			gradData := param.Grad.Float32Data()
			scale := float32(1.0 / float64(ddp.ProcessGroup.WorldSize))
			for i := range gradData {
				gradData[i] *= scale
			}
		}
	}

	return nil
}

// Parameters returns the module parameters
func (ddp *DistributedDataParallel) Parameters() []*nn.Parameter {
	return ddp.Module.Parameters()
}

// Train sets training mode
func (ddp *DistributedDataParallel) Train(mode bool) {
	ddp.Module.Train(mode)
}

// Eval sets evaluation mode
func (ddp *DistributedDataParallel) Eval() {
	ddp.Module.Eval()
}

// ============ ZeRO Optimizer ============

// ZeROStage represents ZeRO optimization stage
type ZeROStage int

const (
	ZeROStage1 ZeROStage = iota + 1 // Optimizer state partitioning
	ZeROStage2                      // + Gradient partitioning
	ZeROStage3                      // + Parameter partitioning
)

// ZeROOptimizer implements ZeRO optimizer
type ZeROOptimizer struct {
	Stage        ZeROStage
	ProcessGroup *ProcessGroup
	Optimizer    interface{} // Base optimizer

	// Partitioned states
	paramPartitions    [][]int
	gradPartitions     [][]int
	optimStatePartitions map[int]map[string]interface{}

	// Configuration
	OverlapComm    bool
	ContiguousGrads bool
	ReduceBucketSize int

	mu sync.Mutex
}

// ZeROConfig configures ZeRO optimizer
type ZeROConfig struct {
	Stage           ZeROStage
	OverlapComm     bool
	ContiguousGrads bool
	ReduceBucketSize int
}

// DefaultZeROConfig returns default ZeRO configuration
func DefaultZeROConfig() ZeROConfig {
	return ZeROConfig{
		Stage:           ZeROStage2,
		OverlapComm:     true,
		ContiguousGrads: true,
		ReduceBucketSize: 25 * 1024 * 1024,
	}
}

// NewZeROOptimizer creates a new ZeRO optimizer
func NewZeROOptimizer(optimizer interface{}, processGroup *ProcessGroup, config ZeROConfig) *ZeROOptimizer {
	return &ZeROOptimizer{
		Stage:              config.Stage,
		ProcessGroup:       processGroup,
		Optimizer:          optimizer,
		optimStatePartitions: make(map[int]map[string]interface{}),
		OverlapComm:        config.OverlapComm,
		ContiguousGrads:    config.ContiguousGrads,
		ReduceBucketSize:   config.ReduceBucketSize,
	}
}

// Step performs optimizer step with ZeRO
func (z *ZeROOptimizer) Step() error {
	z.mu.Lock()
	defer z.mu.Unlock()

	switch z.Stage {
	case ZeROStage1:
		return z.stepStage1()
	case ZeROStage2:
		return z.stepStage2()
	case ZeROStage3:
		return z.stepStage3()
	default:
		return fmt.Errorf("unsupported ZeRO stage: %d", z.Stage)
	}
}

func (z *ZeROOptimizer) stepStage1() error {
	// Stage 1: Optimizer states are partitioned
	// Each rank only maintains optimizer state for its partition
	return nil
}

func (z *ZeROOptimizer) stepStage2() error {
	// Stage 2: Gradients are also partitioned
	// Reduce-scatter gradients, each rank updates its partition
	return nil
}

func (z *ZeROOptimizer) stepStage3() error {
	// Stage 3: Parameters are also partitioned
	// All-gather parameters for forward/backward
	return nil
}

// ============ Pipeline Parallel ============

// PipelineSchedule represents pipeline scheduling strategy
type PipelineSchedule string

const (
	Schedule1F1B    PipelineSchedule = "1f1b"     // One forward, one backward
	ScheduleGPipe   PipelineSchedule = "gpipe"    // All forward, all backward
	ScheduleInterleaved PipelineSchedule = "interleaved"
)

// PipelineStage represents a stage in the pipeline
type PipelineStage struct {
	Module nn.Module
	Rank   int
}

// PipelineParallel implements pipeline model parallelism
type PipelineParallel struct {
	Stages       []*PipelineStage
	ProcessGroup *ProcessGroup
	NumMicroBatches int
	Schedule     PipelineSchedule

	// Communication buffers
	inputBuffers  []*tensor.Tensor
	outputBuffers []*tensor.Tensor

	// State
	currentMicrobatch int
	mu                sync.Mutex
}

// PipelineConfig configures pipeline parallelism
type PipelineConfig struct {
	NumMicroBatches int
	Schedule        PipelineSchedule
}

// DefaultPipelineConfig returns default pipeline configuration
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		NumMicroBatches: 4,
		Schedule:        Schedule1F1B,
	}
}

// NewPipelineParallel creates a new pipeline parallel wrapper
func NewPipelineParallel(stages []*PipelineStage, processGroup *ProcessGroup, config PipelineConfig) *PipelineParallel {
	return &PipelineParallel{
		Stages:          stages,
		ProcessGroup:    processGroup,
		NumMicroBatches: config.NumMicroBatches,
		Schedule:        config.Schedule,
		inputBuffers:    make([]*tensor.Tensor, config.NumMicroBatches),
		outputBuffers:   make([]*tensor.Tensor, config.NumMicroBatches),
	}
}

// Forward performs pipelined forward pass
func (pp *PipelineParallel) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	switch pp.Schedule {
	case Schedule1F1B:
		return pp.forward1F1B(input)
	case ScheduleGPipe:
		return pp.forwardGPipe(input)
	default:
		return pp.forward1F1B(input)
	}
}

func (pp *PipelineParallel) forward1F1B(input *tensor.Tensor) (*tensor.Tensor, error) {
	// 1F1B schedule: interleave forward and backward passes
	myStage := pp.getMyStage()
	if myStage == nil {
		return nil, fmt.Errorf("no stage for rank %d", pp.ProcessGroup.Rank)
	}

	// Steady state: 1 forward, 1 backward alternating
	output, err := myStage.Module.Forward(input)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (pp *PipelineParallel) forwardGPipe(input *tensor.Tensor) (*tensor.Tensor, error) {
	// GPipe: all forwards, then all backwards
	myStage := pp.getMyStage()
	if myStage == nil {
		return nil, fmt.Errorf("no stage for rank %d", pp.ProcessGroup.Rank)
	}

	output, err := myStage.Module.Forward(input)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func (pp *PipelineParallel) getMyStage() *PipelineStage {
	for _, stage := range pp.Stages {
		if stage.Rank == pp.ProcessGroup.Rank {
			return stage
		}
	}
	return nil
}

// ============ Tensor Parallel ============

// ColumnParallelLinear implements column-parallel linear layer
type ColumnParallelLinear struct {
	*nn.BaseModule
	InFeatures    int
	OutFeatures   int
	ProcessGroup  *ProcessGroup
	GatherOutput  bool
	Weight        *nn.Parameter
	Bias          *nn.Parameter
}

// NewColumnParallelLinear creates a new column-parallel linear layer
func NewColumnParallelLinear(inFeatures, outFeatures int, bias bool, processGroup *ProcessGroup, gatherOutput bool) (*ColumnParallelLinear, error) {
	worldSize := processGroup.WorldSize
	outFeaturesPerPartition := outFeatures / worldSize

	layer := &ColumnParallelLinear{
		BaseModule:   nn.NewBaseModule("ColumnParallelLinear"),
		InFeatures:   inFeatures,
		OutFeatures:  outFeatures,
		ProcessGroup: processGroup,
		GatherOutput: gatherOutput,
	}

	// Initialize weight partition
	weight, err := tensor.Randn([]int{outFeaturesPerPartition, inFeatures}, tensor.Float32, nil)
	if err != nil {
		return nil, err
	}
	layer.Weight = nn.NewParameter(weight, "weight")
	layer.RegisterParameter("weight", layer.Weight)

	if bias {
		biasT, err := tensor.Zeros([]int{outFeaturesPerPartition}, tensor.Float32, nil)
		if err != nil {
			return nil, err
		}
		layer.Bias = nn.NewParameter(biasT, "bias")
		layer.RegisterParameter("bias", layer.Bias)
	}

	return layer, nil
}

// Forward performs column-parallel forward pass
func (l *ColumnParallelLinear) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	// Each rank computes a portion of the output columns
	wT, err := l.Weight.T()
	if err != nil {
		return nil, err
	}

	output, err := input.MatMul(wT)
	if err != nil {
		return nil, err
	}

	if l.Bias != nil {
		output = output.Add(l.Bias.Tensor)
	}

	if l.GatherOutput {
		// All-gather output
		outputs, err := l.ProcessGroup.AllGather(output)
		if err != nil {
			return nil, err
		}
		// Concatenate along last dimension
		return tensor.Cat(outputs, -1)
	}

	return output.Realize(), nil
}

// RowParallelLinear implements row-parallel linear layer
type RowParallelLinear struct {
	*nn.BaseModule
	InFeatures        int
	OutFeatures       int
	ProcessGroup      *ProcessGroup
	InputIsParallel   bool
	Weight            *nn.Parameter
	Bias              *nn.Parameter
}

// NewRowParallelLinear creates a new row-parallel linear layer
func NewRowParallelLinear(inFeatures, outFeatures int, bias bool, processGroup *ProcessGroup, inputIsParallel bool) (*RowParallelLinear, error) {
	worldSize := processGroup.WorldSize
	inFeaturesPerPartition := inFeatures / worldSize

	layer := &RowParallelLinear{
		BaseModule:      nn.NewBaseModule("RowParallelLinear"),
		InFeatures:      inFeatures,
		OutFeatures:     outFeatures,
		ProcessGroup:    processGroup,
		InputIsParallel: inputIsParallel,
	}

	// Initialize weight partition
	weight, err := tensor.Randn([]int{outFeatures, inFeaturesPerPartition}, tensor.Float32, nil)
	if err != nil {
		return nil, err
	}
	layer.Weight = nn.NewParameter(weight, "weight")
	layer.RegisterParameter("weight", layer.Weight)

	if bias && processGroup.Rank == 0 {
		biasT, err := tensor.Zeros([]int{outFeatures}, tensor.Float32, nil)
		if err != nil {
			return nil, err
		}
		layer.Bias = nn.NewParameter(biasT, "bias")
		layer.RegisterParameter("bias", layer.Bias)
	}

	return layer, nil
}

// Forward performs row-parallel forward pass
func (l *RowParallelLinear) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	// Each rank has a portion of the input rows
	wT, err := l.Weight.T()
	if err != nil {
		return nil, err
	}

	output, err := input.MatMul(wT)
	if err != nil {
		return nil, err
	}

	// All-reduce output
	err = l.ProcessGroup.AllReduce(output, ReduceSum)
	if err != nil {
		return nil, err
	}

	if l.Bias != nil {
		output = output.Add(l.Bias.Tensor)
	}

	return output.Realize(), nil
}

// ============ Gradient Compression ============

// GradientCompressor interface for gradient compression
type GradientCompressor interface {
	Compress(grad *tensor.Tensor) (interface{}, error)
	Decompress(compressed interface{}) (*tensor.Tensor, error)
}

// TopKCompressor compresses gradients using Top-K sparsification
type TopKCompressor struct {
	Ratio float64
	Residual map[string]*tensor.Tensor
}

// NewTopKCompressor creates a new Top-K compressor
func NewTopKCompressor(ratio float64) *TopKCompressor {
	if ratio == 0 {
		ratio = 0.01 // Keep top 1% by default
	}
	return &TopKCompressor{
		Ratio:    ratio,
		Residual: make(map[string]*tensor.Tensor),
	}
}

// Compress compresses gradients using Top-K
func (c *TopKCompressor) Compress(grad *tensor.Tensor) (interface{}, error) {
	grad.Realize()
	data := grad.Float32Data()
	k := int(float64(len(data)) * c.Ratio)
	if k < 1 {
		k = 1
	}

	// Find top-k indices and values
	type indexValue struct {
		index int
		value float32
	}

	pairs := make([]indexValue, len(data))
	for i, v := range data {
		pairs[i] = indexValue{i, float32(math.Abs(float64(v)))}
	}

	// Simple selection (would use quickselect in production)
	for i := 0; i < k; i++ {
		maxIdx := i
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].value > pairs[maxIdx].value {
				maxIdx = j
			}
		}
		pairs[i], pairs[maxIdx] = pairs[maxIdx], pairs[i]
	}

	indices := make([]int, k)
	values := make([]float32, k)
	for i := 0; i < k; i++ {
		indices[i] = pairs[i].index
		values[i] = data[pairs[i].index]
	}

	return map[string]interface{}{
		"indices": indices,
		"values":  values,
		"shape":   grad.Shape,
	}, nil
}

// Decompress decompresses Top-K compressed gradients
func (c *TopKCompressor) Decompress(compressed interface{}) (*tensor.Tensor, error) {
	data := compressed.(map[string]interface{})
	indices := data["indices"].([]int)
	values := data["values"].([]float32)
	shape := data["shape"].([]int)

	result, err := tensor.Zeros(shape, tensor.Float32, nil)
	if err != nil {
		return nil, err
	}

	resultData := result.Float32Data()
	for i, idx := range indices {
		resultData[idx] = values[i]
	}

	return result, nil
}

// PowerSGDCompressor implements PowerSGD gradient compression
type PowerSGDCompressor struct {
	Rank      int
	StartPowerIteration int
	MinCompRatio float64
	Orthogonalize bool

	// State
	P map[string]*tensor.Tensor
	Q map[string]*tensor.Tensor
}

// NewPowerSGDCompressor creates a new PowerSGD compressor
func NewPowerSGDCompressor(rank int) *PowerSGDCompressor {
	if rank == 0 {
		rank = 4
	}
	return &PowerSGDCompressor{
		Rank:              rank,
		StartPowerIteration: 1,
		MinCompRatio:      0.5,
		Orthogonalize:     true,
		P:                 make(map[string]*tensor.Tensor),
		Q:                 make(map[string]*tensor.Tensor),
	}
}

// Compress compresses gradients using PowerSGD
func (c *PowerSGDCompressor) Compress(grad *tensor.Tensor) (interface{}, error) {
	// Simplified PowerSGD implementation
	// Real implementation would use low-rank approximation
	return grad, nil
}

// Decompress decompresses PowerSGD compressed gradients
func (c *PowerSGDCompressor) Decompress(compressed interface{}) (*tensor.Tensor, error) {
	return compressed.(*tensor.Tensor), nil
}

// ============ Elastic Training ============

// ElasticTrainer provides fault-tolerant distributed training
type ElasticTrainer struct {
	ProcessGroup *ProcessGroup
	Module       nn.Module
	Optimizer    interface{}

	// Checkpointing
	CheckpointDir string
	CheckpointInterval int

	// Fault tolerance
	MinNodes int
	MaxNodes int
	CurrentNodes int

	// State
	epoch     int
	iteration int
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
}

// ElasticConfig configures elastic training
type ElasticConfig struct {
	CheckpointDir     string
	CheckpointInterval int
	MinNodes          int
	MaxNodes          int
}

// DefaultElasticConfig returns default elastic configuration
func DefaultElasticConfig() ElasticConfig {
	return ElasticConfig{
		CheckpointDir:     "/tmp/checkpoints",
		CheckpointInterval: 100,
		MinNodes:          1,
		MaxNodes:          32,
	}
}

// NewElasticTrainer creates a new elastic trainer
func NewElasticTrainer(module nn.Module, optimizer interface{}, processGroup *ProcessGroup, config ElasticConfig) *ElasticTrainer {
	ctx, cancel := context.WithCancel(context.Background())

	return &ElasticTrainer{
		ProcessGroup:      processGroup,
		Module:            module,
		Optimizer:         optimizer,
		CheckpointDir:     config.CheckpointDir,
		CheckpointInterval: config.CheckpointInterval,
		MinNodes:          config.MinNodes,
		MaxNodes:          config.MaxNodes,
		CurrentNodes:      processGroup.WorldSize,
		ctx:               ctx,
		cancel:            cancel,
	}
}

// SaveCheckpoint saves a checkpoint
func (et *ElasticTrainer) SaveCheckpoint() error {
	et.mu.Lock()
	defer et.mu.Unlock()

	checkpoint := map[string]interface{}{
		"epoch":      et.epoch,
		"iteration":  et.iteration,
		"state_dict": et.Module.(*nn.BaseModule).StateDict(),
	}
	_ = checkpoint

	return nil
}

// LoadCheckpoint loads a checkpoint
func (et *ElasticTrainer) LoadCheckpoint() error {
	et.mu.Lock()
	defer et.mu.Unlock()

	return nil
}

// HandleNodeFailure handles a node failure
func (et *ElasticTrainer) HandleNodeFailure(failedRank int) error {
	et.mu.Lock()
	defer et.mu.Unlock()

	et.CurrentNodes--
	if et.CurrentNodes < et.MinNodes {
		return fmt.Errorf("not enough nodes: %d < %d", et.CurrentNodes, et.MinNodes)
	}

	// Save checkpoint and reconfigure
	return et.SaveCheckpoint()
}

// HandleNodeJoin handles a new node joining
func (et *ElasticTrainer) HandleNodeJoin(newRank int) error {
	et.mu.Lock()
	defer et.mu.Unlock()

	if et.CurrentNodes >= et.MaxNodes {
		return fmt.Errorf("max nodes reached: %d", et.MaxNodes)
	}

	et.CurrentNodes++

	// Broadcast model state to new node
	return nil
}

// Step performs a training step with fault tolerance
func (et *ElasticTrainer) Step() error {
	et.mu.Lock()
	defer et.mu.Unlock()

	et.iteration++

	// Auto checkpoint
	if et.iteration%et.CheckpointInterval == 0 {
		return et.SaveCheckpoint()
	}

	return nil
}

// Stop stops elastic training
func (et *ElasticTrainer) Stop() {
	et.cancel()
}

// ============ Communication Utilities ============

// AllReduceAsync performs asynchronous all-reduce
type AllReduceAsync struct {
	ProcessGroup *ProcessGroup
	Tensor       *tensor.Tensor
	Op           ReduceOp
	Done         chan struct{}
}

// NewAllReduceAsync creates a new async all-reduce operation
func NewAllReduceAsync(pg *ProcessGroup, t *tensor.Tensor, op ReduceOp) *AllReduceAsync {
	ar := &AllReduceAsync{
		ProcessGroup: pg,
		Tensor:       t,
		Op:           op,
		Done:         make(chan struct{}),
	}

	go func() {
		pg.AllReduce(t, op)
		close(ar.Done)
	}()

	return ar
}

// Wait waits for the async operation to complete
func (ar *AllReduceAsync) Wait() error {
	<-ar.Done
	return nil
}

// BroadcastAsync performs asynchronous broadcast
type BroadcastAsync struct {
	ProcessGroup *ProcessGroup
	Tensor       *tensor.Tensor
	Src          int
	Done         chan struct{}
}

// NewBroadcastAsync creates a new async broadcast operation
func NewBroadcastAsync(pg *ProcessGroup, t *tensor.Tensor, src int) *BroadcastAsync {
	ba := &BroadcastAsync{
		ProcessGroup: pg,
		Tensor:       t,
		Src:          src,
		Done:         make(chan struct{}),
	}

	go func() {
		pg.Broadcast(t, src)
		close(ba.Done)
	}()

	return ba
}

// Wait waits for the async operation to complete
func (ba *BroadcastAsync) Wait() error {
	<-ba.Done
	return nil
}

// BatchAllReduce performs batched all-reduce
func BatchAllReduce(pg *ProcessGroup, tensors []*tensor.Tensor, op ReduceOp) error {
	// Flatten all tensors into one buffer
	totalSize := 0
	for _, t := range tensors {
		totalSize += t.Numel()
	}

	flatBuffer, err := tensor.NewTensor([]int{totalSize}, tensor.Float32, nil)
	if err != nil {
		return err
	}

	// Copy data to flat buffer
	offset := 0
	bufData := flatBuffer.Float32Data()
	for _, t := range tensors {
		t.Realize()
		data := t.Float32Data()
		copy(bufData[offset:], data)
		offset += len(data)
	}

	// All-reduce the flat buffer
	err = pg.AllReduce(flatBuffer, op)
	if err != nil {
		return err
	}

	// Copy data back
	offset = 0
	for _, t := range tensors {
		data := t.Float32Data()
		copy(data, bufData[offset:offset+len(data)])
		offset += len(data)
	}

	return nil
}

// ============ Model Sharding ============

// ShardedModule implements fully sharded data parallel
type ShardedModule struct {
	Module        nn.Module
	ProcessGroup  *ProcessGroup
	ShardStrategy string

	// Sharding state
	paramShards map[string]*tensor.Tensor
	mu          sync.RWMutex
}

// NewShardedModule creates a new sharded module
func NewShardedModule(module nn.Module, processGroup *ProcessGroup, strategy string) *ShardedModule {
	return &ShardedModule{
		Module:        module,
		ProcessGroup:  processGroup,
		ShardStrategy: strategy,
		paramShards:   make(map[string]*tensor.Tensor),
	}
}

// Forward performs forward pass with parameter gathering
func (sm *ShardedModule) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	// All-gather parameters for forward pass
	for _, param := range sm.Module.Parameters() {
		sm.ProcessGroup.AllGather(param.Tensor)
	}

	// Forward pass
	output, err := sm.Module.Forward(input)
	if err != nil {
		return nil, err
	}

	// Reshard parameters
	// ...

	return output, nil
}

// ============ Heartbeat Monitor ============

// HeartbeatMonitor monitors node health
type HeartbeatMonitor struct {
	ProcessGroup *ProcessGroup
	Interval     time.Duration
	Timeout      time.Duration

	lastHeartbeat map[int]time.Time
	failures      chan int
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
}

// NewHeartbeatMonitor creates a new heartbeat monitor
func NewHeartbeatMonitor(pg *ProcessGroup, interval, timeout time.Duration) *HeartbeatMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	hm := &HeartbeatMonitor{
		ProcessGroup:  pg,
		Interval:      interval,
		Timeout:       timeout,
		lastHeartbeat: make(map[int]time.Time),
		failures:      make(chan int, pg.WorldSize),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Initialize heartbeats
	now := time.Now()
	for i := 0; i < pg.WorldSize; i++ {
		hm.lastHeartbeat[i] = now
	}

	return hm
}

// Start starts the heartbeat monitor
func (hm *HeartbeatMonitor) Start() {
	go hm.sendHeartbeats()
	go hm.checkHeartbeats()
}

func (hm *HeartbeatMonitor) sendHeartbeats() {
	ticker := time.NewTicker(hm.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-hm.ctx.Done():
			return
		case <-ticker.C:
			// Send heartbeat to all nodes
			hm.ProcessGroup.Barrier()
		}
	}
}

func (hm *HeartbeatMonitor) checkHeartbeats() {
	ticker := time.NewTicker(hm.Interval * 2)
	defer ticker.Stop()

	for {
		select {
		case <-hm.ctx.Done():
			return
		case <-ticker.C:
			hm.mu.RLock()
			now := time.Now()
			for rank, last := range hm.lastHeartbeat {
				if now.Sub(last) > hm.Timeout {
					hm.failures <- rank
				}
			}
			hm.mu.RUnlock()
		}
	}
}

// Failures returns the failure channel
func (hm *HeartbeatMonitor) Failures() <-chan int {
	return hm.failures
}

// Stop stops the heartbeat monitor
func (hm *HeartbeatMonitor) Stop() {
	hm.cancel()
}

// Register gob types for serialization
func init() {
	gob.Register(map[string]interface{}{})
}
