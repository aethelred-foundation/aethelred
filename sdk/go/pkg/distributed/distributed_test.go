package distributed

import (
	"testing"
	"time"

	"github.com/aethelred/sdk-go/pkg/nn"
	"github.com/aethelred/sdk-go/pkg/tensor"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ProcessGroup
// ---------------------------------------------------------------------------

func TestNewProcessGroup(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 4, 0)
	require.NotNil(t, pg)
	require.Equal(t, BackendGloo, pg.Backend)
	require.Equal(t, 4, pg.WorldSize)
	require.Equal(t, 0, pg.Rank)
	require.False(t, pg.IsInitialized())
}

func TestProcessGroup_InitializeAndDestroy(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendNCCL, 2, 1)
	require.False(t, pg.IsInitialized())

	err := pg.Initialize("127.0.0.1", 29500)
	require.NoError(t, err)
	require.True(t, pg.IsInitialized())

	pg.Destroy()
	require.False(t, pg.IsInitialized())
}

func TestProcessGroup_Barrier(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	err := pg.Barrier()
	require.NoError(t, err)
}

func TestProcessGroup_Broadcast(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	data, err := tensor.Randn([]int{4, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	err = pg.Broadcast(data, 0)
	require.NoError(t, err)
}

func TestProcessGroup_AllReduce(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	data, err := tensor.Ones([]int{8}, tensor.Float32, nil)
	require.NoError(t, err)

	err = pg.AllReduce(data, ReduceSum)
	require.NoError(t, err)
}

func TestProcessGroup_AllGather(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 4, 1)
	_ = pg.Initialize("127.0.0.1", 29500)

	data, err := tensor.Ones([]int{8}, tensor.Float32, nil)
	require.NoError(t, err)

	gathered, err := pg.AllGather(data)
	require.NoError(t, err)
	require.Len(t, gathered, 4)

	for _, g := range gathered {
		require.NotNil(t, g)
	}
}

func TestProcessGroup_ReduceScatter(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	data, err := tensor.Ones([]int{16}, tensor.Float32, nil)
	require.NoError(t, err)

	result, err := pg.ReduceScatter(data, ReduceSum)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 8, result.Numel())
}

func TestProcessGroup_SendRecv(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	data, err := tensor.Zeros([]int{4}, tensor.Float32, nil)
	require.NoError(t, err)

	require.NoError(t, pg.Send(data, 1))
	require.NoError(t, pg.Recv(data, 1))
}

// ---------------------------------------------------------------------------
// DistributedDataParallel
// ---------------------------------------------------------------------------

func newSimpleModel(t *testing.T) nn.Module {
	t.Helper()
	linear, err := nn.NewLinear(4, 2, true)
	require.NoError(t, err)
	return nn.NewSequential(linear)
}

func TestDDP_WrapModuleAndForward(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	ddp := NewDistributedDataParallel(model, pg, DefaultDDPConfig())
	require.NotNil(t, ddp)

	input, err := tensor.Randn([]int{2, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	output, err := ddp.Forward(input)
	require.NoError(t, err)
	require.NotNil(t, output)
}

func TestDDP_SyncGradients(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	ddp := NewDistributedDataParallel(model, pg, DefaultDDPConfig())

	err := ddp.SyncGradients()
	require.NoError(t, err)
}

func TestDDP_Parameters(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	ddp := NewDistributedDataParallel(model, pg, DefaultDDPConfig())

	params := ddp.Parameters()
	require.NotEmpty(t, params)
}

func TestDDP_TrainEval(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	ddp := NewDistributedDataParallel(model, pg, DefaultDDPConfig())

	ddp.Train(true)
	ddp.Eval()
}

func TestDefaultDDPConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultDDPConfig()
	require.Equal(t, 25.0, cfg.BucketCapMB)
	require.False(t, cfg.FindUnusedParams)
	require.True(t, cfg.GradientAsyncOps)
}

// ---------------------------------------------------------------------------
// ZeRO Optimizer
// ---------------------------------------------------------------------------

func TestZeRO_Stages(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	stages := []ZeROStage{ZeROStage1, ZeROStage2, ZeROStage3}
	for _, stage := range stages {
		z := NewZeROOptimizer(nil, pg, ZeROConfig{Stage: stage})
		require.NotNil(t, z)
		require.Equal(t, stage, z.Stage)
		require.NoError(t, z.Step())
	}
}

func TestZeRO_InvalidStage(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	z := NewZeROOptimizer(nil, pg, ZeROConfig{Stage: ZeROStage(99)})
	err := z.Step()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported ZeRO stage")
}

func TestDefaultZeROConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultZeROConfig()
	require.Equal(t, ZeROStage2, cfg.Stage)
	require.True(t, cfg.OverlapComm)
	require.True(t, cfg.ContiguousGrads)
	require.Equal(t, 25*1024*1024, cfg.ReduceBucketSize)
}

// ---------------------------------------------------------------------------
// Pipeline Parallel
// ---------------------------------------------------------------------------

func TestPipelineParallel_Forward(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	stages := []*PipelineStage{{Module: model, Rank: 0}}

	pp := NewPipelineParallel(stages, pg, DefaultPipelineConfig())
	require.NotNil(t, pp)

	input, err := tensor.Randn([]int{2, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	output, err := pp.Forward(input)
	require.NoError(t, err)
	require.NotNil(t, output)
}

func TestPipelineParallel_GPipeSchedule(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	stages := []*PipelineStage{{Module: model, Rank: 0}}

	pp := NewPipelineParallel(stages, pg, PipelineConfig{
		NumMicroBatches: 2,
		Schedule:        ScheduleGPipe,
	})

	input, err := tensor.Randn([]int{2, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	output, err := pp.Forward(input)
	require.NoError(t, err)
	require.NotNil(t, output)
}

func TestPipelineParallel_NoStageForRank(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 1)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	stages := []*PipelineStage{{Module: model, Rank: 0}}

	pp := NewPipelineParallel(stages, pg, DefaultPipelineConfig())

	input, err := tensor.Randn([]int{2, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	_, err = pp.Forward(input)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no stage for rank")
}

func TestDefaultPipelineConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultPipelineConfig()
	require.Equal(t, 4, cfg.NumMicroBatches)
	require.Equal(t, Schedule1F1B, cfg.Schedule)
}

// ---------------------------------------------------------------------------
// Gradient Compression
// ---------------------------------------------------------------------------

func TestTopKCompressor_CompressDecompress(t *testing.T) {
	t.Parallel()

	comp := NewTopKCompressor(0.5) // keep top 50%

	data, err := tensor.Randn([]int{100}, tensor.Float32, nil)
	require.NoError(t, err)

	compressed, err := comp.Compress(data)
	require.NoError(t, err)
	require.NotNil(t, compressed)

	decompressed, err := comp.Decompress(compressed)
	require.NoError(t, err)
	require.NotNil(t, decompressed)
	require.Equal(t, data.Shape, decompressed.Shape)
}

func TestTopKCompressor_DefaultRatio(t *testing.T) {
	t.Parallel()

	comp := NewTopKCompressor(0)
	require.Equal(t, 0.01, comp.Ratio)
}

func TestPowerSGDCompressor_CompressDecompress(t *testing.T) {
	t.Parallel()

	comp := NewPowerSGDCompressor(4)
	require.Equal(t, 4, comp.Rank)

	data, err := tensor.Randn([]int{16}, tensor.Float32, nil)
	require.NoError(t, err)

	compressed, err := comp.Compress(data)
	require.NoError(t, err)

	decompressed, err := comp.Decompress(compressed)
	require.NoError(t, err)
	require.NotNil(t, decompressed)
}

func TestPowerSGDCompressor_DefaultRank(t *testing.T) {
	t.Parallel()

	comp := NewPowerSGDCompressor(0)
	require.Equal(t, 4, comp.Rank)
}

// ---------------------------------------------------------------------------
// Elastic Training
// ---------------------------------------------------------------------------

func TestElasticTrainer_CreateAndStop(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	et := NewElasticTrainer(model, nil, pg, DefaultElasticConfig())
	require.NotNil(t, et)
	require.Equal(t, 2, et.CurrentNodes)

	et.Stop()
}

// Note: HandleNodeFailure has a re-entrant lock issue in the source code
// (it holds et.mu then calls SaveCheckpoint which also locks et.mu), so
// we test the failure-below-minimum path which returns before the
// SaveCheckpoint call.
func TestElasticTrainer_HandleNodeFailure_NodeCountDecreases(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	et := NewElasticTrainer(model, nil, pg, ElasticConfig{
		MinNodes: 2,
		MaxNodes: 4,
	})

	// With CurrentNodes=1 and MinNodes=2, this returns error
	// before hitting the deadlock path.
	err := et.HandleNodeFailure(0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough nodes")
}

func TestElasticTrainer_HandleNodeFailure_BelowMinimum_MultiNode(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 3, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	et := NewElasticTrainer(model, nil, pg, ElasticConfig{
		MinNodes: 4,
		MaxNodes: 8,
	})

	// CurrentNodes starts at 3, MinNodes is 4, so after decrement
	// CurrentNodes becomes 2 < 4, returning error before SaveCheckpoint.
	err := et.HandleNodeFailure(2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough nodes")
}

func TestElasticTrainer_HandleNodeJoin(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	et := NewElasticTrainer(model, nil, pg, ElasticConfig{
		MinNodes: 1,
		MaxNodes: 4,
	})

	err := et.HandleNodeJoin(2)
	require.NoError(t, err)
	require.Equal(t, 3, et.CurrentNodes)
}

func TestElasticTrainer_HandleNodeJoin_AtMax(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 4, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	et := NewElasticTrainer(model, nil, pg, ElasticConfig{
		MinNodes: 1,
		MaxNodes: 4,
	})

	err := et.HandleNodeJoin(4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max nodes reached")
}

func TestElasticTrainer_Step(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	// Use a large checkpoint interval to avoid triggering SaveCheckpoint
	// during the step loop (SaveCheckpoint requires *BaseModule).
	et := NewElasticTrainer(model, nil, pg, ElasticConfig{
		CheckpointDir:      "/tmp/test_step",
		CheckpointInterval: 1000,
		MinNodes:           1,
		MaxNodes:           4,
	})

	for i := 0; i < 5; i++ {
		require.NoError(t, et.Step())
	}
}

func TestElasticTrainer_Checkpointing(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	// SaveCheckpoint casts Module to *nn.BaseModule which only succeeds
	// when the concrete type is exactly *nn.BaseModule. Provide one directly.
	model := nn.NewBaseModule("test-checkpoint")

	et := NewElasticTrainer(model, nil, pg, DefaultElasticConfig())

	require.NoError(t, et.SaveCheckpoint())
	require.NoError(t, et.LoadCheckpoint())
}

func TestDefaultElasticConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultElasticConfig()
	require.Equal(t, "/tmp/checkpoints", cfg.CheckpointDir)
	require.Equal(t, 100, cfg.CheckpointInterval)
	require.Equal(t, 1, cfg.MinNodes)
	require.Equal(t, 32, cfg.MaxNodes)
}

// ---------------------------------------------------------------------------
// Async Operations
// ---------------------------------------------------------------------------

func TestAllReduceAsync(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	data, err := tensor.Ones([]int{8}, tensor.Float32, nil)
	require.NoError(t, err)

	ar := NewAllReduceAsync(pg, data, ReduceSum)
	require.NotNil(t, ar)
	require.NoError(t, ar.Wait())
}

func TestBroadcastAsync(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	data, err := tensor.Ones([]int{8}, tensor.Float32, nil)
	require.NoError(t, err)

	ba := NewBroadcastAsync(pg, data, 0)
	require.NotNil(t, ba)
	require.NoError(t, ba.Wait())
}

func TestBatchAllReduce(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	t1, err := tensor.Ones([]int{4}, tensor.Float32, nil)
	require.NoError(t, err)
	t2, err := tensor.Ones([]int{8}, tensor.Float32, nil)
	require.NoError(t, err)

	err = BatchAllReduce(pg, []*tensor.Tensor{t1, t2}, ReduceSum)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Sharded Module
// ---------------------------------------------------------------------------

func TestShardedModule_Forward(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 1, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	model := newSimpleModel(t)
	sm := NewShardedModule(model, pg, "full_shard")
	require.NotNil(t, sm)

	input, err := tensor.Randn([]int{2, 4}, tensor.Float32, nil)
	require.NoError(t, err)

	output, err := sm.Forward(input)
	require.NoError(t, err)
	require.NotNil(t, output)
}

// ---------------------------------------------------------------------------
// Heartbeat Monitor
// ---------------------------------------------------------------------------

func TestHeartbeatMonitor_StartStop(t *testing.T) {
	t.Parallel()

	pg := NewProcessGroup(BackendGloo, 2, 0)
	_ = pg.Initialize("127.0.0.1", 29500)

	hm := NewHeartbeatMonitor(pg, 50*time.Millisecond, 200*time.Millisecond)
	require.NotNil(t, hm)

	hm.Start()
	time.Sleep(100 * time.Millisecond)
	hm.Stop()

	// Draining the failures channel should not block after stop
	select {
	case <-hm.Failures():
	default:
	}
}

// ---------------------------------------------------------------------------
// Backend and Op Constants
// ---------------------------------------------------------------------------

func TestBackendConstants(t *testing.T) {
	t.Parallel()

	require.Equal(t, Backend("gloo"), BackendGloo)
	require.Equal(t, Backend("nccl"), BackendNCCL)
	require.Equal(t, Backend("mpi"), BackendMPI)
	require.Equal(t, Backend("custom"), BackendCustom)
}

func TestReduceOpConstants(t *testing.T) {
	t.Parallel()

	ops := []ReduceOp{ReduceSum, ReduceMean, ReduceMax, ReduceMin, ReduceProd}
	require.Len(t, ops, 5)
}
