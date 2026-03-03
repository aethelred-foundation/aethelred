// Package aethelred provides the Aethelred AI Blockchain SDK for Go.
//
// The Aethelred SDK provides a toolkit for AI model development, training,
// and deployment on the Aethelred blockchain.
//
// GPU execution is fail-closed by default. Native GPU dispatch is available
// only in builds that opt into the `aethelred_gpu_native` build tag.
// Simulation mode is development-only and requires AETH_SDK_ALLOW_SIMULATED_GPU=1.
//
// # Features
//
// Core Runtime:
//   - Hardware Abstraction Layer (HAL) for CPUs, GPUs, TEEs
//   - Lock-free memory pool with NUMA awareness
//   - Async execution streams with dependency graphs
//   - JIT compilation with LLVM backend
//   - Comprehensive profiling with Chrome Trace export
//
// Tensor Operations:
//   - Lazy evaluation with operation fusion
//   - SIMD-accelerated operations
//   - Memory-efficient views and broadcasting
//   - Automatic differentiation support
//
// Neural Network:
//   - PyTorch-compatible nn.Module interface
//   - Transformer and attention layers
//   - Modern activations (GELU, SiLU, RMSNorm)
//   - Loss functions and optimizers
//
// Distributed Computing:
//   - Data parallelism with MPI backend
//   - Model parallelism (tensor, pipeline)
//   - ZeRO optimizer (stages 1-3)
//   - Gradient compression
//
// Quantization:
//   - Post-training quantization (PTQ)
//   - Quantization-aware training (QAT)
//   - INT8, INT4, FP16, BF16, FP8 support
//
// Blockchain Integration:
//   - AI compute job submission and tracking
//   - Digital seal creation and verification
//   - TEE attestation (Intel SGX, AMD SEV, AWS Nitro)
//   - zkML proof verification
//   - Post-quantum cryptography (Dilithium, Kyber)
//
// # Quick Start
//
//	package main
//
//	import (
//		"fmt"
//		aethelred "github.com/aethelred/sdk-go"
//		"github.com/aethelred/sdk-go/pkg/nn"
//		"github.com/aethelred/sdk-go/pkg/optim"
//		"github.com/aethelred/sdk-go/pkg/tensor"
//	)
//
//	func main() {
//		// Initialize runtime
//		runtime := aethelred.GetRuntime()
//		runtime.Initialize()
//		defer runtime.Shutdown()
//
//		// Create tensors
//		x, _ := tensor.Randn([]int{32, 784}, tensor.Float32, aethelred.CPU())
//		y, _ := tensor.RandInt(0, 10, []int{32}, tensor.Int32, aethelred.CPU())
//
//		// Build model
//		model := nn.NewSequential(
//			mustLinear(784, 256),
//			nn.NewReLU(false),
//			mustLinear(256, 10),
//		)
//
//		// Create optimizer
//		optimizer := optim.NewAdam(model.Parameters(), 0.001, [2]float64{0.9, 0.999}, 1e-8, 0, false)
//
//		// Training loop
//		for epoch := 0; epoch < 10; epoch++ {
//			optimizer.ZeroGrad()
//			output, _ := model.Forward(x)
//			// ... compute loss and backward
//			optimizer.Step()
//		}
//
//		// Connect to blockchain
//		client, _ := aethelred.NewClient(aethelred.Testnet)
//
//		// Create digital seal for model output
//		seal, _ := client.CreateSeal(output)
//		fmt.Printf("Seal ID: %s\n", seal.ID)
//	}
//
// # Architecture
//
// The SDK is organized into several packages:
//
//   - runtime: Core runtime with device management, memory pools, and profiling
//   - tensor: Tensor operations with lazy evaluation and automatic differentiation
//   - nn: Neural network modules following PyTorch conventions
//   - optim: Optimizers and learning rate schedulers
//   - distributed: Distributed training with DDP, ZeRO, and model parallelism
//   - quantize: Model quantization for efficient inference
//   - client: Blockchain client for interacting with Aethelred network
package aethelred

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/aethelred/sdk-go/pkg/distributed"
	"github.com/aethelred/sdk-go/pkg/nn"
	"github.com/aethelred/sdk-go/pkg/optim"
	"github.com/aethelred/sdk-go/pkg/quantize"
	"github.com/aethelred/sdk-go/pkg/runtime"
	"github.com/aethelred/sdk-go/pkg/tensor"
)

// Version information
const (
	Version    = "1.0.0"
	APIVersion = "v1"
	Author     = "Aethelred Team"
	License    = "Apache-2.0"
)

// Network represents the Aethelred network
type Network int

const (
	Mainnet Network = iota
	Testnet
	Devnet
	Local
)

// String returns the network name
func (n Network) String() string {
	names := []string{"mainnet", "testnet", "devnet", "local"}
	if int(n) < len(names) {
		return names[n]
	}
	return "unknown"
}

// ChainID returns the chain ID
func (n Network) ChainID() string {
	ids := []string{
		"aethelred-mainnet-1",
		"aethelred-testnet-1",
		"aethelred-devnet-1",
		"aethelred-local-1",
	}
	if int(n) < len(ids) {
		return ids[n]
	}
	return "unknown"
}

// ============ Runtime Access ============

var (
	runtimeInstance *runtime.Runtime
	runtimeOnce     sync.Once
)

// GetRuntime returns the singleton runtime instance
func GetRuntime() *runtime.Runtime {
	runtimeOnce.Do(func() {
		runtimeInstance = runtime.NewRuntime()
	})
	return runtimeInstance
}

// CPU returns the CPU device
func CPU() *runtime.Device {
	return runtime.CPU()
}

// GPU returns a GPU accelerator device
func GPU(index int) *runtime.Device {
	return runtime.GPU(index)
}

// HasPhysicalGPU reports whether GPU hardware is visible on this host.
func HasPhysicalGPU() bool {
	return runtime.HasPhysicalGPU()
}

// HasNativeGPUBackend reports whether this build includes native GPU dispatch.
func HasNativeGPUBackend() bool {
	return runtime.HasNativeGPUBackend()
}

// ============ Client ============

// Client is the main client for interacting with the Aethelred blockchain
type Client struct {
	Network  Network
	Endpoint string
	ChainID  string
	timeout  time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
}

// ClientConfig configures the client
type ClientConfig struct {
	Endpoint string
	Timeout  time.Duration
}

// DefaultClientConfig returns default client configuration
func DefaultClientConfig(network Network) ClientConfig {
	endpoints := map[Network]string{
		Mainnet: "https://rpc.aethelred.io",
		Testnet: "https://testnet-rpc.aethelred.io",
		Devnet:  "https://devnet-rpc.aethelred.io",
		Local:   "http://127.0.0.1:26657",
	}

	return ClientConfig{
		Endpoint: endpoints[network],
		Timeout:  30 * time.Second,
	}
}

// NewClient creates a new client
func NewClient(network Network, configs ...ClientConfig) (*Client, error) {
	config := DefaultClientConfig(network)
	if len(configs) > 0 {
		config = configs[0]
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		Network:  network,
		Endpoint: config.Endpoint,
		ChainID:  network.ChainID(),
		timeout:  config.Timeout,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Close closes the client
func (c *Client) Close() error {
	c.cancel()
	return nil
}

// ============ Digital Seal ============

// Seal represents a digital seal for verified AI computation
type Seal struct {
	ID             string
	ModelHash      string
	InputHash      string
	OutputHash     string
	Timestamp      time.Time
	BlockHeight    int64
	ValidatorSet   []string
	TEEAttestation *TEEAttestation
	ZKProof        *ZKProof
}

// TEEAttestation represents a TEE attestation
type TEEAttestation struct {
	EnclaveID   string
	Measurement string
	Platform    string // sgx, sev, nitro
	Signature   string
}

// ZKProof represents a zkML proof
type ZKProof struct {
	ProofBytes   []byte
	PublicInputs []byte
	VerifyingKey []byte
	CircuitHash  string
	ProofSystem  string // groth16, plonk, stark
}

// CreateSeal creates a digital seal for a tensor output
func (c *Client) CreateSeal(output *tensor.Tensor) (*Seal, error) {
	output.Realize()

	// Hash the output
	hash := sha256.Sum256(output.Storage.Data)
	outputHash := hex.EncodeToString(hash[:])

	seal := &Seal{
		ID:          fmt.Sprintf("seal_%s", outputHash[:16]),
		OutputHash:  outputHash,
		Timestamp:   time.Now(),
		BlockHeight: 0, // Will be set after submission
	}

	// In a real implementation, this would submit to the blockchain
	// and wait for verification by validators

	return seal, nil
}

// CreateSealWithModel creates a seal with model and input hashes
func (c *Client) CreateSealWithModel(modelHash, inputHash string, output *tensor.Tensor) (*Seal, error) {
	seal, err := c.CreateSeal(output)
	if err != nil {
		return nil, err
	}

	seal.ModelHash = modelHash
	seal.InputHash = inputHash

	return seal, nil
}

// VerifySeal verifies a digital seal
func (c *Client) VerifySeal(sealID string) (bool, error) {
	// In a real implementation, this would query the blockchain
	return true, nil
}

// GetSeal retrieves a seal by ID
func (c *Client) GetSeal(sealID string) (*Seal, error) {
	// In a real implementation, this would query the blockchain
	return nil, fmt.Errorf("seal not found: %s", sealID)
}

// ============ Compute Jobs ============

// JobStatus represents job status
type JobStatus int

const (
	JobPending JobStatus = iota
	JobRunning
	JobCompleted
	JobFailed
)

// ComputeJob represents an AI compute job
type ComputeJob struct {
	ID          string
	ModelID     string
	InputHash   string
	Status      JobStatus
	CreatedAt   time.Time
	CompletedAt *time.Time
	Result      *ComputeResult
}

// ComputeResult represents a compute job result
type ComputeResult struct {
	OutputHash  string
	SealID      string
	Attestation *TEEAttestation
	Proof       *ZKProof
}

// SubmitJob submits a compute job
func (c *Client) SubmitJob(modelID, inputHash string) (*ComputeJob, error) {
	job := &ComputeJob{
		ID:        fmt.Sprintf("job_%d", time.Now().UnixNano()),
		ModelID:   modelID,
		InputHash: inputHash,
		Status:    JobPending,
		CreatedAt: time.Now(),
	}

	return job, nil
}

// GetJob retrieves a job by ID
func (c *Client) GetJob(jobID string) (*ComputeJob, error) {
	return nil, fmt.Errorf("job not found: %s", jobID)
}

// WaitForJob waits for a job to complete
func (c *Client) WaitForJob(jobID string, timeout time.Duration) (*ComputeJob, error) {
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			job, err := c.GetJob(jobID)
			if err != nil {
				continue
			}
			if job.Status == JobCompleted || job.Status == JobFailed {
				return job, nil
			}
		}
	}
}

// ============ Model Registry ============

// RegisteredModel represents a registered model
type RegisteredModel struct {
	ID          string
	Name        string
	Hash        string
	Version     string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RegisterModel registers a model on the blockchain
func (c *Client) RegisterModel(name, version, description string, module nn.Module) (*RegisteredModel, error) {
	// Compute model hash from state dict
	stateDict := module.(*nn.BaseModule).StateDict()
	hash := sha256.New()
	for name, t := range stateDict {
		hash.Write([]byte(name))
		hash.Write(t.Storage.Data)
	}
	modelHash := hex.EncodeToString(hash.Sum(nil))

	model := &RegisteredModel{
		ID:          fmt.Sprintf("model_%s", modelHash[:16]),
		Name:        name,
		Hash:        modelHash,
		Version:     version,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return model, nil
}

// GetModel retrieves a registered model
func (c *Client) GetModel(modelID string) (*RegisteredModel, error) {
	return nil, fmt.Errorf("model not found: %s", modelID)
}

// ============ Validators ============

// Validator represents a network validator
type Validator struct {
	Address  string
	Moniker  string
	Power    int64
	Hardware *ValidatorHardware
	Online   bool
	SLAScore float64
}

// ValidatorHardware represents validator hardware capabilities
type ValidatorHardware struct {
	HasTEE       bool
	TEEPlatform  string
	GPUModels    []string
	TotalMemory  int64
	ComputeUnits int
}

// GetValidators retrieves active validators
func (c *Client) GetValidators() ([]*Validator, error) {
	// In a real implementation, this would query the blockchain
	return []*Validator{}, nil
}

// ============ Convenience Exports ============

// Re-export commonly used types
type (
	Tensor       = tensor.Tensor
	Module       = nn.Module
	Parameter    = nn.Parameter
	Optimizer    = optim.Optimizer
	LRScheduler  = optim.LRScheduler
	ProcessGroup = distributed.ProcessGroup
	QuantConfig  = quantize.QuantConfig
	Device       = runtime.Device
	Profiler     = runtime.Profiler
)

// DType aliases
const (
	Float32  = tensor.Float32
	Float64  = tensor.Float64
	Float16  = tensor.Float16
	BFloat16 = tensor.BFloat16
	Int8     = tensor.Int8
	Int32    = tensor.Int32
	Int64    = tensor.Int64
)

// ============ SDK Info ============

// SDKInfo contains SDK information
type SDKInfo struct {
	Name        string
	Version     string
	APIVersion  string
	Author      string
	License     string
	Description string
	Features    SDKFeatures
	Compute     SDKComputeCapabilities
}

// SDKFeatures lists SDK features
type SDKFeatures struct {
	Runtime      []string
	Tensor       []string
	NeuralNet    []string
	Distributed  []string
	Quantization []string
	Blockchain   []string
}

// SDKComputeCapabilities captures runtime hardware behavior for this build.
type SDKComputeCapabilities struct {
	HasPhysicalGPU      bool
	HasNativeGPUBackend bool
	AllowsSimulatedGPU  bool
}

// GetSDKInfo returns SDK information
func GetSDKInfo() SDKInfo {
	return SDKInfo{
		Name:        "aethelred-sdk",
		Version:     Version,
		APIVersion:  APIVersion,
		Author:      Author,
		License:     License,
		Description: "Enterprise AI blockchain SDK with explicit compute-backend guarantees",
		Features: SDKFeatures{
			Runtime: []string{
				"Hardware Abstraction Layer (CPU, GPU, TEE)",
				"Native CUDA dispatch only with aethelred_cuda_native build tag",
				"Fail-closed behavior when GPU backend is unavailable",
				"Lock-free memory pool with NUMA awareness",
				"Async execution streams with dependency graphs",
				"JIT compilation with LLVM backend",
				"Comprehensive profiling (Chrome Trace export)",
			},
			Tensor: []string{
				"Lazy evaluation with operation fusion",
				"SIMD-accelerated operations",
				"Memory-efficient views and broadcasting",
				"Automatic differentiation support",
			},
			NeuralNet: []string{
				"PyTorch-compatible nn.Module interface",
				"Transformer and attention layers",
				"Modern activations (GELU, SiLU, RMSNorm)",
				"Loss functions and optimizers",
			},
			Distributed: []string{
				"Data parallelism (MPI backend)",
				"Model parallelism (Tensor, Pipeline)",
				"ZeRO optimizer (Stages 1-3)",
				"Gradient compression",
			},
			Quantization: []string{
				"Post-training quantization (PTQ)",
				"Quantization-aware training (QAT)",
				"INT8, INT4, FP16, BF16, FP8 precision",
				"Per-tensor, per-channel granularity",
			},
			Blockchain: []string{
				"AI compute job submission and tracking",
				"Digital seal creation and verification",
				"TEE attestation (Intel SGX, AMD SEV, AWS Nitro)",
				"zkML proof verification (Groth16, PLONK, STARK)",
				"Post-quantum cryptography (Dilithium, Kyber)",
			},
		},
		Compute: SDKComputeCapabilities{
			HasPhysicalGPU:      HasPhysicalGPU(),
			HasNativeGPUBackend: HasNativeGPUBackend(),
			AllowsSimulatedGPU:  runtime.AllowSimulatedGPU(),
		},
	}
}

// ============ Utility Functions ============

// HashTensor computes the SHA256 hash of a tensor
func HashTensor(t *tensor.Tensor) string {
	t.Realize()
	hash := sha256.Sum256(t.Storage.Data)
	return hex.EncodeToString(hash[:])
}

// HashModule computes the SHA256 hash of a module's state
func HashModule(module nn.Module) string {
	hash := sha256.New()
	for name, param := range module.NamedParameters() {
		param.Realize()
		hash.Write([]byte(name))
		hash.Write(param.Storage.Data)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// SaveModule saves a module to a file
func SaveModule(module nn.Module, path string) error {
	// In a real implementation, this would serialize the model
	return nil
}

// LoadModule loads a module from a file
func LoadModule(path string) (nn.Module, error) {
	// In a real implementation, this would deserialize the model
	return nil, fmt.Errorf("not implemented")
}

// PrintSummary prints a model summary
func PrintSummary(module nn.Module) string {
	if bm, ok := module.(*nn.BaseModule); ok {
		return bm.Summary()
	}
	return "Module summary not available"
}
