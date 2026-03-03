// Package nn provides neural network modules with PyTorch-compatible API.
//
// Features:
//   - Module interface with hooks and parameter management
//   - Linear, Embedding, Normalization layers
//   - Attention and Transformer layers
//   - Modern activations (GELU, SiLU, RMSNorm)
//   - Loss functions and containers
package nn

import (
	"fmt"
	"sync"

	"github.com/aethelred/sdk-go/pkg/tensor"
)

// Module is the base interface for all neural network modules
type Module interface {
	// Forward performs the forward pass
	Forward(input *tensor.Tensor) (*tensor.Tensor, error)

	// Parameters returns all trainable parameters
	Parameters() []*Parameter

	// NamedParameters returns parameters with names
	NamedParameters() map[string]*Parameter

	// Children returns child modules
	Children() []Module

	// NamedChildren returns child modules with names
	NamedChildren() map[string]Module

	// Train sets training mode
	Train(mode bool)

	// Eval sets evaluation mode
	Eval()

	// IsTraining returns training mode
	IsTraining() bool

	// To moves module to device
	To(device interface{}) error

	// ZeroGrad zeros all gradients
	ZeroGrad()

	// Name returns module name
	Name() string

	// SetName sets module name
	SetName(name string)
}

// Parameter is a tensor that requires gradients
type Parameter struct {
	*tensor.Tensor
	Name     string
	Module   string
	Frozen   bool
}

// NewParameter creates a new parameter
func NewParameter(t *tensor.Tensor, name string) *Parameter {
	t.SetRequiresGrad(true)
	return &Parameter{
		Tensor: t,
		Name:   name,
	}
}

// Freeze freezes the parameter (no gradient updates)
func (p *Parameter) Freeze() *Parameter {
	p.Frozen = true
	p.SetRequiresGrad(false)
	return p
}

// Unfreeze unfreezes the parameter
func (p *Parameter) Unfreeze() *Parameter {
	p.Frozen = false
	p.SetRequiresGrad(true)
	return p
}

// Buffer is a non-trainable tensor (e.g., running mean in BatchNorm)
type Buffer struct {
	*tensor.Tensor
	Name       string
	Persistent bool
}

// NewBuffer creates a new buffer
func NewBuffer(t *tensor.Tensor, name string, persistent bool) *Buffer {
	return &Buffer{
		Tensor:     t,
		Name:       name,
		Persistent: persistent,
	}
}

// Hook types for module hooks
type ForwardPreHook func(module Module, input *tensor.Tensor) (*tensor.Tensor, error)
type ForwardHook func(module Module, input, output *tensor.Tensor) (*tensor.Tensor, error)
type BackwardHook func(module Module, gradInput, gradOutput *tensor.Tensor) (*tensor.Tensor, error)

// BaseModule provides common module functionality
type BaseModule struct {
	name            string
	training        bool
	parameters      map[string]*Parameter
	buffers         map[string]*Buffer
	children        map[string]Module
	forwardPreHooks []ForwardPreHook
	forwardHooks    []ForwardHook
	backwardHooks   []BackwardHook
	mu              sync.RWMutex
}

// NewBaseModule creates a new base module
func NewBaseModule(name string) *BaseModule {
	return &BaseModule{
		name:       name,
		training:   true,
		parameters: make(map[string]*Parameter),
		buffers:    make(map[string]*Buffer),
		children:   make(map[string]Module),
	}
}

// Name returns the module name
func (m *BaseModule) Name() string {
	return m.name
}

// SetName sets the module name
func (m *BaseModule) SetName(name string) {
	m.name = name
}

// Train sets training mode
func (m *BaseModule) Train(mode bool) {
	m.training = mode
	for _, child := range m.children {
		child.Train(mode)
	}
}

// Eval sets evaluation mode
func (m *BaseModule) Eval() {
	m.Train(false)
}

// IsTraining returns training mode
func (m *BaseModule) IsTraining() bool {
	return m.training
}

// RegisterParameter registers a parameter
func (m *BaseModule) RegisterParameter(name string, param *Parameter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	param.Name = name
	param.Module = m.name
	m.parameters[name] = param
}

// RegisterBuffer registers a buffer
func (m *BaseModule) RegisterBuffer(name string, buffer *Buffer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	buffer.Name = name
	m.buffers[name] = buffer
}

// RegisterChild registers a child module
func (m *BaseModule) RegisterChild(name string, child Module) {
	m.mu.Lock()
	defer m.mu.Unlock()
	child.SetName(name)
	m.children[name] = child
}

// Parameters returns all trainable parameters
func (m *BaseModule) Parameters() []*Parameter {
	var params []*Parameter

	m.mu.RLock()
	for _, p := range m.parameters {
		if !p.Frozen {
			params = append(params, p)
		}
	}
	m.mu.RUnlock()

	for _, child := range m.Children() {
		params = append(params, child.Parameters()...)
	}

	return params
}

// NamedParameters returns parameters with names
func (m *BaseModule) NamedParameters() map[string]*Parameter {
	params := make(map[string]*Parameter)

	m.mu.RLock()
	for name, p := range m.parameters {
		fullName := m.name + "." + name
		params[fullName] = p
	}
	m.mu.RUnlock()

	for childName, child := range m.NamedChildren() {
		for name, p := range child.NamedParameters() {
			fullName := childName + "." + name
			params[fullName] = p
		}
	}

	return params
}

// Buffers returns all buffers
func (m *BaseModule) Buffers() []*Buffer {
	var bufs []*Buffer

	m.mu.RLock()
	for _, b := range m.buffers {
		bufs = append(bufs, b)
	}
	m.mu.RUnlock()

	for _, child := range m.Children() {
		if bm, ok := child.(*BaseModule); ok {
			bufs = append(bufs, bm.Buffers()...)
		}
	}

	return bufs
}

// Children returns child modules
func (m *BaseModule) Children() []Module {
	m.mu.RLock()
	defer m.mu.RUnlock()

	children := make([]Module, 0, len(m.children))
	for _, child := range m.children {
		children = append(children, child)
	}
	return children
}

// NamedChildren returns child modules with names
func (m *BaseModule) NamedChildren() map[string]Module {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.children
}

// To moves module to device (placeholder for device movement)
func (m *BaseModule) To(device interface{}) error {
	// TODO: Implement device movement
	return nil
}

// ZeroGrad zeros all gradients
func (m *BaseModule) ZeroGrad() {
	for _, p := range m.Parameters() {
		p.ZeroGrad()
	}
}

// RegisterForwardPreHook registers a forward pre-hook
func (m *BaseModule) RegisterForwardPreHook(hook ForwardPreHook) {
	m.forwardPreHooks = append(m.forwardPreHooks, hook)
}

// RegisterForwardHook registers a forward hook
func (m *BaseModule) RegisterForwardHook(hook ForwardHook) {
	m.forwardHooks = append(m.forwardHooks, hook)
}

// RegisterBackwardHook registers a backward hook
func (m *BaseModule) RegisterBackwardHook(hook BackwardHook) {
	m.backwardHooks = append(m.backwardHooks, hook)
}

// Forward is a placeholder that should be overridden
func (m *BaseModule) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("Forward not implemented for BaseModule")
}

// ApplyHooks applies forward hooks
func (m *BaseModule) ApplyHooks(input, output *tensor.Tensor) (*tensor.Tensor, error) {
	var err error

	// Apply pre-hooks
	for _, hook := range m.forwardPreHooks {
		input, err = hook(m, input)
		if err != nil {
			return nil, err
		}
	}

	// Apply post-hooks
	for _, hook := range m.forwardHooks {
		output, err = hook(m, input, output)
		if err != nil {
			return nil, err
		}
	}

	return output, nil
}

// ============ State Dict ============

// StateDict represents module state for serialization
type StateDict map[string]*tensor.Tensor

// StateDict returns the module state
func (m *BaseModule) StateDict() StateDict {
	state := make(StateDict)

	for name, p := range m.NamedParameters() {
		state[name] = p.Tensor
	}

	for name, child := range m.NamedChildren() {
		if bm, ok := child.(*BaseModule); ok {
			for k, v := range bm.StateDict() {
				state[name+"."+k] = v
			}
		}
	}

	return state
}

// LoadStateDict loads module state
func (m *BaseModule) LoadStateDict(state StateDict, strict bool) error {
	params := m.NamedParameters()

	for name, t := range state {
		if p, ok := params[name]; ok {
			// Copy tensor data
			copy(p.Float32Data(), t.Float32Data())
		} else if strict {
			return fmt.Errorf("unexpected key in state_dict: %s", name)
		}
	}

	return nil
}

// NumParameters returns total number of parameters
func (m *BaseModule) NumParameters(trainableOnly bool) int64 {
	var total int64
	for _, p := range m.Parameters() {
		if !trainableOnly || !p.Frozen {
			total += int64(p.Numel())
		}
	}
	return total
}

// ============ Module Summary ============

// Summary returns a summary of the module
func (m *BaseModule) Summary() string {
	summary := fmt.Sprintf("Module: %s\n", m.name)
	summary += fmt.Sprintf("  Parameters: %d\n", m.NumParameters(false))
	summary += fmt.Sprintf("  Trainable: %d\n", m.NumParameters(true))
	summary += fmt.Sprintf("  Children: %d\n", len(m.children))

	for name, child := range m.children {
		summary += fmt.Sprintf("    - %s: %T\n", name, child)
	}

	return summary
}

// ============ Module Utilities ============

// Apply applies a function to all modules
func Apply(module Module, fn func(Module)) {
	fn(module)
	for _, child := range module.Children() {
		Apply(child, fn)
	}
}

// FreezeModule freezes all parameters in a module
func FreezeModule(module Module) {
	for _, p := range module.Parameters() {
		p.Freeze()
	}
}

// UnfreezeModule unfreezes all parameters in a module
func UnfreezeModule(module Module) {
	for _, p := range module.Parameters() {
		p.Unfreeze()
	}
}

// ============ Gradient Utilities ============

// ClipGradNorm clips gradient norm
func ClipGradNorm(parameters []*Parameter, maxNorm float64, normType float64) float64 {
	if normType == 0 {
		normType = 2.0
	}

	// Compute total norm
	var totalNorm float64
	for _, p := range parameters {
		if p.Grad != nil {
			gradData := p.Grad.Float32Data()
			for _, g := range gradData {
				if normType == 2.0 {
					totalNorm += float64(g * g)
				} else {
					// Other norms not implemented
				}
			}
		}
	}

	if normType == 2.0 {
		totalNorm = totalNorm
	}

	// Clip
	if totalNorm > maxNorm*maxNorm {
		clipCoef := maxNorm / (totalNorm + 1e-6)
		for _, p := range parameters {
			if p.Grad != nil {
				gradData := p.Grad.Float32Data()
				for i := range gradData {
					gradData[i] *= float32(clipCoef)
				}
			}
		}
	}

	return totalNorm
}

// ClipGradValue clips gradient values
func ClipGradValue(parameters []*Parameter, clipValue float64) {
	for _, p := range parameters {
		if p.Grad != nil {
			gradData := p.Grad.Float32Data()
			for i, g := range gradData {
				if float64(g) > clipValue {
					gradData[i] = float32(clipValue)
				} else if float64(g) < -clipValue {
					gradData[i] = float32(-clipValue)
				}
			}
		}
	}
}
