package nn

import (
	"fmt"

	"github.com/aethelred/sdk-go/pkg/tensor"
)

// ============ Container Modules ============

// Sequential is a sequential container of modules
type Sequential struct {
	*BaseModule
	Modules []Module
}

// NewSequential creates a new Sequential container
func NewSequential(modules ...Module) *Sequential {
	s := &Sequential{
		BaseModule: NewBaseModule("Sequential"),
		Modules:    modules,
	}

	for i, m := range modules {
		s.RegisterChild(fmt.Sprintf("%d", i), m)
	}

	return s
}

// Forward performs forward pass through all modules
func (s *Sequential) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	var err error
	x := input

	for _, m := range s.Modules {
		x, err = m.Forward(x)
		if err != nil {
			return nil, err
		}
	}

	return x, nil
}

// Add adds a module to the sequence
func (s *Sequential) Add(module Module) {
	idx := len(s.Modules)
	s.Modules = append(s.Modules, module)
	s.RegisterChild(fmt.Sprintf("%d", idx), module)
}

// Len returns the number of modules
func (s *Sequential) Len() int {
	return len(s.Modules)
}

// Get returns module at index
func (s *Sequential) Get(idx int) Module {
	if idx < 0 || idx >= len(s.Modules) {
		return nil
	}
	return s.Modules[idx]
}

// ModuleList is an indexed list of modules
type ModuleList struct {
	*BaseModule
	Modules []Module
}

// NewModuleList creates a new ModuleList
func NewModuleList(modules ...Module) *ModuleList {
	ml := &ModuleList{
		BaseModule: NewBaseModule("ModuleList"),
		Modules:    modules,
	}

	for i, m := range modules {
		ml.RegisterChild(fmt.Sprintf("%d", i), m)
	}

	return ml
}

// Forward is not directly callable on ModuleList
func (ml *ModuleList) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("ModuleList has no forward method, access modules individually")
}

// Append adds a module to the list
func (ml *ModuleList) Append(module Module) {
	idx := len(ml.Modules)
	ml.Modules = append(ml.Modules, module)
	ml.RegisterChild(fmt.Sprintf("%d", idx), module)
}

// Extend adds multiple modules
func (ml *ModuleList) Extend(modules ...Module) {
	for _, m := range modules {
		ml.Append(m)
	}
}

// Get returns module at index
func (ml *ModuleList) Get(idx int) Module {
	if idx < 0 {
		idx += len(ml.Modules)
	}
	if idx < 0 || idx >= len(ml.Modules) {
		return nil
	}
	return ml.Modules[idx]
}

// Len returns the number of modules
func (ml *ModuleList) Len() int {
	return len(ml.Modules)
}

// Iter returns an iterator over modules
func (ml *ModuleList) Iter() []Module {
	return ml.Modules
}

// ModuleDict is a named dictionary of modules
type ModuleDict struct {
	*BaseModule
	Modules map[string]Module
	Order   []string
}

// NewModuleDict creates a new ModuleDict
func NewModuleDict(modules map[string]Module) *ModuleDict {
	md := &ModuleDict{
		BaseModule: NewBaseModule("ModuleDict"),
		Modules:    make(map[string]Module),
		Order:      make([]string, 0),
	}

	for name, m := range modules {
		md.Set(name, m)
	}

	return md
}

// Forward is not directly callable on ModuleDict
func (md *ModuleDict) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("ModuleDict has no forward method, access modules by name")
}

// Set adds or updates a module
func (md *ModuleDict) Set(name string, module Module) {
	if _, exists := md.Modules[name]; !exists {
		md.Order = append(md.Order, name)
	}
	md.Modules[name] = module
	md.RegisterChild(name, module)
}

// Get returns module by name
func (md *ModuleDict) Get(name string) (Module, bool) {
	m, ok := md.Modules[name]
	return m, ok
}

// Delete removes a module
func (md *ModuleDict) Delete(name string) {
	delete(md.Modules, name)
	for i, n := range md.Order {
		if n == name {
			md.Order = append(md.Order[:i], md.Order[i+1:]...)
			break
		}
	}
}

// Keys returns module names in order
func (md *ModuleDict) Keys() []string {
	return md.Order
}

// Values returns modules in order
func (md *ModuleDict) Values() []Module {
	values := make([]Module, len(md.Order))
	for i, name := range md.Order {
		values[i] = md.Modules[name]
	}
	return values
}

// Items returns (name, module) pairs
func (md *ModuleDict) Items() []struct {
	Name   string
	Module Module
} {
	items := make([]struct {
		Name   string
		Module Module
	}, len(md.Order))
	for i, name := range md.Order {
		items[i].Name = name
		items[i].Module = md.Modules[name]
	}
	return items
}

// Len returns the number of modules
func (md *ModuleDict) Len() int {
	return len(md.Modules)
}

// ParameterList is an indexed list of parameters
type ParameterList struct {
	*BaseModule
	Params []*Parameter
}

// NewParameterList creates a new ParameterList
func NewParameterList(params ...*Parameter) *ParameterList {
	pl := &ParameterList{
		BaseModule: NewBaseModule("ParameterList"),
		Params:     params,
	}

	for i, p := range params {
		pl.RegisterParameter(fmt.Sprintf("%d", i), p)
	}

	return pl
}

// Forward is not callable on ParameterList
func (pl *ParameterList) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("ParameterList has no forward method")
}

// Append adds a parameter
func (pl *ParameterList) Append(param *Parameter) {
	idx := len(pl.Params)
	pl.Params = append(pl.Params, param)
	pl.RegisterParameter(fmt.Sprintf("%d", idx), param)
}

// Get returns parameter at index
func (pl *ParameterList) Get(idx int) *Parameter {
	if idx < 0 {
		idx += len(pl.Params)
	}
	if idx < 0 || idx >= len(pl.Params) {
		return nil
	}
	return pl.Params[idx]
}

// Len returns the number of parameters
func (pl *ParameterList) Len() int {
	return len(pl.Params)
}

// ParameterDict is a named dictionary of parameters
type ParameterDict struct {
	*BaseModule
	Params map[string]*Parameter
	Order  []string
}

// NewParameterDict creates a new ParameterDict
func NewParameterDict(params map[string]*Parameter) *ParameterDict {
	pd := &ParameterDict{
		BaseModule: NewBaseModule("ParameterDict"),
		Params:     make(map[string]*Parameter),
		Order:      make([]string, 0),
	}

	for name, p := range params {
		pd.Set(name, p)
	}

	return pd
}

// Forward is not callable on ParameterDict
func (pd *ParameterDict) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("ParameterDict has no forward method")
}

// Set adds or updates a parameter
func (pd *ParameterDict) Set(name string, param *Parameter) {
	if _, exists := pd.Params[name]; !exists {
		pd.Order = append(pd.Order, name)
	}
	pd.Params[name] = param
	pd.RegisterParameter(name, param)
}

// Get returns parameter by name
func (pd *ParameterDict) Get(name string) (*Parameter, bool) {
	p, ok := pd.Params[name]
	return p, ok
}

// Keys returns parameter names
func (pd *ParameterDict) Keys() []string {
	return pd.Order
}

// ============ Identity Module ============

// Identity is a placeholder module that returns input unchanged
type Identity struct {
	*BaseModule
}

// NewIdentity creates a new Identity module
func NewIdentity() *Identity {
	return &Identity{
		BaseModule: NewBaseModule("Identity"),
	}
}

// Forward returns input unchanged
func (i *Identity) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return input, nil
}

// ============ Flatten Module ============

// Flatten flattens a contiguous range of dimensions
type Flatten struct {
	*BaseModule
	StartDim int
	EndDim   int
}

// NewFlatten creates a new Flatten module
func NewFlatten(startDim, endDim int) *Flatten {
	if startDim == 0 {
		startDim = 1
	}
	if endDim == 0 {
		endDim = -1
	}
	return &Flatten{
		BaseModule: NewBaseModule("Flatten"),
		StartDim:   startDim,
		EndDim:     endDim,
	}
}

// Forward flattens the input
func (f *Flatten) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	// Handle negative indices
	startDim := f.StartDim
	endDim := f.EndDim
	if startDim < 0 {
		startDim += len(input.Shape)
	}
	if endDim < 0 {
		endDim += len(input.Shape)
	}

	// Compute new shape
	newShape := make([]int, 0)
	newShape = append(newShape, input.Shape[:startDim]...)

	flatSize := 1
	for i := startDim; i <= endDim; i++ {
		flatSize *= input.Shape[i]
	}
	newShape = append(newShape, flatSize)

	if endDim+1 < len(input.Shape) {
		newShape = append(newShape, input.Shape[endDim+1:]...)
	}

	return input.View(newShape...)
}

// Unflatten unflattens a dimension
type Unflatten struct {
	*BaseModule
	Dim  int
	Size []int
}

// NewUnflatten creates a new Unflatten module
func NewUnflatten(dim int, size []int) *Unflatten {
	return &Unflatten{
		BaseModule: NewBaseModule("Unflatten"),
		Dim:        dim,
		Size:       size,
	}
}

// Forward unflattens the input
func (u *Unflatten) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	dim := u.Dim
	if dim < 0 {
		dim += len(input.Shape)
	}

	newShape := make([]int, 0)
	newShape = append(newShape, input.Shape[:dim]...)
	newShape = append(newShape, u.Size...)
	if dim+1 < len(input.Shape) {
		newShape = append(newShape, input.Shape[dim+1:]...)
	}

	return input.View(newShape...)
}

// ============ Skip Connection Modules ============

// Residual wraps a module with a residual connection
type Residual struct {
	*BaseModule
	Inner Module
}

// NewResidual creates a new Residual module
func NewResidual(inner Module) *Residual {
	r := &Residual{
		BaseModule: NewBaseModule("Residual"),
		Inner:      inner,
	}
	r.RegisterChild("inner", inner)
	return r
}

// Forward applies residual connection
func (r *Residual) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	out, err := r.Inner.Forward(input)
	if err != nil {
		return nil, err
	}
	return out.Add(input).Realize(), nil
}

// ============ Parallel Modules ============

// Parallel applies multiple modules in parallel and combines outputs
type Parallel struct {
	*BaseModule
	Modules []Module
	Mode    string // "add", "cat", "stack"
	CatDim  int
}

// NewParallel creates a new Parallel module
func NewParallel(mode string, catDim int, modules ...Module) *Parallel {
	if mode == "" {
		mode = "cat"
	}
	p := &Parallel{
		BaseModule: NewBaseModule("Parallel"),
		Modules:    modules,
		Mode:       mode,
		CatDim:     catDim,
	}
	for i, m := range modules {
		p.RegisterChild(fmt.Sprintf("%d", i), m)
	}
	return p
}

// Forward applies all modules and combines outputs
func (p *Parallel) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	outputs := make([]*tensor.Tensor, len(p.Modules))
	for i, m := range p.Modules {
		out, err := m.Forward(input)
		if err != nil {
			return nil, err
		}
		outputs[i] = out
	}

	switch p.Mode {
	case "add":
		result := outputs[0]
		for _, out := range outputs[1:] {
			result = result.Add(out)
		}
		return result.Realize(), nil
	case "cat":
		return tensor.Cat(outputs, p.CatDim)
	case "stack":
		return tensor.Stack(outputs, p.CatDim)
	default:
		return nil, fmt.Errorf("unknown parallel mode: %s", p.Mode)
	}
}

// ============ Conditional Modules ============

// ConditionalModule selects between modules based on a condition
type ConditionalModule struct {
	*BaseModule
	TrueModule  Module
	FalseModule Module
	Condition   func(*tensor.Tensor) bool
}

// NewConditionalModule creates a new ConditionalModule
func NewConditionalModule(trueModule, falseModule Module, condition func(*tensor.Tensor) bool) *ConditionalModule {
	c := &ConditionalModule{
		BaseModule:  NewBaseModule("ConditionalModule"),
		TrueModule:  trueModule,
		FalseModule: falseModule,
		Condition:   condition,
	}
	c.RegisterChild("true", trueModule)
	c.RegisterChild("false", falseModule)
	return c
}

// Forward applies the appropriate module based on condition
func (c *ConditionalModule) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	if c.Condition(input) {
		return c.TrueModule.Forward(input)
	}
	return c.FalseModule.Forward(input)
}
