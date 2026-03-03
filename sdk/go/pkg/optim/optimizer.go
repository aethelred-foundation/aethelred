// Package optim provides optimizers and learning rate schedulers for training.
//
// Features:
//   - SGD, Adam, AdamW, LAMB, Lion optimizers
//   - Learning rate schedulers (Step, Cosine, OneCycle, etc.)
//   - Gradient accumulation and clipping
//   - Fused optimizer implementations
package optim

import (
	"math"

	"github.com/aethelred/sdk-go/pkg/nn"
	"github.com/aethelred/sdk-go/pkg/tensor"
)

// Optimizer is the interface for all optimizers
type Optimizer interface {
	// Step performs a single optimization step
	Step() error

	// ZeroGrad zeros all parameter gradients
	ZeroGrad()

	// GetLR returns the current learning rate
	GetLR() float64

	// SetLR sets the learning rate
	SetLR(lr float64)

	// State returns the optimizer state
	State() map[string]interface{}

	// LoadState loads optimizer state
	LoadState(state map[string]interface{}) error

	// ParamGroups returns parameter groups
	ParamGroups() []ParamGroup
}

// ParamGroup represents a group of parameters with shared hyperparameters
type ParamGroup struct {
	Params      []*nn.Parameter
	LR          float64
	WeightDecay float64
	Momentum    float64
	Betas       [2]float64
	Eps         float64
	Maximize    bool
}

// DefaultParamGroup creates a default parameter group
func DefaultParamGroup(params []*nn.Parameter, lr float64) ParamGroup {
	return ParamGroup{
		Params:      params,
		LR:          lr,
		WeightDecay: 0,
		Momentum:    0,
		Betas:       [2]float64{0.9, 0.999},
		Eps:         1e-8,
		Maximize:    false,
	}
}

// BaseOptimizer provides common optimizer functionality
type BaseOptimizer struct {
	paramGroups []ParamGroup
	state       map[string]interface{}
	step        int
	defaults    ParamGroup
}

// NewBaseOptimizer creates a new base optimizer
func NewBaseOptimizer(params []*nn.Parameter, defaults ParamGroup) *BaseOptimizer {
	return &BaseOptimizer{
		paramGroups: []ParamGroup{{
			Params:      params,
			LR:          defaults.LR,
			WeightDecay: defaults.WeightDecay,
			Momentum:    defaults.Momentum,
			Betas:       defaults.Betas,
			Eps:         defaults.Eps,
			Maximize:    defaults.Maximize,
		}},
		state:    make(map[string]interface{}),
		step:     0,
		defaults: defaults,
	}
}

// ZeroGrad zeros all parameter gradients
func (o *BaseOptimizer) ZeroGrad() {
	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			p.ZeroGrad()
		}
	}
}

// GetLR returns the learning rate of the first param group
func (o *BaseOptimizer) GetLR() float64 {
	if len(o.paramGroups) > 0 {
		return o.paramGroups[0].LR
	}
	return 0
}

// SetLR sets the learning rate for all param groups
func (o *BaseOptimizer) SetLR(lr float64) {
	for i := range o.paramGroups {
		o.paramGroups[i].LR = lr
	}
}

// State returns the optimizer state
func (o *BaseOptimizer) State() map[string]interface{} {
	return o.state
}

// LoadState loads optimizer state
func (o *BaseOptimizer) LoadState(state map[string]interface{}) error {
	o.state = state
	return nil
}

// ParamGroups returns parameter groups
func (o *BaseOptimizer) ParamGroups() []ParamGroup {
	return o.paramGroups
}

// AddParamGroup adds a parameter group
func (o *BaseOptimizer) AddParamGroup(group ParamGroup) {
	o.paramGroups = append(o.paramGroups, group)
}

// ============ SGD Optimizer ============

// SGD implements Stochastic Gradient Descent with momentum
type SGD struct {
	*BaseOptimizer
	Momentum  float64
	Dampening float64
	Nesterov  bool
}

// NewSGD creates a new SGD optimizer
func NewSGD(params []*nn.Parameter, lr, momentum, dampening, weightDecay float64, nesterov bool) *SGD {
	return &SGD{
		BaseOptimizer: NewBaseOptimizer(params, ParamGroup{
			LR:          lr,
			WeightDecay: weightDecay,
			Momentum:    momentum,
		}),
		Momentum:  momentum,
		Dampening: dampening,
		Nesterov:  nesterov,
	}
}

// Step performs a single optimization step
func (o *SGD) Step() error {
	o.step++

	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			if p.Grad == nil {
				continue
			}

			grad := p.Grad.Float32Data()
			data := p.Float32Data()

			// Weight decay
			if group.WeightDecay != 0 {
				for i := range grad {
					grad[i] += float32(group.WeightDecay) * data[i]
				}
			}

			// Momentum
			if o.Momentum != 0 {
				key := p.Name + "_momentum"
				var buf []float32

				if stored, ok := o.state[key]; ok {
					buf = stored.([]float32)
				} else {
					buf = make([]float32, len(grad))
					o.state[key] = buf
				}

				for i := range grad {
					buf[i] = float32(o.Momentum)*buf[i] + (1-float32(o.Dampening))*grad[i]
				}

				if o.Nesterov {
					for i := range grad {
						grad[i] += float32(o.Momentum) * buf[i]
					}
				} else {
					grad = buf
				}
			}

			// Update
			lr := float32(group.LR)
			if group.Maximize {
				lr = -lr
			}
			for i := range data {
				data[i] -= lr * grad[i]
			}
		}
	}

	return nil
}

// ============ Adam Optimizer ============

// Adam implements the Adam optimizer
type Adam struct {
	*BaseOptimizer
	Beta1   float64
	Beta2   float64
	Eps     float64
	Amsgrad bool
}

// NewAdam creates a new Adam optimizer
func NewAdam(params []*nn.Parameter, lr float64, betas [2]float64, eps, weightDecay float64, amsgrad bool) *Adam {
	return &Adam{
		BaseOptimizer: NewBaseOptimizer(params, ParamGroup{
			LR:          lr,
			WeightDecay: weightDecay,
			Betas:       betas,
			Eps:         eps,
		}),
		Beta1:   betas[0],
		Beta2:   betas[1],
		Eps:     eps,
		Amsgrad: amsgrad,
	}
}

// Step performs a single optimization step
func (o *Adam) Step() error {
	o.step++

	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			if p.Grad == nil {
				continue
			}

			grad := p.Grad.Float32Data()
			data := p.Float32Data()

			// Get or initialize momentum buffers
			keyM := p.Name + "_m"
			keyV := p.Name + "_v"

			var expAvg, expAvgSq []float32
			if stored, ok := o.state[keyM]; ok {
				expAvg = stored.([]float32)
			} else {
				expAvg = make([]float32, len(grad))
				o.state[keyM] = expAvg
			}

			if stored, ok := o.state[keyV]; ok {
				expAvgSq = stored.([]float32)
			} else {
				expAvgSq = make([]float32, len(grad))
				o.state[keyV] = expAvgSq
			}

			var maxExpAvgSq []float32
			if o.Amsgrad {
				keyMax := p.Name + "_max_v"
				if stored, ok := o.state[keyMax]; ok {
					maxExpAvgSq = stored.([]float32)
				} else {
					maxExpAvgSq = make([]float32, len(grad))
					o.state[keyMax] = maxExpAvgSq
				}
			}

			beta1 := float32(o.Beta1)
			beta2 := float32(o.Beta2)

			// Bias correction
			biasCorr1 := 1 - float32(math.Pow(o.Beta1, float64(o.step)))
			biasCorr2 := 1 - float32(math.Pow(o.Beta2, float64(o.step)))

			for i := range grad {
				g := grad[i]

				// L2 regularization (not decoupled)
				if group.WeightDecay != 0 {
					g += float32(group.WeightDecay) * data[i]
				}

				// Update biased first moment estimate
				expAvg[i] = beta1*expAvg[i] + (1-beta1)*g

				// Update biased second moment estimate
				expAvgSq[i] = beta2*expAvgSq[i] + (1-beta2)*g*g

				// Compute bias-corrected estimates
				mHat := expAvg[i] / biasCorr1
				var vHat float32

				if o.Amsgrad {
					if expAvgSq[i] > maxExpAvgSq[i] {
						maxExpAvgSq[i] = expAvgSq[i]
					}
					vHat = maxExpAvgSq[i] / biasCorr2
				} else {
					vHat = expAvgSq[i] / biasCorr2
				}

				// Update parameter
				data[i] -= float32(group.LR) * mHat / (float32(math.Sqrt(float64(vHat))) + float32(o.Eps))
			}
		}
	}

	return nil
}

// ============ AdamW Optimizer ============

// AdamW implements Adam with decoupled weight decay
type AdamW struct {
	*Adam
}

// NewAdamW creates a new AdamW optimizer
func NewAdamW(params []*nn.Parameter, lr float64, betas [2]float64, eps, weightDecay float64, amsgrad bool) *AdamW {
	return &AdamW{
		Adam: NewAdam(params, lr, betas, eps, weightDecay, amsgrad),
	}
}

// Step performs a single optimization step with decoupled weight decay
func (o *AdamW) Step() error {
	o.step++

	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			if p.Grad == nil {
				continue
			}

			grad := p.Grad.Float32Data()
			data := p.Float32Data()

			// Decoupled weight decay
			if group.WeightDecay != 0 {
				wd := float32(group.LR * group.WeightDecay)
				for i := range data {
					data[i] -= wd * data[i]
				}
			}

			// Get or initialize momentum buffers
			keyM := p.Name + "_m"
			keyV := p.Name + "_v"

			var expAvg, expAvgSq []float32
			if stored, ok := o.state[keyM]; ok {
				expAvg = stored.([]float32)
			} else {
				expAvg = make([]float32, len(grad))
				o.state[keyM] = expAvg
			}

			if stored, ok := o.state[keyV]; ok {
				expAvgSq = stored.([]float32)
			} else {
				expAvgSq = make([]float32, len(grad))
				o.state[keyV] = expAvgSq
			}

			beta1 := float32(o.Beta1)
			beta2 := float32(o.Beta2)

			// Bias correction
			biasCorr1 := 1 - float32(math.Pow(o.Beta1, float64(o.step)))
			biasCorr2 := 1 - float32(math.Pow(o.Beta2, float64(o.step)))

			for i := range grad {
				g := grad[i]

				// Update biased first moment estimate
				expAvg[i] = beta1*expAvg[i] + (1-beta1)*g

				// Update biased second moment estimate
				expAvgSq[i] = beta2*expAvgSq[i] + (1-beta2)*g*g

				// Compute bias-corrected estimates
				mHat := expAvg[i] / biasCorr1
				vHat := expAvgSq[i] / biasCorr2

				// Update parameter
				data[i] -= float32(group.LR) * mHat / (float32(math.Sqrt(float64(vHat))) + float32(o.Eps))
			}
		}
	}

	return nil
}

// ============ LAMB Optimizer ============

// LAMB implements Layer-wise Adaptive Moments for large batch training
type LAMB struct {
	*BaseOptimizer
	Beta1      float64
	Beta2      float64
	Eps        float64
	TrustClip  bool
	ClipValue  float64
}

// NewLAMB creates a new LAMB optimizer
func NewLAMB(params []*nn.Parameter, lr float64, betas [2]float64, eps, weightDecay float64, trustClip bool, clipValue float64) *LAMB {
	if clipValue == 0 {
		clipValue = 10.0
	}
	return &LAMB{
		BaseOptimizer: NewBaseOptimizer(params, ParamGroup{
			LR:          lr,
			WeightDecay: weightDecay,
			Betas:       betas,
			Eps:         eps,
		}),
		Beta1:     betas[0],
		Beta2:     betas[1],
		Eps:       eps,
		TrustClip: trustClip,
		ClipValue: clipValue,
	}
}

// Step performs a single optimization step
func (o *LAMB) Step() error {
	o.step++

	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			if p.Grad == nil {
				continue
			}

			grad := p.Grad.Float32Data()
			data := p.Float32Data()

			// Get or initialize momentum buffers
			keyM := p.Name + "_m"
			keyV := p.Name + "_v"

			var expAvg, expAvgSq []float32
			if stored, ok := o.state[keyM]; ok {
				expAvg = stored.([]float32)
			} else {
				expAvg = make([]float32, len(grad))
				o.state[keyM] = expAvg
			}

			if stored, ok := o.state[keyV]; ok {
				expAvgSq = stored.([]float32)
			} else {
				expAvgSq = make([]float32, len(grad))
				o.state[keyV] = expAvgSq
			}

			beta1 := float32(o.Beta1)
			beta2 := float32(o.Beta2)

			// Bias correction
			biasCorr1 := 1 - float32(math.Pow(o.Beta1, float64(o.step)))
			biasCorr2 := 1 - float32(math.Pow(o.Beta2, float64(o.step)))

			// Compute update direction
			update := make([]float32, len(grad))
			var weightNorm, updateNorm float64

			for i := range grad {
				g := grad[i]

				// Update moments
				expAvg[i] = beta1*expAvg[i] + (1-beta1)*g
				expAvgSq[i] = beta2*expAvgSq[i] + (1-beta2)*g*g

				// Bias correction
				mHat := expAvg[i] / biasCorr1
				vHat := expAvgSq[i] / biasCorr2

				// Adam update
				update[i] = mHat / (float32(math.Sqrt(float64(vHat))) + float32(o.Eps))

				// Add weight decay
				if group.WeightDecay != 0 {
					update[i] += float32(group.WeightDecay) * data[i]
				}

				weightNorm += float64(data[i] * data[i])
				updateNorm += float64(update[i] * update[i])
			}

			weightNorm = math.Sqrt(weightNorm)
			updateNorm = math.Sqrt(updateNorm)

			// Compute trust ratio
			var trustRatio float64 = 1.0
			if weightNorm > 0 && updateNorm > 0 {
				trustRatio = weightNorm / updateNorm
			}

			if o.TrustClip && trustRatio > o.ClipValue {
				trustRatio = o.ClipValue
			}

			// Update parameters
			lr := float32(group.LR * trustRatio)
			for i := range data {
				data[i] -= lr * update[i]
			}
		}
	}

	return nil
}

// ============ Lion Optimizer ============

// Lion implements the Lion optimizer (EvoLved Sign Momentum)
type Lion struct {
	*BaseOptimizer
	Beta1 float64
	Beta2 float64
}

// NewLion creates a new Lion optimizer
func NewLion(params []*nn.Parameter, lr float64, betas [2]float64, weightDecay float64) *Lion {
	return &Lion{
		BaseOptimizer: NewBaseOptimizer(params, ParamGroup{
			LR:          lr,
			WeightDecay: weightDecay,
			Betas:       betas,
		}),
		Beta1: betas[0],
		Beta2: betas[1],
	}
}

// Step performs a single optimization step
func (o *Lion) Step() error {
	o.step++

	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			if p.Grad == nil {
				continue
			}

			grad := p.Grad.Float32Data()
			data := p.Float32Data()

			// Get or initialize momentum buffer
			keyM := p.Name + "_m"
			var expAvg []float32
			if stored, ok := o.state[keyM]; ok {
				expAvg = stored.([]float32)
			} else {
				expAvg = make([]float32, len(grad))
				o.state[keyM] = expAvg
			}

			beta1 := float32(o.Beta1)
			beta2 := float32(o.Beta2)

			for i := range grad {
				g := grad[i]

				// Compute update = sign(beta1 * m + (1 - beta1) * g)
				update := beta1*expAvg[i] + (1-beta1)*g
				var sign float32
				if update > 0 {
					sign = 1
				} else if update < 0 {
					sign = -1
				}

				// Weight decay
				if group.WeightDecay != 0 {
					data[i] -= float32(group.LR*group.WeightDecay) * data[i]
				}

				// Update
				data[i] -= float32(group.LR) * sign

				// Update momentum
				expAvg[i] = beta2*expAvg[i] + (1-beta2)*g
			}
		}
	}

	return nil
}

// ============ RMSprop Optimizer ============

// RMSprop implements the RMSprop optimizer
type RMSprop struct {
	*BaseOptimizer
	Alpha      float64
	Eps        float64
	Momentum   float64
	Centered   bool
}

// NewRMSprop creates a new RMSprop optimizer
func NewRMSprop(params []*nn.Parameter, lr, alpha, eps, weightDecay, momentum float64, centered bool) *RMSprop {
	if alpha == 0 {
		alpha = 0.99
	}
	if eps == 0 {
		eps = 1e-8
	}
	return &RMSprop{
		BaseOptimizer: NewBaseOptimizer(params, ParamGroup{
			LR:          lr,
			WeightDecay: weightDecay,
			Momentum:    momentum,
			Eps:         eps,
		}),
		Alpha:    alpha,
		Eps:      eps,
		Momentum: momentum,
		Centered: centered,
	}
}

// Step performs a single optimization step
func (o *RMSprop) Step() error {
	o.step++

	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			if p.Grad == nil {
				continue
			}

			grad := p.Grad.Float32Data()
			data := p.Float32Data()

			// Get or initialize buffers
			keyV := p.Name + "_v"
			var squareAvg []float32
			if stored, ok := o.state[keyV]; ok {
				squareAvg = stored.([]float32)
			} else {
				squareAvg = make([]float32, len(grad))
				o.state[keyV] = squareAvg
			}

			var gradAvg []float32
			if o.Centered {
				keyG := p.Name + "_g"
				if stored, ok := o.state[keyG]; ok {
					gradAvg = stored.([]float32)
				} else {
					gradAvg = make([]float32, len(grad))
					o.state[keyG] = gradAvg
				}
			}

			var momentum []float32
			if o.Momentum > 0 {
				keyM := p.Name + "_m"
				if stored, ok := o.state[keyM]; ok {
					momentum = stored.([]float32)
				} else {
					momentum = make([]float32, len(grad))
					o.state[keyM] = momentum
				}
			}

			alpha := float32(o.Alpha)

			for i := range grad {
				g := grad[i]

				// Weight decay
				if group.WeightDecay != 0 {
					g += float32(group.WeightDecay) * data[i]
				}

				// Update running average of squared gradients
				squareAvg[i] = alpha*squareAvg[i] + (1-alpha)*g*g

				var avg float32
				if o.Centered {
					gradAvg[i] = alpha*gradAvg[i] + (1-alpha)*g
					avg = squareAvg[i] - gradAvg[i]*gradAvg[i]
				} else {
					avg = squareAvg[i]
				}

				if o.Momentum > 0 {
					momentum[i] = float32(o.Momentum)*momentum[i] + g/(float32(math.Sqrt(float64(avg)))+float32(o.Eps))
					data[i] -= float32(group.LR) * momentum[i]
				} else {
					data[i] -= float32(group.LR) * g / (float32(math.Sqrt(float64(avg))) + float32(o.Eps))
				}
			}
		}
	}

	return nil
}

// ============ Adagrad Optimizer ============

// Adagrad implements the Adagrad optimizer
type Adagrad struct {
	*BaseOptimizer
	LRDecay    float64
	Eps        float64
	InitialAcc float64
}

// NewAdagrad creates a new Adagrad optimizer
func NewAdagrad(params []*nn.Parameter, lr, lrDecay, weightDecay, eps, initialAcc float64) *Adagrad {
	if eps == 0 {
		eps = 1e-10
	}
	return &Adagrad{
		BaseOptimizer: NewBaseOptimizer(params, ParamGroup{
			LR:          lr,
			WeightDecay: weightDecay,
			Eps:         eps,
		}),
		LRDecay:    lrDecay,
		Eps:        eps,
		InitialAcc: initialAcc,
	}
}

// Step performs a single optimization step
func (o *Adagrad) Step() error {
	o.step++

	for _, group := range o.paramGroups {
		for _, p := range group.Params {
			if p.Grad == nil {
				continue
			}

			grad := p.Grad.Float32Data()
			data := p.Float32Data()

			// Get or initialize sum buffer
			keySum := p.Name + "_sum"
			var sum []float32
			if stored, ok := o.state[keySum]; ok {
				sum = stored.([]float32)
			} else {
				sum = make([]float32, len(grad))
				for i := range sum {
					sum[i] = float32(o.InitialAcc)
				}
				o.state[keySum] = sum
			}

			// Compute learning rate with decay
			lr := group.LR / (1 + o.LRDecay*float64(o.step-1))

			for i := range grad {
				g := grad[i]

				// Weight decay
				if group.WeightDecay != 0 {
					g += float32(group.WeightDecay) * data[i]
				}

				// Accumulate squared gradients
				sum[i] += g * g

				// Update
				data[i] -= float32(lr) * g / (float32(math.Sqrt(float64(sum[i]))) + float32(o.Eps))
			}
		}
	}

	return nil
}

// ============ Gradient Accumulation ============

// GradientAccumulator handles gradient accumulation across multiple steps
type GradientAccumulator struct {
	Optimizer       Optimizer
	AccumSteps      int
	currentStep     int
	scaler          float64
}

// NewGradientAccumulator creates a new gradient accumulator
func NewGradientAccumulator(optimizer Optimizer, accumSteps int) *GradientAccumulator {
	return &GradientAccumulator{
		Optimizer:   optimizer,
		AccumSteps:  accumSteps,
		currentStep: 0,
		scaler:      1.0 / float64(accumSteps),
	}
}

// Step accumulates gradients and steps when ready
func (ga *GradientAccumulator) Step() (bool, error) {
	ga.currentStep++

	if ga.currentStep >= ga.AccumSteps {
		// Scale gradients
		for _, group := range ga.Optimizer.ParamGroups() {
			for _, p := range group.Params {
				if p.Grad != nil {
					gradData := p.Grad.Float32Data()
					for i := range gradData {
						gradData[i] *= float32(ga.scaler)
					}
				}
			}
		}

		// Perform optimizer step
		err := ga.Optimizer.Step()
		if err != nil {
			return false, err
		}

		ga.Optimizer.ZeroGrad()
		ga.currentStep = 0
		return true, nil
	}

	return false, nil
}

// ZeroGrad zeros gradients
func (ga *GradientAccumulator) ZeroGrad() {
	ga.Optimizer.ZeroGrad()
	ga.currentStep = 0
}

// ============ Mixed Precision Training ============

// GradScaler for mixed precision training
type GradScaler struct {
	InitScale      float64
	GrowthFactor   float64
	BackoffFactor  float64
	GrowthInterval int
	MaxScale       float64
	MinScale       float64

	scale       float64
	growth      int
	foundInf    bool
}

// NewGradScaler creates a new gradient scaler
func NewGradScaler(initScale, growthFactor, backoffFactor float64, growthInterval int) *GradScaler {
	if initScale == 0 {
		initScale = 65536.0
	}
	if growthFactor == 0 {
		growthFactor = 2.0
	}
	if backoffFactor == 0 {
		backoffFactor = 0.5
	}
	if growthInterval == 0 {
		growthInterval = 2000
	}

	return &GradScaler{
		InitScale:      initScale,
		GrowthFactor:   growthFactor,
		BackoffFactor:  backoffFactor,
		GrowthInterval: growthInterval,
		MaxScale:       65536.0 * 65536.0,
		MinScale:       1.0,
		scale:          initScale,
		growth:         0,
		foundInf:       false,
	}
}

// Scale scales a tensor for mixed precision
func (gs *GradScaler) Scale(t *tensor.Tensor) *tensor.Tensor {
	scaleT, _ := tensor.Full([]int{1}, gs.scale, tensor.Float32, t.Device)
	return t.Mul(scaleT)
}

// Unscale unscales optimizer gradients
func (gs *GradScaler) Unscale(optimizer Optimizer) {
	invScale := float32(1.0 / gs.scale)

	for _, group := range optimizer.ParamGroups() {
		for _, p := range group.Params {
			if p.Grad != nil {
				gradData := p.Grad.Float32Data()
				for i := range gradData {
					g := gradData[i] * invScale
					if math.IsInf(float64(g), 0) || math.IsNaN(float64(g)) {
						gs.foundInf = true
					}
					gradData[i] = g
				}
			}
		}
	}
}

// Step steps the optimizer if gradients are finite
func (gs *GradScaler) Step(optimizer Optimizer) error {
	if !gs.foundInf {
		return optimizer.Step()
	}
	return nil
}

// Update updates the scale factor
func (gs *GradScaler) Update() {
	if gs.foundInf {
		gs.scale *= gs.BackoffFactor
		if gs.scale < gs.MinScale {
			gs.scale = gs.MinScale
		}
		gs.growth = 0
	} else {
		gs.growth++
		if gs.growth >= gs.GrowthInterval {
			gs.scale *= gs.GrowthFactor
			if gs.scale > gs.MaxScale {
				gs.scale = gs.MaxScale
			}
			gs.growth = 0
		}
	}
	gs.foundInf = false
}

// GetScale returns the current scale
func (gs *GradScaler) GetScale() float64 {
	return gs.scale
}
