package optim

import (
	"math"
)

// LRScheduler is the interface for learning rate schedulers
type LRScheduler interface {
	// Step performs a scheduler step
	Step() float64

	// GetLR returns the current learning rate
	GetLR() float64

	// GetLastLR returns the last computed learning rate
	GetLastLR() float64

	// State returns the scheduler state
	State() map[string]interface{}

	// LoadState loads scheduler state
	LoadState(state map[string]interface{}) error
}

// BaseLRScheduler provides common scheduler functionality
type BaseLRScheduler struct {
	optimizer Optimizer
	baseLRs   []float64
	lastLR    float64
	epoch     int
}

// NewBaseLRScheduler creates a new base scheduler
func NewBaseLRScheduler(optimizer Optimizer) *BaseLRScheduler {
	baseLRs := make([]float64, len(optimizer.ParamGroups()))
	for i, group := range optimizer.ParamGroups() {
		baseLRs[i] = group.LR
	}

	return &BaseLRScheduler{
		optimizer: optimizer,
		baseLRs:   baseLRs,
		lastLR:    baseLRs[0],
		epoch:     0,
	}
}

// GetLR returns the current learning rate
func (s *BaseLRScheduler) GetLR() float64 {
	return s.optimizer.GetLR()
}

// GetLastLR returns the last computed learning rate
func (s *BaseLRScheduler) GetLastLR() float64 {
	return s.lastLR
}

// State returns the scheduler state
func (s *BaseLRScheduler) State() map[string]interface{} {
	return map[string]interface{}{
		"epoch":   s.epoch,
		"last_lr": s.lastLR,
	}
}

// LoadState loads scheduler state
func (s *BaseLRScheduler) LoadState(state map[string]interface{}) error {
	if epoch, ok := state["epoch"].(int); ok {
		s.epoch = epoch
	}
	if lastLR, ok := state["last_lr"].(float64); ok {
		s.lastLR = lastLR
	}
	return nil
}

// setLR sets the learning rate
func (s *BaseLRScheduler) setLR(lr float64) {
	s.optimizer.SetLR(lr)
	s.lastLR = lr
}

// ============ Step LR Scheduler ============

// StepLR decays the learning rate by gamma every step_size epochs
type StepLR struct {
	*BaseLRScheduler
	StepSize int
	Gamma    float64
}

// NewStepLR creates a new StepLR scheduler
func NewStepLR(optimizer Optimizer, stepSize int, gamma float64) *StepLR {
	if gamma == 0 {
		gamma = 0.1
	}
	return &StepLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		StepSize:        stepSize,
		Gamma:           gamma,
	}
}

// Step performs a scheduler step
func (s *StepLR) Step() float64 {
	s.epoch++
	lr := s.baseLRs[0] * math.Pow(s.Gamma, math.Floor(float64(s.epoch)/float64(s.StepSize)))
	s.setLR(lr)
	return lr
}

// ============ MultiStep LR Scheduler ============

// MultiStepLR decays the learning rate at specific milestones
type MultiStepLR struct {
	*BaseLRScheduler
	Milestones []int
	Gamma      float64
}

// NewMultiStepLR creates a new MultiStepLR scheduler
func NewMultiStepLR(optimizer Optimizer, milestones []int, gamma float64) *MultiStepLR {
	if gamma == 0 {
		gamma = 0.1
	}
	return &MultiStepLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		Milestones:      milestones,
		Gamma:           gamma,
	}
}

// Step performs a scheduler step
func (s *MultiStepLR) Step() float64 {
	s.epoch++

	numDecays := 0
	for _, m := range s.Milestones {
		if s.epoch >= m {
			numDecays++
		}
	}

	lr := s.baseLRs[0] * math.Pow(s.Gamma, float64(numDecays))
	s.setLR(lr)
	return lr
}

// ============ Exponential LR Scheduler ============

// ExponentialLR decays the learning rate exponentially
type ExponentialLR struct {
	*BaseLRScheduler
	Gamma float64
}

// NewExponentialLR creates a new ExponentialLR scheduler
func NewExponentialLR(optimizer Optimizer, gamma float64) *ExponentialLR {
	return &ExponentialLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		Gamma:           gamma,
	}
}

// Step performs a scheduler step
func (s *ExponentialLR) Step() float64 {
	s.epoch++
	lr := s.baseLRs[0] * math.Pow(s.Gamma, float64(s.epoch))
	s.setLR(lr)
	return lr
}

// ============ Cosine Annealing LR Scheduler ============

// CosineAnnealingLR uses a cosine annealing schedule
type CosineAnnealingLR struct {
	*BaseLRScheduler
	TMax  int
	EtaMin float64
}

// NewCosineAnnealingLR creates a new CosineAnnealingLR scheduler
func NewCosineAnnealingLR(optimizer Optimizer, tMax int, etaMin float64) *CosineAnnealingLR {
	return &CosineAnnealingLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		TMax:            tMax,
		EtaMin:          etaMin,
	}
}

// Step performs a scheduler step
func (s *CosineAnnealingLR) Step() float64 {
	s.epoch++
	progress := float64(s.epoch) / float64(s.TMax)
	lr := s.EtaMin + (s.baseLRs[0]-s.EtaMin)*(1+math.Cos(math.Pi*progress))/2
	s.setLR(lr)
	return lr
}

// ============ Cosine Annealing Warm Restarts ============

// CosineAnnealingWarmRestarts uses cosine annealing with warm restarts
type CosineAnnealingWarmRestarts struct {
	*BaseLRScheduler
	T0     int
	TMult  int
	EtaMin float64

	Ti     int
	Tcur   int
}

// NewCosineAnnealingWarmRestarts creates a new scheduler
func NewCosineAnnealingWarmRestarts(optimizer Optimizer, t0, tMult int, etaMin float64) *CosineAnnealingWarmRestarts {
	if tMult == 0 {
		tMult = 1
	}
	return &CosineAnnealingWarmRestarts{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		T0:              t0,
		TMult:           tMult,
		EtaMin:          etaMin,
		Ti:              t0,
		Tcur:            0,
	}
}

// Step performs a scheduler step
func (s *CosineAnnealingWarmRestarts) Step() float64 {
	s.Tcur++
	if s.Tcur >= s.Ti {
		s.Tcur = 0
		s.Ti *= s.TMult
	}

	progress := float64(s.Tcur) / float64(s.Ti)
	lr := s.EtaMin + (s.baseLRs[0]-s.EtaMin)*(1+math.Cos(math.Pi*progress))/2
	s.setLR(lr)
	return lr
}

// ============ Linear Warmup LR Scheduler ============

// LinearWarmup linearly increases LR during warmup
type LinearWarmup struct {
	*BaseLRScheduler
	WarmupSteps int
	StartFactor float64
	EndFactor   float64
}

// NewLinearWarmup creates a new LinearWarmup scheduler
func NewLinearWarmup(optimizer Optimizer, warmupSteps int, startFactor, endFactor float64) *LinearWarmup {
	if startFactor == 0 {
		startFactor = 1.0 / 3.0
	}
	if endFactor == 0 {
		endFactor = 1.0
	}
	return &LinearWarmup{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		WarmupSteps:     warmupSteps,
		StartFactor:     startFactor,
		EndFactor:       endFactor,
	}
}

// Step performs a scheduler step
func (s *LinearWarmup) Step() float64 {
	s.epoch++
	var lr float64

	if s.epoch <= s.WarmupSteps {
		progress := float64(s.epoch) / float64(s.WarmupSteps)
		factor := s.StartFactor + (s.EndFactor-s.StartFactor)*progress
		lr = s.baseLRs[0] * factor
	} else {
		lr = s.baseLRs[0] * s.EndFactor
	}

	s.setLR(lr)
	return lr
}

// ============ OneCycle LR Scheduler ============

// OneCycleLR implements the 1cycle learning rate policy
type OneCycleLR struct {
	*BaseLRScheduler
	MaxLR           float64
	TotalSteps      int
	PctStart        float64
	AnnealStrategy  string
	DivFactor       float64
	FinalDivFactor  float64

	initialLR float64
	finalLR   float64
}

// NewOneCycleLR creates a new OneCycleLR scheduler
func NewOneCycleLR(optimizer Optimizer, maxLR float64, totalSteps int, pctStart float64, annealStrategy string, divFactor, finalDivFactor float64) *OneCycleLR {
	if pctStart == 0 {
		pctStart = 0.3
	}
	if annealStrategy == "" {
		annealStrategy = "cos"
	}
	if divFactor == 0 {
		divFactor = 25.0
	}
	if finalDivFactor == 0 {
		finalDivFactor = 10000.0
	}

	initialLR := maxLR / divFactor
	finalLR := maxLR / finalDivFactor

	return &OneCycleLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		MaxLR:           maxLR,
		TotalSteps:      totalSteps,
		PctStart:        pctStart,
		AnnealStrategy:  annealStrategy,
		DivFactor:       divFactor,
		FinalDivFactor:  finalDivFactor,
		initialLR:       initialLR,
		finalLR:         finalLR,
	}
}

// Step performs a scheduler step
func (s *OneCycleLR) Step() float64 {
	s.epoch++

	warmupSteps := int(float64(s.TotalSteps) * s.PctStart)
	annealSteps := s.TotalSteps - warmupSteps

	var lr float64

	if s.epoch <= warmupSteps {
		// Warmup phase
		progress := float64(s.epoch) / float64(warmupSteps)
		lr = s.initialLR + (s.MaxLR-s.initialLR)*progress
	} else {
		// Annealing phase
		progress := float64(s.epoch-warmupSteps) / float64(annealSteps)

		switch s.AnnealStrategy {
		case "cos":
			lr = s.finalLR + (s.MaxLR-s.finalLR)*(1+math.Cos(math.Pi*progress))/2
		case "linear":
			lr = s.MaxLR + (s.finalLR-s.MaxLR)*progress
		default:
			lr = s.finalLR + (s.MaxLR-s.finalLR)*(1+math.Cos(math.Pi*progress))/2
		}
	}

	s.setLR(lr)
	return lr
}

// ============ Polynomial LR Scheduler ============

// PolynomialLR decays the learning rate using a polynomial function
type PolynomialLR struct {
	*BaseLRScheduler
	TotalIters int
	Power      float64
	EndLR      float64
}

// NewPolynomialLR creates a new PolynomialLR scheduler
func NewPolynomialLR(optimizer Optimizer, totalIters int, power, endLR float64) *PolynomialLR {
	if power == 0 {
		power = 1.0
	}
	return &PolynomialLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		TotalIters:      totalIters,
		Power:           power,
		EndLR:           endLR,
	}
}

// Step performs a scheduler step
func (s *PolynomialLR) Step() float64 {
	s.epoch++

	if s.epoch > s.TotalIters {
		s.setLR(s.EndLR)
		return s.EndLR
	}

	decay := math.Pow(1-float64(s.epoch)/float64(s.TotalIters), s.Power)
	lr := (s.baseLRs[0]-s.EndLR)*decay + s.EndLR
	s.setLR(lr)
	return lr
}

// ============ Reduce On Plateau ============

// ReduceLROnPlateau reduces LR when a metric has stopped improving
type ReduceLROnPlateau struct {
	*BaseLRScheduler
	Mode       string
	Factor     float64
	Patience   int
	Threshold  float64
	ThresholdMode string
	Cooldown   int
	MinLR      float64
	Eps        float64

	best       float64
	badEpochs  int
	cooldownCounter int
	numBadEpochs int
}

// NewReduceLROnPlateau creates a new ReduceLROnPlateau scheduler
func NewReduceLROnPlateau(optimizer Optimizer, mode string, factor float64, patience int, threshold float64, thresholdMode string, cooldown int, minLR, eps float64) *ReduceLROnPlateau {
	if mode == "" {
		mode = "min"
	}
	if factor == 0 {
		factor = 0.1
	}
	if patience == 0 {
		patience = 10
	}
	if threshold == 0 {
		threshold = 1e-4
	}
	if thresholdMode == "" {
		thresholdMode = "rel"
	}
	if eps == 0 {
		eps = 1e-8
	}

	var best float64
	if mode == "min" {
		best = math.Inf(1)
	} else {
		best = math.Inf(-1)
	}

	return &ReduceLROnPlateau{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		Mode:            mode,
		Factor:          factor,
		Patience:        patience,
		Threshold:       threshold,
		ThresholdMode:   thresholdMode,
		Cooldown:        cooldown,
		MinLR:           minLR,
		Eps:             eps,
		best:            best,
		badEpochs:       0,
		cooldownCounter: 0,
	}
}

// Step performs a scheduler step with the given metric
func (s *ReduceLROnPlateau) Step() float64 {
	return s.GetLR()
}

// StepWithMetric performs a scheduler step based on a metric
func (s *ReduceLROnPlateau) StepWithMetric(metric float64) float64 {
	s.epoch++

	if s.cooldownCounter > 0 {
		s.cooldownCounter--
		s.badEpochs = 0
	}

	improved := false
	if s.Mode == "min" {
		if s.ThresholdMode == "rel" {
			improved = metric < s.best*(1-s.Threshold)
		} else {
			improved = metric < s.best-s.Threshold
		}
	} else {
		if s.ThresholdMode == "rel" {
			improved = metric > s.best*(1+s.Threshold)
		} else {
			improved = metric > s.best+s.Threshold
		}
	}

	if improved {
		s.best = metric
		s.badEpochs = 0
	} else {
		s.badEpochs++
	}

	if s.badEpochs > s.Patience {
		currentLR := s.GetLR()
		newLR := math.Max(currentLR*s.Factor, s.MinLR)

		if currentLR-newLR > s.Eps {
			s.setLR(newLR)
		}

		s.cooldownCounter = s.Cooldown
		s.badEpochs = 0
	}

	return s.GetLR()
}

// ============ Chained LR Scheduler ============

// ChainedScheduler chains multiple schedulers
type ChainedScheduler struct {
	schedulers []LRScheduler
}

// NewChainedScheduler creates a new chained scheduler
func NewChainedScheduler(schedulers ...LRScheduler) *ChainedScheduler {
	return &ChainedScheduler{
		schedulers: schedulers,
	}
}

// Step performs a step on all schedulers
func (s *ChainedScheduler) Step() float64 {
	var lr float64
	for _, scheduler := range s.schedulers {
		lr = scheduler.Step()
	}
	return lr
}

// GetLR returns the current learning rate
func (s *ChainedScheduler) GetLR() float64 {
	if len(s.schedulers) > 0 {
		return s.schedulers[len(s.schedulers)-1].GetLR()
	}
	return 0
}

// GetLastLR returns the last computed learning rate
func (s *ChainedScheduler) GetLastLR() float64 {
	if len(s.schedulers) > 0 {
		return s.schedulers[len(s.schedulers)-1].GetLastLR()
	}
	return 0
}

// State returns the scheduler state
func (s *ChainedScheduler) State() map[string]interface{} {
	states := make([]map[string]interface{}, len(s.schedulers))
	for i, scheduler := range s.schedulers {
		states[i] = scheduler.State()
	}
	return map[string]interface{}{
		"schedulers": states,
	}
}

// LoadState loads scheduler state
func (s *ChainedScheduler) LoadState(state map[string]interface{}) error {
	if states, ok := state["schedulers"].([]map[string]interface{}); ok {
		for i, scheduler := range s.schedulers {
			if i < len(states) {
				scheduler.LoadState(states[i])
			}
		}
	}
	return nil
}

// ============ Lambda LR Scheduler ============

// LambdaLR sets LR using a lambda function
type LambdaLR struct {
	*BaseLRScheduler
	LRLambda func(epoch int) float64
}

// NewLambdaLR creates a new LambdaLR scheduler
func NewLambdaLR(optimizer Optimizer, lrLambda func(epoch int) float64) *LambdaLR {
	return &LambdaLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		LRLambda:        lrLambda,
	}
}

// Step performs a scheduler step
func (s *LambdaLR) Step() float64 {
	s.epoch++
	factor := s.LRLambda(s.epoch)
	lr := s.baseLRs[0] * factor
	s.setLR(lr)
	return lr
}

// ============ Cyclical LR Scheduler ============

// CyclicLR implements cyclical learning rate
type CyclicLR struct {
	*BaseLRScheduler
	BaseLR      float64
	MaxLR       float64
	StepSizeUp  int
	StepSizeDown int
	Mode        string
	Gamma       float64
	ScaleMode   string

	cycle      int
	stepInCycle int
}

// NewCyclicLR creates a new CyclicLR scheduler
func NewCyclicLR(optimizer Optimizer, baseLR, maxLR float64, stepSizeUp, stepSizeDown int, mode string, gamma float64) *CyclicLR {
	if stepSizeDown == 0 {
		stepSizeDown = stepSizeUp
	}
	if mode == "" {
		mode = "triangular"
	}
	if gamma == 0 {
		gamma = 1.0
	}

	return &CyclicLR{
		BaseLRScheduler: NewBaseLRScheduler(optimizer),
		BaseLR:          baseLR,
		MaxLR:           maxLR,
		StepSizeUp:      stepSizeUp,
		StepSizeDown:    stepSizeDown,
		Mode:            mode,
		Gamma:           gamma,
		cycle:           0,
		stepInCycle:     0,
	}
}

// Step performs a scheduler step
func (s *CyclicLR) Step() float64 {
	s.epoch++
	s.stepInCycle++

	cycleLen := s.StepSizeUp + s.StepSizeDown
	if s.stepInCycle > cycleLen {
		s.stepInCycle = 1
		s.cycle++
	}

	var lr float64
	if s.stepInCycle <= s.StepSizeUp {
		// Ascending
		progress := float64(s.stepInCycle) / float64(s.StepSizeUp)
		lr = s.BaseLR + (s.MaxLR-s.BaseLR)*progress
	} else {
		// Descending
		progress := float64(s.stepInCycle-s.StepSizeUp) / float64(s.StepSizeDown)
		lr = s.MaxLR - (s.MaxLR-s.BaseLR)*progress
	}

	// Apply mode
	switch s.Mode {
	case "triangular2":
		lr = s.BaseLR + (lr-s.BaseLR)/math.Pow(2, float64(s.cycle))
	case "exp_range":
		lr = s.BaseLR + (lr-s.BaseLR)*math.Pow(s.Gamma, float64(s.epoch))
	}

	s.setLR(lr)
	return lr
}
