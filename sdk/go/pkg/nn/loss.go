package nn

import (
	"fmt"
	"math"

	"github.com/aethelred/sdk-go/pkg/runtime"
	"github.com/aethelred/sdk-go/pkg/tensor"
)

// ============ Loss Reduction ============

// Reduction specifies how to reduce loss
type Reduction int

const (
	ReductionNone Reduction = iota
	ReductionMean
	ReductionSum
)

// ============ Loss Functions ============

// MSELoss computes mean squared error loss
type MSELoss struct {
	*BaseModule
	Reduction Reduction
}

// NewMSELoss creates a new MSELoss
func NewMSELoss(reduction Reduction) *MSELoss {
	return &MSELoss{
		BaseModule: NewBaseModule("MSELoss"),
		Reduction:  reduction,
	}
}

// Forward computes MSE loss
func (l *MSELoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("MSELoss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes MSE loss with target
func (l *MSELoss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	diff := input.Sub(target)
	sqDiff := diff.Mul(diff)
	sqDiff.Realize()

	switch l.Reduction {
	case ReductionNone:
		return sqDiff, nil
	case ReductionMean:
		return sqDiff.Mean()
	case ReductionSum:
		return sqDiff.Sum()
	default:
		return sqDiff.Mean()
	}
}

// L1Loss computes L1 (mean absolute error) loss
type L1Loss struct {
	*BaseModule
	Reduction Reduction
}

// NewL1Loss creates a new L1Loss
func NewL1Loss(reduction Reduction) *L1Loss {
	return &L1Loss{
		BaseModule: NewBaseModule("L1Loss"),
		Reduction:  reduction,
	}
}

// Forward computes L1 loss
func (l *L1Loss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("L1Loss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes L1 loss with target
func (l *L1Loss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	diff := input.Sub(target)
	absDiff := diff.Abs()
	absDiff.Realize()

	switch l.Reduction {
	case ReductionNone:
		return absDiff, nil
	case ReductionMean:
		return absDiff.Mean()
	case ReductionSum:
		return absDiff.Sum()
	default:
		return absDiff.Mean()
	}
}

// SmoothL1Loss computes smooth L1 loss (Huber loss)
type SmoothL1Loss struct {
	*BaseModule
	Reduction Reduction
	Beta      float64
}

// NewSmoothL1Loss creates a new SmoothL1Loss
func NewSmoothL1Loss(reduction Reduction, beta float64) *SmoothL1Loss {
	if beta == 0 {
		beta = 1.0
	}
	return &SmoothL1Loss{
		BaseModule: NewBaseModule("SmoothL1Loss"),
		Reduction:  reduction,
		Beta:       beta,
	}
}

// Forward computes smooth L1 loss
func (l *SmoothL1Loss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("SmoothL1Loss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes smooth L1 loss with target
func (l *SmoothL1Loss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	output, err := tensor.NewTensor(input.Shape, input.DType, input.Device)
	if err != nil {
		return nil, err
	}

	inData := input.Float32Data()
	tgtData := target.Float32Data()
	outData := output.Float32Data()

	beta := float32(l.Beta)
	halfBeta := beta / 2

	for i := range outData {
		diff := inData[i] - tgtData[i]
		if diff < 0 {
			diff = -diff
		}

		if diff < beta {
			outData[i] = 0.5 * diff * diff / beta
		} else {
			outData[i] = diff - halfBeta
		}
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// CrossEntropyLoss computes cross-entropy loss
type CrossEntropyLoss struct {
	*BaseModule
	Reduction    Reduction
	LabelSmooth  float64
	IgnoreIndex  int
	Weight       *tensor.Tensor
}

// NewCrossEntropyLoss creates a new CrossEntropyLoss
func NewCrossEntropyLoss(reduction Reduction, labelSmoothing float64, ignoreIndex int, weight *tensor.Tensor) *CrossEntropyLoss {
	return &CrossEntropyLoss{
		BaseModule:  NewBaseModule("CrossEntropyLoss"),
		Reduction:   reduction,
		LabelSmooth: labelSmoothing,
		IgnoreIndex: ignoreIndex,
		Weight:      weight,
	}
}

// Forward computes cross-entropy loss
func (l *CrossEntropyLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("CrossEntropyLoss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes cross-entropy loss with target
func (l *CrossEntropyLoss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	// input: (batch, classes) or (batch, classes, ...)
	// target: (batch,) or (batch, ...)

	// Apply log softmax
	logProbs, err := tensor.LogSoftmax(input, -1)
	if err != nil {
		return nil, err
	}
	logProbs.Realize()

	logProbsData := logProbs.Float32Data()
	targetData := target.Int32Data()

	numClasses := input.Shape[len(input.Shape)-1]
	batchSize := len(targetData)

	// Compute NLL loss
	losses := make([]float32, batchSize)
	for i := 0; i < batchSize; i++ {
		classIdx := int(targetData[i])
		if classIdx == l.IgnoreIndex {
			losses[i] = 0
		} else if l.LabelSmooth > 0 {
			// Label smoothing
			smooth := float32(l.LabelSmooth / float64(numClasses))
			hard := float32(1 - l.LabelSmooth)
			var loss float32
			for c := 0; c < numClasses; c++ {
				if c == classIdx {
					loss -= (hard + smooth) * logProbsData[i*numClasses+c]
				} else {
					loss -= smooth * logProbsData[i*numClasses+c]
				}
			}
			losses[i] = loss
		} else {
			losses[i] = -logProbsData[i*numClasses+classIdx]
		}
	}

	output, err := tensor.FromSlice(losses, []int{batchSize}, input.Device)
	if err != nil {
		return nil, err
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// NLLLoss computes negative log likelihood loss
type NLLLoss struct {
	*BaseModule
	Reduction   Reduction
	IgnoreIndex int
	Weight      *tensor.Tensor
}

// NewNLLLoss creates a new NLLLoss
func NewNLLLoss(reduction Reduction, ignoreIndex int, weight *tensor.Tensor) *NLLLoss {
	return &NLLLoss{
		BaseModule:  NewBaseModule("NLLLoss"),
		Reduction:   reduction,
		IgnoreIndex: ignoreIndex,
		Weight:      weight,
	}
}

// Forward computes NLL loss
func (l *NLLLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("NLLLoss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes NLL loss with target
func (l *NLLLoss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	inputData := input.Float32Data()
	targetData := target.Int32Data()

	numClasses := input.Shape[len(input.Shape)-1]
	batchSize := len(targetData)

	losses := make([]float32, batchSize)
	for i := 0; i < batchSize; i++ {
		classIdx := int(targetData[i])
		if classIdx == l.IgnoreIndex {
			losses[i] = 0
		} else {
			losses[i] = -inputData[i*numClasses+classIdx]
		}
	}

	output, err := tensor.FromSlice(losses, []int{batchSize}, input.Device)
	if err != nil {
		return nil, err
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// BCELoss computes binary cross-entropy loss
type BCELoss struct {
	*BaseModule
	Reduction Reduction
	Weight    *tensor.Tensor
}

// NewBCELoss creates a new BCELoss
func NewBCELoss(reduction Reduction, weight *tensor.Tensor) *BCELoss {
	return &BCELoss{
		BaseModule: NewBaseModule("BCELoss"),
		Reduction:  reduction,
		Weight:     weight,
	}
}

// Forward computes BCE loss
func (l *BCELoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("BCELoss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes BCE loss with target
func (l *BCELoss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	output, err := tensor.NewTensor(input.Shape, input.DType, input.Device)
	if err != nil {
		return nil, err
	}

	inData := input.Float32Data()
	tgtData := target.Float32Data()
	outData := output.Float32Data()

	for i := range outData {
		p := float64(inData[i])
		t := float64(tgtData[i])

		// Clamp for numerical stability
		eps := 1e-7
		p = math.Max(eps, math.Min(1-eps, p))

		outData[i] = -float32(t*math.Log(p) + (1-t)*math.Log(1-p))
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// BCEWithLogitsLoss computes BCE with logits (more numerically stable)
type BCEWithLogitsLoss struct {
	*BaseModule
	Reduction Reduction
	PosWeight *tensor.Tensor
	Weight    *tensor.Tensor
}

// NewBCEWithLogitsLoss creates a new BCEWithLogitsLoss
func NewBCEWithLogitsLoss(reduction Reduction, posWeight, weight *tensor.Tensor) *BCEWithLogitsLoss {
	return &BCEWithLogitsLoss{
		BaseModule: NewBaseModule("BCEWithLogitsLoss"),
		Reduction:  reduction,
		PosWeight:  posWeight,
		Weight:     weight,
	}
}

// Forward computes BCE with logits loss
func (l *BCEWithLogitsLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("BCEWithLogitsLoss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes BCE with logits loss with target
func (l *BCEWithLogitsLoss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	output, err := tensor.NewTensor(input.Shape, input.DType, input.Device)
	if err != nil {
		return nil, err
	}

	inData := input.Float32Data()
	tgtData := target.Float32Data()
	outData := output.Float32Data()

	for i := range outData {
		x := float64(inData[i])
		t := float64(tgtData[i])

		// max(x, 0) - x * t + log(1 + exp(-|x|))
		maxX := math.Max(x, 0)
		absX := math.Abs(x)
		outData[i] = float32(maxX - x*t + math.Log(1+math.Exp(-absX)))
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// FocalLoss computes focal loss for class imbalance
type FocalLoss struct {
	*BaseModule
	Reduction Reduction
	Alpha     float64
	Gamma     float64
}

// NewFocalLoss creates a new FocalLoss
func NewFocalLoss(reduction Reduction, alpha, gamma float64) *FocalLoss {
	if gamma == 0 {
		gamma = 2.0
	}
	if alpha == 0 {
		alpha = 0.25
	}
	return &FocalLoss{
		BaseModule: NewBaseModule("FocalLoss"),
		Reduction:  reduction,
		Alpha:      alpha,
		Gamma:      gamma,
	}
}

// Forward computes focal loss
func (l *FocalLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("FocalLoss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes focal loss with target
func (l *FocalLoss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	// Apply softmax
	probs, err := tensor.Softmax(input, -1)
	if err != nil {
		return nil, err
	}
	probs.Realize()

	probsData := probs.Float32Data()
	targetData := target.Int32Data()

	numClasses := input.Shape[len(input.Shape)-1]
	batchSize := len(targetData)

	losses := make([]float32, batchSize)
	for i := 0; i < batchSize; i++ {
		classIdx := int(targetData[i])
		pt := float64(probsData[i*numClasses+classIdx])

		// Focal loss: -alpha * (1-pt)^gamma * log(pt)
		loss := -l.Alpha * math.Pow(1-pt, l.Gamma) * math.Log(math.Max(pt, 1e-7))
		losses[i] = float32(loss)
	}

	output, err := tensor.FromSlice(losses, []int{batchSize}, input.Device)
	if err != nil {
		return nil, err
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// KLDivLoss computes KL divergence loss
type KLDivLoss struct {
	*BaseModule
	Reduction  Reduction
	LogTarget  bool
}

// NewKLDivLoss creates a new KLDivLoss
func NewKLDivLoss(reduction Reduction, logTarget bool) *KLDivLoss {
	return &KLDivLoss{
		BaseModule: NewBaseModule("KLDivLoss"),
		Reduction:  reduction,
		LogTarget:  logTarget,
	}
}

// Forward computes KL divergence loss
func (l *KLDivLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("KLDivLoss.Forward requires target, use ForwardWithTarget")
}

// ForwardWithTarget computes KL divergence loss with target
func (l *KLDivLoss) ForwardWithTarget(input, target *tensor.Tensor) (*tensor.Tensor, error) {
	input.Realize()
	target.Realize()

	output, err := tensor.NewTensor(input.Shape, input.DType, input.Device)
	if err != nil {
		return nil, err
	}

	inData := input.Float32Data()
	tgtData := target.Float32Data()
	outData := output.Float32Data()

	for i := range outData {
		var t float64
		if l.LogTarget {
			t = math.Exp(float64(tgtData[i]))
		} else {
			t = float64(tgtData[i])
		}

		if t > 0 {
			// KL = target * (log(target) - input)
			logT := math.Log(t)
			outData[i] = float32(t * (logT - float64(inData[i])))
		} else {
			outData[i] = 0
		}
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// TripletMarginLoss computes triplet margin loss
type TripletMarginLoss struct {
	*BaseModule
	Reduction Reduction
	Margin    float64
	P         float64 // Norm degree
	Swap      bool
}

// NewTripletMarginLoss creates a new TripletMarginLoss
func NewTripletMarginLoss(reduction Reduction, margin, p float64, swap bool) *TripletMarginLoss {
	if margin == 0 {
		margin = 1.0
	}
	if p == 0 {
		p = 2.0
	}
	return &TripletMarginLoss{
		BaseModule: NewBaseModule("TripletMarginLoss"),
		Reduction:  reduction,
		Margin:     margin,
		P:          p,
		Swap:       swap,
	}
}

// Forward computes triplet margin loss
func (l *TripletMarginLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("TripletMarginLoss.Forward requires anchor, positive, negative")
}

// ForwardTriplet computes triplet margin loss with anchor, positive, negative
func (l *TripletMarginLoss) ForwardTriplet(anchor, positive, negative *tensor.Tensor) (*tensor.Tensor, error) {
	anchor.Realize()
	positive.Realize()
	negative.Realize()

	// d(a, p) - d(a, n) + margin
	distPos := pairwiseDistance(anchor, positive, l.P)
	distNeg := pairwiseDistance(anchor, negative, l.P)

	if l.Swap {
		// Swap if d(p, n) < d(a, n)
		distPN := pairwiseDistance(positive, negative, l.P)
		distNegData := distNeg.Float32Data()
		distPNData := distPN.Float32Data()
		for i := range distNegData {
			if distPNData[i] < distNegData[i] {
				distNegData[i] = distPNData[i]
			}
		}
	}

	// loss = max(d_pos - d_neg + margin, 0)
	marginT, _ := tensor.Full([]int{1}, l.Margin, tensor.Float32, anchor.Device)
	loss := distPos.Sub(distNeg).Add(marginT)
	loss.Realize()

	// ReLU (clamp to 0)
	lossData := loss.Float32Data()
	for i, v := range lossData {
		if v < 0 {
			lossData[i] = 0
		}
	}

	switch l.Reduction {
	case ReductionNone:
		return loss, nil
	case ReductionMean:
		return loss.Mean()
	case ReductionSum:
		return loss.Sum()
	default:
		return loss.Mean()
	}
}

// pairwiseDistance computes pairwise distance
func pairwiseDistance(a, b *tensor.Tensor, p float64) *tensor.Tensor {
	diff := a.Sub(b)
	diff.Realize()

	diffData := diff.Float32Data()
	batchSize := a.Shape[0]
	dim := a.Numel() / batchSize

	distances := make([]float32, batchSize)
	for i := 0; i < batchSize; i++ {
		var sum float64
		for j := 0; j < dim; j++ {
			val := math.Abs(float64(diffData[i*dim+j]))
			sum += math.Pow(val, p)
		}
		distances[i] = float32(math.Pow(sum, 1.0/p))
	}

	result, _ := tensor.FromSlice(distances, []int{batchSize}, a.Device)
	return result
}

// CosineEmbeddingLoss computes cosine embedding loss
type CosineEmbeddingLoss struct {
	*BaseModule
	Reduction Reduction
	Margin    float64
}

// NewCosineEmbeddingLoss creates a new CosineEmbeddingLoss
func NewCosineEmbeddingLoss(reduction Reduction, margin float64) *CosineEmbeddingLoss {
	return &CosineEmbeddingLoss{
		BaseModule: NewBaseModule("CosineEmbeddingLoss"),
		Reduction:  reduction,
		Margin:     margin,
	}
}

// Forward computes cosine embedding loss
func (l *CosineEmbeddingLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("CosineEmbeddingLoss.Forward requires x1, x2, y")
}

// ForwardWithInputs computes cosine embedding loss with x1, x2, y
func (l *CosineEmbeddingLoss) ForwardWithInputs(x1, x2 *tensor.Tensor, y *tensor.Tensor) (*tensor.Tensor, error) {
	x1.Realize()
	x2.Realize()
	y.Realize()

	// Compute cosine similarity
	cos := cosineSimilarity(x1, x2)
	cos.Realize()

	cosData := cos.Float32Data()
	yData := y.Float32Data()
	batchSize := len(yData)

	losses := make([]float32, batchSize)
	for i := 0; i < batchSize; i++ {
		if yData[i] == 1 {
			// Similar: loss = 1 - cos
			losses[i] = 1 - cosData[i]
		} else {
			// Dissimilar: loss = max(0, cos - margin)
			loss := cosData[i] - float32(l.Margin)
			if loss < 0 {
				loss = 0
			}
			losses[i] = loss
		}
	}

	output, err := tensor.FromSlice(losses, []int{batchSize}, x1.Device)
	if err != nil {
		return nil, err
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}

// cosineSimilarity computes cosine similarity
func cosineSimilarity(x1, x2 *tensor.Tensor) *tensor.Tensor {
	x1.Realize()
	x2.Realize()

	x1Data := x1.Float32Data()
	x2Data := x2.Float32Data()

	batchSize := x1.Shape[0]
	dim := x1.Numel() / batchSize

	similarities := make([]float32, batchSize)
	for i := 0; i < batchSize; i++ {
		var dot, norm1, norm2 float64
		for j := 0; j < dim; j++ {
			v1 := float64(x1Data[i*dim+j])
			v2 := float64(x2Data[i*dim+j])
			dot += v1 * v2
			norm1 += v1 * v1
			norm2 += v2 * v2
		}
		similarities[i] = float32(dot / (math.Sqrt(norm1) * math.Sqrt(norm2) + 1e-8))
	}

	result, _ := tensor.FromSlice(similarities, []int{batchSize}, runtime.CPU())
	return result
}

// ContrastiveLoss computes contrastive loss for siamese networks
type ContrastiveLoss struct {
	*BaseModule
	Reduction Reduction
	Margin    float64
}

// NewContrastiveLoss creates a new ContrastiveLoss
func NewContrastiveLoss(reduction Reduction, margin float64) *ContrastiveLoss {
	if margin == 0 {
		margin = 1.0
	}
	return &ContrastiveLoss{
		BaseModule: NewBaseModule("ContrastiveLoss"),
		Reduction:  reduction,
		Margin:     margin,
	}
}

// Forward computes contrastive loss
func (l *ContrastiveLoss) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	return nil, fmt.Errorf("ContrastiveLoss.Forward requires x1, x2, y")
}

// ForwardWithInputs computes contrastive loss with x1, x2, y
func (l *ContrastiveLoss) ForwardWithInputs(x1, x2, y *tensor.Tensor) (*tensor.Tensor, error) {
	// Euclidean distance
	dist := pairwiseDistance(x1, x2, 2.0)
	dist.Realize()

	distData := dist.Float32Data()
	yData := y.Float32Data()
	batchSize := len(yData)

	losses := make([]float32, batchSize)
	for i := 0; i < batchSize; i++ {
		d := float64(distData[i])
		if yData[i] == 1 {
			// Similar: loss = d^2
			losses[i] = float32(d * d)
		} else {
			// Dissimilar: loss = max(0, margin - d)^2
			diff := l.Margin - d
			if diff < 0 {
				diff = 0
			}
			losses[i] = float32(diff * diff)
		}
	}

	output, err := tensor.FromSlice(losses, []int{batchSize}, x1.Device)
	if err != nil {
		return nil, err
	}

	switch l.Reduction {
	case ReductionNone:
		return output, nil
	case ReductionMean:
		return output.Mean()
	case ReductionSum:
		return output.Sum()
	default:
		return output.Mean()
	}
}
