package nn

import (
	"fmt"
	"testing"

	"github.com/aethelred/sdk-go/pkg/runtime"
	"github.com/aethelred/sdk-go/pkg/tensor"
	"github.com/stretchr/testify/require"
)

type addConstModule struct {
	*BaseModule
	delta float32
}

func newAddConstModule(delta float32) *addConstModule {
	return &addConstModule{
		BaseModule: NewBaseModule(fmt.Sprintf("AddConst(%v)", delta)),
		delta:      delta,
	}
}

func (m *addConstModule) Forward(input *tensor.Tensor) (*tensor.Tensor, error) {
	addend, err := tensor.NewTensor(input.Shape, input.DType, input.Device)
	if err != nil {
		return nil, err
	}
	addend.Fill(float64(m.delta))
	return input.Add(addend).Realize(), nil
}

func TestLinearParameters_RespectFreezeUnfreeze(t *testing.T) {
	t.Parallel()

	layer, err := NewLinear(4, 3, true)
	require.NoError(t, err)

	require.Len(t, layer.Parameters(), 2)

	layer.Weight.Freeze()
	require.Len(t, layer.Parameters(), 1)

	layer.Weight.Unfreeze()
	require.Len(t, layer.Parameters(), 2)
}

func TestMSELossForwardWithTarget(t *testing.T) {
	t.Parallel()

	input, err := tensor.FromSlice([]float32{1, 2}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	target, err := tensor.FromSlice([]float32{1, 4}, []int{2}, runtime.CPU())
	require.NoError(t, err)

	loss := NewMSELoss(ReductionMean)
	meanOut, err := loss.ForwardWithTarget(input, target)
	require.NoError(t, err)
	require.InDelta(t, 2.0, meanOut.Float32Data()[0], 1e-6)

	lossNone := NewMSELoss(ReductionNone)
	vecOut, err := lossNone.ForwardWithTarget(input, target)
	require.NoError(t, err)
	require.Equal(t, []float32{0, 4}, vecOut.Float32Data())
}

func TestModuleContainers_BasicIndexing(t *testing.T) {
	t.Parallel()

	l1, err := NewLinear(2, 2, false)
	require.NoError(t, err)
	l2, err := NewLinear(2, 2, false)
	require.NoError(t, err)

	ml := NewModuleList(l1)
	ml.Append(l2)
	require.Equal(t, 2, ml.Len())
	require.NotNil(t, ml.Get(0))
	require.NotNil(t, ml.Get(-1))
	require.Nil(t, ml.Get(100))

	md := NewModuleDict(map[string]Module{"first": l1})
	md.Set("second", l2)
	require.Equal(t, 2, md.Len())
	_, ok := md.Get("second")
	require.True(t, ok)
	md.Delete("first")
	require.Equal(t, 1, md.Len())
}

func TestBaseModule_TrainEvalPropagatesToChildren(t *testing.T) {
	t.Parallel()

	parent := NewBaseModule("parent")
	child := newAddConstModule(1)
	parent.RegisterChild("child", child)

	parent.Eval()
	require.False(t, parent.IsTraining())
	require.False(t, child.IsTraining())

	parent.Train(true)
	require.True(t, parent.IsTraining())
	require.True(t, child.IsTraining())
}

func TestBaseModule_NamedParametersPrefixesChildNames(t *testing.T) {
	t.Parallel()

	parent := NewBaseModule("root")
	child, err := NewLinear(2, 2, true)
	require.NoError(t, err)
	parent.RegisterChild("layer", child)

	named := parent.NamedParameters()
	require.Contains(t, named, "layer.layer.weight")
	require.Contains(t, named, "layer.layer.bias")
}

func TestBaseModule_ApplyHooks_ModifiesInputAndOutput(t *testing.T) {
	t.Parallel()

	mod := NewBaseModule("hooks")
	mod.RegisterForwardPreHook(func(module Module, input *tensor.Tensor) (*tensor.Tensor, error) {
		add, _ := tensor.FromSlice([]float32{1, 1}, []int{2}, runtime.CPU())
		return input.Add(add).Realize(), nil
	})
	mod.RegisterForwardHook(func(module Module, input, output *tensor.Tensor) (*tensor.Tensor, error) {
		scale, _ := tensor.FromSlice([]float32{2, 2}, []int{2}, runtime.CPU())
		return output.Mul(scale).Realize(), nil
	})

	in, err := tensor.FromSlice([]float32{1, 2}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	out, err := tensor.FromSlice([]float32{2, 3}, []int{2}, runtime.CPU())
	require.NoError(t, err)

	got, err := mod.ApplyHooks(in, out)
	require.NoError(t, err)
	require.Equal(t, []float32{4, 6}, got.Float32Data())
}

func TestBaseModule_StateDictAndLoadStateDict(t *testing.T) {
	t.Parallel()

	src, err := NewLinear(2, 2, true)
	require.NoError(t, err)
	dst, err := NewLinear(2, 2, true)
	require.NoError(t, err)

	for i := range src.Weight.Float32Data() {
		src.Weight.Float32Data()[i] = float32(i + 1)
	}
	for i := range src.BiasParam.Float32Data() {
		src.BiasParam.Float32Data()[i] = float32(10 + i)
	}

	state := src.StateDict()
	err = dst.LoadStateDict(state, true)
	require.NoError(t, err)
	require.Equal(t, src.Weight.Float32Data(), dst.Weight.Float32Data())
	require.Equal(t, src.BiasParam.Float32Data(), dst.BiasParam.Float32Data())
}

func TestBaseModule_LoadStateDictStrictRejectsUnexpectedKeys(t *testing.T) {
	t.Parallel()

	mod, err := NewLinear(2, 2, false)
	require.NoError(t, err)
	extra, err := tensor.FromSlice([]float32{1}, []int{1}, runtime.CPU())
	require.NoError(t, err)

	err = mod.LoadStateDict(StateDict{"unexpected": extra}, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected key")
}

func TestBaseModule_NumParametersAndSummary(t *testing.T) {
	t.Parallel()

	layer, err := NewLinear(4, 3, true)
	require.NoError(t, err)

	total := layer.NumParameters(false)
	trainable := layer.NumParameters(true)
	require.EqualValues(t, 15, total)    // weight 12 + bias 3
	require.EqualValues(t, 15, trainable)

	layer.Weight.Freeze()
	require.EqualValues(t, 3, layer.NumParameters(true))
	require.Contains(t, layer.Summary(), "Parameters:")
}

func TestFreezeAndUnfreezeModuleHelpers(t *testing.T) {
	t.Parallel()

	layer, err := NewLinear(3, 2, true)
	require.NoError(t, err)

	FreezeModule(layer)
	for _, p := range layer.Parameters() {
		require.True(t, p.Frozen)
	}

	UnfreezeModule(layer)
	for _, p := range layer.Parameters() {
		require.False(t, p.Frozen)
	}
}

func TestClipGradValue_ClampsGradientValues(t *testing.T) {
	t.Parallel()

	tensorParam, err := tensor.FromSlice([]float32{0, 0}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	p := NewParameter(tensorParam, "p")
	grad, err := tensor.FromSlice([]float32{10, -10}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	p.Grad = grad

	ClipGradValue([]*Parameter{p}, 3)
	require.Equal(t, []float32{3, -3}, p.Grad.Float32Data())
}

func TestClipGradNorm_ScalesGradientsWhenAboveThreshold(t *testing.T) {
	t.Parallel()

	tensorParam, err := tensor.FromSlice([]float32{0, 0}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	p := NewParameter(tensorParam, "p")
	grad, err := tensor.FromSlice([]float32{4, 0}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	p.Grad = grad

	totalNormSq := ClipGradNorm([]*Parameter{p}, 1.0, 2.0)
	require.Greater(t, totalNormSq, 1.0)
	require.Less(t, p.Grad.Float32Data()[0], float32(4))
}

func TestL1AndSmoothL1LossForwardWithTarget(t *testing.T) {
	t.Parallel()

	input, err := tensor.FromSlice([]float32{1, 4}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	target, err := tensor.FromSlice([]float32{2, 1}, []int{2}, runtime.CPU())
	require.NoError(t, err)

	l1 := NewL1Loss(ReductionSum)
	l1Out, err := l1.ForwardWithTarget(input, target)
	require.NoError(t, err)
	require.InDelta(t, 4.0, l1Out.Float32Data()[0], 1e-6)

	huber := NewSmoothL1Loss(ReductionMean, 1.0)
	huberOut, err := huber.ForwardWithTarget(input, target)
	require.NoError(t, err)
	require.Greater(t, huberOut.Float32Data()[0], float32(0))
}

func TestEmbeddingForwardAndOutOfRange(t *testing.T) {
	t.Parallel()

	emb, err := NewEmbedding(3, 2, -1)
	require.NoError(t, err)
	weights := emb.Weight.Float32Data()
	copy(weights, []float32{
		1, 2, // idx 0
		3, 4, // idx 1
		5, 6, // idx 2
	})

	idx, err := tensor.NewTensor([]int{2}, tensor.Int32, runtime.CPU())
	require.NoError(t, err)
	copy(idx.Int32Data(), []int32{0, 2})

	out, err := emb.Forward(idx)
	require.NoError(t, err)
	require.Equal(t, []int{2, 2}, out.Shape)
	require.Equal(t, []float32{1, 2, 5, 6}, out.Float32Data())

	copy(idx.Int32Data(), []int32{3, 0})
	_, err = emb.Forward(idx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}

func TestSequentialConditionalAndParallelContainers(t *testing.T) {
	t.Parallel()

	in, err := tensor.FromSlice([]float32{1, 2}, []int{2}, runtime.CPU())
	require.NoError(t, err)

	seq := NewSequential(newAddConstModule(1), newAddConstModule(2))
	out, err := seq.Forward(in)
	require.NoError(t, err)
	require.Equal(t, []float32{4, 5}, out.Float32Data())
	require.Equal(t, 2, seq.Len())

	cond := NewConditionalModule(newAddConstModule(10), newAddConstModule(-10), func(t *tensor.Tensor) bool {
		return t.Float32Data()[0] > 0
	})
	condOut, err := cond.Forward(in)
	require.NoError(t, err)
	require.Equal(t, []float32{11, 12}, condOut.Float32Data())

	par := NewParallel("add", 0, newAddConstModule(1), newAddConstModule(2))
	parOut, err := par.Forward(in)
	require.NoError(t, err)
	require.Equal(t, []float32{5, 7}, parOut.Float32Data()) // (in+1) + (in+2)
}

func TestModuleListAndParameterListEdgeCases(t *testing.T) {
	t.Parallel()

	ml := NewModuleList()
	_, err := ml.Forward(nil)
	require.Error(t, err)

	pl := NewParameterList()
	require.Nil(t, pl.Get(0))
	t0, err := tensor.FromSlice([]float32{1}, []int{1}, runtime.CPU())
	require.NoError(t, err)
	p0 := NewParameter(t0, "p0")
	pl.Append(p0)
	require.Equal(t, 1, pl.Len())
	require.Equal(t, p0, pl.Get(-1))
}

func TestSequentialHelpersAndModuleListExtendIter(t *testing.T) {
	t.Parallel()

	s := NewSequential()
	s.Add(newAddConstModule(1))
	s.Add(newAddConstModule(2))
	require.Equal(t, 2, s.Len())
	require.NotNil(t, s.Get(0))
	require.Nil(t, s.Get(99))

	ml := NewModuleList()
	ml.Extend(newAddConstModule(1), newAddConstModule(2))
	require.Equal(t, 2, ml.Len())
	iter := ml.Iter()
	require.Len(t, iter, 2)
}

func TestModuleDictHelpersAndParameterDictCoverage(t *testing.T) {
	t.Parallel()

	m1 := newAddConstModule(1)
	m2 := newAddConstModule(2)
	md := NewModuleDict(map[string]Module{"a": m1})
	md.Set("b", m2)

	_, err := md.Forward(nil)
	require.Error(t, err)
	require.Equal(t, []string{"a", "b"}, md.Keys())
	require.Len(t, md.Values(), 2)
	items := md.Items()
	require.Len(t, items, 2)
	require.Equal(t, "a", items[0].Name)

	t0, err := tensor.FromSlice([]float32{1}, []int{1}, runtime.CPU())
	require.NoError(t, err)
	p0 := NewParameter(t0, "p0")
	pd := NewParameterDict(map[string]*Parameter{"w": p0})

	_, err = pd.Forward(nil)
	require.Error(t, err)
	gotP, ok := pd.Get("w")
	require.True(t, ok)
	require.Equal(t, p0, gotP)
	require.Equal(t, []string{"w"}, pd.Keys())

	t1, err := tensor.FromSlice([]float32{2}, []int{1}, runtime.CPU())
	require.NoError(t, err)
	p1 := NewParameter(t1, "p1")
	pd.Set("b", p1)
	require.Equal(t, []string{"w", "b"}, pd.Keys())
}

func TestIdentityFlattenUnflattenAndResidual(t *testing.T) {
	t.Parallel()

	data := make([]float32, 24)
	for i := range data {
		data[i] = float32(i)
	}
	in3d, err := tensor.FromSlice(data, []int{2, 3, 4}, runtime.CPU())
	require.NoError(t, err)

	id := NewIdentity()
	idOut, err := id.Forward(in3d)
	require.NoError(t, err)
	require.Equal(t, in3d, idOut)

	flat := NewFlatten(0, 0) // defaults -> flatten dims 1..end
	flatOut, err := flat.Forward(in3d)
	require.NoError(t, err)
	require.Equal(t, []int{2, 12}, flatOut.Shape)

	unflat := NewUnflatten(1, []int{3, 4})
	unflatOut, err := unflat.Forward(flatOut)
	require.NoError(t, err)
	require.Equal(t, []int{2, 3, 4}, unflatOut.Shape)

	vec, err := tensor.FromSlice([]float32{1, 2}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	res := NewResidual(newAddConstModule(1))
	resOut, err := res.Forward(vec)
	require.NoError(t, err)
	require.Equal(t, []float32{3, 5}, resOut.Float32Data()) // (x+1)+x
}

func TestBaseModuleMiscCoverageHelpers(t *testing.T) {
	t.Parallel()

	bm := NewBaseModule("misc")
	require.Equal(t, "misc", bm.Name())
	bm.SetName("misc2")
	require.Equal(t, "misc2", bm.Name())

	bufTensor, err := tensor.FromSlice([]float32{7}, []int{1}, runtime.CPU())
	require.NoError(t, err)
	buf := NewBuffer(bufTensor, "buf", true)
	bm.RegisterBuffer("buf", buf)
	require.Len(t, bm.Buffers(), 1)

	require.NoError(t, bm.To(nil))
	bm.RegisterBackwardHook(func(module Module, gradInput, gradOutput *tensor.Tensor) (*tensor.Tensor, error) {
		return gradOutput, nil
	})
	_, err = bm.Forward(nil)
	require.Error(t, err)

	pTensor, err := tensor.FromSlice([]float32{1, 2}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	param := NewParameter(pTensor, "p")
	grad, err := tensor.FromSlice([]float32{9, -9}, []int{2}, runtime.CPU())
	require.NoError(t, err)
	param.Grad = grad
	bm.RegisterParameter("p", param)
	bm.ZeroGrad()
	require.Equal(t, []float32{0, 0}, param.Grad.Float32Data())

	child := NewBaseModule("child")
	bm.RegisterChild("child", child)
	var visited []string
	Apply(bm, func(m Module) {
		visited = append(visited, m.Name())
	})
	require.GreaterOrEqual(t, len(visited), 2)
}
