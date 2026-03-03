//go:build aethelred_cuda_native

package runtime

// nativeCUDAEnabled reports native CUDA dispatch support for builds that opt in
// to the aethelred_cuda_native tag.
func nativeCUDAEnabled() bool {
	return true
}
