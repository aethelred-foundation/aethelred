//go:build !aethelred_gpu_native

package runtime

// nativeGPUEnabled reports whether the SDK was built with a native GPU backend.
//
// Current default is false. This keeps behavior explicit: detecting a GPU does
// not imply kernels are dispatched to the accelerator unless a native backend is linked.
func nativeGPUEnabled() bool {
	return false
}
