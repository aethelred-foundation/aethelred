module github.com/aethelred/sdk-go

go 1.21

require github.com/stretchr/testify v1.11.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// The Aethelred SDK provides source-first AI development support with explicit
// runtime gating for optional native accelerator backends.
//
// Optional dependencies (uncomment as needed):
//
// GPU support via NVIDIA go-nvml:
// require github.com/NVIDIA/go-nvml v0.12.0
//
// Distributed training via MPI:
// require github.com/mpi-forum/mpi-go v0.0.0
//
// Intel SGX TEE support:
// require github.com/edgelesssys/ego v1.5.0
