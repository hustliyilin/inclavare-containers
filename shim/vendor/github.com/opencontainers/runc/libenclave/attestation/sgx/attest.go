package sgx // import "github.com/opencontainers/runc/libenclave/attestation/sgx"

// RA Type
const (
	UnknownRaType = iota
	EPID
	DCAP
)

// RA Enclave Type
const (
	InvalidEnclaveType = iota
	DebugEnclave
	ProductEnclave
)
