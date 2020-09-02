package enclave_runtime_core // import "github.com/opencontainers/runc/libenclave/internal/runtime/core"

import (
	"fmt"
	"github.com/opencontainers/runc/libenclave/configs"
	"os"
)

type enclaveRuntimeCore struct {
}

func StartInitialization(config *configs.InitEnclaveConfig) (*enclaveRuntimeCore, error) {
	return nil, fmt.Errorf("enclave runtime core unimplemented")
}

func (core *enclaveRuntimeCore) Name() string {
	return "core"
}

func (core *enclaveRuntimeCore) Load(palPath string) (err error) {
	return fmt.Errorf("enclave runtime core Load() unimplemented")
}

func (pal *enclaveRuntimeCore) Init(args string, logLevel string) (err error) {
	return fmt.Errorf("enclave runtime core Init() unimplemented")
}

func (pal *enclaveRuntimeCore) Attest(string, string, uint32, uint32) (map[string]string, error) {
	return nil, fmt.Errorf("enclave runtime core Attest() unimplemented")
}

func (pal *enclaveRuntimeCore) Exec(cmd []string, envp []string, stdio [3]*os.File) (int32, error) {
	return -1, fmt.Errorf("enclave runtime core Exec() unimplemented")
}

func (pal *enclaveRuntimeCore) Kill(sig int, pid int) error {
	return fmt.Errorf("enclave runtime core Kill() unimplemented")
}

func (pal *enclaveRuntimeCore) Destroy() error {
	return fmt.Errorf("enclave runtime core Destroy() unimplemented")
}
