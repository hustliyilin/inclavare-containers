package enclave_runtime_pal // import "github.com/opencontainers/runc/libenclave/internal/runtime/pal"

/*
#include <sys/prctl.h>

static void workaround_nanosleep(void) {
	// nanosleep() may return the remaining duration longer than
	// requested one due to timer slack.
	prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/opencontainers/runc/libenclave/attestation"
	"github.com/opencontainers/runc/libenclave/attestation/sgx"
	_ "github.com/opencontainers/runc/libenclave/attestation/sgx/ias"
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"log"
	"os"
)

const (
	palApiVersion = 2
)

func (pal *enclaveRuntimePal) Init(args string, logLevel string) error {
	api := &enclaveRuntimePalApiV1{}
	ver := api.get_version()
	if ver > palApiVersion {
		return fmt.Errorf("unsupported pal api version %d", ver)
	}
	pal.version = ver

	C.workaround_nanosleep()

	return api.init(args, logLevel)
}

func (pal *enclaveRuntimePal) Exec(cmd []string, envp []string, stdio [3]*os.File) (int32, error) {
	if pal.version == 1 {
		api := &enclaveRuntimePalApiV1{}
		return api.exec(cmd, envp, stdio)
	}

	api := &enclaveRuntimePalApiV2{}
	return api.exec(cmd, envp, stdio)
}

func (pal *enclaveRuntimePal) Kill(pid int, sig int) error {
	if pal.version == 1 {
		return nil
	}

	api := &enclaveRuntimePalApiV2{}
	return api.kill(pid, sig)
}

func (pal *enclaveRuntimePal) Destroy() error {
	api := &enclaveRuntimePalApiV1{}
	return api.destroy()
}

func (pal *enclaveRuntimePal) GetLocalReport(targetInfo []byte) ([]byte, error) {
	if pal.version >= 3 {
		api := &enclaveRuntimePalApiV3{}
		return api.getLocalReport(targetInfo)
	}

	return nil, fmt.Errorf("unsupported pal api version %d", pal.version)
}

func parseAttestParameters(spid string, subscriptionKey string, product uint32) map[string]string {
	p := make(map[string]string)

	p["spid"] = spid
	p["subscription-key"] = subscriptionKey
	if product == sgx.ProductEnclave {
		p["service-class"] = "product"
	} else if product == sgx.DebugEnclave {
		p["service-class"] = "dev"
	}

	return p
}

func (pal *enclaveRuntimePal) Attest(spid string, subscriptionKey string, product uint32, quoteType uint32) (map[string]string, error) {
	if pal.GetLocalReport == nil {
		return nil, nil
	}

	targetInfo, err := intelsgx.GetQeTargetInfo()
	if err != nil {
		return nil, err
	}

	if len(targetInfo) != intelsgx.TargetinfoLength {
		return nil, fmt.Errorf("len(targetInfo) is not %d, but %d", intelsgx.TargetinfoLength, len(targetInfo))
	}

	// get local report of SGX
	report, err := pal.GetLocalReport(targetInfo)
	if err != nil {
		return nil, err
	}
	if len(report) != intelsgx.ReportLength {
		return nil, fmt.Errorf("len(report) is not %d, but %d", intelsgx.ReportLength, len(report))
	}

	// get quote from QE(aesmd)
	linkable := false
	if quoteType == intelsgx.QuoteSignatureTypeLinkable {
		linkable = true
	}
	quote, err := intelsgx.GetQuote(report, spid, linkable)
	if err != nil {
		return nil, err
	}

	q := &intelsgx.Quote{}
	if err := restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
		return nil, err
	}

	// get IAS remote attestation report
	var verbose bool = true
	p := parseAttestParameters(spid, subscriptionKey, product)
	svc, err := attestation.NewService(p, verbose)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	if err = svc.Check(quote); err != nil {
		log.Fatal(err)
		return nil, err
	}

	status, iasReport, err := svc.GetVerifiedReport(quote)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	svc.ShowStatus(status)

	return iasReport, nil
}
