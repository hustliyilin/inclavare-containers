package attestation // import "github.com/opencontainers/runc/libenclave/attestation"

import (
	"net/http"
)

func (svc *Service) GetIASReport(q []byte) (string, http.Response, *Status) {
	return svc.Attester.GetIASReport(q)
}
