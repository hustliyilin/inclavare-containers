package main // import "github.com/inclavare-containers/sgx-tools"

/*
#cgo LDFLAGS:-lsgx_dcap_ql

#include <stdio.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"

static int getDCAPTargetInfo(void *target_info, int target_info_len)
{
	if (!target_info) {
		printf("Error: the input parameter target_info is NULL\n");
                return -1;
	}
	if (target_info_len != sizeof(sgx_target_info_t)) {
		printf("Error: the target_info_len is not %d, but %d\n", sizeof(sgx_target_info_t), target_info_len);
		return -1;
	}

	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
	qe3_ret = sgx_qe_get_target_info(target_info);
	if (SGX_QL_SUCCESS != qe3_ret) {
        	printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
                return -1;
	}

	return qe3_ret;
}

static int getDCAPQuoteSize(uint32_t *quote_size)
{
	if (!quote_size) {
		printf("Error: the input parameter quote_size is NULL\n");
                return -1;
	}

	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
	qe3_ret = sgx_qe_get_quote_size(&quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
        	printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        	return -1;
	}

	return qe3_ret;
}

static int getDCAPQuote(void *local_report, int local_report_len, void* quote, uint32_t quote_size)
{
	if (!local_report) {
		printf("Error: the input parameter local_report is NULL\n");
		return -1;
	}
	if (local_report_len != sizeof(sgx_report_t)) {
		printf("Error: the local_report_len is not %d, but %d\n", sizeof(sgx_report_t), local_report_len);
		return -1;
	}

	if (!quote) {
		printf("Error: the input parameter quote is NULL\n");
		return -1;
	}
	if (quote_size <= 0) {
		printf("Error: the input parameter quote_size:%u is invalid\n", quote_size);
		return -1;
	}

	quote3_error_t qe3_ret = SGX_QL_SUCCESS;
	qe3_ret = sgx_qe_get_quote(local_report, quote_size, quote);
   	if (SGX_QL_SUCCESS != qe3_ret) {
        	printf("Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        	return -1;
	}

	return qe3_ret;
}
*/
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"unsafe"
)

func GetDCAPTargetInfo() ([]byte, error) {
	logrus.Infof("Get DCAP target info!\n")
	ti := make([]byte, intelsgx.TargetinfoLength)

	ret := C.getDCAPTargetInfo(unsafe.Pointer(&ti[0]),
		C.int(len(ti)))
	if ret != 0 {
		return nil, fmt.Errorf("C.getDCAPTargetInfo() failed, return %d.\n", ret)
	}
	logrus.Infof("targetInfo = %v", ti)

	targetInfo := &intelsgx.Targetinfo{}
	if err := restruct.Unpack(ti, binary.LittleEndian, &targetInfo); err != nil {
		return nil, err
	}

	logrus.Infof("Quoting Enclave's TARGETINFO:\n")
	logrus.Infof("  Enclave Hash:       0x%v\n",
		hex.EncodeToString(targetInfo.Measurement[:]))
	logrus.Infof("  Enclave Attributes: 0x%v\n",
		hex.EncodeToString(targetInfo.Attributes[:]))
	logrus.Infof("  CET Attributes:     %#02x\n",
		targetInfo.CetAttributes)
	logrus.Infof("  Config SVN:         %#04x\n",
		targetInfo.ConfigSvn)
	logrus.Infof("  Misc Select:        %#08x\n",
		targetInfo.MiscSelect)
	logrus.Infof("  Config ID:          0x%v\n",
		hex.EncodeToString(targetInfo.ConfigId[:]))

	return ti, nil
}

func getDCAPQuoteSize() (uint32, error) {
	logrus.Infof("Get DCAP quote size!\n")
	var quoteSize uint32

	ret := C.getDCAPQuoteSize((*C.uint32_t)(unsafe.Pointer(&quoteSize)))
	if ret != 0 {
		return 0, fmt.Errorf("C.getDCAPQuoteSize() failed, return %d.\n", ret)
	}
	logrus.Infof("quote size is %v\n", quoteSize)

	return quoteSize, nil
}

func GetDCAPQuote(report []byte) ([]byte, error) {
	logrus.Infof("Get DCAP quote!\n")
	if len(report) != intelsgx.ReportLength {
		return nil, fmt.Errorf("signature not match REPORT")
	}

	r := &intelsgx.Report{}
	if err := restruct.Unpack(report, binary.LittleEndian, &r); err != nil {
		return nil, err
	}

	logrus.Infof("REPORT:")
	logrus.Infof("  CPU SVN:                        0x%v\n",
		hex.EncodeToString(r.CpuSvn[:]))
	logrus.Infof("  Misc Select:                    %#08x\n",
		r.MiscSelect)
	logrus.Infof("  Product ID:                     0x%v\n",
		hex.EncodeToString(r.IsvExtProdId[:]))
	logrus.Infof("  Attributes:                     0x%v\n",
		hex.EncodeToString(r.Attributes[:]))
	logrus.Infof("  Enclave Hash:                   0x%v\n",
		hex.EncodeToString(r.MrEnclave[:]))
	logrus.Infof("  Enclave Signer:                 0x%v\n",
		hex.EncodeToString(r.MrSigner[:]))
	logrus.Infof("  Config ID:                      0x%v\n",
		hex.EncodeToString(r.ConfigId[:]))
	logrus.Infof("  ISV assigned Produdct ID:       %#04x\n",
		r.IsvProdId)
	logrus.Infof("  ISV assigned SVN:               %d\n",
		r.IsvSvn)
	logrus.Infof("  Config SVN:                     %#04x\n",
		r.ConfigSvn)
	logrus.Infof("  ISV assigned Product Family ID: 0x%v\n",
		hex.EncodeToString(r.IsvFamilyId[:]))
	logrus.Infof("  Report Data:                    0x%v\n",
		hex.EncodeToString(r.ReportData[:]))

	quoteSize, err:= getDCAPQuoteSize()
	if err != nil || quoteSize == 0 {
		return nil, err
	}

	quote := make([]byte, quoteSize)
	ret := C.getDCAPQuote(unsafe.Pointer(&report[0]),
			C.int(len(report)),
			unsafe.Pointer(&quote[0]),
			C.uint32_t(quoteSize))
	if ret != 0 {
                return nil, fmt.Errorf("C.getDCAPQuote() failed, return %d.\n", ret)
        }
	logrus.Infof("quote is %v\n", quote)

	q := &intelsgx.Quote{}
	if err := restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
		return nil, err
	}

	logrus.Infof("QUOTE:")
	logrus.Infof("  Version:                              %d\n",
		q.Version)
	logrus.Infof("  Signature Type:                       %d\n",
		q.SignatureType)
	logrus.Infof("  Gid:                                  %#08x\n",
		q.Gid)
	logrus.Infof("  ISV assigned SVN for Quoting Enclave: %d\n",
		q.ISVSvnQe)
	logrus.Infof("  ISV assigned SVN for PCE:             %d\n",
		q.ISVSvnPce)
	logrus.Infof("  Base name:                            0x%v\n",
		hex.EncodeToString(q.Basename[:]))
	logrus.Infof("  Report:                               ...\n")
	logrus.Infof("  Signature Length:                     %d\n",
		q.SigLen)

	return quote, nil
}
