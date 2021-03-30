#include <enclave-tls/enclave_quote.h>
#include <enclave-tls/log.h>

extern enclave_quote_err_t enclave_quote_register(enclave_quote_opts_t *);
extern enclave_quote_err_t sgx_epid_pre_init(void);
extern enclave_quote_err_t sgx_epid_init(enclave_quote_ctx_t *,
                                     enclave_tls_cert_algo_t algo);
//extern enclave_quote_err_t sgx_epid_extend_cert(enclave_quote_ctx_t *ctx,
//                                          const enclave_tls_cert_info_t *cert_info);
extern enclave_quote_err_t sgx_epid_collect_evidence(enclave_quote_ctx_t *,
                                                 attestation_evidence_t *,
                                                 enclave_tls_cert_algo_t algo,
                                                 uint8_t *);
extern enclave_quote_err_t sgx_epid_verify_evidence(enclave_quote_ctx_t *,
                                                attestation_evidence_t *, uint8_t *);
extern enclave_quote_err_t sgx_epid_cleanup(enclave_quote_ctx_t *);


static enclave_quote_opts_t opts_sgx_epid = {
        .version = ENCLAVE_QUOTE_API_VERSION_DEFAULT,
        .flags = ENCLAVE_QUOTE_OPTS_FLAGS_SGX_ENCLAVE,
        .type = "sgx_epid",
        .priority = 2,
        .pre_init = sgx_epid_pre_init,
        .init = sgx_epid_init,
        //.extend_cert = sgx_epid_extend_cert,
        .collect_evidence = sgx_epid_collect_evidence,
        .verify_evidence = sgx_epid_verify_evidence,
        .cleanup = sgx_epid_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libenclave_quote_null_init(void)
{
        ETLS_DEBUG("called\n");

        enclave_quote_err_t err = enclave_quote_register(&opts_sgx_epid);
        if (err != ENCLAVE_QUOTE_ERR_NONE)
                ETLS_FATAL("ERROR: failed to register enclave quote \"%s\"\n", opts_sgx_epid.type);
}
