#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

/* *INDENT-OFF* */
enclave_quote_err_t sgx_epid_cleanup(enclave_quote_ctx_t *ctx)
{
        ETLS_DEBUG("enclave_quote_sgx_epid cleanup() is called\n");

        return ENCLAVE_QUOTE_ERR_NONE;
}
/* *INDENT-ON* */
