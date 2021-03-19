#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>

static unsigned int dummy_private;

/* *INDENT-OFF* */
crypto_wrapper_err_t nullcrypto_init(crypto_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	ctx->crypto_private = &dummy_private;

	return CRYPTO_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
