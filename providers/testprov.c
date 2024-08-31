/*
 * Copyright 2020-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/ciphercommon.h"
#include "prov/ciphercommon_gcm.h"
#include "prov/names.h"
#include "prov/provider_util.h"
#include "internal/param_names.h"

OSSL_provider_init_fn ossl_test_provider_init;

/* Parameters we provide to the core */
static const OSSL_PARAM test_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *test_gettable_params(const OSSL_PROVIDER *prov)
{
    return test_param_types;
}

static int test_get_params(const OSSL_PROVIDER *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Test Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

typedef struct prov_gcm_pipeline_ctx_st {
    void  *provctx;
    size_t keybits;
    size_t numpipes;
    void  *cipher_ctxs;
    void  *hw;
} PIPE_CTX;

const PROV_GCM_HW *ossl_prov_aes_hw_gcm(size_t keybits);
static void *aes_gcm_pipeline_newctx(void *provctx, size_t keybits)
{
    PIPE_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ctx->provctx = provctx;
        ctx->keybits = keybits;
        ctx->numpipes = 0;
        ctx->cipher_ctxs = NULL;
        ctx->hw = (void*) ossl_prov_aes_hw_gcm(ctx->keybits);
    }
    return ctx;
}

static OSSL_FUNC_cipher_freectx_fn aes_gcm_pipeline_freectx;
static void aes_gcm_pipeline_freectx(void *vctx)
{
    PIPE_CTX *ctx = (PIPE_CTX *)vctx;
    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

OSSL_FUNC_cipher_pipeline_encrypt_init_fn test_gcm_pipeline_einit;
OSSL_FUNC_cipher_pipeline_decrypt_init_fn test_gcm_pipeline_dinit;
OSSL_FUNC_cipher_pipeline_update_fn test_gcm_pipeline_update;
OSSL_FUNC_cipher_pipeline_final_fn test_gcm_pipeline_final;
OSSL_FUNC_cipher_gettable_ctx_params_fn test_cipher_aead_gettable_ctx_pipeline_params;
OSSL_FUNC_cipher_get_ctx_params_fn test_gcm_get_ctx_pipeline_params;
OSSL_FUNC_cipher_settable_ctx_params_fn test_cipher_aead_settable_ctx_pipeline_params;
OSSL_FUNC_cipher_set_ctx_params_fn test_gcm_set_ctx_pipeline_params;

int test_gcm_pipeline_einit(void *vctx,
                            const unsigned char *key, size_t keylen,
                            size_t numpipes, const unsigned char **iv,
                            size_t ivlen, const OSSL_PARAM params[])
{
   PIPE_CTX *ctx = (PIPE_CTX *)vctx;
   ctx->cipher_ctxs = OPENSSL_zalloc(numpipes * sizeof(PROV_GCM_CTX));
   if (ctx->cipher_ctxs == NULL) {
       return 0;
   }
   for (size_t i = 0; i < numpipes; i++) {
       ossl_gcm_initctx(ctx->provctx, ((PROV_GCM_CTX *)ctx->cipher_ctxs),
                        ctx->keybits,
                        ctx->hw);
       if (!ossl_gcm_einit(((PROV_GCM_CTX *)ctx->cipher_ctxs) + i,
                           key, keylen, iv[i], ivlen, params)) {
           OPENSSL_free(ctx->cipher_ctxs);
           ctx->cipher_ctxs = NULL;
           return 0;
       }
   }
   return 1;
}

int test_gcm_pipeline_dinit(void *vctx,
                            const unsigned char *key, size_t keylen,
                            size_t numpipes, const unsigned char **iv,
                            size_t ivlen, const OSSL_PARAM params[])
{
   PIPE_CTX *ctx = (PIPE_CTX *)vctx;
   ctx->cipher_ctxs = OPENSSL_zalloc(numpipes * sizeof(PROV_GCM_CTX));
   if (ctx->cipher_ctxs == NULL) {
       return 0;
   }
   for (size_t i = 0; i < numpipes; i++) {
       ossl_gcm_initctx(ctx->provctx, ((PROV_GCM_CTX *)ctx->cipher_ctxs),
                        ctx->keybits,
                        ctx->hw);
       if (!ossl_gcm_dinit(((PROV_GCM_CTX *)ctx->cipher_ctxs) + i,
                           key, keylen, iv[i], ivlen, params)) {
           OPENSSL_free(ctx->cipher_ctxs);
           ctx->cipher_ctxs = NULL;
           return 0;
       }
   }
   return 1;
}

int test_gcm_pipeline_update(void *vctx, size_t numpipes,
                             unsigned char **out, size_t *outl,
                             size_t *outsize,
                             const unsigned char **in, size_t *inl)
{
    PIPE_CTX *ctx = (PIPE_CTX *)vctx;
    for (size_t i = 0; i < numpipes; i++) {
        if (!ossl_gcm_stream_update(((PROV_GCM_CTX *)ctx->cipher_ctxs) + i,
                                    out[i], outl + i, outsize[i],
                                    in[i], inl[i])) {
            return 0;
        }
    }
    return 1;
}

int test_gcm_pipeline_final(void *vctx, size_t numpipes,
                            unsigned char **out, size_t *outl, size_t *outsize)
{
    PIPE_CTX *ctx = (PIPE_CTX *)vctx;
    for (size_t i = 0; i < numpipes; i++) {
        if (!ossl_gcm_stream_final(((PROV_GCM_CTX *)ctx->cipher_ctxs) + i,
                                   out[i], outl + i, outsize[i])) {
            return 0;
        }
    }
    return 1;
}

/*-
 * AEAD cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_aead_known_gettable_ctx_pipeline_params[] = {
    OSSL_PARAM_octet_ptr(OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *test_cipher_aead_gettable_ctx_pipeline_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return cipher_aead_known_gettable_ctx_pipeline_params;
}

static const OSSL_PARAM cipher_aead_known_settable_ctx_pipeline_params[] = {
    OSSL_PARAM_octet_ptr(OSSL_CIPHER_PARAM_PIPELINE_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *test_cipher_aead_settable_ctx_pipeline_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return cipher_aead_known_settable_ctx_pipeline_params;
}

int test_gcm_get_ctx_pipeline_params(void *vctx, OSSL_PARAM params[])
{
    // PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;
    OSSL_PARAM *p;
    int type;

    for (p = params; p->key != NULL; p++) {
        type = ossl_param_find_pidx(p->key);
        switch (type) {
        default:
            break;

        case PIDX_CIPHER_PARAM_PIPELINE_AEAD_TAG:
            if (!OSSL_PARAM_set_octet_ptr(p, NULL, 0)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
            }
            break;
        }
    }
    return 1;
}

int test_gcm_set_ctx_pipeline_params(void *vctx, const OSSL_PARAM params[])
{
    // PROV_GCM_CTX *ctx = (PROV_GCM_CTX *)vctx;
    const OSSL_PARAM *p;
    int type;

    for (p = params; p->key != NULL; p++) {
        type = ossl_param_find_pidx(p->key);
        switch (type) {
        default:
            break;

        case PIDX_CIPHER_PARAM_PIPELINE_AEAD_TAG:
            if (!OSSL_PARAM_get_octet_ptr(p, NULL, 0)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
            }
            break;
        }
    }
    return 1;
}

#define IMPLEMENT_aead_cipher_pipeline(alg, lc, UCMODE, flags, kbits, blkbits, ivbits)  \
static OSSL_FUNC_cipher_get_params_fn alg##_##kbits##_##lc##_get_params;       \
static int alg##_##kbits##_##lc##_get_params(OSSL_PARAM params[])              \
{                                                                              \
    return ossl_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,    \
                                          flags, kbits, blkbits, ivbits);      \
}                                                                              \
static OSSL_FUNC_cipher_newctx_fn alg##kbits##lc##_pipeline_newctx;            \
static void * alg##kbits##lc##_pipeline_newctx(void *provctx)                  \
{                                                                              \
    return alg##_##lc##_pipeline_newctx(provctx, kbits);                       \
}                                                                              \
const OSSL_DISPATCH test_##alg##kbits##lc##_functions[] = {                    \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void))alg##kbits##lc##_pipeline_newctx },                      \
    { OSSL_FUNC_CIPHER_FREECTX,                                                \
      (void (*)(void))alg##_##lc##_pipeline_freectx },                         \
    { OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT,                                  \
      (void (*)(void))test_##lc##_pipeline_einit },                            \
    { OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT,                                  \
      (void (*)(void))test_##lc##_pipeline_dinit },                            \
    { OSSL_FUNC_CIPHER_PIPELINE_UPDATE,                                        \
      (void (*)(void))test_##lc##_pipeline_update },                           \
    { OSSL_FUNC_CIPHER_PIPELINE_FINAL,                                         \
      (void (*)(void))test_##lc##_pipeline_final },                            \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lc##_get_params },                    \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void)) test_##lc##_get_ctx_pipeline_params },                  \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void)) test_##lc##_set_ctx_pipeline_params },                  \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void)) ossl_cipher_generic_gettable_params },                  \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void)) test_cipher_aead_gettable_ctx_pipeline_params },        \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
      (void (*)(void)) test_cipher_aead_settable_ctx_pipeline_params },        \
    OSSL_DISPATCH_END                                                          \
}

IMPLEMENT_aead_cipher_pipeline(aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96);

static const OSSL_ALGORITHM test_ciphers[] = {
    {PROV_NAMES_NULL, "provider=test", ossl_null_functions},
    {PROV_NAMES_AES_256_GCM, "provider=test", test_aes256gcm_functions},
};

static const OSSL_ALGORITHM *test_query(OSSL_PROVIDER *prov,
                                          int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return test_ciphers;
    }
    return NULL;
}

static void test_teardown(void *provctx)
{
    OSSL_LIB_CTX_free(ossl_prov_ctx_get0_libctx(provctx));
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH test_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))test_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))test_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))test_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))test_query },
    OSSL_DISPATCH_END
};

int ossl_test_provider_init(const OSSL_CORE_HANDLE *handle,
                            const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out,
                            void **provctx)
{
    *out = test_dispatch_table;

    if ((*provctx = ossl_prov_ctx_new()) == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx, OSSL_LIB_CTX_new());
    ossl_prov_ctx_set0_handle(*provctx, handle);
    return 1;
}
