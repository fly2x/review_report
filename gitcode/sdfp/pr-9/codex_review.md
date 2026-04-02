# Code Review: openHiTLS/sdfp#9
**Reviewer**: CODEX


## High

### RSA provider support is registered but its SDF symbols are never loaded
`src/common/sdf_dl.c:183-193`
```
/*
 * RSA internal key operations are loaded on demand when an internal RSA
 * key index is configured (not all SDF devices support them).
 */
/* LOAD_SYM(genKeyPairRsa,           SDF_GenerateKeyPair_RSA); */
/* LOAD_SYM(exportSignPubKeyRsa,     SDF_ExportSignPublicKey_RSA); */
/* LOAD_SYM(exportEncPubKeyRsa,      SDF_ExportEncPublicKey_RSA); */
/* LOAD_SYM(intPubKeyOpRsa,          SDF_InternalPublicKeyOperation_RSA); */
/* LOAD_SYM(intPrivKeyOpRsa,         SDF_InternalPrivateKeyOperation_RSA); */
/* LOAD_SYM(extPubKeyOpRsa,          SDF_ExternalPublicKeyOperation_RSA); */
/* LOAD_SYM(extPrivKeyOpRsa,         SDF_ExternalPrivateKeyOperation_RSA); */
```
**Issue**: The provider still advertises RSA key management, signing, and asymmetric cipher support, but `SDF_DL_Load()` no longer resolves any RSA entry points. Every RSA wrapper in `src/rsa/` then hits a NULL function pointer and returns `SDFP_ERR_NOT_LOADED`, so all RSA operations fail at runtime.
**Fix**:
```
LOAD_SYM(genKeyPairRsa,           SDF_GenerateKeyPair_RSA);
LOAD_SYM(exportSignPubKeyRsa,     SDF_ExportSignPublicKey_RSA);
LOAD_SYM(exportEncPubKeyRsa,      SDF_ExportEncPublicKey_RSA);
LOAD_SYM(intPubKeyOpRsa,          SDF_InternalPublicKeyOperation_RSA);
LOAD_SYM(intPrivKeyOpRsa,         SDF_InternalPrivateKeyOperation_RSA);
LOAD_SYM(extPubKeyOpRsa,          SDF_ExternalPublicKeyOperation_RSA);
LOAD_SYM(extPrivKeyOpRsa,         SDF_ExternalPrivateKeyOperation_RSA);
```

---

### GCM `Final` now appends the tag and breaks the existing AEAD API
`src/sm4/sm4_gcm.c:219-233`
```
if (ctx->enc) {
    unsigned int tagOutLen = SM4_GCM_TAG_MAX;
    if (*outLen < tagOutLen) {
        SDFP_LOG(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
    if (ret == SDR_OK) {
        ctx->tagLen = tagOutLen;
        memcpy(out + tmpLen, ctx->tag, tagOutLen);
        tmpLen += tagOutLen;
    }
}
```
**Issue**: Before this PR, and in the current README, callers finish encryption with `Final` and then fetch the tag with `CRYPT_CTRL_GET_TAG`. This change makes `Final` require at least 16 extra output bytes and appends the tag into the ciphertext buffer. Existing callers that sized `Final` for ciphertext tail only will now fail with `CRYPT_INVALID_ARG` or have to adopt a non-standard buffer contract.
**Fix**:
```
if (ctx->enc) {
    unsigned int tagOutLen = ctx->tagLen;
    ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
    if (ret == SDR_OK) {
        ctx->tagLen = tagOutLen;
    }
}
```

---


## Medium

### Reusing a GCM context carries the previous AAD and tag into the next operation
`src/sm4/sm4_gcm.c:148-160`
```
ret = SDF_DL_AuthEncInit(ctx->hSessionHandle, ctx->hKeyHandle, SGD_SM4_GCM,
    ctx->iv, ctx->ivLen,
    ctx->aadLen > 0 ? ctx->aad : NULL, ctx->aadLen,
    0);
...
ret = SDF_DL_AuthDecInit(ctx->hSessionHandle, ctx->hKeyHandle, SGD_SM4_GCM,
    ctx->iv, ctx->ivLen,
    ctx->aadLen > 0 ? ctx->aad : NULL, ctx->aadLen,
    ctx->tag, ctx->tagLen,
    0);

static int32_t SDFP_SM4_GCM_DeinitCtx(void *c)
{
    /* Method A: only destroy key handle; session + config preserved. */
    SDFP_SM4_GCM_CleanKey((SDFP_SM4_GCM_Ctx *)c);
    return CRYPT_SUCCESS;
}
```
**Issue**: `SDFP_SM4_GCM_DeinitCtx()` now preserves all per-message AEAD state, but `SDFP_SM4_GCM_SdfInit()` still consumes `ctx->aadLen`, `ctx->aad`, `ctx->tag`, and `ctx->tagLen` on the next `Init/Update`. Reusing a cipher context without explicitly resetting AAD/tag will silently authenticate the next message with stale values from the previous operation.
**Fix**:
```
static int32_t SDFP_SM4_GCM_DeinitCtx(void *c)
{
    SDFP_SM4_GCM_Ctx *ctx = (SDFP_SM4_GCM_Ctx *)c;
    if (ctx == NULL) {
        return CRYPT_SUCCESS;
    }
    SDFP_SM4_GCM_CleanKey(ctx);
    BSL_SAL_CleanseData(ctx->iv, sizeof(ctx->iv));
    BSL_SAL_CleanseData(ctx->aad, sizeof(ctx->aad));
    BSL_SAL_CleanseData(ctx->tag, sizeof(ctx->tag));
    ctx->ivLen = 0;
    ctx->aadLen = 0;
    ctx->tagLen = SM4_GCM_TAG_MAX;
    ctx->started = false;
    return CRYPT_SUCCESS;
}
```

---

### The build ignores `HITLS_LIB_DIR` and hard-codes the openHiTLS build tree
`CMakeLists.txt:35-50`
```
if(NOT DEFINED HITLS_LIB_DIR)
    set(HITLS_LIB_DIR ${HITLS_DIR}/lib)
endif()

find_library(HITLS_BSL_LIB libhitls_bsl.so
    PATHS ${HITLS_DIR}/build
    REQUIRED
)

find_library(HITLS_CRYPTO_LIB libhitls_crypto.a
    PATHS ${HITLS_DIR}/build
    REQUIRED
)

find_library(HITLS_BSL_SO libhitls_bsl.so
    PATHS ${HITLS_DIR}/build
    REQUIRED
)
```
**Issue**: `HITLS_LIB_DIR` is still configurable, but the new `find_library()` calls never use it and search only `${HITLS_DIR}/build`. That breaks the documented `HITLS_DIR/include + HITLS_DIR/lib` layout and makes configured installed-library paths ineffective.
**Fix**:
```
find_library(HITLS_BSL_LIB NAMES hitls_bsl libhitls_bsl.so libhitls_bsl.a
    PATHS ${HITLS_LIB_DIR} ${HITLS_DIR}/build
    REQUIRED
)
find_library(HITLS_CRYPTO_LIB NAMES hitls_crypto libhitls_crypto.so libhitls_crypto.a
    PATHS ${HITLS_LIB_DIR} ${HITLS_DIR}/build
    REQUIRED
)
find_library(HITLS_BSL_SO NAMES hitls_bsl libhitls_bsl.so
    PATHS ${HITLS_LIB_DIR} ${HITLS_DIR}/build
    REQUIRED
)
```

---
