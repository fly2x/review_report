# Code Review: openHiTLS/openhitls#1108
**Reviewer**: CLAUDE


## High

### Potential use of uninitialized data in CRYPT_COMPOSITE_SetPrvKeyEx
`crypto/composite/src/composite.c:517-526`
```
int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
}
```
**Issue**: GetConstParamValue return value is ignored with (void) cast. If the parameter is not found, *value and *valueLen won't be set, leaving prv.data and prv.len uninitialized (zero). The subsequent CRYPT_COMPOSITE_SetPrvKey call will use this uninitialized data, potentially causing memory corruption or incorrect behavior.
**Fix**:
```
int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    if (GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
}
```

---

### Potential use of uninitialized data in CRYPT_COMPOSITE_SetPubKeyEx
`crypto/composite/src/composite.c:528-537`
```
int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
}
```
**Issue**: GetConstParamValue return value is ignored with (void) cast. If the parameter is not found, *value and *valueLen won't be set, leaving pub.data and pub.len uninitialized (zero). The subsequent CRYPT_COMPOSITE_SetPubKey call will use this uninitialized data, potentially causing memory corruption or incorrect behavior.
**Fix**:
```
int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    if (GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
}
```

---

### Potential NULL pointer dereference in CRYPT_COMPOSITE_GetPrvKeyEx
`crypto/composite/src/composite.c:485-499`
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return CRYPT_SUCCESS;
}
```
**Issue**: GetParamValue may return NULL if the parameter is not found, but the code doesn't check for this before dereferencing paramPrv to set paramPrv->useLen. This could cause a NULL pointer dereference and crash.
**Fix**:
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    if (paramPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;
    return CRYPT_SUCCESS;
}
```

---

### Potential NULL pointer dereference in CRYPT_COMPOSITE_GetPubKeyEx
`crypto/composite/src/composite.c:501-515`
```
int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
    int32_t ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return CRYPT_SUCCESS;
}
```
**Issue**: GetParamValue may return NULL if the parameter is not found, but the code doesn't check for this before dereferencing paramPub to set paramPub->useLen. This could cause a NULL pointer dereference and crash.
**Fix**:
```
int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
    if (paramPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;
    return CRYPT_SUCCESS;
}
```

---


## Medium

### Missing NULL checks in CRYPT_COMPOSITE_DupCtx
`crypto/composite/src/composite.c:195-221`
```
newCtx->info = ctx->info;
    newCtx->pqcMethod = ctx->pqcMethod;
    newCtx->tradMethod = ctx->tradMethod;
    ...
    if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
        newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
        newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
        if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
```
**Issue**: The code dereferences ctx->pqcMethod and ctx->tradMethod without first checking if they are NULL. While this is called after setting algorithm info, a defensive check would be safer to prevent potential NULL pointer dereference if the context is in an inconsistent state.
**Fix**:
```
newCtx->info = ctx->info;
    if (ctx->pqcMethod == NULL || ctx->tradMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        goto ERR;
    }
    newCtx->pqcMethod = ctx->pqcMethod;
    newCtx->tradMethod = ctx->tradMethod;
    ...
```

---

### Potential integer overflow in key length subtraction
`crypto/composite/src/composite.c:455-464`
```
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(prv->len > ctx->info->prvKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```
**Issue**: The code checks `prv->len <= ctx->info->pqcPrvkeyLen` and `prv->len > ctx->info->prvKeyLen`, but doesn't verify that `prv->len - ctx->info->pqcPrvkeyLen` won't underflow when computing the tradPrv length. While the checks should prevent this, explicit bounds checking would be safer.
**Fix**:
```
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(prv->len > ctx->info->prvKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    uint32_t tradLen = prv->len - ctx->info->pqcPrvkeyLen;
    if (tradLen > ctx->info->prvKeyLen - ctx->info->pqcPrvkeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
        return CRYPT_COMPOSITE_KEYLEN_ERROR;
    }
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, tradLen};
```

---

### Potential integer overflow in public key length subtraction
`crypto/composite/src/composite.c:473-482`
```
RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(pub->len > ctx->info->pubKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
```
**Issue**: The code checks `pub->len <= ctx->info->pqcPubkeyLen` and `pub->len > ctx->info->pubKeyLen`, but doesn't verify that `pub->len - ctx->info->pqcPubkeyLen` won't underflow when computing the tradPub length.
**Fix**:
```
RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(pub->len > ctx->info->pubKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    uint32_t tradLen = pub->len - ctx->info->pqcPubkeyLen;
    if (tradLen > ctx->info->pubKeyLen - ctx->info->pqcPubkeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
        return CRYPT_COMPOSITE_KEYLEN_ERROR;
    }
    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, tradLen};
```

---

### Missing BSL_ERR_PUSH_ERROR after CRYPT_COMPOSITE_SetPrvKeyEx failure
`crypto/codecskey/src/crypt_decoder_composite.c:93-94`
```
ret = CRYPT_COMPOSITE_SetPrvKeyEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_COMPOSITE_FreeCtx(pctx);
        return ret;
    }
```
**Issue**: When CRYPT_COMPOSITE_SetPrvKeyEx fails, the error is not pushed via BSL_ERR_PUSH_ERROR, making debugging harder and potentially losing context about the actual error.
**Fix**:
```
ret = CRYPT_COMPOSITE_SetPrvKeyEx(pctx, priParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CRYPT_COMPOSITE_FreeCtx(pctx);
        return ret;
    }
```

---


## Low

### Inconsistent error handling in ParseCompositePrikeyAsn1Buff
`crypto/codecskey/src/crypt_codecskey_local.c:1169-1177`
```
ret = CRYPT_EAL_PkeySetPrv(pctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
```
**Issue**: After calling CRYPT_EAL_PkeySetPrv, if it fails, the code frees pctx but returns without pushing error via BSL_ERR_PUSH_ERROR. This is inconsistent with other similar functions like ParseMldsaPrikeyAsn1Buff.

---

### Insufficient signature length validation in CRYPT_COMPOSITE_Sign
`crypto/composite/src/composite.c:598-604`
```
if (*signLen < ctx->info->pqcSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_INVALID_SIG_LEN);
        return CRYPT_COMPOSITE_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = *signLen - pqcSigLen;
```
**Issue**: The code checks `*signLen < ctx->info->pqcSigLen` but doesn't verify that the remaining buffer space (*signLen - pqcSigLen) is sufficient for the traditional signature. While tradSigLen is passed to the sign function, there's no explicit check that the total expected signature length fits.
**Fix**:
```
if (*signLen < ctx->info->pqcSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_INVALID_SIG_LEN);
        return CRYPT_COMPOSITE_INVALID_SIG_LEN;
    }
    uint32_t expectedSigLen = ctx->info->pqcSigLen + ctx->info->tradSigLen;
    if (*signLen < expectedSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_INVALID_SIG_LEN);
        return CRYPT_COMPOSITE_INVALID_SIG_LEN;
    }
    int32_t ret;
    uint32_t pqcSigLen = ctx->info->pqcSigLen;
    uint32_t tradSigLen = *signLen - pqcSigLen;
```

---

### Missing NULL check for ctx->info->label in CompositeMsgEncode
`crypto/composite/src/composite.c:567`
```
const char *label = ctx->info->label;
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
```
**Issue**: The code calls strlen(ctx->info->label) without verifying that ctx->info->label is not NULL. If label is NULL, this will cause a crash.
**Fix**:
```
const char *label = ctx->info->label;
    if (label == NULL) {
        return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
    }
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
```

---

### Unsafe pointer cast in CRYPT_COMPOSITE_Sign
`crypto/composite/src/composite.c:607-608`
```
GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
```
**Issue**: The code casts ctx->info->label (a const char pointer) to void* via uintptr_t. This is technically undefined behavior in C/C++ as it converts a pointer to data to a pointer to function (or vice versa). The control function expects a different type of data.
**Fix**:
```
GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
```

---

### Missing HITLS_CRYPTO_COMPOSITE in PKEY_SIGN condition
`config/macro_config/hitls_config_layer_crypto.h:739-740`
```
#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY) || \
    defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_SM9) || \
    defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLDSA)
```
**Issue**: The preprocessor condition for HITLS_CRYPTO_PKEY_SIGN includes ML-DSA but not COMPOSITE. Since COMPOSITE keys can sign, this might cause issues with feature detection or linking.
**Fix**:
```
#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY) || \
    defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_SM9) || \
    defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLDSA) || \
    defined(HITLS_CRYPTO_COMPOSITE)
```

---
