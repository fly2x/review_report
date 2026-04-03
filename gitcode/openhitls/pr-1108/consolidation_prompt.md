# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1108
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1108
**Reviewer**: CODEX


## High

### ECDSA composite public keys allocate only one coordinate
`crypto/composite/src/composite_encdec.c:295-301`
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
pubLen = BITS_TO_BYTES(pubLen);
uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
```
**Issue**: `CRYPT_CTRL_GET_BITS` returns the curve size in bits, but `CRYPT_PARAM_EC_PUBKEY` exports the full encoded EC point. This allocates 32/48/66 bytes for P-256/P-384/P-521 instead of 65/97/133, so `getPub()` fails and every ECDSA-based composite keygen/export path breaks.
**Fix**:
```
uint32_t bits = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &bits, sizeof(bits)), ret);
RETURN_RET_IF(bits == 0, CRYPT_EAL_ALG_NOT_SUPPORT);

uint32_t coordLen = BITS_TO_BYTES(bits);
uint32_t pubLen = (coordLen << 1) + 1; /* uncompressed EC point */
uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
```

---

### Reinitializing a composite context can overflow stale key buffers
`crypto/composite/src/composite.c:246-279`
```
ctx->info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
...
ctx->pqcCtx = pqcMethod->newCtx();
RETURN_RET_IF((ctx->pqcCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
ctx->tradCtx = tradMethod->newCtx();
...
if (ctx->pubKey == NULL) {
    ctx->pubKey = BSL_SAL_Malloc(ctx->pubLen);
}
...
ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
(void)memcpy_s(ctx->pubKey, ctx->pubLen, pqcPub.data, pqcPub.dataLen);
```
**Issue**: `CRYPT_CompositeSetAlgInfo()` can be called multiple times on the same context. It replaces `ctx->info` and allocates new subcontexts, but `CRYPT_CompositeCreateKeyBuf()` only allocates when `pubKey`/`prvKey` are `NULL`. If the context already holds a smaller key and is reconfigured to a larger algorithm, `CRYPT_COMPOSITE_GenKey()` copies the larger key into the old allocation. Even before keygen, repeated initialization leaks the old `pqcCtx` and `tradCtx`.
**Fix**:
```
if (ctx->info != NULL || ctx->pqcCtx != NULL || ctx->tradCtx != NULL ||
    ctx->pubKey != NULL || ctx->prvKey != NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}

ctx->info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
```

---


## Medium

### `CRYPT_CTRL_SET_RSA_E` is ignored after parameter setup
`crypto/composite/src/composite.c:210-223`
```
uint8_t *e = BSL_SAL_Dump((uint8_t *)val, len);
RETURN_RET_IF(e == NULL, CRYPT_MEM_ALLOC_FAIL);
BSL_SAL_FREE(ctx->e);
ctx->e = e;
ctx->eLen = len;
return CRYPT_SUCCESS;
...
if (ctx->info->tradAlg == CRYPT_PKEY_RSA) {
    GOTO_ERR_IF(CRYPT_CompositeSetRsaPara(ctx), ret);
}
```
**Issue**: The new control only updates `ctx->e`, but the RSA subcontext consumes that value only once inside `CRYPT_CompositeSetAlgInfo()`. In the normal call order (`PkeySetParaById` then `PkeyCtrl(...SET_RSA_E...)` then `PkeyGen`), the generated key still uses the default exponent `65537`.
**Fix**:
```
if (val == NULL && len == 0) {
    BSL_SAL_FREE(ctx->e);
    ctx->eLen = 0;
    if (ctx->info != NULL && ctx->tradCtx != NULL && ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        return CRYPT_CompositeSetRsaPara(ctx);
    }
    return CRYPT_SUCCESS;
}

uint8_t *e = BSL_SAL_Dump((uint8_t *)val, len);
RETURN_RET_IF(e == NULL, CRYPT_MEM_ALLOC_FAIL);
BSL_SAL_FREE(ctx->e);
ctx->e = e;
ctx->eLen = len;
if (ctx->info != NULL && ctx->tradCtx != NULL && ctx->info->tradAlg == CRYPT_PKEY_RSA) {
    return CRYPT_CompositeSetRsaPara(ctx);
}
return CRYPT_SUCCESS;
```

---

### MLDSA87/P-384 private-key length table has a misplaced digit
`crypto/composite/src/composite.c:71-73`
```
{CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512, "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
 CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP384,
 CRYPT_MD_SHA512, CRYPT_MD_SHA384, 0, 2689, 962, 2592, 32, 4627},
```
**Issue**: The max composite private-key length for `CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512` is recorded as `962` instead of `96`. `CRYPT_COMPOSITE_SetPrvKey()` uses this table entry as its upper bound, so malformed inputs with a valid 96-byte key plus trailing garbage are accepted.
**Fix**:
```
{CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512, "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
 CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP384,
 CRYPT_MD_SHA512, CRYPT_MD_SHA384, 0, 2689, 96, 2592, 32, 4627},
```

---

### Ed448 composite OIDs are routed to an unimplemented parser
`crypto/codecskey/src/crypt_codecskey_local.c:1171-1178`
```
case BSL_CID_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
case BSL_CID_MLDSA87_ED448_SHAKE256:
case BSL_CID_MLDSA87_RSA3072_PSS_SHA512:
...
    return ParseCompositePrikeyAsn1Buff(...);

case BSL_CID_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
case BSL_CID_MLDSA87_ED448_SHAKE256:
case BSL_CID_MLDSA87_RSA3072_PSS_SHA512:
...
    return ParseCompositePubkeyAsn1Buff(...);
```
**Issue**: The new PKCS#8 and SPKI dispatch tables treat `BSL_CID_MLDSA87_ED448_SHAKE256` as a supported composite key type, but the composite implementation has no `g_composite_info` entry or traditional-key handler for Ed448. Any key with this OID is advertised as supported and then fails during `CRYPT_EAL_PkeySetParaById()`.
**Fix**:
```
case BSL_CID_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
case BSL_CID_MLDSA87_RSA3072_PSS_SHA512:
case BSL_CID_MLDSA87_RSA4096_PSS_SHA512:
case BSL_CID_MLDSA87_ECDSA_P521_SHA512:
    return ParseCompositePrikeyAsn1Buff(...);

case BSL_CID_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
case BSL_CID_MLDSA87_RSA3072_PSS_SHA512:
case BSL_CID_MLDSA87_RSA4096_PSS_SHA512:
case BSL_CID_MLDSA87_ECDSA_P521_SHA512:
    return ParseCompositePubkeyAsn1Buff(...);
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
