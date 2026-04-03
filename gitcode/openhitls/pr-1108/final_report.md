# Final Code Review Report
## openHiTLS/openhitls - PR #1108

### Summary
- **Total Issues**: 12
- **Critical**: 0
- **High**: 6
- **Medium**: 4
- **Low**: 2
- **Reviewers**: claude, gemini, codex

---


## High

### ECDSA composite public keys allocate only one coordinate
`crypto/composite/src/composite_encdec.c:292-301`
**Reviewers**: CODEX | **置信度**: 可信
```
static int32_t CRYPT_CompositeGetEcdsaPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
    RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
    pubLen = BITS_TO_BYTES(pubLen);
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
```
**Issue**: CRYPT_CompositeGetEcdsaPubKey uses CRYPT_CTRL_GET_BITS which returns the curve size in bits (e.g., 256 for P-256), then converts to bytes. However, CRYPT_PARAM_EC_PUBKEY exports the full encoded EC point in uncompressed format (0x04 + X + Y), which requires 2*coordLen + 1 bytes. For P-256 this allocates 32 bytes instead of 65 bytes, for P-384 it allocates 48 bytes instead of 97 bytes. This causes getPub() to fail and breaks all ECDSA-based composite keygen/export paths.
**Fix**:
```
static int32_t CRYPT_CompositeGetEcdsaPubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t bits = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &bits, sizeof(bits)), ret);
    RETURN_RET_IF(bits == 0, CRYPT_EAL_ALG_NOT_SUPPORT);

    uint32_t coordLen = BITS_TO_BYTES(bits);
    uint32_t pubLen = (coordLen << 1) + 1; /* uncompressed EC point: 0x04 + X + Y */
    uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
    RETURN_RET_IF(pub == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
```

---

### Reinitializing a composite context can overflow stale key buffers
`crypto/composite/src/composite.c:246-293`
**Reviewers**: CODEX | **置信度**: 可信
```
static int32_t CRYPT_CompositeSetAlgInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    int32_t ret;
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const EAL_PkeyMethod *pqcMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->pqcAlg);
    const EAL_PkeyMethod *tradMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->tradAlg);
    if (pqcMethod == NULL || tradMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    ctx->pqcMethod = pqcMethod;
    ctx->tradMethod = tradMethod;
    ctx->pqcCtx = pqcMethod->newCtx();
    RETURN_RET_IF((ctx->pqcCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
    ctx->tradCtx = tradMethod->newCtx();
```
**Issue**: CRYPT_CompositeSetAlgInfo() can be called multiple times on the same context. It replaces ctx->info and allocates new subcontexts (pqcCtx, tradCtx), but CRYPT_CompositeCreateKeyBuf() only allocates when pubKey/prvKey are NULL. If the context already holds a smaller key and is reconfigured to a larger algorithm, CRYPT_COMPOSITE_GenKey() will copy the larger key into the old smaller allocation, causing heap buffer overflow. Additionally, repeated initialization leaks the old pqcCtx and tradCtx.
**Fix**:
```
static int32_t CRYPT_CompositeSetAlgInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    int32_t ret;
    if (len != sizeof(int32_t) || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    /* Prevent reinitialization which could cause buffer overflow */
    if (ctx->info != NULL || ctx->pqcCtx != NULL || ctx->tradCtx != NULL ||
        ctx->pubKey != NULL || ctx->prvKey != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    const EAL_PkeyMethod *pqcMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->pqcAlg);
    const EAL_PkeyMethod *tradMethod = CRYPT_EAL_PkeyFindMethod(ctx->info->tradAlg);
    if (pqcMethod == NULL || tradMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
        return CRYPT_NOT_SUPPORT;
    }
    ctx->pqcMethod = pqcMethod;
    ctx->tradMethod = tradMethod;
    ctx->pqcCtx = pqcMethod->newCtx();
```

---

### Potential use of uninitialized data in CRYPT_COMPOSITE_SetPrvKeyEx
`crypto/composite/src/composite.c:517-526`
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: GetConstParamValue return value is ignored with (void) cast. If the parameter is not found, prv.data and prv.len won't be set, leaving them at their initialized zero values. The subsequent CRYPT_COMPOSITE_SetPrvKey call will use this uninitialized data, causing incorrect key length validation failures or potential memory issues.
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
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: GetConstParamValue return value is ignored with (void) cast. If the parameter is not found, pub.data and pub.len won't be set, leaving them at their initialized zero values. The subsequent CRYPT_COMPOSITE_SetPubKey call will use this uninitialized data.
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
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: GetParamValue may return NULL if the parameter is not found, but the code doesn't check for this before dereferencing paramPrv to set paramPrv->useLen. This will cause a NULL pointer dereference and crash.
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
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: GetParamValue may return NULL if the parameter is not found, but the code doesn't check for this before dereferencing paramPub to set paramPub->useLen. This will cause a NULL pointer dereference and crash.
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

### CRYPT_CTRL_SET_RSA_E is ignored after parameter setup
`crypto/composite/src/composite.c:210-224`
**Reviewers**: CODEX | **置信度**: 可信
```
static int32_t CRYPT_CompositeSetRsaE(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL && len == 0) {
        BSL_SAL_FREE(ctx->e);
        ctx->eLen = 0;
        return CRYPT_SUCCESS;
    }
    RETURN_RET_IF((val == NULL || len == 0), CRYPT_INVALID_ARG);
    uint8_t *e = BSL_SAL_Dump((uint8_t *)val, len);
    RETURN_RET_IF(e == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_FREE(ctx->e);
    ctx->e = e;
    ctx->eLen = len;
    return CRYPT_SUCCESS;
}
```
**Issue**: CRYPT_CompositeSetRsaE only stores the exponent in ctx->e but doesn't call CRYPT_CompositeSetRsaPara to apply it. In the normal call order (PkeySetParaById then PkeyCtrl(...SET_RSA_E...) then PkeyGen), the RSA subcontext is configured in SetParaById with the default exponent 65537, and the later SET_RSA_E call doesn't update the subcontext, so the generated key still uses the default exponent.
**Fix**:
```
static int32_t CRYPT_CompositeSetRsaE(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (val == NULL && len == 0) {
        BSL_SAL_FREE(ctx->e);
        ctx->eLen = 0;
        /* Reset to default exponent if subcontext exists */
        if (ctx->info != NULL && ctx->tradCtx != NULL && ctx->info->tradAlg == CRYPT_PKEY_RSA) {
            return CRYPT_CompositeSetRsaPara(ctx);
        }
        return CRYPT_SUCCESS;
    }
    RETURN_RET_IF((val == NULL || len == 0), CRYPT_INVALID_ARG);
    uint8_t *e = BSL_SAL_Dump((uint8_t *)val, len);
    RETURN_RET_IF(e == NULL, CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_FREE(ctx->e);
    ctx->e = e;
    ctx->eLen = len;
    /* Apply the new exponent if subcontext exists */
    if (ctx->info != NULL && ctx->tradCtx != NULL && ctx->info->tradAlg == CRYPT_PKEY_RSA) {
        return CRYPT_CompositeSetRsaPara(ctx);
    }
    return CRYPT_SUCCESS;
}
```

---

### MLDSA87/P-384 private-key length table has a misplaced digit
`crypto/composite/src/composite.c:71-73`
**Reviewers**: CODEX | **置信度**: 可信
```
static const COMPOSITE_ALG_INFO g_composite_info[] = {
    ...
    {CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512, "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP384,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 0, 2689, 962, 2592, 32, 4627},
```
**Issue**: The max composite private-key length for CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512 is recorded as 962 instead of 96. CRYPT_COMPOSITE_SetPrvKey uses this table entry as its upper bound, so malformed inputs with a valid 96-byte P-384 private key plus trailing garbage are accepted. The correct value for P-384 ECDSA private key (48 bytes) + ML-DSA-87 private key (2432 bytes) should give a tradPrvkeyLen of 96, not 962.
**Fix**:
```
static const COMPOSITE_ALG_INFO g_composite_info[] = {
    ...
    {CRYPT_COMPOSITE_MLDSA87_ECDSA_P384_SHA512, "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
     CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87, CRYPT_PKEY_ECDSA, CRYPT_ECC_NISTP384,
     CRYPT_MD_SHA512, CRYPT_MD_SHA384, 0, 2689, 96, 2592, 32, 4627},
```

---

### Ed448 composite OIDs are routed to an unimplemented parser
`crypto/codecskey/src/crypt_codecskey_local.c:1173`
**Reviewers**: CODEX | **置信度**: 可信
```
#ifdef HITLS_CRYPTO_COMPOSITE
        case BSL_CID_MLDSA87_ECDSA_P384_SHA512:
        case BSL_CID_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
        case BSL_CID_MLDSA87_ED448_SHAKE256:
        case BSL_CID_MLDSA87_RSA3072_PSS_SHA512:
        case BSL_CID_MLDSA87_RSA4096_PSS_SHA512:
        case BSL_CID_MLDSA87_ECDSA_P521_SHA512:
            return ParseCompositePrikeyAsn1Buff(libctx, attrName, pk8PrikeyInfo->pkeyRawKey,
                                                pk8PrikeyInfo->pkeyRawKeyLen, pk8PrikeyInfo->keyType, ealPriKey);
#endif
```
**Issue**: The PKCS#8 and SPKI dispatch tables treat BSL_CID_MLDSA87_ED448_SHAKE256 as a supported composite key type, but the composite implementation has no g_composite_info entry or traditional-key handler for Ed448 (CRYPT_PKEY_ED448). The comment at line 86 explicitly states "Ed448 not implemented, placeholder". Any key with this OID is advertised as supported but fails during CRYPT_EAL_PkeyFindMethod when setting algorithm parameters.
**Fix**:
```
#ifdef HITLS_CRYPTO_COMPOSITE
        case BSL_CID_MLDSA87_ECDSA_P384_SHA512:
        case BSL_CID_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512:
        case BSL_CID_MLDSA87_RSA3072_PSS_SHA512:
        case BSL_CID_MLDSA87_RSA4096_PSS_SHA512:
        case BSL_CID_MLDSA87_ECDSA_P521_SHA512:
            return ParseCompositePrikeyAsn1Buff(libctx, attrName, pk8PrikeyInfo->pkeyRawKey,
                                                pk8PrikeyInfo->pkeyRawKeyLen, pk8PrikeyInfo->keyType, ealPriKey);
#endif
```

---

### Missing NULL check for ctx->info->label in CompositeMsgEncode
`crypto/composite/src/composite.c:565-567`
**Reviewers**: CLAUDE | **置信度**: 可信
```
static int32_t CompositeMsgEncode(CRYPT_CompositeCtx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
                                  CRYPT_Data *msg)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);
    RETURN_RET_IF_ERR(CompositePreHash(hashId, data, dataLen, digest, &digestLen), ret);
    const char *label = ctx->info->label;
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
```
**Issue**: The code calls strlen(ctx->info->label) without verifying that ctx->info->label is not NULL. If label is NULL, this will cause a crash in strlen. The label field is a const char* that could be NULL.
**Fix**:
```
static int32_t CompositeMsgEncode(CRYPT_CompositeCtx *ctx, int32_t hashId, const uint8_t *data, uint32_t dataLen,
                                  CRYPT_Data *msg)
{
    int32_t ret;
    uint8_t digest[64];
    uint32_t digestLen = sizeof(digest);
    RETURN_RET_IF_ERR(CompositePreHash(hashId, data, dataLen, digest, &digestLen), ret);
    const char *label = ctx->info->label;
    if (label == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
    }
    uint32_t prefixLen = COMPOSITE_SIGNATURE_PREFIX_LEN;
    uint32_t labelLen = (uint32_t)strlen(label);
```

---


## Low

### Missing BSL_ERR_PUSH_ERROR after CRYPT_COMPOSITE_SetPrvKeyEx failure
`crypto/codecskey/src/crypt_decoder_composite.c:96-100`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
ret = CRYPT_COMPOSITE_SetPrvKeyEx(pctx, priParam);
if (ret != CRYPT_SUCCESS) {
    CRYPT_COMPOSITE_FreeCtx(pctx);
    return ret;
}
```
**Issue**: When CRYPT_COMPOSITE_SetPrvKeyEx fails, the error is not pushed via BSL_ERR_PUSH_ERROR before returning. This makes debugging harder as the actual error context from the failed call is lost.
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

### Missing HITLS_CRYPTO_COMPOSITE in PKEY_SIGN condition
`config/macro_config/hitls_config_layer_crypto.h:768-771`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY) || \
    defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_SM9) || \
    defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLDSA)
    #ifndef HITLS_CRYPTO_PKEY_SIGN
        #define HITLS_CRYPTO_PKEY_SIGN
    #endif
#endif
```
**Issue**: The preprocessor condition for HITLS_CRYPTO_PKEY_SIGN includes ML-DSA but not COMPOSITE. Since COMPOSITE keys support signing, this might cause issues with feature detection or linking when composite signature support is expected.
**Fix**:
```
#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY) || \
    defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN) || defined(HITLS_CRYPTO_SM9) || \
    defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLDSA) || \
    defined(HITLS_CRYPTO_COMPOSITE)
    #ifndef HITLS_CRYPTO_PKEY_SIGN
        #define HITLS_CRYPTO_PKEY_SIGN
    #endif
#endif
```

---
