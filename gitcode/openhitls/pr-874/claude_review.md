# Code Review: openHiTLS/openhitls#874
**Reviewer**: CLAUDE


## High

### Missing NULL check for tradMethod->dupCtx result before use
`crypto/composite/src/composite.c:181-192`
```
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
        newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
        newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
        if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
```
**Issue**: In CRYPT_COMPOSITE_DupCtx, if pqcMethod->dupCtx succeeds but tradMethod->dupCtx fails, the code returns NULL without cleaning up the successfully allocated pqcCtx. More critically, it uses newCtx->pqcCtx which could be non-NULL to check if both succeeded, but if tradCtx allocation fails, pqcCtx is leaked.
**Fix**:
```
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
        newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
        if (newCtx->pqcCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
        newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
        if (newCtx->tradCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
```

---

### Missing NULL check on method before dereferencing in sign/verify
`crypto/composite/src/composite.c:479`
```
GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    int32_t pqcRet = ctx->pqcMethod->sign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, &pqcSigLen);
    int32_t tradRet = ctx->tradMethod->sign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
                                           &tradSigLen);
```
**Issue**: In CRYPT_COMPOSITE_Sign, the code calls ctx->pqcMethod->sign and ctx->tradMethod->sign but doesn't verify that ctx->pqcMethod and ctx->tradMethod are non-NULL before use. If these are NULL, it will crash.
**Fix**:
```
RETURN_RET_IF(ctx->pqcMethod == NULL || ctx->tradMethod == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    int32_t pqcRet = ctx->pqcMethod->sign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, &pqcSigLen);
    int32_t tradRet = ctx->tradMethod->sign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
                                           &tradSigLen);
```

---

### Invalid range check for composite key type
`crypto/codecskey/src/crypt_decoder_composite.c:30-33`
```
bool isCompositePubkey = (subPubkeyInfo.keyType >= BSL_CID_MLDSA44_RSA2048_PSS_SHA256 &&
                                   subPubkeyInfo.keyType <= BSL_CID_MLDSA87_ECDSA_P521_SHA512);
```
**Issue**: The range check uses hardcoded min/max values instead of constants. If new composite algorithms are added between these values but outside the expected range, they would be rejected. More critically, the check doesn't account for potential gaps in the enum values.
**Fix**:
```
bool isCompositePubkey = (subPubkeyInfo.keyType >= BSL_CID_MLDSA44_RSA2048_PSS_SHA256 &&
                                   subPubkeyInfo.keyType <= BSL_CID_MLDSA87_ECDSA_P521_SHA512) &&
                                  !((subPubkeyInfo.keyType > BSL_CID_MLDSA87_ECDSA_P521_SHA512 &&
                                     subPubkeyInfo.keyType < BSL_CID_MLDSA44_ED25519_SHA512));
```

---

### Return value ignored in CRYPT_CompositeGetEd25519PubKey
`crypto/composite/src/composite_encdec.c:254-260`
```
static int32_t CRYPT_CompositeGetEd25519PubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen));
    RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```
**Issue**: The return value from ctx->tradMethod->ctrl is ignored, but then pubLen is used. If the ctrl call fails, pubLen remains 0, causing BITS_TO_BYTES(0) = 0, leading to 0-size allocation.
**Fix**:
```
static int32_t CRYPT_CompositeGetEd25519PubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
    RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```

---


## Medium

### Missing NULL check for ctx->info before dereferencing
`crypto/composite/src/composite.c:257-262`
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
        return CRYPT_COMPOSITE_KEYLEN_ERROR;
    }
```
**Issue**: CRYPT_CompositeSetctxInfo uses ctx->info without checking if it's NULL first. If ctx->info is NULL, ctx->prvLen and ctx->pubLen may not be initialized, potentially leading to issues.
**Fix**:
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
        return CRYPT_COMPOSITE_KEYLEN_ERROR;
    }
```

---

### Missing NULL check for ctx->info in CRYPT_CompositeGetParaId
`crypto/composite/src/composite.c:283-288`
```
static int32_t CRYPT_CompositeGetParaId(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    *(int32_t *)val = ctx->info->paramId;
    return CRYPT_SUCCESS;
}
```
**Issue**: The function returns CRYPT_COMPOSITE_KEYINFO_NOT_SET if ctx->info is NULL, but it doesn't check if ctx itself is NULL first.
**Fix**:
```
static int32_t CRYPT_CompositeGetParaId(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    *(int32_t *)val = ctx->info->paramId;
    return CRYPT_SUCCESS;
}
```

---

### Potential integer overflow in length calculation
`crypto/composite/src/composite.c:364-367`
```
ctx->prvLen = pqcPrv.dataLen + tradPrv.dataLen;
    ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
    RETURN_RET_IF_ERR(CRYPT_CompositeCreateKeyBuf(ctx), ret);
```
**Issue**: The length calculation `pqcPrv.dataLen + tradPrv.dataLen` could overflow if both values are large. While unlikely with the current key sizes, defensive coding should prevent this.
**Fix**:
```
if (pqcPrv.dataLen > UINT32_MAX - tradPrv.dataLen || pqcPub.dataLen > UINT32_MAX - tradPub.dataLen) {
        ret = CRYPT_COMPOSITE_KEYLEN_ERROR;
        goto ERR;
    }
    ctx->prvLen = pqcPrv.dataLen + tradPrv.dataLen;
    ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
    RETURN_RET_IF_ERR(CRYPT_CompositeCreateKeyBuf(ctx), ret);
```

---

### Missing bounds check before memcpy_s
`crypto/composite/src/composite.c:409-414`
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->prvKey = (uint8_t *)BSL_SAL_Malloc(prv->len);
```
**Issue**: CRYPT_COMPOSITE_SetPrvKey checks that prv->len > pqcPrvkeyLen but doesn't verify that prv->len <= expected total key length. Malformed input could pass this check.
**Fix**:
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(prv->len > ctx->info->pqcPrvkeyLen + ctx->info->tradPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->prvKey = (uint8_t *)BSL_SAL_Malloc(prv->len);
```

---

### Missing bounds check in CRYPT_COMPOSITE_SetPubKey
`crypto/composite/src/composite.c:428-433`
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->pubKey = (uint8_t *)BSL_SAL_Malloc(pub->len);
```
**Issue**: Similar to SetPrvKey, only checks lower bound but not upper bound for total expected key length.
**Fix**:
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(pub->len > ctx->info->pqcPubkeyLen + ctx->info->tradPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->pubKey = (uint8_t *)BSL_SAL_Malloc(pub->len);
```

---

### Unchecked return value from memcpy_s
`crypto/composite/src/composite.c:147`
```
(void)memcpy_s(ctx->prvKey, ctx->prvLen, pqcPrv.data, pqcPrv.dataLen);
    (void)memcpy_s(ctx->prvKey + pqcPrv.dataLen, ctx->prvLen - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
    (void)memcpy_s(ctx->pubKey, ctx->pubLen, pqcPub.data, pqcPub.dataLen);
    (void)memcpy_s(ctx->pubKey + pqcPub.dataLen, ctx->pubLen - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
```
**Issue**: The return values from memcpy_s calls are explicitly cast to void and ignored. If the memcpy fails, the function continues with potentially corrupted data.
**Fix**:
```
ret = memcpy_s(ctx->prvKey, ctx->prvLen, pqcPrv.data, pqcPrv.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
    ret = memcpy_s(ctx->prvKey + pqcPrv.dataLen, ctx->prvLen - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
    ret = memcpy_s(ctx->pubKey, ctx->pubLen, pqcPub.data, pqcPub.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
    ret = memcpy_s(ctx->pubKey + pqcPub.dataLen, ctx->pubLen - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
```

---

### Missing error code push on failure
`crypto/codecskey/src/crypt_decoder_composite.c:69`
```
CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
```
**Issue**: When CRYPT_COMPOSITE_NewCtxEx fails, the function returns CRYPT_MEM_ALLOC_FAIL without pushing the error code using BSL_ERR_PUSH_ERROR, unlike other error paths.
**Fix**:
```
CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
```

---
