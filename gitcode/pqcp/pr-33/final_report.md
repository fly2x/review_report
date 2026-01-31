# Final Code Review Report
## openhitls/pqcp - PR #33

### Summary
- **Total Issues**: 12
- **Critical**: 1
- **High**: 5
- **Medium**: 4
- **Low**: 2
- **Reviewers**: claude, gemini, codex

---


## Critical

### Incorrect buffer pointer causes traditional private key to use PQC key data
`src/composite_sign/src/crypt_composite_sign.c:387`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
BSL_Buffer tradPrv = {prv->data, + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```
**Issue**: The tradPrv buffer is incorrectly initialized with `prv->data` instead of `prv->data + ctx->info->pqcPrvkeyLen`. The comma operator in the brace initializer `{prv->data, + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen}` evaluates to just the last value, and the data pointer is set to the start of the buffer instead of the offset. This causes the traditional private key to be set using PQC private key data, corrupting key imports.
**Fix**:
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```

---


## High

### Duplicate const qualifier is invalid C syntax
`src/provider/pqcp_pkey.c:145`
**Reviewers**: CLAUDE, CODEX, GEMINI | **置信度**: 可信
```
const const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```
**Issue**: The declaration uses `const const` which is not valid C syntax and will cause a compilation error.
**Fix**:
```
const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```

---

### Missing break statement causes fallthrough in switch case
`src/composite_sign/src/crypt_composite_sign.c:44-46`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
case CRYPT_PKEY_COMPOSITE_SIGN:
    pkeyCtx = CRYPT_COMPOSITE_NewCtx();
default:
    break;
```
**Issue**: The CRYPT_PKEY_COMPOSITE_SIGN case is missing a break statement, causing fallthrough to the default case. This means pkeyCtx will be set to NULL even though CRYPT_COMPOSITE_NewCtx() was called, because the default case doesn't set pkeyCtx.
**Fix**:
```
case CRYPT_PKEY_COMPOSITE_SIGN:
    pkeyCtx = CRYPT_COMPOSITE_NewCtx();
    break;
default:
    break;
```

---

### Wrong memcpy_s size parameter uses digestLen instead of destination buffer size
`src/composite_sign/src/crypt_composite_sign.c:506`
**Reviewers**: CLAUDE | **置信度**: 可信
```
(void)memcpy_s(ptr, digestLen, digest, digestLen);
```
**Issue**: The memcpy_s call uses digestLen as the size parameter instead of the actual destination buffer size. The memcpy_s function expects the destination buffer size as the second parameter, not the source length.
**Fix**:
```
(void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1 + ctx->ctxLen), digest, digestLen);
```

---

### CRYPT_COMPOSITE_DupCtx does not check if ctx->info is NULL before dereferencing
`src/composite_sign/src/crypt_composite_sign.c:127`
**Reviewers**: CLAUDE | **置信度**: 可信
```
newCtx->info = ctx->info;
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
```
**Issue**: The function assigns ctx->info to newCtx->info without checking if ctx->info is NULL. If a context is duplicated before setting algorithm info, the duplicated context will have NULL info, leading to potential crashes when used.
**Fix**:
```
if (ctx->info == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    return NULL;
}
newCtx->info = ctx->info;
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
```

---

### GetParamValue return value not checked before dereferencing causing potential NULL dereference
`src/composite_sign/src/crypt_composite_sign.c:414-435`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
if (ret != CRYPT_SUCCESS) {
    return ret;
}
paramPrv->useLen = prv.len;
```
**Issue**: In CRYPT_COMPOSITE_GetPrvKeyEx and CRYPT_COMPOSITE_GetPubKeyEx, the return value of GetParamValue is not checked. If the parameter is not found (returns NULL), paramPrv/paramPub is dereferenced, causing a crash.
**Fix**:
```
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
```

---


## Medium

### Composite key length validation allows truncated traditional keys
`src/composite_sign/src/crypt_composite_sign.c:385`
**Reviewers**: CODEX | **置信度**: 可信
```
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
```
**Issue**: The length checks only ensure the buffer is larger than the PQC part (using `<=` comparison instead of exact length match), so a too-short TRAD component can be accepted, resulting in malformed keys and undefined behavior in downstream algorithms.
**Fix**:
```
RETURN_RET_IF(prv->len != ctx->info->compPrvKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
```

---

### CRYPT_CTRL_SET_CTX_INFO does not validate val before BSL_SAL_Dump
`src/composite_sign/src/crypt_composite_sign.c:224`
**Reviewers**: CODEX | **置信度**: 可信
```
if (len > COMPOSITE_MAX_CTX_BYTES) {
    BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
    return CRYPT_COMPOSITE_KEYLEN_ERROR;
}
ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
```
**Issue**: The val parameter is not validated before being passed to BSL_SAL_Dump. If the caller passes len > 0 with val == NULL, BSL_SAL_Dump will dereference NULL and crash.
**Fix**:
```
if (len > COMPOSITE_MAX_CTX_BYTES) {
    BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
    return CRYPT_COMPOSITE_KEYLEN_ERROR;
}
if (val == NULL && len > 0) {
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return CRYPT_NULL_INPUT;
}
ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
```

---

### GetConstParamValue return value ignored in SetPrvKeyEx/SetPubKeyEx
`src/composite_sign/src/crypt_composite_sign.c:446`
**Reviewers**: CLAUDE | **置信度**: 可信
```
CRYPT_CompositePrv prv = {0};
(void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
```
**Issue**: The return value of GetConstParamValue is cast to void and ignored. If the parameter is not found, prv.data and prv.len remain uninitialized (zero), which will cause CRYPT_COMPOSITE_SetPrvKey to fail with a misleading error.
**Fix**:
```
CRYPT_CompositePrv prv = {0};
if (GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len) == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}
return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
```

---

### Duplicate algorithm labels for MLDSA65 and MLDSA87 composite algorithms
`src/composite_sign/src/crypt_composite_sign.c:54-58`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
{CRYPT_COMPOSITE_MLDSA44_SM2, "COMPSIG-MLDSA44-SM2", ...},
{CRYPT_COMPOSITE_MLDSA65_SM2, "COMPSIG-MLDSA44-SM2", ...},
{CRYPT_COMPOSITE_MLDSA87_SM2, "COMPSIG-MLDSA44-SM2", ...},
```
**Issue**: All three entries in g_composite_info have the same label "COMPSIG-MLDSA44-SM2". The labels for MLDSA65 and MLDSA87 should match their algorithm IDs. The domain-separation label in the signed message is incorrect for those variants, which can break interoperability and produce non-spec signatures.
**Fix**:
```
{CRYPT_COMPOSITE_MLDSA44_SM2, "COMPSIG-MLDSA44-SM2", ...},
{CRYPT_COMPOSITE_MLDSA65_SM2, "COMPSIG-MLDSA65-SM2", ...},
{CRYPT_COMPOSITE_MLDSA87_SM2, "COMPSIG-MLDSA87-SM2", ...},
```

---


## Low

### Missing null check after malloc before use in CRYPT_CompositeGetMldsaPrvKey
`src/composite_sign/src/crypt_composite_sign_encdec.c:42-47`
**Reviewers**: CLAUDE | **置信度**: 可信
```
uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
RETURN_RET_IF(prv == NULL, CRYPT_MEM_ALLOC_FAIL);
GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_MLDSA_SEED, prv, prvLen), ret);
encode->data = prv;
encode->dataLen = prvLen;
```
**Issue**: In CRYPT_CompositeGetMldsaPrvKey, the return value of the ctrl call is not checked before using the result in encode->dataLen. If the ctrl call fails, the allocated memory leaks.
**Fix**:
```
uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
RETURN_RET_IF(prv == NULL, CRYPT_MEM_ALLOC_FAIL);
ret = ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_MLDSA_SEED, prv, prvLen);
if (ret != CRYPT_SUCCESS) {
    BSL_SAL_Free(prv);
    return ret;
}
encode->data = prv;
encode->dataLen = prvLen;
```

---

### CRYPT_COMPOSITE_GetPrvKeyEx does not validate ctx parameter
`src/composite_sign/src/crypt_composite_sign.c:407`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
```
**Issue**: The function only checks if para is NULL but doesn't validate ctx before calling CRYPT_COMPOSITE_GetPrvKey. This means error messages may be misleading when ctx is NULL.
**Fix**:
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL || ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
```

---
