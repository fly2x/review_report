# Code Review: openHiTLS/pqcp#33
**Reviewer**: CODEX


## High

### Partial initialization left behind on allocation failure
`src/composite_sign/src/crypt_composite_sign.c:190-199`
```
ctx->pqcMethod = pqcMethod;
ctx->tradMethod = tradMethod;
ctx->pqcCtx = pqcMethod->newCtx();
RETURN_RET_IF((ctx->pqcCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
ctx->tradCtx = tradMethod->newCtx();
if (ctx->tradCtx == NULL) {
    pqcMethod->freeCtx(ctx->pqcCtx);
    ctx->pqcCtx = NULL;
    return CRYPT_MEM_ALLOC_FAIL;
}
```
**Issue**: `CRYPT_CompositeSetAlgInfo` sets `ctx->info` and method pointers before allocating subcontexts. If `newCtx()` fails, the function returns with `ctx->info` still set and `ctx->pqcCtx`/`ctx->tradCtx` null. This makes the context unrecoverable (`SET_PARA_BY_ID` returns “already set”) and can later hit null subcontext paths.
**Fix**:
```
const COMPOSITE_ALG_INFO *info = CRYPT_COMPOSITE_GetInfo(*(int32_t *)val);
if (info == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}

const EAL_PkeyMethod *pqcMethod = CRYPT_EAL_PkeyFindMethod(info->pqcAlg);
const EAL_PkeyMethod *tradMethod = CRYPT_EAL_PkeyFindMethod(info->tradAlg);
RETURN_RET_IF((pqcMethod == NULL || tradMethod == NULL), CRYPT_NOT_SUPPORT);

void *pqcCtx = pqcMethod->newCtx();
RETURN_RET_IF(pqcCtx == NULL, CRYPT_MEM_ALLOC_FAIL);

void *tradCtx = tradMethod->newCtx();
if (tradCtx == NULL) {
    pqcMethod->freeCtx(pqcCtx);
    return CRYPT_MEM_ALLOC_FAIL;
}

ctx->info = info;
ctx->pqcMethod = pqcMethod;
ctx->tradMethod = tradMethod;
ctx->pqcCtx = pqcCtx;
ctx->tradCtx = tradCtx;
```

---

### Public PolarLAC control IDs no longer handled
`src/polarlac/src/polarlac.c:263-290`
```
switch (cmd) {
    case CRYPT_CTRL_SET_PARA_BY_ID:
        return PolarLacSetAlgInfo(ctx, val, valLen);
    case CRYPT_CTRL_GET_CIPHERTEXT_LEN:
        ...
    case CRYPT_CTRL_GET_PRVKEY_LEN:
        ...
    case CRYPT_CTRL_GET_PUBKEY_LEN:
        ...
```
**Issue**: The control switch now accepts only generic `CRYPT_CTRL_*` IDs, but `include/pqcp_types.h` still exposes `PQCP_POLAR_LAC_*` IDs and existing callers use them. This is a runtime compatibility break (`PQCP_INVALID_ARG`) for existing API users.
**Fix**:
```
switch (cmd) {
    case PQCP_POLAR_LAC_SET_PARAMS_BY_ID:
    case CRYPT_CTRL_SET_PARA_BY_ID:
        return PolarLacSetAlgInfo(ctx, val, valLen);

    case PQCP_POLAR_LAC_GET_CIPHER_LEN:
    case CRYPT_CTRL_GET_CIPHERTEXT_LEN:
        ...

    case PQCP_POLAR_LAC_GET_PRVKEY_LEN:
    case CRYPT_CTRL_GET_PRVKEY_LEN:
        ...

    case PQCP_POLAR_LAC_GET_PUBKEY_LEN:
    case CRYPT_CTRL_GET_PUBKEY_LEN:
        ...
```

---


## Medium

### DupCtx does not copy signing context info
`src/composite_sign/src/crypt_composite_sign.c:125-137`
```
newCtx->info = ctx->info;
...
newCtx->pqcMethod = ctx->pqcMethod;
newCtx->tradMethod = ctx->tradMethod;
newCtx->libCtx = ctx->libCtx;
return newCtx;
```
**Issue**: `CRYPT_COMPOSITE_DupCtx` duplicates keys/methods but drops `ctxInfo`/`ctxLen`. Any context string set via `CRYPT_CTRL_SET_CTX_INFO` is lost in the duplicate, so signatures from original and duplicate can diverge unexpectedly.
**Fix**:
```
newCtx->info = ctx->info;
newCtx->pqcMethod = ctx->pqcMethod;
newCtx->tradMethod = ctx->tradMethod;
newCtx->libCtx = ctx->libCtx;

if (ctx->ctxLen > 0) {
    newCtx->ctxInfo = BSL_SAL_Dump(ctx->ctxInfo, ctx->ctxLen);
    if (newCtx->ctxInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    newCtx->ctxLen = ctx->ctxLen;
}
return newCtx;
```

---

### SetCtxInfo rejects valid clear operation and misclassifies null input
`src/composite_sign/src/crypt_composite_sign.c:212-227`
```
if (len > COMPOSITE_MAX_CTX_BYTES) {
    ...
}
if (ctx->ctxInfo != NULL) {
    BSL_SAL_FREE(ctx->ctxInfo);
    ctx->ctxLen = 0;
}
ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
if (ctx->ctxInfo == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
    return CRYPT_MEM_ALLOC_FAIL;
}
ctx->ctxLen = len;
```
**Issue**: `CRYPT_CompositeSetctxInfo` always calls `BSL_SAL_Dump(val, len)`. With `len == 0`, `BSL_SAL_Dump` returns null and this path returns `CRYPT_MEM_ALLOC_FAIL`, so callers cannot clear context info. Also `val == NULL && len > 0` is treated as allocation failure instead of null input.
**Fix**:
```
if (len > COMPOSITE_MAX_CTX_BYTES) {
    BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
    return PQCP_COMPOSITE_KEYLEN_ERROR;
}

if (len == 0) {
    BSL_SAL_FREE(ctx->ctxInfo);
    ctx->ctxInfo = NULL;
    ctx->ctxLen = 0;
    return CRYPT_SUCCESS;
}

if (val == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return CRYPT_NULL_INPUT;
}

BSL_SAL_FREE(ctx->ctxInfo);
ctx->ctxInfo = BSL_SAL_Dump(val, len);
if (ctx->ctxInfo == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
    return CRYPT_MEM_ALLOC_FAIL;
}
ctx->ctxLen = len;
```

---


## Low

### Uninitialized context pointers freed on error path
`test/demo/composite_sign_demo.c:22-23`
```
CRYPT_EAL_PkeyCtx *signCtx;
CRYPT_EAL_PkeyCtx *verifyCtx;
...
EXIT:
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
```
**Issue**: `signCtx` and `verifyCtx` are uninitialized. If context creation fails and execution jumps to `EXIT`, `CRYPT_EAL_PkeyFreeCtx` may be called on garbage pointers.
**Fix**:
```
CRYPT_EAL_PkeyCtx *signCtx = NULL;
CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
...
EXIT:
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
```

---
