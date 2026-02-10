# Code Review: openHiTLS/pqcp#33
**Reviewer**: CODEX


## High

### Hybrid length controls can dereference NULL `val`
`src/composite_sign/src/crypt_composite_sign.c:29-42`
```
#define CHECK_UINT32_LEN_AND_INFO(ctx, len)                      \
    do                                                           \
    {                                                            \
        if (len != sizeof(uint32_t))                             \
        {                                                        \
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);               \
            return CRYPT_INVALID_ARG;                            \
        }                                                        \
        if (ctx->info == NULL)                                   \
        {                                                        \
            BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYINFO_NOT_SET); \
            return PQCP_COMPOSITE_KEYINFO_NOT_SET;              \
        }                                                        \
    } while (0)

case PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN:
    CHECK_UINT32_LEN_AND_INFO(ctx, len);
    *(uint32_t *)val = MLDSA_SEED_LEN;
    return CRYPT_SUCCESS;
```
**Issue**: `CHECK_UINT32_LEN_AND_INFO` validates `len` and `ctx->info` but never validates `val`. In `PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN`, `val` is dereferenced unconditionally, which can crash on `CRYPT_COMPOSITE_Ctrl(ctx, ..., NULL, sizeof(uint32_t))`.
**Fix**:
```
#define CHECK_UINT32_LEN_AND_INFO(ctx, val, len)                        \
    do                                                                   \
    {                                                                    \
        if ((val) == NULL || (len) != sizeof(uint32_t))                 \
        {                                                                \
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);                       \
            return CRYPT_INVALID_ARG;                                    \
        }                                                                \
        if ((ctx)->info == NULL || (ctx)->pqcCtx == NULL || (ctx)->tradCtx == NULL) \
        {                                                                \
            BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYINFO_NOT_SET);         \
            return PQCP_COMPOSITE_KEYINFO_NOT_SET;                      \
        }                                                                \
    } while (0)

case PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN:
    CHECK_UINT32_LEN_AND_INFO(ctx, val, len);
    *(uint32_t *)val = MLDSA_SEED_LEN;
    return CRYPT_SUCCESS;
```

---


## Medium

### Failed `SET_PARA_BY_ID` leaves context in partially initialized state
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
**Issue**: On `pqcMethod->newCtx()` or `tradMethod->newCtx()` failure, the function returns early after already setting `ctx->info`, `ctx->pqcMethod`, and `ctx->tradMethod`. This leaves the context unusable (`KEY_INFO_ALREADY_SET` on retry) and inconsistent.
**Fix**:
```
void *pqcCtx = pqcMethod->newCtx();
if (pqcCtx == NULL) {
    return CRYPT_MEM_ALLOC_FAIL;
}
void *tradCtx = tradMethod->newCtx();
if (tradCtx == NULL) {
    pqcMethod->freeCtx(pqcCtx);
    return CRYPT_MEM_ALLOC_FAIL;
}
int32_t pqcParam = info->pqcParam;
ret = pqcMethod->ctrl(pqcCtx, CRYPT_CTRL_SET_PARA_BY_ID, &pqcParam, sizeof(pqcParam));
if (ret != CRYPT_SUCCESS) {
    pqcMethod->freeCtx(pqcCtx);
    tradMethod->freeCtx(tradCtx);
    return ret;
}

ctx->info = info;
ctx->pqcMethod = pqcMethod;
ctx->tradMethod = tradMethod;
ctx->pqcCtx = pqcCtx;
ctx->tradCtx = tradCtx;
```

---

### `DupCtx` leaks duplicated sub-context on partial failure
`src/composite_sign/src/crypt_composite_sign.c:125-139`
```
newCtx->info = ctx->info;
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
    newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
    newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
    if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
}
newCtx->pqcMethod = ctx->pqcMethod;
newCtx->tradMethod = ctx->tradMethod;
```
**Issue**: `newCtx->pqcMethod`/`tradMethod` are assigned only after duplication. If one duplication succeeds and the other fails, `CRYPT_COMPOSITE_FreeCtx(newCtx)` cannot free the already duplicated sub-context because method pointers are still NULL.
**Fix**:
```
newCtx->info = ctx->info;
newCtx->pqcMethod = ctx->pqcMethod;
newCtx->tradMethod = ctx->tradMethod;

if (newCtx->pqcMethod != NULL && newCtx->tradMethod != NULL) {
    newCtx->pqcCtx = newCtx->pqcMethod->dupCtx(ctx->pqcCtx);
    newCtx->tradCtx = newCtx->tradMethod->dupCtx(ctx->tradCtx);
    if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
        if (newCtx->pqcCtx != NULL) {
            newCtx->pqcMethod->freeCtx(newCtx->pqcCtx);
            newCtx->pqcCtx = NULL;
        }
        if (newCtx->tradCtx != NULL) {
            newCtx->tradMethod->freeCtx(newCtx->tradCtx);
            newCtx->tradCtx = NULL;
        }
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
}
```

---

### `DupCtx` does not copy context-binding data (`ctxInfo`)
`src/composite_sign/src/crypt_composite_sign.c:125-137`
```
newCtx->info = ctx->info;
...
newCtx->pqcMethod = ctx->pqcMethod;
newCtx->tradMethod = ctx->tradMethod;
newCtx->libCtx = ctx->libCtx;
return newCtx;
```
**Issue**: `CRYPT_COMPOSITE_DupCtx` copies key contexts but not `ctxInfo`/`ctxLen`. Sign/verify encoding uses `ctxInfo`, so duplicated contexts can produce different signatures from the original when context info is set.
**Fix**:
```
newCtx->info = ctx->info;
newCtx->pqcMethod = ctx->pqcMethod;
newCtx->tradMethod = ctx->tradMethod;
newCtx->libCtx = ctx->libCtx;
newCtx->ctxLen = ctx->ctxLen;

if (ctx->ctxLen > 0) {
    newCtx->ctxInfo = BSL_SAL_Dump(ctx->ctxInfo, ctx->ctxLen);
    if (newCtx->ctxInfo == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
}
```

---

### Control command compatibility regression for PolarLAC
`src/polarlac/src/polarlac.c:263-284`
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
    default:
        return PQCP_INVALID_ARG;
}
```
**Issue**: The control switch dropped support for existing `PQCP_POLAR_LAC_*` command IDs and only accepts `CRYPT_CTRL_*`. Existing callers using documented PQCP command IDs now get `PQCP_INVALID_ARG`.
**Fix**:
```
switch (cmd) {
    case CRYPT_CTRL_SET_PARA_BY_ID:
    case PQCP_POLAR_LAC_SET_PARAMS_BY_ID:
        return PolarLacSetAlgInfo(ctx, val, valLen);

    case CRYPT_CTRL_GET_CIPHERTEXT_LEN:
    case PQCP_POLAR_LAC_GET_CIPHER_LEN:
        ...

    case CRYPT_CTRL_GET_PRVKEY_LEN:
    case PQCP_POLAR_LAC_GET_PRVKEY_LEN:
        ...

    case CRYPT_CTRL_GET_PUBKEY_LEN:
    case PQCP_POLAR_LAC_GET_PUBKEY_LEN:
        ...
}
```

---


## Low

### Uninitialized pointer may be freed on early error path
`test/demo/composite_sign_demo.c:22-23`
```
int32_t ret = -1;
CRYPT_EAL_PkeyCtx *signCtx;
CRYPT_EAL_PkeyCtx *verifyCtx;
...
EXIT:
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
```
**Issue**: `verifyCtx` is not initialized before possible `goto EXIT`, but `CRYPT_EAL_PkeyFreeCtx(verifyCtx)` is always called in `EXIT`. If `signCtx` creation fails, `verifyCtx` is indeterminate and freeing it is undefined behavior.
**Fix**:
```
int32_t ret = -1;
CRYPT_EAL_PkeyCtx *signCtx = NULL;
CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
...
EXIT:
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
```

---
