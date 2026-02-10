# Final Code Review Report
## openHiTLS/pqcp - PR #33

### Summary
- **Total Issues**: 18
- **Critical**: 0
- **High**: 3
- **Medium**: 10
- **Low**: 5
- **Reviewers**: claude, gemini, codex

---


## High

### Non-existent hybrid_env include directory referenced
`CMakeLists.txt:98`
**Reviewers**: CLAUDE | **置信度**: 可信
```
target_include_directories(pqcp_provider
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/provider
        ${CMAKE_CURRENT_SOURCE_DIR}/src/scloudplus/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/classic_mceliece/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/frodokem/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/polarlac/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hybrid_env/include    // <- Does not exist
        ${CMAKE_CURRENT_SOURCE_DIR}/src/composite_sign/include
```
**Issue**: Line 98 adds `${CMAKE_CURRENT_SOURCE_DIR}/src/hybrid_env/include` to the include directories, but this directory does not exist in the repository. The commit messages indicate "移除hybrid_env相关代码" (Remove hybrid_env related code), so this reference was not cleaned up and will cause build failures.
**Fix**:
```
Remove the line:
${CMAKE_CURRENT_SOURCE_DIR}/src/hybrid_env/include
```

---

### Missing NULL check for input parameter val in CRYPT_CompositeSetctxInfo
`src/composite_sign/src/crypt_composite_sign.c:212-228`
**Reviewers**: GEMINI | **置信度**: 可信
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
        return PQCP_COMPOSITE_KEYLEN_ERROR;
    }
    if (ctx->ctxInfo != NULL) {
        BSL_SAL_FREE(ctx->ctxInfo);
        ctx->ctxLen = 0;
    }
    ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);  // val could be NULL
```
**Issue**: The function `CRYPT_CompositeSetctxInfo` does not check if `val` is NULL before passing it to `BSL_SAL_Dump`. If `len > 0` but `val` is NULL, `BSL_SAL_Dump` will dereference NULL and cause a segmentation fault.
**Fix**:
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
        return PQCP_COMPOSITE_KEYLEN_ERROR;
    }
    if (val == NULL && len > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->ctxInfo != NULL) {
        BSL_SAL_FREE(ctx->ctxInfo);
        ctx->ctxLen = 0;
    }
    ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
```

---

### Hybrid length controls can dereference NULL val parameter
`src/composite_sign/src/crypt_composite_sign.c:271-289`
**Reviewers**: CODEX | **置信度**: 可信
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
    *(uint32_t *)val = MLDSA_SEED_LEN;  // val could be NULL
```
**Issue**: The `CHECK_UINT32_LEN_AND_INFO` macro validates `len` and `ctx->info` but never validates `val`. In `PQCP_CTRL_HYBRID_GET_PQC_PRVKEY_LEN` and other hybrid controls, `val` is dereferenced unconditionally which can crash if called with NULL val.
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
        if ((ctx)->info == NULL)                                        \
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

### GetPrvKeyEx doesn't validate GetParamValue return value before dereferencing
`src/composite_sign/src/crypt_composite_sign.c:379-393`
**Reviewers**: CLAUDE | **置信度**: 可信
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPrv->useLen = prv.len;  // paramPrv could be NULL
    return CRYPT_SUCCESS;
}
```
**Issue**: The `CRYPT_COMPOSITE_GetPrvKeyEx` function calls `GetParamValue` but doesn't check if it returns NULL before using `paramPrv`. If `GetParamValue` fails or the parameter isn't found, `paramPrv` will be NULL and `paramPrv->useLen` will cause a NULL pointer dereference.
**Fix**:
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
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

### GetPubKeyEx doesn't validate GetParamValue return value before dereferencing
`src/composite_sign/src/crypt_composite_sign.c:395-409`
**Reviewers**: CLAUDE | **置信度**: 可信
```
int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
    int32_t ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    paramPub->useLen = pub.len;  // paramPub could be NULL
    return CRYPT_SUCCESS;
}
```
**Issue**: The `CRYPT_COMPOSITE_GetPubKeyEx` function has the same issue as `GetPrvKeyEx` - it doesn't check if `GetParamValue` returns NULL before using `paramPub`.
**Fix**:
```
int32_t CRYPT_COMPOSITE_GetPubKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    BSL_Param *paramPub = GetParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
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

### SetPrvKeyEx doesn't validate GetConstParamValue return value before using result
`src/composite_sign/src/crypt_composite_sign.c:411-420`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    (void)GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
}
```
**Issue**: The `CRYPT_COMPOSITE_SetPrvKeyEx` function calls `GetConstParamValue` but doesn't validate its return before using the result. The return value is explicitly cast to void. If the parameter isn't found, `prv.data` and `prv.len` remain uninitialized (zero), which could lead to incorrect behavior.
**Fix**:
```
int32_t CRYPT_COMPOSITE_SetPrvKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    int32_t ret = GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
}
```

---

### SetPubKeyEx doesn't validate GetConstParamValue return value before using result
`src/composite_sign/src/crypt_composite_sign.c:422-431`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    (void)GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
}
```
**Issue**: The `CRYPT_COMPOSITE_SetPubKeyEx` function has the same issue as `SetPrvKeyEx` - it doesn't validate `GetConstParamValue` return before using the result.
**Fix**:
```
int32_t CRYPT_COMPOSITE_SetPubKeyEx(CRYPT_CompositeCtx *ctx, const BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePub pub = {0};
    int32_t ret = GetConstParamValue(para, PQCP_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
}
```

---

### DupCtx leaks duplicated sub-context on partial failure
`src/composite_sign/src/crypt_composite_sign.c:114-141`
**Reviewers**: CODEX | **置信度**: 可信
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
**Issue**: In `CRYPT_COMPOSITE_DupCtx`, `newCtx->pqcMethod`/`tradMethod` are assigned only after duplication. If one duplication succeeds and the other fails, `CRYPT_COMPOSITE_FreeCtx(newCtx)` cannot free the already duplicated sub-context because the method pointers are still NULL, causing a memory leak.
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

### DupCtx does not copy context-binding data (ctxInfo/ctxLen)
`src/composite_sign/src/crypt_composite_sign.c:114-141`
**Reviewers**: CODEX | **置信度**: 可信
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

if (newCtx->pqcMethod != NULL && newCtx->tradMethod != NULL) {
    newCtx->pqcCtx = newCtx->pqcMethod->dupCtx(ctx->pqcCtx);
    newCtx->tradCtx = newCtx->tradMethod->dupCtx(ctx->tradCtx);
    if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
}
```

---

### Failed SET_PARA_BY_ID leaves context in partially initialized state
`src/composite_sign/src/crypt_composite_sign.c:168-210`
**Reviewers**: CODEX | **置信度**: 可信
```
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
```
**Issue**: On `pqcMethod->newCtx()` or `tradMethod->newCtx()` failure, or `ctrl` failure, the function returns early after already setting `ctx->info`, `ctx->pqcMethod`, and `ctx->tradMethod`. This leaves the context unusable (`KEY_INFO_ALREADY_SET` on retry) and inconsistent.
**Fix**:
```
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
void *pqcCtx = pqcMethod->newCtx();
if (pqcCtx == NULL) {
    return CRYPT_MEM_ALLOC_FAIL;
}
void *tradCtx = tradMethod->newCtx();
if (tradCtx == NULL) {
    pqcMethod->freeCtx(pqcCtx);
    return CRYPT_MEM_ALLOC_FAIL;
}
int32_t pqcParam = ctx->info->pqcParam;
int32_t ret = pqcMethod->ctrl(pqcCtx, CRYPT_CTRL_SET_PARA_BY_ID, &(pqcParam), sizeof(pqcParam));
if (ret != CRYPT_SUCCESS) {
    pqcMethod->freeCtx(pqcCtx);
    tradMethod->freeCtx(tradCtx);
    return ret;
}

ctx->pqcMethod = pqcMethod;
ctx->tradMethod = tradMethod;
ctx->pqcCtx = pqcCtx;
ctx->tradCtx = tradCtx;
```

---

### Incomplete private key length validation
`src/composite_sign/src/crypt_composite_sign.c:352-363`
**Reviewers**: GEMINI | **置信度**: 可信
```
int32_t CRYPT_COMPOSITE_SetPrvKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePrv *prv)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```
**Issue**: `CRYPT_COMPOSITE_SetPrvKey` checks if `prv->len` is greater than `pqcPrvkeyLen`, but does not enforce that `prv->len` matches `compPrvKeyLen`. This allows passing arbitrarily large buffers as the private key, potentially causing issues in the underlying traditional key setter.
**Fix**:
```
int32_t CRYPT_COMPOSITE_SetPrvKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePrv *prv)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || prv == NULL || prv->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(prv->len != ctx->info->compPrvKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```

---

### Incomplete public key length validation
`src/composite_sign/src/crypt_composite_sign.c:365-377`
**Reviewers**: GEMINI | **置信度**: 可信
```
int32_t CRYPT_COMPOSITE_SetPubKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePub *pub)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
```
**Issue**: `CRYPT_COMPOSITE_SetPubKey` checks if `pub->len` is greater than `pqcPubkeyLen`, but it does not check if `pub->len` exactly matches `compPubKeyLen`. Excessively large `pub->len` will result in a larger-than-expected `tradPub` buffer being passed to the traditional method.
**Fix**:
```
int32_t CRYPT_COMPOSITE_SetPubKey(CRYPT_CompositeCtx *ctx, const CRYPT_CompositePub *pub)
{
    int32_t ret;
    RETURN_RET_IF((ctx == NULL || pub == NULL || pub->data == NULL), CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, PQCP_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len != ctx->info->compPubKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
```

---

### Control command compatibility regression for PolarLAC
`src/polarlac/src/polarlac.c:257-297`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
int32_t PQCP_LAC2_Ctrl(CRYPT_POLAR_LAC_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        return PQCP_NULL_INPUT;
    }
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
```
**Issue**: The control switch dropped support for existing `PQCP_POLAR_LAC_*` command IDs and only accepts `CRYPT_CTRL_*`. Existing callers using documented PQCP command IDs now get `PQCP_INVALID_ARG`. The test/demo/polarlac_demo.c still uses `PQCP_POLAR_LAC_SET_PARAMS_BY_ID` which creates inconsistency.
**Fix**:
```
int32_t PQCP_LAC2_Ctrl(CRYPT_POLAR_LAC_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        return PQCP_NULL_INPUT;
    }
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
        default:
            return PQCP_INVALID_ARG;
```

---


## Low

### Commented out error handling in pkey context creation
`src/provider/pqcp_pkey.c:50-52`
**Reviewers**: GEMINI | **置信度**: 可信
```
if (pkeyCtx == NULL) {
        // BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
```
**Issue**: The error reporting macro `BSL_ERR_PUSH_ERROR` is commented out. If context creation fails (e.g., unsupported algorithm), the function returns NULL without pushing an error code to the stack, making diagnostics difficult.
**Fix**:
```
if (pkeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
```

---

### Uninitialized pointer may be freed on early error path
`test/demo/composite_sign_demo.c:20-23`
**Reviewers**: CODEX | **置信度**: 可信
```
static int32_t CompositeSignDemo(void)
{
    printf("\n=== Composite Sign ===\n\n");
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *signCtx;
    CRYPT_EAL_PkeyCtx *verifyCtx;
```
**Issue**: `verifyCtx` is not initialized before possible `goto EXIT`, but `CRYPT_EAL_PkeyFreeCtx(verifyCtx)` is always called in `EXIT`. If `signCtx` creation fails, `verifyCtx` is indeterminate and freeing it is undefined behavior.
**Fix**:
```
static int32_t CompositeSignDemo(void)
{
    printf("\n=== Composite Sign ===\n\n");
    int32_t ret = -1;
    CRYPT_EAL_PkeyCtx *signCtx = NULL;
    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
```

---

### Missing newline at end of file
`src/composite_sign/include/crypt_composite_sign.h:59`
**Reviewers**: CLAUDE | **置信度**: 可信
```
#endif// CRYPT_COMPOSITE_H
```
**Issue**: The file is missing a trailing newline. This is a minor issue but can cause warnings with some compilers and doesn't follow standard Unix text file conventions.
**Fix**:
```
#endif// CRYPT_COMPOSITE_H
```

---

### Extra blank line in enum definition
`include/pqcp_types.h:98-101`
**Reviewers**: CLAUDE | **置信度**: 可信
```
PQCP_ALG_ID_MCELIECE_8192128_F,
    PQCP_ALG_ID_MCELIECE_8192128_PC,
    PQCP_ALG_ID_MCELIECE_8192128_PCF

    
} PQCP_MCELIECE_ALG_ID;
```
**Issue**: There's an extra blank line in the `PQCP_MCELIECE_ALG_ID` enum definition which is inconsistent with the coding style.
**Fix**:
```
PQCP_ALG_ID_MCELIECE_8192128_F,
    PQCP_ALG_ID_MCELIECE_8192128_PC,
    PQCP_ALG_ID_MCELIECE_8192128_PCF
} PQCP_MCELIECE_ALG_ID;
```

---

### clean-all custom target has dangerous recursive delete
`CMakeLists.txt:160-168`
**Reviewers**: CLAUDE | **置信度**: 可信
```
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove
        *.log
        *.tmp
        *.bak
    COMMENT "Cleaning all build artifacts and temporary files"
)
```
**Issue**: The clean-all custom target uses `CMAKE_COMMAND -E remove_directory ${CMAKE_BINARY_DIR}` which removes the entire build directory. This could be dangerous if run accidentally and could remove important build artifacts that the user wants to keep.
**Fix**:
```
Either remove the remove_directory line or add a warning comment about the destructive nature of this target.
```

---
