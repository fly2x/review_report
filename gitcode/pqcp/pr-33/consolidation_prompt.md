# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/pqcp
- PR: #33
- Title: 

## Individual Review Reports

## GEMINI Review

# Code Review: openHiTLS/pqcp#33
**Reviewer**: GEMINI


## High

### Missing NULL Check for Input Parameter
`src/composite_sign/src/crypt_composite_sign.c:228`
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
        return PQCP_COMPOSITE_KEYLEN_ERROR;
    }
    if (ctx->ctxInfo != NULL) {
```
**Issue**: The function `CRYPT_CompositeSetctxInfo` does not check if `val` is NULL before passing it to `BSL_SAL_Dump` (which presumably copies from it). If `len > 0` but `val` is NULL, this will likely cause a segmentation fault.
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
```

---

### Ignored Return Value of Secure Memory Copy
`src/composite_sign/src/crypt_composite_sign.c:541-546`
```
(void)memcpy_s(ptr, msg->len, PREFIX, prefixLen);
    ptr += prefixLen;
    (void)memcpy_s(ptr, msg->len - prefixLen, label, labelLen);
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        (void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1), ctx->ctxInfo, ctx->ctxLen);
        ptr += ctx->ctxLen;
    }
```
**Issue**: The return value of `memcpy_s` is explicitly ignored (`(void)memcpy_s(...)`) in `CompositeMsgEncode`. If `memcpy_s` fails (e.g., due to invalid overlap or size parameters), the destination buffer `msg->data` will contain uninitialized or partial data. The function then returns `CRYPT_SUCCESS`, causing the caller to sign/verify this invalid data.
**Fix**:
```
if (memcpy_s(ptr, msg->len, PREFIX, prefixLen) != EOK) {
        BSL_SAL_FREE(msg->data);
        return CRYPT_MEM_CPY_FAIL;
    }
    ptr += prefixLen;
    if (memcpy_s(ptr, msg->len - prefixLen, label, labelLen) != EOK) {
        BSL_SAL_FREE(msg->data);
        return CRYPT_MEM_CPY_FAIL;
    }
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        if (memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1), ctx->ctxInfo, ctx->ctxLen) != EOK) {
            BSL_SAL_FREE(msg->data);
            return CRYPT_MEM_CPY_FAIL;
        }
        ptr += ctx->ctxLen;
    }
```

---

### Breaking API Change in Parameter IDs
`include/pqcp_types.h:22-42`
```
#define PQCP_PARAM_BASE 5000
#define PQCP_PARAM_SCLOUDPLUS_BASE (PQCP_PARAM_BASE + 100)
// ...
#define PQCP_PARAM_FRODOKEM_BASE (PQCP_PARAM_BASE + 200)
```
**Issue**: The parameter ID base values have changed significantly (e.g., `CRYPT_PARAM_SCLOUDPLUS_BASE` 900 -> `PQCP_PARAM_SCLOUDPLUS_BASE` 5100). This is a binary and source incompatibility for any external application relying on the old values. While the rename suggests an API refactor, changing the underlying integer values breaks ABI with existing compiled code.
**Fix**:
```
/* Ensure these values align with external expectations or version the API explicitly. 
   If backward compatibility is required, restore original values: */
#define PQCP_PARAM_BASE 900 // Adjusted base if necessary
// Or map specific bases back to 900, 1000, 1100, 1200 as before.
```

---


## Medium

### Incomplete Public Key Length Validation
`src/composite_sign/src/crypt_composite_sign.c:366`
```
RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
```
**Issue**: `CRYPT_COMPOSITE_SetPubKey` checks if `pub->len` is greater than `pqcPubkeyLen`, but it does not check if `pub->len` exactly matches the expected composite public key length (`ctx->info->compPubKeyLen`). Excessively large `pub->len` will result in a larger-than-expected `tradPub` buffer being passed to the traditional method, relying on that method's validation which may be insufficient.
**Fix**:
```
RETURN_RET_IF(pub->len != ctx->info->compPubKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
```

---

### Incomplete Private Key Length Validation
`src/composite_sign/src/crypt_composite_sign.c:351`
```
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```
**Issue**: `CRYPT_COMPOSITE_SetPrvKey` checks if `prv->len` is greater than `pqcPrvkeyLen`, but does not enforce that `prv->len` matches `ctx->info->compPrvKeyLen`. This allows passing arbitrarily large buffers as the private key, potentially causing issues in the underlying traditional key setter.
**Fix**:
```
RETURN_RET_IF(prv->len != ctx->info->compPrvKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```

---


## Low

### Commented Out Error Handling
`src/provider/pqcp_pkey.c:51`
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


---

## CLAUDE Review

# Code Review: openHiTLS/pqcp#33
**Reviewer**: CLAUDE


## High

### PolarLAC Ctrl function uses undefined CRYPT_CTRL_* constants
`src/polarlac/src/polarlac.c:263-291`
```
int32_t PQCP_LAC2_Ctrl(CRYPT_POLAR_LAC_Ctx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || val == NULL) {
        return PQCP_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_SET_PARA_BY_ID:  // Was PQCP_POLAR_LAC_SET_PARAMS_BY_ID
            return PolarLacSetAlgInfo(ctx, val, valLen);
        case CRYPT_CTRL_GET_CIPHERTEXT_LEN:  // Was PQCP_POLAR_LAC_GET_CIPHER_LEN
        ...
```
**Issue**: The PQCP_LAC2_Ctrl function was changed to use CRYPT_CTRL_SET_PARA_BY_ID, CRYPT_CTRL_GET_CIPHERTEXT_LEN, CRYPT_CTRL_GET_PRVKEY_LEN, and CRYPT_CTRL_GET_PUBKEY_LEN instead of the PQCP_POLAR_LAC_* constants. However, these CRYPT_CTRL_* constants are not defined in the pqcp codebase and are expected to come from OpenHiTLS. If OpenHiTLS doesn't define these constants with the same values, this will cause compilation errors or runtime issues. The test/demo/polarlac_demo.c still uses PQCP_POLAR_LAC_SET_PARAMS_BY_ID which creates inconsistency.
**Fix**:
```
Either:
1. Keep using PQCP_POLAR_LAC_* constants defined in pqcp_types.h for internal consistency
2. Or ensure CRYPT_CTRL_* constants are properly defined/included from OpenHiTLS with appropriate compatibility layer
3. Update test/demo/polarlac_demo.c to use CRYPT_CTRL_* constants if that's the intended API
```

---

### CMakeLists.txt references non-existent hybrid_env include directory
`CMakeLists.txt:98`
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
**Issue**: Line 98 adds `${CMAKE_CURRENT_SOURCE_DIR}/src/hybrid_env/include` to the include directories, but this directory does not exist in the repository. Based on commit messages like "移除hybrid_env相关代码" (Remove hybrid_env related code), the hybrid_env was removed but this CMakeLists.txt reference was not cleaned up. This will cause build failures.
**Fix**:
```
Remove the line:
${CMAKE_CURRENT_SOURCE_DIR}/src/hybrid_env/include
```

---


## Medium

### GetPrvKeyEx doesn't validate GetParamValue return value
`src/composite_sign/src/crypt_composite_sign.c:379-393`
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
**Issue**: The CRYPT_COMPOSITE_GetPrvKeyEx function calls GetParamValue but doesn't check if it returns NULL before using paramPrv. If GetParamValue fails or the parameter isn't found, paramPrv will be NULL and the subsequent assignment to paramPrv->useLen will cause a NULL pointer dereference.
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

### GetPubKeyEx doesn't validate GetParamValue return value
`src/composite_sign/src/crypt_composite_sign.c:395-409`
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
**Issue**: The CRYPT_COMPOSITE_GetPubKeyEx function has the same issue as GetPrvKeyEx - it doesn't check if GetParamValue returns NULL before using paramPub.
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

### SetPrvKeyEx doesn't validate GetConstParamValue return value
`src/composite_sign/src/crypt_composite_sign.c:411-420`
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
**Issue**: The CRYPT_COMPOSITE_SetPrvKeyEx function calls GetConstParamValue but doesn't validate its return before using the result. If the parameter isn't found, prv.data and prv.len will remain uninitialized (zero), which could lead to incorrect behavior.
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

### SetPubKeyEx doesn't validate GetConstParamValue return value
`src/composite_sign/src/crypt_composite_sign.c:422-431`
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
**Issue**: The CRYPT_COMPOSITE_SetPubKeyEx function has the same issue - it doesn't validate GetConstParamValue return before using the result.
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


## Low

### CompositeMsgEncode has potential buffer overflow on memcpy_s
`src/composite_sign/src/crypt_composite_sign.c:452-477`
```
(void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1), ctx->ctxInfo, ctx->ctxLen);
    ptr += ctx->ctxLen;
    }
    (void)memcpy_s(ptr, digestLen, digest, digestLen);  // Should use remaining buffer size
```
**Issue**: In CompositeMsgEncode, the third memcpy_s uses digestLen as the size parameter instead of the actual destination buffer size. The destination buffer size should be `msg->len - (prefixLen + labelLen + 1 + ctx->ctxLen)` not `digestLen`. While this happens to work because digestLen equals the remaining space, it's fragile and could break if the logic changes.
**Fix**:
```
(void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1 + ctx->ctxLen), ctx->ctxInfo, ctx->ctxLen);
    ptr += ctx->ctxLen;
    }
    (void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1 + ctx->ctxLen), digest, digestLen);
```

---

### Missing newline at end of file
`src/provider/pqcp_pkey.c:163`
```
const CRYPT_EAL_Func g_pqcpCompositeSign[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_COMPOSITE_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_COMPOSITE_Verify},
    CRYPT_EAL_FUNC_END,
};  // <- No newline at end of file
```
**Issue**: The pqcp_pkey.c file is missing a trailing newline. This is a minor issue but can cause warnings with some compilers and doesn't follow standard Unix text file conventions.
**Fix**:
```
Add a newline character at the end of the file.
```

---

### Missing newline at end of file
`src/composite_sign/include/crypt_composite_sign.h:59`
```
#endif// CRYPT_COMPOSITE_H  // <- No newline at end of file
```
**Issue**: The crypt_composite_sign.h file is missing a trailing newline.
**Fix**:
```
Add a newline character at the end of the file.
```

---

### Extra blank line in enum definition
`include/pqcp_types.h:99-100`
```
PQCP_ALG_ID_MCELIECE_8192128_F,
    PQCP_ALG_ID_MCELIECE_8192128_PC,
    PQCP_ALG_ID_MCELIECE_8192128_PCF

    
} PQCP_MCELIECE_ALG_ID;
```
**Issue**: There's an extra blank line in the PQCP_MCELIECE_ALG_ID enum definition which is inconsistent with the coding style.
**Fix**:
```
PQCP_ALG_ID_MCELIECE_8192128_F,
    PQCP_ALG_ID_MCELIECE_8192128_PC,
    PQCP_ALG_ID_MCELIECE_8192128_PCF
} PQCP_MCELIECE_ALG_ID;
```

---

### clean-all custom target has dangerous recursive delete
`CMakeLists.txt:163-168`
```
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}  # <- Removes entire build dir
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


---

## CODEX Review

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
