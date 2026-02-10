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
