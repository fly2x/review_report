# Code Review: openHiTLS/pqcp#33
**Reviewer**: GEMINI


## High

### Inclusion of non-existent directory
`CMakeLists.txt:98`
```
target_include_directories(pqcp_provider
        ${CMAKE_CURRENT_SOURCE_DIR}/src/classic_mceliece/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/frodokem/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/polarlac/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hybrid_env/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/composite_sign/include
        ${OPENHITLS_INCLUDE_DIRS}
```
**Issue**: The build configuration includes `${CMAKE_CURRENT_SOURCE_DIR}/src/hybrid_env/include`, but this directory does not exist in the source tree. This causes build errors or warnings.
**Fix**:
```
target_include_directories(pqcp_provider
        ${CMAKE_CURRENT_SOURCE_DIR}/src/classic_mceliece/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/frodokem/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/polarlac/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/composite_sign/include
        ${OPENHITLS_INCLUDE_DIRS}
```

---

### Inclusion of non-existent directory
`test/CMakeLists.txt:92-93`
```
${CMAKE_SOURCE_DIR}/../platform/openhitls/platform/Secure_C/include
    ${CMAKE_SOURCE_DIR}/../src/hybrid_env/include
    ${CMAKE_SOURCE_DIR}/../src/hybrid_env/src
    ${CMAKE_SOURCE_DIR}/../src/composite_sign/include
```
**Issue**: The test build configuration includes `hybrid_env` directories that do not exist.
**Fix**:
```
${CMAKE_SOURCE_DIR}/../platform/openhitls/platform/Secure_C/include
    ${CMAKE_SOURCE_DIR}/../src/composite_sign/include
```

---


## Medium

### Ignored return value of secure memory copy
`src/composite_sign/src/crypt_composite_sign.c:320-321`
```
(void)memcpy_s(prv->data, prv->len, pqcPrv.data, pqcPrv.dataLen);
    (void)memcpy_s(prv->data + pqcPrv.dataLen, prv->len - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
```
**Issue**: The return values of `memcpy_s` are explicitly cast to `void`. Ignoring the error code hides potential failures (e.g. invalid arguments) and violates secure coding standards.
**Fix**:
```
if (memcpy_s(prv->data, prv->len, pqcPrv.data, pqcPrv.dataLen) != EOK) {
        ret = CRYPT_MEM_ALLOC_FAIL; // Or appropriate error code
        goto ERR;
    }
    if (memcpy_s(prv->data + pqcPrv.dataLen, prv->len - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen) != EOK) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
```

---

### Ignored return value of secure memory copy
`src/composite_sign/src/crypt_composite_sign.c:343-344`
```
(void)memcpy_s(pub->data, pub->len, pqcPub.data, pqcPub.dataLen);
    (void)memcpy_s(pub->data + pqcPub.dataLen, pub->len - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
```
**Issue**: The return values of `memcpy_s` are explicitly cast to `void`.
**Fix**:
```
if (memcpy_s(pub->data, pub->len, pqcPub.data, pqcPub.dataLen) != EOK) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    if (memcpy_s(pub->data + pqcPub.dataLen, pub->len - pqcPub.dataLen, tradPub.data, tradPub.dataLen) != EOK) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
```

---

### Ignored return value of secure memory copy
`src/composite_sign/src/crypt_composite_sign.c:466-476`
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
    (void)memcpy_s(ptr, digestLen, digest, digestLen);
```
**Issue**: Multiple `memcpy_s` calls in `CompositeMsgEncode` ignore the return value.
**Fix**:
```
if (memcpy_s(ptr, msg->len, PREFIX, prefixLen) != EOK) return CRYPT_MEM_ALLOC_FAIL;
    ptr += prefixLen;
    if (memcpy_s(ptr, msg->len - prefixLen, label, labelLen) != EOK) return CRYPT_MEM_ALLOC_FAIL;
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        if (memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1), ctx->ctxInfo, ctx->ctxLen) != EOK) return CRYPT_MEM_ALLOC_FAIL;
        ptr += ctx->ctxLen;
    }
    if (memcpy_s(ptr, digestLen, digest, digestLen) != EOK) return CRYPT_MEM_ALLOC_FAIL;
```

---

### Insufficient buffer size for MLDSA-87 signatures
`test/demo/composite_sign_demo.c:27`
```
uint8_t signData[4096];
```
**Issue**: `signData` buffer is 4096 bytes. MLDSA-87 composite signatures require > 4600 bytes. If the algorithm is changed to MLDSA-87, this buffer will overflow.
**Fix**:
```
uint8_t signData[5000];
```

---


## Low

### Function naming inconsistency
`src/composite_sign/src/crypt_composite_sign.c:211`
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
```
**Issue**: `CRYPT_CompositeSetctxInfo` uses lowercase `ctx` in the name, inconsistent with `CRYPT_CompositeSetAlgInfo` and standard CamelCase convention.
**Fix**:
```
static int32_t CRYPT_CompositeSetCtxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
```

---

### Typo in comment
`src/composite_sign/src/crypt_composite_sign_local.h:43`
```
uint32_t compPrvKeyLen; // composiet prvkey len
```
**Issue**: `composiet` is misspelled.
**Fix**:
```
uint32_t compPrvKeyLen; // composite prvkey len
```

---
