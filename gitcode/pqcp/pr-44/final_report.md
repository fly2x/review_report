# Final Code Review Report
## openHiTLS/pqcp - PR #44

### Summary
- **Total Issues**: 5
- **Critical**: 2
- **High**: 1
- **Medium**: 1
- **Low**: 1
- **Reviewers**: claude, gemini, codex

---


## Critical

### HiAE sources compiled but code never actually enabled due to missing PQCP_HIAE define
`CMakeLists.txt:70-75`
**Reviewers**: CODEX | **置信度**: 可信
```
if(PQCP_HIAE_SUPPORTED)
    list(APPEND PROVIDER_SOURCES ${HIAE_SOURCES})
    message(STATUS "HiAE enabled for ${CMAKE_SYSTEM_PROCESSOR}")
else()
    message(STATUS "HiAE disabled: unsupported target platform or compiler flags for ${CMAKE_SYSTEM_PROCESSOR}")
endif()
...
if(NOT PQCP_HIAE_SUPPORTED)
    target_compile_options(pqcp_provider PRIVATE -UPQCP_HIAE)
endif()
```
**Issue**: When PQCP_HIAE_SUPPORTED is TRUE, the HIAE_SOURCES are added to PROVIDER_SOURCES and "HiAE enabled" is printed, but CMakeLists.txt never defines PQCP_HIAE. All HiAE implementation code is wrapped in `#ifdef PQCP_HIAE` (see hiae_cipher.c:16, hiae_mac.c:16, hiae_impl.c:16, pqcp_provider_impl.h:36-39). Without the define, the functions compile as empty stubs and the algorithm tables are not registered, making HiAE completely non-functional despite being reported as enabled.
**Fix**:
```
option(PQCP_ENABLE_HIAE "Build HiAE support" ON)

set(PQCP_HIAE_ENABLED FALSE)
if(PQCP_ENABLE_HIAE AND PQCP_HIAE_SUPPORTED)
    list(APPEND PROVIDER_SOURCES ${HIAE_SOURCES})
    set(PQCP_HIAE_ENABLED TRUE)
    message(STATUS "HiAE enabled for ${CMAKE_SYSTEM_PROCESSOR}")
else()
    message(STATUS "HiAE disabled: unsupported target platform or compiler flags for ${CMAKE_SYSTEM_PROCESSOR}")
endif()

add_library(pqcp_provider ${PQCP_LIB_TYPE} ${PROVIDER_SOURCES})

target_compile_definitions(pqcp_provider PRIVATE
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_PKEY
    HITLS_CRYPTO_MD
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_MAC
    HITLS_NO_CONFIG_CHECK
)

if(PQCP_HIAE_ENABLED)
    target_compile_definitions(pqcp_provider PRIVATE PQCP_HIAE)
endif()
```

---

### AEAD decrypt path never verifies authentication tag, breaking AEAD security contract
`src/hiae/src/hiae_cipher.c:256-276`
**Reviewers**: CODEX | **置信度**: 可信
```
int32_t PQCP_HIAE_CipherFinal(void *ctx, uint8_t *out, uint32_t *outLen)
{
    PQCP_HIAE_CipherCtx *c = (PQCP_HIAE_CipherCtx *)ctx;
    int32_t ret;
    (void)out;
    if (c == NULL || outLen == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (!c->inited) {
        return CRYPT_EAL_ERR_STATE;
    }
    if (c->finalized) {
        *outLen = 0;
        return PQCP_SUCCESS;
    }
    ret = FinalizeIfNeeded(c);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    *outLen = 0;
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_CipherCtrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    ...
    switch (cmd) {
        case CRYPT_CTRL_SET_IV:
        case CRYPT_CTRL_REINIT_STATUS:
            return SetIv(c, (const uint8_t *)val, valLen);
        case CRYPT_CTRL_SET_AAD:
            return SetAad(c, (const uint8_t *)val, valLen);
        case CRYPT_CTRL_GET_TAG:
            return GetTag(c, (uint8_t *)val, valLen);
        ...
    }
}
```
**Issue**: The AEAD implementation exposes CRYPT_CTRL_GET_TAG for encryption but has no CRYPT_CTRL_SET_TAG for decryption. PQCP_HIAE_CipherFinal() always returns success after finalization without verifying any expected tag. This means forged ciphertext is accepted and plaintext returned without authentication, completely defeating the purpose of AEAD. Callers who forget to separately fetch and compare tags will silently accept tampered data.
**Fix**:
```
/* Add to PQCP_HIAE_CipherCtx structure:
    uint8_t expectedTag[HIAE_TAG_LEN];
    bool tagSet;
*/

static bool TagEqualConstTime(const uint8_t *lhs, const uint8_t *rhs, uint32_t len)
{
    uint8_t diff = 0;
    for (uint32_t i = 0; i < len; i++) {
        diff |= (uint8_t)(lhs[i] ^ rhs[i]);
    }
    return diff == 0;
}

static int32_t SetTag(PQCP_HIAE_CipherCtx *ctx, const uint8_t *tag, uint32_t tagLen)
{
    if (ctx == NULL || tag == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (tagLen != HIAE_TAG_LEN) {
        return PQCP_INVALID_ARG;
    }
    if (memcpy_s(ctx->expectedTag, sizeof(ctx->expectedTag), tag, tagLen) != EOK) {
        return PQCP_INVALID_ARG;
    }
    ctx->tagSet = true;
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_CipherFinal(void *ctx, uint8_t *out, uint32_t *outLen)
{
    PQCP_HIAE_CipherCtx *c = (PQCP_HIAE_CipherCtx *)ctx;
    int32_t ret;
    if (c == NULL || outLen == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (!c->inited) {
        return CRYPT_EAL_ERR_STATE;
    }
    if (c->finalized) {
        *outLen = 0;
        return PQCP_SUCCESS;
    }
    ret = FinalizeIfNeeded(c);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
    if (!c->isEnc) {
        if (!c->tagSet || !TagEqualConstTime(c->tag, c->expectedTag, HIAE_TAG_LEN)) {
            return PQCP_VERIFY_FAIL; /* Add to pqcp_err.h */
        }
    }
    *outLen = 0;
    return PQCP_SUCCESS;
}

int32_t PQCP_HIAE_CipherCtrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    ...
    switch (cmd) {
        case CRYPT_CTRL_SET_IV:
        case CRYPT_CTRL_REINIT_STATUS:
            return SetIv(c, (const uint8_t *)val, valLen);
        case CRYPT_CTRL_SET_TAG:
            return SetTag(c, (const uint8_t *)val, valLen);
        case CRYPT_CTRL_SET_AAD:
            return SetAad(c, (const uint8_t *)val, valLen);
        case CRYPT_CTRL_GET_TAG:
            return GetTag(c, (uint8_t *)val, valLen);
        ...
    }
}
```

---


## High

### Compiler support check doesn't verify actual CPU capability, may cause runtime SIGILL
`CMakeLists.txt:56-68`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    check_c_compiler_flag("-maes" PQCP_COMPILER_SUPPORTS_MAES)
    if(PQCP_COMPILER_SUPPORTS_MAES)
        set(PQCP_HIAE_SUPPORTED TRUE)
        list(APPEND PQCP_HIAE_COMPILE_OPTIONS "-maes")
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    check_c_compiler_flag("-march=armv8-a+crypto+aes+sha2" PQCP_COMPILER_SUPPORTS_ARMV8_CRYPTO)
    if(PQCP_COMPILER_SUPPORTS_ARMV8_CRYPTO)
        set(PQCP_HIAE_SUPPORTED TRUE)
        list(APPEND PQCP_HIAE_COMPILE_OPTIONS "-march=armv8-a+crypto+aes+sha2")
    endif()
endif()
```
**Issue**: check_c_compiler_flag() only tests if the compiler accepts the flag (e.g., -maes or -march=armv8-a+crypto), not whether the target CPU actually supports AES-NI or ARM Crypto extensions. This can lead to binaries that crash with SIGILL when deployed to older CPUs lacking these instructions. The check should require explicit opt-in rather than auto-detecting based solely on processor architecture.
**Fix**:
```
option(PQCP_ENABLE_HIAE "Enable HiAE on targets guaranteed to have AES/crypto extensions" OFF)

set(PQCP_HIAE_SUPPORTED FALSE)
set(PQCP_HIAE_COMPILE_OPTIONS)

if(PQCP_ENABLE_HIAE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
        check_c_compiler_flag("-maes" PQCP_COMPILER_SUPPORTS_MAES)
        if(NOT PQCP_COMPILER_SUPPORTS_MAES)
            message(FATAL_ERROR "HiAE requires a compiler that supports -maes")
        endif()
        list(APPEND PQCP_HIAE_COMPILE_OPTIONS "-maes")
        set(PQCP_HIAE_SUPPORTED TRUE)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
        check_c_compiler_flag("-march=armv8-a+crypto" PQCP_COMPILER_SUPPORTS_ARMV8_CRYPTO)
        if(NOT PQCP_COMPILER_SUPPORTS_ARMV8_CRYPTO)
            message(FATAL_ERROR "HiAE requires ARMv8 crypto extensions")
        endif()
        list(APPEND PQCP_HIAE_COMPILE_OPTIONS "-march=armv8-a+crypto")
        set(PQCP_HIAE_SUPPORTED TRUE)
    endif()
endif()
```

---


## Medium

### SET_AAD unnecessarily rejects valid multi-chunk AAD processing
`src/hiae/src/hiae_cipher.c:321-349`
**Reviewers**: CODEX | **置信度**: 可信
```
static int32_t SetAad(PQCP_HIAE_CipherCtx *ctx, const uint8_t *aad, uint32_t aadLen)
{
    if (!ctx->inited || ctx->finalized) {
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->msgBufLen >= HIAE_BLOCK_SIZE) {
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->aadSet) {
        return CRYPT_EAL_ERR_STATE;  /* Rejects multi-chunk AAD */
    }
    if (aadLen > 0 && aad == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->msgLen != 0 || ctx->msgBufLen != 0) {
        return CRYPT_EAL_ERR_STATE;
    }
    if (aadLen == 0) {
        ctx->aadSet = true;
        return PQCP_SUCCESS;
    }
    if (CheckLenLimitU64(ctx->aadLen, aadLen, HIAE_A_MAX) != PQCP_SUCCESS) {
        return PQCP_INVALID_ARG;
    }

    ctx->aadLen += aadLen;
    HIAE_Stream_ProcAD(ctx->state, aad, aadLen);
    ctx->aadSet = true;
    return PQCP_SUCCESS;
}
```
**Issue**: SetAad() returns CRYPT_EAL_ERR_STATE on any second SET_AAD call (line 329-331), even when no payload has been processed yet. This prevents legitimate use cases where callers need to feed associated data in multiple chunks. The low-level HIAE_Stream_ProcAD implementation already supports incremental AD absorption, so this restriction is an unnecessary API regression.
**Fix**:
```
static int32_t SetAad(PQCP_HIAE_CipherCtx *ctx, const uint8_t *aad, uint32_t aadLen)
{
    if (!ctx->inited || ctx->finalized) {
        return CRYPT_EAL_ERR_STATE;
    }
    if (ctx->msgBufLen >= HIAE_BLOCK_SIZE) {
        return CRYPT_EAL_ERR_STATE;
    }
    if (aadLen > 0 && aad == NULL) {
        return PQCP_NULL_INPUT;
    }
    if (ctx->msgLen != 0 || ctx->msgBufLen != 0) {
        return CRYPT_EAL_ERR_STATE;  /* Only reject AAD after payload started */
    }
    if (aadLen == 0) {
        ctx->aadSet = true;
        return PQCP_SUCCESS;
    }
    if (CheckLenLimitU64(ctx->aadLen, aadLen, HIAE_A_MAX) != PQCP_SUCCESS) {
        return PQCP_INVALID_ARG;
    }

    ctx->aadLen += aadLen;
    HIAE_Stream_ProcAD(ctx->state, aad, aadLen);
    ctx->aadSet = true;
    return PQCP_SUCCESS;
}
```

---


## Low

### Empty foreach loop executes when HiAE is not supported
`CMakeLists.txt:131-135`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
foreach(src ${HIAE_SOURCES})
    if(PQCP_HIAE_SUPPORTED)
        set_source_files_properties(${src} PROPERTIES COMPILE_OPTIONS "${PQCP_HIAE_COMPILE_OPTIONS}")
    endif()
endforeach()
```
**Issue**: When PQCP_HIAE_SUPPORTED is FALSE, HIAE_SOURCES still contains files (from the glob at line 49-51), and the foreach loop iterates over them only to check the condition that's already known to be false. This is a minor inefficiency.
**Fix**:
```
if(PQCP_HIAE_SUPPORTED)
    foreach(src ${HIAE_SOURCES})
        set_source_files_properties(${src} PROPERTIES COMPILE_OPTIONS "${PQCP_HIAE_COMPILE_OPTIONS}")
    endforeach()
endif()
```

---
