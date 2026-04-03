# Code Review: openHiTLS/pqcp#44
**Reviewer**: CLAUDE


## High

### Compiler support check doesn't verify CPU capability
`CMakeLists.txt:56-68`
```
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    check_c_compiler_flag("-maes" PQCP_COMPILER_SUPPORTS_MAES)
    if(PQCP_COMPILER_SUPPORTS_MAES)
        set(PQCP_HIAE_SUPPORTED TRUE)
        list(APPEND PQCP_HIAE_COMPILE_OPTIONS "-maes")
    endif()
```
**Issue**: check_c_compiler_flag only tests if the compiler accepts the flag, not if the target CPU actually supports the AES/ARM Crypto instructions. This can lead to runtime SIGILL errors when the code runs on a CPU without these instructions (e.g., compiling on a x86_64 with AES-NI but running on an older x86_64 without it, or cross-compiling for a different target).

---


## Medium

### ProcessPartialNoCommit lacks platform support validation
`src/hiae/src/hiae_cipher.c:63-73`
```
static void ProcessPartialNoCommit(const PQCP_HIAE_CipherCtx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *out)
{
    DATA128b tmpState[HIAE_STATE_NUM];
    (void)memcpy_s(tmpState, sizeof(tmpState), ctx->state, sizeof(ctx->state));
    if (ctx->isEnc) {
        HIAE_Stream_Encrypt(tmpState, out, in, inLen);
    } else {
        HIAE_Stream_Decrypt(tmpState, out, in, inLen);
    }
    BSL_SAL_CleanseData(tmpState, sizeof(tmpState));
}
```
**Issue**: The ProcessPartialNoCommit function calls HIAE_Stream_Encrypt/Decrypt which use SIMD intrinsics. If the code somehow runs on an unsupported platform (where the compiler flag was accepted but CPU doesn't support the instructions), this will cause undefined behavior or crash.

---

### SetIv doesn't validate platform support before calling HIAE_Init
`src/hiae/src/hiae_cipher.c:296-318`
```
static int32_t SetIv(PQCP_HIAE_CipherCtx *ctx, const uint8_t *iv, uint32_t ivLen)
{
    ...
    if (memcpy_s(ctx->iv, sizeof(ctx->iv), iv, ivLen) != EOK) {
        return PQCP_INVALID_ARG;
    }
    HIAE_Init(ctx->state, ctx->key, ctx->iv);
    ...
}
```
**Issue**: The SetIv function calls HIAE_Init without checking if the platform actually supports HiAE. If CMake incorrectly detected support, this could cause runtime errors.

---


## Low

### Inefficient empty foreach loop when HiAE is not supported
`CMakeLists.txt:131-134`
```
foreach(src ${HIAE_SOURCES})
    if(PQCP_HIAE_SUPPORTED)
        set_source_files_properties(${src} PROPERTIES COMPILE_OPTIONS "${PQCP_HIAE_COMPILE_OPTIONS}")
    endif()
endforeach()
```
**Issue**: When PQCP_HIAE_SUPPORTED is FALSE, HIAE_SOURCES is empty and the foreach loop serves no purpose. The loop body has an if check for PQCP_HIAE_SUPPORTED which is already known to be FALSE at this point.
**Fix**:
```
if(PQCP_HIAE_SUPPORTED)
    foreach(src ${HIAE_SOURCES})
        set_source_files_properties(${src} PROPERTIES COMPILE_OPTIONS "${PQCP_HIAE_COMPILE_OPTIONS}")
    endforeach()
endif()
```

---

### FlushPendingData always processes full 16-byte block
`src/hiae/src/hiae_mac.c:61-72`
```
static int32_t FlushPendingData(PQCP_HIAE_MacCtx *ctx)
{
    uint8_t block[HIAE_BLOCK_SIZE] = {0};
    if (ctx->dataBufLen == 0) {
        return PQCP_SUCCESS;
    }
    if (memcpy_s(block, sizeof(block), ctx->dataBuf, ctx->dataBufLen) != EOK) {
        return PQCP_INVALID_ARG;
    }
    HIAE_Stream_ProcAD(ctx->state, block, sizeof(block));
    ctx->dataBufLen = 0;
    return PQCP_SUCCESS;
}
```
**Issue**: The function passes sizeof(block) (16 bytes) to HIAE_Stream_ProcAD even when only partial data (ctx->dataBufLen bytes) is buffered. While the zero-padding is correct for the algorithm, this is inconsistent with how the cipher's CommitPendingMsg handles partial blocks and could be confusing.

---

### HIAE_Init returns void on error without indication
`src/hiae/src/hiae_impl.c:442-459`
```
void HIAE_Init(DATA128b *state, const uint8_t *key, const uint8_t *iv)
{
    if (state == NULL || key == NULL || iv == NULL) {
        return;
    }
    DATA128b c0 = SIMD_LOAD(CONST0);
    ...
}
```
**Issue**: HIAE_Init checks for NULL pointers and returns early, but returns void. If called directly (bypassing the provider layer) with NULL inputs, the state remains uninitialized with no error indication. While provider callers check first, this low-level API could be misused.

---
