# Final Code Review Report
## openHiTLS/openhitls - PR #1153

### Summary
- **Total Issues**: 4
- **Critical**: 0
- **High**: 1
- **Medium**: 1
- **Low**: 2
- **Reviewers**: claude, gemini, codex

---


## High

### Pre-swapping SHAKE128 output buffer breaks ML-DSA on big-endian platforms
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:100-104`
**Reviewers**: CODEX, GEMINI | **置信度**: 可信
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
for (uint32_t i = 0; i < buflen; i++) {
    buf[i] = CRYPT_HTOLE32(buf[i]);
}
uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
```
**Issue**: Lines 100-101 pre-byte-swap the entire SHAKE128 output buffer using `CRYPT_HTOLE32()` before passing it to `MldRejUniformAsm()`. On big-endian AArch64, this reverses every 4-byte chunk, corrupting the byte stream that the assembly function expects to read as raw bytes. The assembly function `MldRejUniformAsm()` consumes the SHAKE output as a raw byte stream (using `ld3` instruction), but the pre-swapping corrupts this data. The C fallback implementation (export_mldsa_c.c) correctly does per-element byte-swapping DURING reading (lines 107-109), not pre-swapping the buffer. This causes incorrect matrix generation in `ExpandA()`, breaking ML-DSA keygen/sign/verify on big-endian builds.
**Fix**:
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);

/* MldRejUniformAsm reads raw bytes, so do not byte-swap the buffer in place. */
uint32_t gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
```

---


## Medium

### MLDSA_ARMV8 option lacks architecture guard
`cmake/hitls_options.cmake:301`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
option(HITLS_CRYPTO_MLDSA_ARMV8                                "MLDSA ARMv8" OFF)
```
**Issue**: The HITLS_CRYPTO_MLDSA_ARMV8 option at line 301 has no architecture detection to prevent it from being enabled on non-ARMv8 platforms. If a user enables this option on x86, x86_64, ARMv7, or other architectures, the build will fail with assembler errors since the assembly files are ARMv8-specific.
**Fix**:
```
# Only allow MLDSA_ARMV8 on AArch64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
    option(HITLS_CRYPTO_MLDSA_ARMV8                            "MLDSA ARMv8" OFF)
else()
    set(HITLS_CRYPTO_MLDSA_ARMV8 OFF CACHE BOOL "MLDSA ARMv8 (not supported on this platform)" FORCE)
endif()
```

---


## Low

### Misleading unused parameter cast
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:46`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    (void) h;  // This is misleading - h IS used in the loop below
    void (*fp)(int32_t *, int32_t const *);
    fp = ctx->info->k == K_VALUE_OF_MLDSA_44? Usehint88: Usehint32;

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        fp(w[i], h[i]);
    }
}
```
**Issue**: Line 46 contains `(void) h;` to suppress unused parameter warnings, but the `h` parameter is actually used on line 51 in the loop `fp(w[i], h[i])`. The cast is unnecessary and confusing as it suggests the parameter is not used when it actually is.
**Fix**:
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    void (*fp)(int32_t *, int32_t const *);
    fp = ctx->info->k == K_VALUE_OF_MLDSA_44? Usehint88: Usehint32;

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        fp(w[i], h[i]);
    }
}
```

---

### MLDSA_MatrixMul relies on implicit memory layout assumptions
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:32-42`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
void MLDSA_MatrixMul(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t, int32_t *const matrix[MLDSA_L_MAX],
    int32_t *const s[MLDSA_L_MAX])
{
    if (ctx->info->k == K_VALUE_OF_MLDSA_44) {
        PolyveclPointwiseAccMontgomeryL4Asm(t, matrix[0], s[0]);
    } else if (ctx->info->k == K_VALUE_OF_MLDSA_65) {
        PolyveclPointwiseAccMontgomeryL5Asm(t, matrix[0], s[0]);
    } else {
        PolyveclPointwiseAccMontgomeryL7Asm(t, matrix[0], s[0]);
    }
}
```
**Issue**: The ARMv8 implementation of MLDSA_MatrixMul only passes `matrix[0]` and `s[0]` to the assembly functions, unlike the C implementation which iterates over all rows. This relies on the specific memory layout created by MLDSASetMatrixMem where the matrix is allocated contiguously. The assembly functions expect `matrix[0]` to point to a contiguous array with 1024-byte stride between polynomials. If the memory allocation pattern in MLDSASetMatrixMem changes, this will silently break. The code is currently correct based on MLDSASetMatrixMem implementation, but the dependency is implicit and fragile.
**Fix**:
```
/* Add documentation noting the memory layout dependency */
/* matrix[0] must point to contiguous memory with MLDSA_N * sizeof(int32_t) stride.
 * This assumes MLDSASetMatrixMem allocation pattern: matrix[i][j] is stored
 * contiguously with stride MLDSA_N between adjacent polynomials in each row.
 */
void MLDSA_MatrixMul(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t, int32_t *const matrix[MLDSA_L_MAX],
    int32_t *const s[MLDSA_L_MAX])
{
    if (ctx->info->k == K_VALUE_OF_MLDSA_44) {
        PolyveclPointwiseAccMontgomeryL4Asm(t, matrix[0], s[0]);
    } else if (ctx->info->k == K_VALUE_OF_MLDSA_65) {
        PolyveclPointwiseAccMontgomeryL5Asm(t, matrix[0], s[0]);
    } else {
        PolyveclPointwiseAccMontgomeryL7Asm(t, matrix[0], s[0]);
    }
}
```

---
