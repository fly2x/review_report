# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CLAUDE


## High

### MLDSA_MatrixMul may process incorrect matrix row
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:32-42`
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
**Issue**: The assembly function PolyveclPointwiseAccMontgomeryL4Asm expects the second parameter (matrix row) to be a contiguous array of l polynomials with stride 1024. The code passes matrix[i] which points to matrix[i][0]. However, based on MLDSASetMatrixMem allocation, the matrix[i] row IS contiguous with 1024-byte stride. The current code is correct, but this is fragile and depends on the specific memory layout in MLDSASetMatrixMem. If the memory allocation pattern changes, this will silently break.
**Fix**:
```
// Add compile-time assertion to verify matrix memory layout
static_assert(offsetof(MLDSA_KeyGenMatrixSt, matrix) < 10000, 
    "Matrix layout verification failed");

void MLDSA_MatrixMul(const CRYPT_ML_DSA_Ctx *ctx, int32_t *t, int32_t *const matrix[MLDSA_L_MAX],
    int32_t *const s[MLDSA_L_MAX])
{
    // Verify that matrix[0] points to contiguous memory
    // This assumes MLDSASetMatrixMem allocates matrix[i][0..l-1] contiguously
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


## Medium

### Missing architecture guard for MLDSA_ARMV8 option
`cmake/hitls_options.cmake:301`
```
option(HITLS_CRYPTO_MLDSA_ARMV8                                "MLDSA ARMv8" OFF)
```
**Issue**: The HITLS_CRYPTO_MLDSA_ARMV8 option has no architecture detection to prevent it from being enabled on non-ARMv8 platforms. If a user enables this option on x86 or other architectures, the build will fail with assembler errors. The option should be automatically disabled or hidden on non-ARMv8 platforms.
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

### Unused parameter warning
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:46`
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    (void) h;  // This is misleading - h IS used in the loop below
    void (*fp)(int32_t *, int32_t const *);
    fp = ctx->info->k == K_VALUE_OF_MLDSA_44? Usehint88: Usehint32;
```
**Issue**: The `h` parameter in MLDSA_UseHint is marked as unused with `(void) h;` but it is actually used indirectly through the `fp(w[i], h[i])` call. The cast is unnecessary and confusing.
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
