# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1153
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CODEX


## High

### Pre-swapping the XOF buffer breaks ARMv8 rejection sampling on big-endian targets
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:99-104`
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
    for (uint32_t i = 0; i < buflen; i++) {
        buf[i] = CRYPT_HTOLE32(buf[i]);
    }
    uint32_t gensize = 0;
    gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
```
**Issue**: `MldRejUniformAsm()` consumes the SHAKE output as a raw byte stream, but this code rewrites that stream with `CRYPT_HTOLE32()` before calling the asm routine. On big-endian AArch64, that reverses every 4-byte chunk in memory, so the asm path parses different 24-bit values than the scalar fallback and than the no-asm implementation. The result is a corrupted `ExpandA()` matrix, which in turn breaks ML-DSA keygen/sign/verify on supported big-endian builds.
**Fix**:
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);

    /* MldRejUniformAsm reads raw bytes, so do not byte-swap the buffer in place. */
    uint32_t gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
    outlen = CRYPT_SHAKE128_BLOCKSIZE;
    buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;

    for (uint32_t i = gensize, j = buflen + 1; i < MLDSA_N;) {
        if (j >= buflen && i < MLDSA_N) {
            GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
            j = 0;
        }

        const uint32_t w0 = GET_UINT32_LE((const uint8_t *)buf, j * sizeof(uint32_t));
        const uint32_t w1 = GET_UINT32_LE((const uint8_t *)buf, (j + 1) * sizeof(uint32_t));
        const uint32_t w2 = GET_UINT32_LE((const uint8_t *)buf, (j + 2) * sizeof(uint32_t));
        ...
    }
```

---


---

## GEMINI Review

# Code Review: openHiTLS/openhitls#1153
**Reviewer**: GEMINI


## Low

### Unnecessary and potentially harmful byte-swap of SHAKE128 output buffer
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:98-100`
```
for (uint32_t i = 0; i < buflen; i++) {
        buf[i] = CRYPT_HTOLE32(buf[i]);
    }
```
**Issue**: The loop calls `CRYPT_HTOLE32(buf[i])` on the buffer produced by `hashMethod->squeeze` before passing it to `MldRejUniformAsm`. `MldRejUniformAsm` expects a raw byte array (as its signature implies: `const uint8_t *buf`), and unpacks bytes directly using the `ld3` instruction. On Little Endian (AArch64 default), `CRYPT_HTOLE32` is a no-op, so the code works. However, on Big Endian architectures, this loop would reverse the byte order of every 32-bit chunk, corrupting the byte stream for the ASM function. Furthermore, the C fallback loop at line 105 performs its own per-element `CRYPT_HTOLE32` swapping during reading, so pre-swapping the buffer is both useless and logically incorrect.
**Fix**:
```
// The useless and potentially harmful byte-swap loop has been removed.
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
