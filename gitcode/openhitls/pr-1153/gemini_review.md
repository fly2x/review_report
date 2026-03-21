# Code Review: openHiTLS/openhitls#1153
**Reviewer**: GEMINI


## High

### Re-use of consumed SHAKE128 output in MLDSA_RejNTTPoly
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:108-110`
```
uint32_t j = 0;
    for (uint32_t i = gensize; i < MLDSA_N;) {
        const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
```
**Issue**: In `MLDSA_RejNTTPoly`, `buf` is populated with SHAKE128 output and consumed by `MldRejUniformAsm`. If `MldRejUniformAsm` doesn't generate all `MLDSA_N` coefficients, the loop is meant to generate the remaining ones. However, `j` is reset to 0 without squeezing a new SHAKE128 block, causing the code to incorrectly reuse and process the already-consumed, modified bytes from `buf`.
**Fix**:
```
uint32_t j = 0;
    if (gensize < MLDSA_N) {
        GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
    }
    for (uint32_t i = gensize; i < MLDSA_N;) {
        const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
```

---


## Medium

### Unused parameter s2 and divergent behavior in MLDSA_VectorsCaddQ
`crypto/mldsa/src/noasm/export_mldsa_c.c:269-275`
```
void MLDSA_VectorsCaddQ(int32_t w[MLDSA_N], int32_t s2[MLDSA_N])
{
    (void) s2;
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        w[i] += (MLDSA_Q & (((MLDSA_Q + 1) / 2 - w[i] - 1) >> 31));
        MLDSA_MOD_Q(w[i]);
    }
}
```
**Issue**: In the `noasm` implementation of `MLDSA_VectorsCaddQ`, the parameter `s2` is completely ignored (`(void) s2;`), while the ASM implementation (`VecCaddq`) adds `s2` to `w`. This divergence means the two implementations do completely different things.
**Fix**:
```
void MLDSA_VectorsCaddQ(int32_t w[MLDSA_N], int32_t s2[MLDSA_N])
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        w[i] += s2[i];
        w[i] += (MLDSA_Q & (w[i] >> 31));
    }
}
```

---

### MLDSA_Batch_Decompose discards r0 and fails to update array a
`crypto/mldsa/src/noasm/export_mldsa_c.c:75-81`
```
void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t a[MLDSA_N], int32_t r1[MLDSA_N])
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        int32_t r0;
        MLDSA_Decompose(ctx, a[i], &r1[i], &r0);
    }
}
```
**Issue**: In the `noasm` implementation of `MLDSA_Batch_Decompose`, the result `r0` from `MLDSA_Decompose` is written to a local variable and discarded. It fails to update `a[i]`, which diverges from the ASM implementation (`BatchDecompose88` / `BatchDecompose32`) where `a` is modified in-place to store the `r0` values.
**Fix**:
```
void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t a[MLDSA_N], int32_t r1[MLDSA_N])
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        int32_t r0;
        MLDSA_Decompose(ctx, a[i], &r1[i], &r0);
        a[i] = r0;
    }
}
```

---


## Low

### Unnecessary (void) cast for used parameter h
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:44-46`
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    (void) h;
```
**Issue**: The parameter `h` is cast to void to suppress an unused parameter warning, but it is actually used later in the function (`fp(w[i], h[i]);`).
**Fix**:
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
```

---

### Unnecessary (void) cast for used parameter s
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:158-160`
```
int32_t MLDSA_RejBoundedPolyEta2(int32_t *a, const uint8_t *s)
{
    (void) s;
```
**Issue**: The parameter `s` is cast to void to suppress an unused parameter warning, but it is actually used later in the function (`GOTO_ERR_IF(hashMethod->update(mdCtx, s, MLDSA_PRIVATE_SEED_LEN + 2), ret);`).
**Fix**:
```
int32_t MLDSA_RejBoundedPolyEta2(int32_t *a, const uint8_t *s)
{
```

---

### Unnecessary (void) cast for used parameter s
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:211-213`
```
int32_t MLDSA_RejBoundedPolyEta4(int32_t *a, const uint8_t *s)
{
    (void) s;
```
**Issue**: The parameter `s` is cast to void to suppress an unused parameter warning, but it is actually used later in the function (`GOTO_ERR_IF(hashMethod->update(mdCtx, s, MLDSA_PRIVATE_SEED_LEN + 2), ret);`).
**Fix**:
```
int32_t MLDSA_RejBoundedPolyEta4(int32_t *a, const uint8_t *s)
{
```

---
