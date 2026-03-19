# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CLAUDE


## High

### Function declaration missing const qualifier for ctx parameter
`crypto/mldsa/src/ml_dsa_local.h:105`
```
// Header declaration (ml_dsa_local.h line 105)
void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t a[MLDSA_N], int32_t r1[MLDSA_N]);
```
**Issue**: The declaration `void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, ...)` adds a const qualifier for ctx, but the implementation in noasm/export_mldsa_c.c shows `void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, ...)` with const. However, looking more closely, the ARMv8 implementation incorrectly passes ctx to an assembly function that expects array pointers.
**Fix**:
```
// Remove unused function declaration, or implement it correctly:
void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t a[MLDSA_N], int32_t r1[MLDSA_N])
{
    void (*fp)(int32_t *, int32_t *);
    fp = ctx->info->k == K_VALUE_OF_MLDSA_44 ? batch_decompose_88 : batch_decompose_32;
    fp(a, r1);
}
```

---


## Medium

### Incorrect (void) h; cast in MLDSA_UseHint function
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:73-80`
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX]) {
    (void) h;  // INCORRECT: h is used below!
    void (*fp)(int32_t *, int32_t const *);
    fp = ctx->info->k == K_VALUE_OF_MLDSA_44? usehint_88: usehint_32;

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        fp(w[i], h[i]);  // h IS used here
    }
}
```
**Issue**: The line `(void) h;` suppresses the unused parameter warning, but `h` is actually used later in the function (`fp(w[i], h[i])`). This cast should be removed as it misleads readers about the parameter usage.
**Fix**:
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX]) {
    void (*fp)(int32_t *, int32_t const *);
    fp = ctx->info->k == K_VALUE_OF_MLDSA_44? usehint_88: usehint_32;

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        fp(w[i], h[i]);
    }
}
```

---

### Confusing loop initialization in MLDSA_RejBoundedPolyEta2
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:254`
```
gensize = mld_rej_uniform_eta2_asm(a, buf, bufLen, mld_rej_uniform_eta_table);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
        GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, CRYPT_SHAKE256_BLOCKSIZE), ret);
        j = 0;
    }
    int32_t z0 = (int32_t)(buf[j] & 0x0F);
    ...
}
```
**Issue**: The loop starts with `j = bufLen+1` which causes an immediate buffer refill on first iteration. This skips one byte (the second byte) of each buffer after the first. While this may be intentional optimization, it's non-obvious and differs from the reference C implementation.
**Fix**:
```
gensize = mld_rej_uniform_eta2_asm(a, buf, bufLen, mld_rej_uniform_eta_table);

// The asm function processes bufLen bytes, leaving buf[bufLen] unprocessed.
// Start loop at bufLen to process this byte before refilling buffer.
for (uint32_t i = gensize, j = bufLen; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
        GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, CRYPT_SHAKE256_BLOCKSIZE), ret);
        j = 0;
    }
    int32_t z0 = (int32_t)(buf[j] & 0x0F);
    ...
}
```

---

### Same confusing loop initialization in MLDSA_RejBoundedPolyEta4
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:282`
```
gensize = mld_rej_uniform_eta4_asm(a, buf, bufLen, mld_rej_uniform_eta_table);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
        GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, CRYPT_SHAKE256_BLOCKSIZE), ret);
        j = 0;
    }
    ...
}
```
**Issue**: Same issue as MLDSA_RejBoundedPolyEta2 - loop starts with `j = bufLen+1` causing immediate buffer refill.
**Fix**:
```
gensize = mld_rej_uniform_eta4_asm(a, buf, bufLen, mld_rej_uniform_eta_table);

// The asm function processes bufLen bytes, leaving buf[bufLen] unprocessed.
// Start loop at bufLen to process this byte before refilling buffer.
for (uint32_t i = gensize, j = bufLen; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
        GOTO_ERR_IF(hashMethod->squeeze(mdCtx, buf, CRYPT_SHAKE256_BLOCKSIZE), ret);
        j = 0;
    }
    ...
}
```

---
