# Final Code Review Report
## openHiTLS/openhitls - PR #1153

### Summary
- **Total Issues**: 9
- **Critical**: 6
- **High**: 0
- **Medium**: 0
- **Low**: 3
- **Reviewers**: claude, gemini, codex

---


## Critical

### Incorrect buffer index initialization in MLDSA_RejBoundedPolyEta2
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:182`
**Reviewers**: CLAUDE | **置信度**: 可信
```
gensize = MldRejUniformEta2Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
```
**Issue**: The fallback loop initializes j = bufLen+1 (137), which immediately triggers j >= CRYPT_SHAKE256_BLOCKSIZE (136), causing an immediate buffer refill. This skips the bytes that were just fetched from SHAKE256. The C reference implementation (export_mldsa_c.c:170) uses j = 0, which is the correct initialization. This bug causes incorrect polynomial generation in the ML-DSA signature algorithm, weakening cryptographic security.
**Fix**:
```
gensize = MldRejUniformEta2Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = 0; i < MLDSA_N; j++) {
    if (j == CRYPT_SHAKE256_BLOCKSIZE) {
```

---

### Incorrect buffer index initialization in MLDSA_RejBoundedPolyEta4
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:235`
**Reviewers**: CLAUDE | **置信度**: 可信
```
gensize = MldRejUniformEta4Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
```
**Issue**: Similar to the Eta2 function, the loop initializes j = bufLen+1 (273), causing immediate buffer refill and skipping valid SHAKE256 bytes. Additionally, the condition compares j against CRYPT_SHAKE256_BLOCKSIZE (136) instead of bufLen (272), which is inconsistent with the 2-block buffer allocation. The C reference implementation (export_mldsa_c.c:217) uses j = 0. This causes incorrect polynomial generation.
**Fix**:
```
gensize = MldRejUniformEta4Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = 0; i < MLDSA_N; j++) {
    if (j == CRYPT_SHAKE256_BLOCKSIZE) {
```

---

### MLDSA_RejNTTPoly reuses consumed SHAKE128 buffer bytes
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:108-149`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;

uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
    const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
```
**Issue**: After MldRejUniformAsm processes the initial SHAKE128 data and returns gensize < MLDSA_N coefficients, the scalar fallback loop starts with j = 0. This re-reads from buf[0] instead of squeezing a new SHAKE128 block, causing the ARMv8 implementation to diverge from the reference rejection sampler. The C reference implementation (export_mldsa_c.c:103) starts fresh with j = 0 after a single squeeze, but the ARMv8 version has already consumed 5 blocks via assembly.
**Fix**:
```
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;

if (gensize < MLDSA_N) {
    GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
}
uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
```

---

### MLDSA_VectorsCaddQ ignores s2 parameter in noasm implementation
`crypto/mldsa/src/noasm/export_mldsa_c.c:269-276`
**Reviewers**: GEMINI | **置信度**: 可信
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
**Issue**: The noasm implementation completely ignores the s2 parameter ((void) s2;) and only applies conditional modular reduction to w. However, the ARMv8 assembly version calls VecCaddq(w, w, s2) which adds s2 to w before modular reduction. This is a fundamental semantic difference - the two implementations do completely different operations, causing signature verification failures depending on which implementation is used.
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

### MLDSA_Batch_Decompose fails to store r0 values in array a
`crypto/mldsa/src/noasm/export_mldsa_c.c:75-81`
**Reviewers**: GEMINI | **置信度**: 可信
```
void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t a[MLDSA_N], int32_t r1[MLDSA_N])
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        int32_t r0;
        MLDSA_Decompose(ctx, a[i], &r1[i], &r0);
    }
}
```
**Issue**: The noasm implementation writes r0 to a local variable and discards it. It fails to update a[i] with the r0 value. The ARMv8 assembly implementation (BatchDecompose88/BatchDecompose32) modifies the input array a in-place to store the r0 values while storing r1 in the output array. This divergence causes incorrect cryptographic computations.
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

### Build configuration references deleted ml_dsa_ntt.c path
`config/json/feature.json:1417-1427`
**Reviewers**: CODEX | **置信度**: 可信
```
".srcs": {
    "public": [
        "crypto/mldsa/src/ml_dsa_core.c",
        "crypto/mldsa/src/ml_dsa_ntt.c",
        "crypto/mldsa/src/ml_dsa.c"
    ],
    "no_asm": "crypto/mldsa/src/noasm/*.c",
```
**Issue**: The ML-DSA source reorganization moved ml_dsa_ntt.c from crypto/mldsa/src/ to crypto/mldsa/src/noasm/, but the .srcs.public list still points to the old deleted path "crypto/mldsa/src/ml_dsa_ntt.c". The local source resolver always includes .srcs.public before variant-specific lists, so any build with mldsa enabled attempts to compile a non-existent source file, causing build failures.
**Fix**:
```
".srcs": {
    "public": [
        "crypto/mldsa/src/ml_dsa_core.c",
        "crypto/mldsa/src/ml_dsa.c"
    ],
    "no_asm": "crypto/mldsa/src/noasm/*.c",
```

---


## Low

### Unnecessary (void) cast for used parameter h
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:46`
**Reviewers**: GEMINI | **置信度**: 较可信
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    (void) h;
    void (*fp)(int32_t *, int32_t const *);
    fp = ctx->info->k == K_VALUE_OF_MLDSA_44? Usehint88: Usehint32;

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        fp(w[i], h[i]);
    }
}
```
**Issue**: Parameter h is cast to void to suppress unused warning, but it is actually used at line 51 (fp(w[i], h[i]);). The (void) h; cast at line 46 is unnecessary and should be removed.
**Fix**:
```
void MLDSA_UseHint(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const h[MLDSA_K_MAX], int32_t *w[MLDSA_K_MAX])
{
    void (*fp)(int32_t *, int32_t const *);
```

---

### Unnecessary (void) cast for used parameter s
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:160`
**Reviewers**: GEMINI | **置信度**: 较可信
```
int32_t MLDSA_RejBoundedPolyEta2(int32_t *a, const uint8_t *s)
{
    (void) s;
    uint8_t buf[CRYPT_SHAKE256_BLOCKSIZE] = {0};
    ...
    GOTO_ERR_IF(hashMethod->update(mdCtx, s, MLDSA_PRIVATE_SEED_LEN + 2), ret);
```
**Issue**: Parameter s is cast to void at line 160, but it is used at line 177 (hashMethod->update(mdCtx, s, MLDSA_PRIVATE_SEED_LEN + 2)). The (void) s; cast is unnecessary.
**Fix**:
```
int32_t MLDSA_RejBoundedPolyEta2(int32_t *a, const uint8_t *s)
{
    uint8_t buf[CRYPT_SHAKE256_BLOCKSIZE] = {0};
```

---

### Unnecessary (void) cast for used parameter s
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:213`
**Reviewers**: GEMINI | **置信度**: 较可信
```
int32_t MLDSA_RejBoundedPolyEta4(int32_t *a, const uint8_t *s)
{
    (void) s;
    uint8_t buf[2*CRYPT_SHAKE256_BLOCKSIZE] = {0};
    ...
    GOTO_ERR_IF(hashMethod->update(mdCtx, s, MLDSA_PRIVATE_SEED_LEN + 2), ret);
```
**Issue**: Parameter s is cast to void at line 213, but it is used at line 230 (hashMethod->update(mdCtx, s, MLDSA_PRIVATE_SEED_LEN + 2)). The (void) s; cast is unnecessary.
**Fix**:
```
int32_t MLDSA_RejBoundedPolyEta4(int32_t *a, const uint8_t *s)
{
    uint8_t buf[2*CRYPT_SHAKE256_BLOCKSIZE] = {0};
```

---
