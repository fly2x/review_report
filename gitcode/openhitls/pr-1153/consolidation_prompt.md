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


## Critical

### Incorrect buffer index initialization in MLDSA_RejBoundedPolyEta2
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:182`
```
gensize = MldRejUniformEta2Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
```
**Issue**: The fallback loop initializes j = bufLen+1 (137), which immediately triggers a buffer refill on the first iteration (j >= CRYPT_SHAKE256_BLOCKSIZE). This skips bytes from the buffer that were just fetched from SHAKE256. The C reference implementation uses j = 0. This could cause incorrect polynomial generation and weaken cryptographic security.
**Fix**:
```
gensize = MldRejUniformEta2Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = 0; i < MLDSA_N; j++) {
    if (j == CRYPT_SHAKE256_BLOCKSIZE) {
```

---

### Incorrect buffer index initialization in MLDSA_RejBoundedPolyEta4
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:235`
```
gensize = MldRejUniformEta4Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
```
**Issue**: Similar to issue in Eta2, the loop initializes j = bufLen+1 (273), causing immediate buffer refill and skipping valid bytes. Additionally, the condition compares j against CRYPT_SHAKE256_BLOCKSIZE (136) instead of bufLen (272), which is inconsistent with the 2-block buffer allocation.
**Fix**:
```
gensize = MldRejUniformEta4Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = 0; i < MLDSA_N; j++) {
    if (j == CRYPT_SHAKE256_BLOCKSIZE) {
```

---


## High

### Memory allocation bug fix for MLDSAKeyGenCreateMatrix
`crypto/mldsa/src/ml_dsa_core.c:95-102`
```
for (uint8_t i = 0; i < l; i++) {
    MLDSA_SET_VECTOR_MEM(st->s1[i], buf);
}
for (uint8_t i = 0; i < l; i++) {
    MLDSA_SET_VECTOR_MEM(st->s1Ntt[i], buf);
}
```
**Issue**: The original code had a critical bug where s1[i] and s1Ntt[i] were assigned memory in the same loop iteration, causing them to point to overlapping memory regions. The fix correctly splits this into two separate loops. This is a correct fix for a memory corruption bug.

---


## Medium

### Inconsistent buffer handling in MLDSA_RejNTTPoly fallback loop
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:108-109`
```
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;

uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
```
**Issue**: After the assembly call processes 5 blocks of SHAKE128 data, the fallback loop starts with j = 0. This means it re-processes the buffer from the beginning rather than continuing from where the assembly function left off. The C reference implementation starts with j = 0 but in a different context (no initial assembly preprocessing).
**Fix**:
```
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
// Calculate how many bytes were consumed by the assembly function
uint32_t bytesConsumed = (gensize * 3 + 2) / 4 * sizeof(uint32_t); // Approximate
uint32_t j = bytesConsumed / sizeof(uint32_t);
buflen = outlen / sizeof(uint32_t);

for (uint32_t i = gensize; i < MLDSA_N;) {
```

---


## Low

### Malformed comments missing mathematical symbols
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:190`
```
// if  = 2 and b < 15 then return 2  (b mod 5)
...
// 2  (b mod 5)
```
**Issue**: The comments are missing mathematical operators (eta symbol η and minus sign -), making them incomplete and potentially misleading for developers trying to understand the algorithm.
**Fix**:
```
// if η = 2 and b < 15 then return 2 − (b mod 5)
...
// 2 − (b mod 5)
```

---


---

## GEMINI Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CODEX


## High

### ML-DSA source split still leaves the deleted NTT file in the always-built public list
`config/json/feature.json:1417-1427`
```
".srcs": {
    "public": [
        "crypto/mldsa/src/ml_dsa_core.c",
        "crypto/mldsa/src/ml_dsa_ntt.c",
        "crypto/mldsa/src/ml_dsa.c"
    ],
    "no_asm": "crypto/mldsa/src/noasm/*.c",
    "armv8": [
        "crypto/mldsa/src/asm/*armv8.S",
        "crypto/mldsa/src/asm/*armv8.c",
        "crypto/mldsa/src/asm/*table.c"
    ]
}
```
**Issue**: The new `no_asm`/`armv8` split moved `ml_dsa_ntt.c` into `crypto/mldsa/src/noasm/`, but the `public` list still points at the old deleted path. The local source resolver always includes `.srcs.public` before the variant-specific list, so any build with `mldsa` enabled expands a missing source file.
**Fix**:
```
".srcs": {
    "public": [
        "crypto/mldsa/src/ml_dsa_core.c",
        "crypto/mldsa/src/ml_dsa.c"
    ],
    "no_asm": "crypto/mldsa/src/noasm/*.c",
    "armv8": [
        "crypto/mldsa/src/asm/*armv8.S",
        "crypto/mldsa/src/asm/*armv8.c",
        "crypto/mldsa/src/asm/*table.c"
    ]
}
```

---


## Medium

### ARMv8 rejection sampler byte-swaps the raw SHAKE stream before parsing it
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:99-104`
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
for (uint32_t i = 0; i < buflen; i++) {
    buf[i] = CRYPT_HTOLE32(buf[i]);
}
uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
```
**Issue**: `MldRejUniformAsm` consumes the SHAKE output as a byte stream, but this wrapper rewrites every `uint32_t` with `CRYPT_HTOLE32` before casting the buffer back to `uint8_t *`. On big-endian AArch64 that permutes the bytes inside each 32-bit word, so the armv8 path expands a different matrix than the scalar implementation.
**Fix**:
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);

uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
```

---


## Low

### Scalar fallback for `MLDSA_RejNTTPoly` restarts from an already-consumed buffer
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:103-149`
```
uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4; // buflen in terms of uint32_t

uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
    const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
    const uint32_t w1 = CRYPT_HTOLE32(buf[j + 1]);
    const uint32_t w2 = CRYPT_HTOLE32(buf[j + 2]);
    ...
    j += 3;
    if (j >= buflen && i < MLDSA_N) {
        GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
        j = 0;
    }
}
```
**Issue**: After `MldRejUniformAsm` processes the initial five SHAKE128 blocks, the scalar tail starts with `j = 0` and reads from `buf[0]` again. If the fast path returns fewer than 256 accepted coefficients, the continuation duplicates bytes from the beginning of the XOF output instead of squeezing the next block, so the ARMv8 result diverges from the reference rejection sampler on that edge path.
**Fix**:
```
uint32_t gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;

if (gensize < MLDSA_N) {
    GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
}
uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
    const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
    const uint32_t w1 = CRYPT_HTOLE32(buf[j + 1]);
    const uint32_t w2 = CRYPT_HTOLE32(buf[j + 2]);
    ...
}
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
