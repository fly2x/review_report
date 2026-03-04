# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1114
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/openhitls#1114
**Reviewer**: CLAUDE


## High

### Removal of pointer authentication reduces security hardening
`config/json/compile.json:61`
```
"CC_DEFINE_FLAGS_REMOVE": [
                "-DHITLS_AARCH64_PACIASP"
            ]
```
**Issue**: The removal of `-DHITLS_AARCH64_PACIASP` from CC_DEFINE_FLAGS_REMOVE disables pointer authentication for ALL ARMv8 assembly code (AES, SHA, SM2/3/4, ECC, ML-KEM, etc.). This is a security regression as PAC (Pointer Authentication Codes) is a significant hardening feature that helps prevent ROP (Return-Oriented Programming) attacks on ARMv8.3-A+ processors.

The change affects not just the new ML-KEM code but ALL existing ARMv8 assembly implementations.
**Fix**:
```
"CC_DEFINE_FLAGS_REMOVE": [
            ]
```

---


## Medium

### Potential buffer overflow in GenMatrixSingle
`crypto/mlkem/src/asm_ml_kem_poly.c:226`
```
KyberShakeAbsorb(&state, seed, x, y);
    Shake128Squeeze(buf, GEN_MATRIX_NBLOCKS, &state);  // May be unnecessary if MLKEMRejUniform fills all
    uint32_t buflen = GEN_MATRIX_NBLOCKS * CRYPT_SHAKE128_BLOCKSIZE;
    uint32_t ctr = MLKEMRejUniform(poly, buf);
    
    while (ctr < MLKEM_N) {  // If ctr == MLKEM_N above, this loop is unnecessary
```
**Issue**: The `Shake128Squeeze` function is called without verifying the state has been properly initialized. The `buf` array size calculation assumes GEN_MATRIX_NBLOCKS is sufficient, but rejection sampling may require significantly more data. The while loop on line 221 correctly handles the case by calling `Shake128Squeeze` again, but the initial call on line 216 should check if ctr == MLKEM_N before the loop to avoid unnecessary XOF calls.
**Fix**:
```
KyberShakeAbsorb(&state, seed, x, y);
    uint32_t ctr = 0;
    uint32_t buflen = 0;
    uint8_t buf[GEN_MATRIX_NBLOCKS * CRYPT_SHAKE128_BLOCKSIZE + 2];
    
    while (ctr < MLKEM_N) {
        uint32_t off = buflen % 3;
        for (uint32_t m = 0; m < off; m++) {
            buf[m] = buf[buflen - off + m];
        }
        Shake128Squeeze(buf + off, 1, &state);
        buflen = off + CRYPT_SHAKE128_BLOCKSIZE;
        ctr += Parse(poly + ctr, buf, buflen, MLKEM_N - ctr);
    }
```

---

### VLA array declaration may cause stack overflow for large k
`crypto/mlkem/src/asm_ml_kem_poly.c:267`
```
void MLKEM_PKEGen(uint32_t k, MLKEM_MatrixSt *mat, uint8_t *seed, uint8_t *pk, uint8_t *dk)
{
    int16_t s_asym[k][MLKEM_N >> 1];  // VLA: k * 128 * 2 = k * 256 bytes
    int16_t e[MLKEM_K_MAX][MLKEM_N];  // 4 * 256 * 2 = 2048 bytes
```
**Issue**: The `s_asym` variable is declared as a VLA (Variable Length Array) with size `k * (MLKEM_N >> 1)` elements (k * 128 * sizeof(int16_t) = k * 256 bytes). For k=4, this is 1024 bytes on stack. Combined with other local variables and the Keccakx2State (400 bytes), the stack usage per function call could exceed 2KB. While MLKEM_K_MAX is 4, defensive coding should ensure this doesn't cause issues in deep call stacks or with threads with small stacks.
**Fix**:
```
int16_t s_asym[MLKEM_K_MAX][MLKEM_N >> 1];  // Fixed size, no VLA
    // or use BSL_SAL_Calloc/BSL_SAL_Free for dynamic allocation
```

---


## Low

### Unaligned NEON load may have performance impact
`crypto/sha3/src/aarch64_sha3.c:232`
```
uint64_t lane0 = ((uint64_t)in0[i]) << (8 * (i % 8));
        uint64_t lane1 = ((uint64_t)in1[i]) << (8 * (i % 8));
        tmp0[0] = lane0;
        tmp0[1] = lane1;
        state[i / 8] = veorq_u64(state[i / 8], vld1q_u64(tmp0));  // Potentially unaligned load
```
**Issue**: The `vld1q_u64(tmp0)` loads from a stack-allocated array `tmp0[2]` which may not be 16-byte aligned on all ARMv8 implementations. While ARMv8 supports unaligned loads, they may be slower than aligned loads. This occurs in the hot path of the absorb function.
**Fix**:
```
uint64x1_t v0 = vcreate_u64(((uint64_t)in0[i]) << (8 * (i % 8)));
        uint64x1_t v1 = vcreate_u64(((uint64_t)in1[i]) << (8 * (i % 8)));
        state[i / 8] = veorq_u64(state[i / 8], vcombine_u64(v0, v1));
```

---


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1114
**Reviewer**: CODEX


## Medium

### AArch64 PAC return-address signing macro removed from default defines
`config/json/compile.json:33-39`
```
"CC_DEFINE_FLAGS": [
    "-DHITLS_CRYPTO_EAL_REPORT",
    "-DHITLS_CRYPTO_NIST_ECC_ACCELERATE",
    "-DHITLS_CRYPTO_BN_COMBA",
    "-DHITLS_CRYPTO_AES_PRECALC_TABLES",
    "-DHITLS_CRYPTO_SM2_PRECOMPUTE_512K_TBL"
]
```
**Issue**: The default compile defines no longer include `-DHITLS_AARCH64_PACIASP`, so `AARCH64_PACIASP/AARCH64_AUTIASP` expand to no-ops in assembly (`crypt_arm.h`). This removes return-address signing hardening for AArch64 assembly crypto code.
**Fix**:
```
"CC_DEFINE_FLAGS": [
    "-DHITLS_CRYPTO_EAL_REPORT",
    "-DHITLS_CRYPTO_NIST_ECC_ACCELERATE",
    "-DHITLS_CRYPTO_BN_COMBA",
    "-DHITLS_CRYPTO_AES_PRECALC_TABLES",
    "-DHITLS_AARCH64_PACIASP",
    "-DHITLS_CRYPTO_SM2_PRECOMPUTE_512K_TBL"
]
```

---

### x2 SHAKE path is endianness-incorrect on big-endian AArch64
`crypto/sha3/src/aarch64_sha3.c:216-218`
```
uint64x1_t v0 = vreinterpret_u64_u8(vld1_u8(in0 + i * 8));
uint64x1_t v1 = vreinterpret_u64_u8(vld1_u8(in1 + i * 8));
state[i] = veorq_u64(state[i], vcombine_u64(v0, v1));

...

vst1_u8(out0 + i * 8, vreinterpret_u8_u64(vget_low_u64(s[i])));
vst1_u8(out1 + i * 8, vreinterpret_u8_u64(vget_high_u64(s[i])));
```
**Issue**: The new NEON x2 SHAKE absorb/squeeze path loads/stores 64-bit lanes as raw bytes without LE conversion. Existing SHA3 ARMv8 assembly handles `HITLS_BIG_ENDIAN`, but this new C path does not, producing wrong SHAKE output on big-endian targets.
**Fix**:
```
#ifdef HITLS_BIG_ENDIAN
uint64_t lane0 = GET_UINT64_LE(in0, i * 8);
uint64_t lane1 = GET_UINT64_LE(in1, i * 8);
state[i] = veorq_u64(state[i], vcombine_u64(vcreate_u64(lane0), vcreate_u64(lane1)));
#else
uint64x1_t v0 = vreinterpret_u64_u8(vld1_u8(in0 + i * 8));
uint64x1_t v1 = vreinterpret_u64_u8(vld1_u8(in1 + i * 8));
state[i] = veorq_u64(state[i], vcombine_u64(v0, v1));
#endif

...

#ifdef HITLS_BIG_ENDIAN
PUT_UINT64_LE(vgetq_lane_u64(s[i], 0), out0, i * 8);
PUT_UINT64_LE(vgetq_lane_u64(s[i], 1), out1, i * 8);
#else
vst1_u8(out0 + i * 8, vreinterpret_u8_u64(vget_low_u64(s[i])));
vst1_u8(out1 + i * 8, vreinterpret_u8_u64(vget_high_u64(s[i])));
#endif
```

---

### ML-KEM switched from provider-aware hash dispatch to hardwired local SHA3/SHAKE
`crypto/mlkem/src/ml_kem_pke.c:346`
```
CRYPT_SHA3_512(digest, seed, MLKEM_SEED_LEN + 1);

...

CRYPT_SHAKE256(bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2, r, MLKEM_SEED_LEN + 1);
```
**Issue**: Keygen/encrypt now call direct one-shot SHA3/SHAKE functions, bypassing `ctx->libCtx` provider dispatch and its error path. This breaks consistency with provider-based operation used elsewhere in the file and can violate provider/FIPS routing expectations.
**Fix**:
```
ret = HashFuncG(ctx->libCtx, seed, MLKEM_SEED_LEN + 1, digest, CRYPT_SHA3_512_DIGESTSIZE);
RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

...

ret = HashFuncJ(ctx->libCtx, r, MLKEM_SEED_LEN + 1, bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2);
GOTO_ERR_IF_EX(ret, ret);
```

---

### Noise PRF path ignores `libCtx` and cannot report SHAKE provider errors
`crypto/mlkem/src/ml_kem_poly.c:266-273`
```
CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX, q, MLKEM_SEED_LEN + 1);
...
CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX, q, MLKEM_SEED_LEN + 1);
```
**Issue**: `SampleEta1/2` now use direct `CRYPT_SHAKE256` one-shot calls and always return success, bypassing provider dispatch (`ctx->libCtx`) and removing error propagation previously provided by EAL MD calls.
**Fix**:
```
uint32_t outLen = MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX;
int32_t ret = EAL_Md(CRYPT_MD_SHAKE256, ctx->libCtx, NULL, q, MLKEM_SEED_LEN + 1,
    prfOut, &outLen, false, ctx->libCtx != NULL);
RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

/* Apply the same pattern for eta2 output length */
outLen = MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX;
ret = EAL_Md(CRYPT_MD_SHAKE256, ctx->libCtx, NULL, q, MLKEM_SEED_LEN + 1,
    prfOut, &outLen, false, ctx->libCtx != NULL);
RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
```

---


## Low

### Sensitive buffer cleanse length not updated after buffer size increase
`crypto/mlkem/src/ml_kem_pke.c:551`
```
uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE + 1];    // K and r
...
BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
...
BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
```
**Issue**: `kr` was expanded from 64 to 65 bytes, but cleansing still wipes only 64 bytes. One byte remains uncleansed on stack.
**Fix**:
```
uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE + 1];    // K and r
...
BSL_SAL_CleanseData(kr, sizeof(kr));
...
BSL_SAL_CleanseData(kr, sizeof(kr));
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
