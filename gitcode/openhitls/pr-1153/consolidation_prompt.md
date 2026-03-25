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


## Low

### Inconsistent register naming in PolyzUnpack19Asm
`crypto/mldsa/src/asm/polyz_unpack_armv8.S:145-146`
```
polyz_unpack_19_loop:
    ldr q_buf1, [buf, #16]
    ldr d2, [buf, #32]
    ldr q0, [buf], #40
```
**Issue**: The PolyzUnpack19Asm function uses raw register names (d2, q0) instead of the defined aliases (buf2, buf0) used elsewhere in the code. This is inconsistent with the coding style and could cause confusion during maintenance. The code is functionally correct because d2 is the lower 64 bits of v2 (aliased as buf2), and the index table only accesses bytes 0-7 which are properly loaded.
**Fix**:
```
polyz_unpack_19_loop:
    ldr q_buf1, [buf, #16]
    ldr q_buf2, [buf, #32]
    ldr q_buf0, [buf], #40
```

---


---

## GEMINI Review

# Code Review: openHiTLS/openhitls#1153
**Reviewer**: GEMINI


## High

### Missing negative value correction in MLDSA_Batch_Decompose
`crypto/mldsa/src/noasm/export_mldsa_c.c:76-83`
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
**Issue**: In `ml_dsa_core.c`, the original `ComputesW` function correctly added `MLDSA_Q` to negative values of `w[i][j]` before calling `Decompose()`. The refactored code extracts this loop into `MLDSA_Batch_Decompose()`. While the assembly version (`BatchDecompose88`/`32`) includes this correction via the `finit` macro, the C fallback version in `export_mldsa_c.c` omits it. Since `MLDSA_ComputesINVNTT()` can yield negative values, passing a negative `int32_t` directly to `MLDSA_Decompose()` causes the cast to `uint32_t` to produce a huge number, breaking the decomposition logic.
**Fix**:
```
void MLDSA_Batch_Decompose(const CRYPT_ML_DSA_Ctx *ctx, int32_t a[MLDSA_N], int32_t r1[MLDSA_N])
{
    for (uint32_t i = 0; i < MLDSA_N; i++) {
        int32_t r0;
        a[i] = a[i] + (MLDSA_Q & (a[i] >> 31));
        MLDSA_Decompose(ctx, a[i], &r1[i], &r0);
        a[i] = r0;
    }
}
```

---


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CODEX


## High

### AArch64 rejection sampler incorrectly rejects the valid value `q - 1`
`crypto/mldsa/src/asm/rej_uniform_armv8.S:103-106`
```
// load q = 8380417 - 1
    movz wtmp, #0xE000
    movk wtmp, #0x7F, lsl #16    // 8380417 = 0x7FE001
    dup mldsa_q.4s, wtmp
...
        cmhi tmp0.4s, mldsa_q.4s, val0.4s
        cmhi tmp1.4s, mldsa_q.4s, val1.4s
        cmhi tmp2.4s, mldsa_q.4s, val2.4s
        cmhi tmp3.4s, mldsa_q.4s, val3.4s
...
        cmhi    tmp0.4s, mldsa_q.4s, val0.4s
        cmhi    tmp1.4s, mldsa_q.4s, val1.4s
```
**Issue**: The sampler loads `8380417 - 1` into `mldsa_q` and then uses `cmhi`, which is a strict `>` comparison. That accepts only values `< q - 1`, so the valid coefficient `8380416` is rejected in both the main loop and the 24-byte tail path. This biases `ExpandA` on every armv8 build and makes the generated ML-DSA matrices diverge from the spec and from the portable implementation.
**Fix**:
```
// load q = 8380417
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16
    dup mldsa_q.4s, wtmp

    cmhi tmp0.4s, mldsa_q.4s, val0.4s
    cmhi tmp1.4s, mldsa_q.4s, val1.4s
    cmhi tmp2.4s, mldsa_q.4s, val2.4s
    cmhi tmp3.4s, mldsa_q.4s, val3.4s

    cmhi tmp0.4s, mldsa_q.4s, val0.4s
    cmhi tmp1.4s, mldsa_q.4s, val1.4s
```

---


## Medium

### In-place `HTOLE32` conversion corrupts the byte stream for big-endian armv8
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:99-104`
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
    for (uint32_t i = 0; i < buflen; i++) {
        buf[i] = CRYPT_HTOLE32(buf[i]);
    }
    uint32_t gensize = 0;
    gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
```
**Issue**: `MldRejUniformAsm` consumes the SHAKE output as raw bytes, not as 32-bit words. Swapping every `uint32_t` in `buf` before passing it to the assembly routine reverses the byte order inside each 4-byte chunk on big-endian AArch64 builds. The project already has big-endian support paths, so this makes armv8 big-endian derive a different public matrix than the portable implementation.
**Fix**:
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
    uint32_t gensize = 0;
    gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
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
