# Final Code Review Report
## openHiTLS/openhitls - PR #1153

### Summary
- **Total Issues**: 4
- **Critical**: 0
- **High**: 2
- **Medium**: 1
- **Low**: 1
- **Reviewers**: claude, gemini, codex

---


## High

### AArch64 rejection sampler incorrectly rejects the valid value q-1
`crypto/mldsa/src/asm/rej_uniform_armv8.S:103-106`
**Reviewers**: CODEX | **置信度**: 可信
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
```
**Issue**: The sampler loads `8380417 - 1` (q-1 = 0x7FE000) into `mldsa_q` and uses `cmhi` for unsigned greater-than comparison. This accepts only values `< q - 1`, so the valid coefficient `8380416` is rejected in both the main loop and the 24-byte tail path. The C version in `export_mldsa_c.c` correctly uses `(MLDSA_Q - 1 - t0) >> 31` which accepts values `<= 8380416`. This biases the rejection sampler on every armv8 build and makes the generated ML-DSA matrices diverge from the spec.
**Fix**:
```
// load q = 8380417
    movz wtmp, #0xE001
    movk wtmp, #0x7F, lsl #16
    dup mldsa_q.4s, wtmp
```

---

### Missing negative value correction in MLDSA_Batch_Decompose
`crypto/mldsa/src/noasm/export_mldsa_c.c:75-82`
**Reviewers**: GEMINI | **置信度**: 可信
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
**Issue**: In the original `ml_dsa_core.c`, `ComputesW` correctly added `MLDSA_Q` to negative values before calling `Decompose()`: `w[i][j] = w[i][j] + (MLDSA_Q & (w[i][j] >> 31))`. The refactored code extracts this loop into `MLDSA_Batch_Decompose()`. The assembly version (`BatchDecompose88`/`32`) includes this correction via the `finit` macro, but the C fallback version omits it. Since `MLDSA_ComputesINVNTT()` can yield negative values, passing a negative `int32_t` directly to `MLDSA_Decompose()` causes the cast to `uint32_t` to produce a huge number, breaking the decomposition logic.
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


## Medium

### In-place HTOLE32 conversion corrupts byte stream for big-endian armv8
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:100-104`
**Reviewers**: CODEX | **置信度**: 可信
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
for (uint32_t i = 0; i < buflen; i++) {
    buf[i] = CRYPT_HTOLE32(buf[i]);
}
uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
```
**Issue**: `MldRejUniformAsm` consumes the SHAKE output as raw bytes, not as 32-bit words. The loop swaps every `uint32_t` in `buf` before passing it to the assembly routine. On big-endian AArch64 builds, this reverses the byte order inside each 4-byte chunk, causing the assembly to derive a different public matrix than the portable implementation. The project has big-endian support paths, so this breaks cross-platform consistency.
**Fix**:
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
```

---


## Low

### Inconsistent register naming in PolyzUnpack19Asm
`crypto/mldsa/src/asm/polyz_unpack_armv8.S:145-146`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
polyz_unpack_19_loop:
    ldr q_buf1, [buf, #16]
    ldr d2, [buf, #32]
    ldr q0, [buf], #40
```
**Issue**: The `PolyzUnpack19Asm` function uses raw register names (`d2`, `q0`) instead of the defined aliases (`s_buf2`, `q_buf0`) used elsewhere in the code. In contrast, `PolyzUnpack17Asm` consistently uses the aliases (`q_buf1`, `s_buf2`, `q_buf0`). This inconsistency could cause confusion during maintenance. The code is functionally correct because `d2` is the lower 64 bits of `v2`, and the index table only accesses bytes 0-7.
**Fix**:
```
polyz_unpack_19_loop:
    ldr q_buf1, [buf, #16]
    ldr q_buf2, [buf, #32]
    ldr q_buf0, [buf], #40
```

---
