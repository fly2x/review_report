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
