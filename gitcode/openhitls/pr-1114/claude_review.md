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
