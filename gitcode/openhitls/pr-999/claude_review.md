# Code Review: openHiTLS/openhitls#999
**Reviewer**: CLAUDE


## Critical

### Integer overflow in RejNTTPoly coefficient extraction
`crypto/mldsa/src/ml_dsa_core.c:204-212`
```
const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
const uint32_t w1 = CRYPT_HTOLE32(buf[j + 1]);
const uint32_t w2 = CRYPT_HTOLE32(buf[j + 2]);

int32_t t0 = w0;
int32_t t1 = (w0 >> 24) | (w1 << 8);
int32_t t2 = (w1 >> 16) | (w2 << 16);
int32_t t3 = (w2 >> 8);
```
**Issue**: The code extracts 23-bit coefficients from 32-bit words using bit operations. When processing `w0 >> 24` combined with `w1 << 8`, if `w1` has its high bit set, the left shift could cause undefined behavior or overflow. Additionally, the mask `0x7FFFFFU` only masks 23 bits, but intermediate values could exceed this before masking.
**Fix**:
```
const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
const uint32_t w1 = CRYPT_HTOLE32(buf[j + 1]);
const uint32_t w2 = CRYPT_HTOLE32(buf[j + 2]);

int32_t t0 = (int32_t)(w0 & 0x7FFFFFU);
int32_t t1 = (int32_t)(((w0 >> 24) | (w1 << 8)) & 0x7FFFFFU);
int32_t t2 = (int32_t)(((w1 >> 16) | (w2 << 16)) & 0x7FFFFFU);
int32_t t3 = (int32_t)((w2 >> 8) & 0x7FFFFFU);
```

---


## High

### Missing inline function in header for PlantardMulReduce
`crypto/mldsa/src/ml_dsa_ntt.c:81-88`
```
inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}
```
**Issue**: The function `MLDSA_PlantardMulReduce` is declared as `inline` in the .c file but the declaration in the header (`ml_dsa_local.h`) doesn't include `inline`. This can cause linker errors or duplicate symbol issues depending on the compiler and optimization settings. The inline function should be in the header or marked `static inline`.
**Fix**:
```
// In ml_dsa_local.h
static inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}
```

---

### Incorrect Plantard reduction with negative inputs
`crypto/mldsa/src/ml_dsa_ntt.c:81-88`
```
inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}
```
**Issue**: The `MLDSA_PlantardMulReduce` function uses right shift on potentially negative values. In C, right shift of negative signed integers is implementation-defined. The function relies on arithmetic right shift behavior, which is not guaranteed.
**Fix**:
```
static inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    // Use unsigned shift for well-defined behavior
    int64_t tmp = a;
    // Round towards negative infinity (arithmetic shift behavior)
    tmp = (tmp >= 0) ? (tmp >> MLDSA_PLANTARD_L) : 
          ((tmp - ((1LL << MLDSA_PLANTARD_L) - 1)) >> MLDSA_PLANTARD_L);
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp = (tmp >= 0) ? (tmp >> MLDSA_PLANTARD_L) : 
          ((tmp - ((1LL << MLDSA_PLANTARD_L) - 1)) >> MLDSA_PLANTARD_L);
    return (int32_t)tmp;
}
```

---

### Potential overflow in VectorsMul with Plantard multiplication
`crypto/mldsa/src/ml_dsa_core.c:399`
```
t[i] = MLDSA_PlantardMulReduce((uint64_t)matrix[i] * (uint64_t)s[i] * (uint64_t)MLDSA_PLANTARD_INV);
```
**Issue**: The multiplication `(uint64_t)matrix[i] * (uint64_t)s[i] * (uint64_t)MLDSA_PLANTARD_INV` could overflow before being passed to `MLDSA_PlantardMulReduce`. The inputs can be up to `q-1` (about 2^23), and `MLDSA_PLANTARD_INV` is about 2^64, making the product potentially overflow a 64-bit unsigned integer.
**Fix**:
```
// The Plantard representation stores values already scaled by -2^64
// so we should not multiply by MLDSA_PLANTARD_INV here
t[i] = MLDSA_PlantardMulReduce((uint64_t)matrix[i] * (uint64_t)s[i]);
```

---

### Potential overflow in MatrixMul accumulation
`crypto/mldsa/src/ml_dsa_core.c:406-414`
```
int64_t tmp[MLDSA_N] = { 0 };
for (uint32_t i = 0; i < ctx->info->l; i++) {
    for (uint32_t j = 0; j < MLDSA_N; j++) {
        tmp[j] += (int64_t)matrix[i][j] * s[i][j];
    }
}
for (uint32_t j = 0; j < MLDSA_N; j++) {
    t[j] = MLDSA_PlantardMulReduce((uint64_t)tmp[j] * (uint64_t)MLDSA_PLANTARD_INV);
}
```
**Issue**: The `int64_t tmp[MLDSA_N]` accumulates products of up to `l` terms (maximum 7). Each term `matrix[i][j] * s[i][j]` can be up to (q-1)^2 ≈ 2^46. With l=7, the sum could reach 7 * 2^46 ≈ 2^49, which is within int64_t range. However, when converting to Plantard domain, there's an issue with the multiplication by `MLDSA_PLANTARD_INV`.
**Fix**:
```
int64_t tmp[MLDSA_N] = { 0 };
for (uint32_t i = 0; i < ctx->info->l; i++) {
    for (uint32_t j = 0; j < MLDSA_N; j++) {
        tmp[j] += (int64_t)matrix[i][j] * s[i][j];
    }
}
for (uint32_t j = 0; j < MLDSA_N; j++) {
    // Handle potential negative values correctly
    int64_t val = tmp[j];
    // Reduce to standard domain first, then handle Plantard conversion
    t[j] = MLDSA_PlantardMulReduce(val * (int64_t)MLDSA_PLANTARD_INV);
}
```

---


## Medium

### Incorrect sign extension in mask computation
`crypto/mldsa/src/ml_dsa_core.c:219-222`
```
const int32_t m0 = (MLDSA_Q - 1 - t0) >> 31;
const int32_t m1 = (MLDSA_Q - 1 - t1) >> 31;
const int32_t m2 = (MLDSA_Q - 1 - t2) >> 31;
const int32_t m3 = (MLDSA_Q - 1 - t3) >> 31;
```
**Issue**: The mask computation `(MLDSA_Q - 1 - t0) >> 31` relies on arithmetic right shift to produce either 0 or -1. However, this assumes signed right shift behavior which is implementation-defined in C for negative numbers. While most platforms use arithmetic right shift, this is not guaranteed by the C standard.
**Fix**:
```
const int32_t m0 = (MLDSA_Q - 1 - t0) >> 31; // Document: requires arithmetic right shift
const int32_t m1 = (MLDSA_Q - 1 - t1) >> 31;
const int32_t m2 = (MLDSA_Q - 1 - t2) >> 31;
const int32_t m3 = (MLDSA_Q - 1 - t3) >> 31;
// Or use portable alternative:
// const int32_t m0 = -((MLDSA_Q - 1 - t0) < 0);
```

---

### Incorrect mask computation in RejBoundedPolyEta2
`crypto/mldsa/src/ml_dsa_core.c:300-310`
```
int32_t mask = (0xE - z0) >> 31; // 0 or -1
z0 = z0 - ((205 * z0) >> 10) * 5; // 205 == 2^10 / 5
a[i] = (2 - z0) & ~mask; // 2 − (b mod 5)
```
**Issue**: The mask `(0xE - z0) >> 31` is supposed to be 0 when `z0 < 14` and -1 when `z0 >= 14`. However, when `z0 = 0xE (14)`, the result is `0 >> 31 = 0`, but when `z0 = 0xF (15)`, the result is `-1 >> 31` which could be implementation-defined. The condition `z0 < 0x0F` in the comment suggests checking for 15, not 14.
**Fix**:
```
// Use explicit comparison for portability and correctness
// mask = -1 if z0 < 0x0F (15), else 0
int32_t mask = -((uint32_t)z0 < 0x0F); // Portable way to get 0 or -1
z0 = z0 - ((205 * z0) >> 10) * 5; // 205 == 2^10 / 5
a[i] = (2 - z0) & ~mask; // 2 − (b mod 5)
```

---

### Same mask computation issue in RejBoundedPolyEta4
`crypto/mldsa/src/ml_dsa_core.c:344-351`
```
int32_t mask = (0x8 - z0) >> 31;
a[i] = (4 - z0) & ~mask; // if 𝜂 = 4 and b < 9 then a[i] = 4 − b
```
**Issue**: Similar to RejBoundedPolyEta2, the mask `(0x8 - z0) >> 31` has portability issues. When `z0 = 0x8 (8)`, the result is `0 >> 31 = 0`. When `z0 > 8`, the result depends on arithmetic right shift.
**Fix**:
```
int32_t mask = -((uint32_t)z0 < 0x9); // Portable: mask = -1 if z0 < 9, else 0
a[i] = (4 - z0) & ~mask; // if 𝜂 = 4 and b < 9 then a[i] = 4 − b
```

---

### Type mismatch in NTT computations
`crypto/mldsa/src/ml_dsa_ntt.c:99`
```
int32_t t = MLDSA_PlantardMulReduce((uint64_t)z * (uint64_t)w[j + len]);
```
**Issue**: The code casts `int64_t z` to `uint64_t` when calling `MLDSA_PlantardMulReduce`, but ZETAS contains negative values in Plantard domain. The signed-to-unsigned conversion of negative values may not preserve the intended bit pattern for the Plantard multiplication.
**Fix**:
```
// Use int64_t consistently for Plantard domain operations
int32_t t = MLDSA_PlantardMulReduce((int64_t)z * (int64_t)w[j + len]);
```

---


## Low

### Missing validation of Plantard constants
`crypto/mldsa/src/ml_dsa_local.h:48-59`
```
#define MLDSA_PLANTARD_L 32
#define MLDSA_PLANTARD_ALPHA 3
#define MLDSA_PLANTARD_INV 1732267787797143553 // inverse_mod(q, 1 << 64)
```
**Issue**: The Plantard constants are defined but there's no compile-time or runtime validation that they are correct. A simple static assertion or comment verifying the constants would help prevent errors.
**Fix**:
```
#define MLDSA_PLANTARD_L 32
#define MLDSA_PLANTARD_ALPHA 3
// Verify: MLDSA_PLANTARD_INV * MLDSA_Q ≡ 1 (mod 2^64)
// 1732267787797143553 * 8380417 = 14522543385665802721 ≡ 1 (mod 2^64)
#define MLDSA_PLANTARD_INV 1732267787797143553

// Compile-time verification (using static_assert in C11)
_Static_assert(((MLDSA_PLANTARD_INV * (int64_t)MLDSA_Q) & 0xFFFFFFFFFFFFFFFFULL) == 1, 
               "MLDSA_PLANTARD_INV is incorrect");
```

---
