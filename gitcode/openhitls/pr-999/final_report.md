# Final Code Review Report
## openHiTLS/openhitls - PR #999

### Summary
- **Total Issues**: 7
- **Critical**: 0
- **High**: 2
- **Medium**: 3
- **Low**: 2
- **Reviewers**: claude, gemini, codex

---


## High

### Inline function without external symbol causes linker errors
`crypto/mldsa/src/ml_dsa_ntt.c:81-88`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
```
// In ml_dsa_local.h (line 101)
int32_t MLDSA_PlantardMulReduce(int64_t a);

// In ml_dsa_ntt.c (lines 81-88)
inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}
```
**Issue**: The function `MLDSA_PlantardMulReduce` is defined as `inline` in `ml_dsa_ntt.c` but declared as a non-inline prototype in `ml_dsa_local.h` (line 101) and used in `ml_dsa_core.c` (lines 399, 413). Under C99/C11 inline semantics, an `inline` definition without `extern` or `static` does not emit an external symbol, causing "undefined reference" linker errors when other translation units try to call this function. The function needs to be either `static inline` in the header, or a regular non-inline function.
**Fix**:
```
// Option 1: Move to header as static inline (recommended for small function)
// In ml_dsa_local.h
static inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}

// Then remove the definition from ml_dsa_ntt.c

// Option 2: Remove inline keyword from the definition
// In ml_dsa_ntt.c
int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}
```

---

### Right shift of negative signed integer is implementation-defined
`crypto/mldsa/src/ml_dsa_ntt.c:81-88`
**Reviewers**: CLAUDE | **置信度**: 可信
```
inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    tmp >>= MLDSA_PLANTARD_L;  // Implementation-defined if tmp is negative
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;  // Implementation-defined if tmp is negative
    return (int32_t)tmp;
}
```
**Issue**: The `MLDSA_PlantardMulReduce` function uses right shift (`>>=`) on a signed `int64_t` value. In C, right shift of negative signed integers is implementation-defined behavior - the result depends on whether the compiler uses arithmetic or logical shift. This cryptographic code relies on arithmetic right shift behavior, which is not guaranteed by the C standard.
**Fix**:
```
static inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
    // Use portable division for negative values to ensure arithmetic shift behavior
    tmp = (tmp >= 0) ? (tmp >> MLDSA_PLANTARD_L) : 
          ((tmp - ((1LL << MLDSA_PLANTARD_L) - 1)) >> MLDSA_PLANTARD_L);
    tmp = (tmp + (1 << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp = (tmp >= 0) ? (tmp >> MLDSA_PLANTARD_L) : 
          ((tmp - ((1LL << MLDSA_PLANTARD_L) - 1)) >> MLDSA_PLANTARD_L);
    return (int32_t)tmp;
}
```

---


## Medium

### Arithmetic right shift for mask computation is implementation-defined
`crypto/mldsa/src/ml_dsa_core.c:204-217`
**Reviewers**: CLAUDE | **置信度**: 可信
```
const int32_t m0 = (MLDSA_Q - 1 - t0) >> 31;
const int32_t m1 = (MLDSA_Q - 1 - t1) >> 31;
const int32_t m2 = (MLDSA_Q - 1 - t2) >> 31;
const int32_t m3 = (MLDSA_Q - 1 - t3) >> 31;
```
**Issue**: The mask computation `(MLDSA_Q - 1 - t0) >> 31` relies on arithmetic right shift to produce 0 for non-negative values and -1 for negative values. While this works on most platforms (x86, ARM), the C standard only guarantees this behavior for arithmetic right shift, not logical shift. This could fail on platforms using logical right shift for signed integers.
**Fix**:
```
// Portable alternative using comparison
const int32_t m0 = -((MLDSA_Q - 1 - t0) < 0);
const int32_t m1 = -((MLDSA_Q - 1 - t1) < 0);
const int32_t m2 = -((MLDSA_Q - 1 - t2) < 0);
const int32_t m3 = -((MLDSA_Q - 1 - t3) < 0);
```

---

### Mask computation in RejBoundedPolyEta2 has portability issues
`crypto/mldsa/src/ml_dsa_core.c:300`
**Reviewers**: CLAUDE | **置信度**: 可信
```
int32_t mask = (0xE - z0) >> 31; // 0 or -1
z0 = z0 - ((205 * z0) >> 10) * 5; // 205 == 2^10 / 5
a[i] = (2 - z0) & ~mask; // 2 − (b mod 5)
```
**Issue**: The mask `(0xE - z0) >> 31` is meant to be 0 when `z0 < 14` and -1 when `z0 >= 14`. However, this relies on arithmetic right shift. When `z0 = 14`, `0xE - 14 = 0`, and `0 >> 31 = 0`. When `z0 = 15`, `0xE - 15 = -1`, and `-1 >> 31` produces -1 only with arithmetic shift. The code also has a comment saying `b < 15`, suggesting the threshold should be 15, not 14.
**Fix**:
```
// Use explicit comparison for portability
// mask = -1 if z0 < 0x0F (15), else 0 (based on comment "b < 15")
int32_t mask = -((uint32_t)z0 < 0x0F); // Portable: produces -1 if true, 0 if false
z0 = z0 - ((205 * z0) >> 10) * 5; // 205 == 2^10 / 5
a[i] = (2 - z0) & ~mask; // 2 − (b mod 5)
```

---

### Mask computation in RejBoundedPolyEta4 has portability issues
`crypto/mldsa/src/ml_dsa_core.c:344`
**Reviewers**: CLAUDE | **置信度**: 可信
```
int32_t mask = (0x8 - z0) >> 31;
a[i] = (4 - z0) & ~mask; // if 𝜂 = 4 and b < 9 then a[i] = 4 − b
```
**Issue**: Similar to RejBoundedPolyEta2, the mask `(0x8 - z0) >> 31` relies on arithmetic right shift behavior. The comment says `if 𝜂 = 4 and b < 9`, indicating the check should be for `z0 < 9`, but using `(0x8 - z0) >> 31` only works correctly when `z0 > 8` with arithmetic shift.
**Fix**:
```
int32_t mask = -((uint32_t)z0 < 0x9); // Portable: mask = -1 if z0 < 9, else 0
a[i] = (4 - z0) & ~mask; // if 𝜂 = 4 and b < 9 then a[i] = 4 − b
```

---


## Low

### Buffer size calculation assumes SHAKE128_BLOCKSIZE is divisible by 4
`crypto/mldsa/src/ml_dsa_core.c:186-188`
**Reviewers**: GEMINI | **置信度**: 较可信
```
unsigned int outlen = CRYPT_SHAKE128_BLOCKSIZE;
const uint32_t buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;
uint32_t buf[CRYPT_SHAKE128_BLOCKSIZE / 4];
```
**Issue**: The buffer `buf` is declared as `uint32_t buf[CRYPT_SHAKE128_BLOCKSIZE / 4]` and `hashMethod->squeeze` is called with `outlen = CRYPT_SHAKE128_BLOCKSIZE`. If `CRYPT_SHAKE128_BLOCKSIZE` is not divisible by 4, integer division truncates the buffer size but the full `outlen` is still written, causing a buffer overflow. While SHAKE128's rate (168) is divisible by 4, this assumption is brittle.
**Fix**:
```
unsigned int outlen = CRYPT_SHAKE128_BLOCKSIZE;
const uint32_t buflen = (CRYPT_SHAKE128_BLOCKSIZE + 3) / 4; 
uint32_t buf[(CRYPT_SHAKE128_BLOCKSIZE + 3) / 4];
```

---

### Missing validation of Plantard constants
`crypto/mldsa/src/ml_dsa_local.h:48-52`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
#define MLDSA_PLANTARD_L 32
#define MLDSA_PLANTARD_ALPHA 3
#define MLDSA_PLANTARD_INV 1732267787797143553 // inverse_mod(q, 1 << 64)
```
**Issue**: The Plantard constants are defined without any compile-time verification that they are correct. For cryptographic code, a wrong constant could cause subtle security issues. A static assertion would help catch errors at compile time.
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
