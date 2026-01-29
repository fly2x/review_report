# Code Review: openHiTLS/openhitls#999
**Reviewer**: GEMINI


## High

### Inline function definition without external symbol
`crypto/mldsa/src/ml_dsa_ntt.c:62`
```
inline int32_t MLDSA_PlantardMulReduce(int64_t a)
{
    int64_t tmp = a;
```
**Issue**: The function `MLDSA_PlantardMulReduce` is defined as `inline` in `ml_dsa_ntt.c` but declared as a prototype in `ml_dsa_local.h` and used in `ml_dsa_core.c`. In C99/C11, an `inline` definition without `extern` does not emit an external symbol, which will cause a linker error ("undefined reference") when `ml_dsa_core.c` tries to call it.
**Fix**:
```
// Replace the prototype with the definition
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


## Low

### Buffer overflow risk if SHAKE128 block size is not multiple of 4
`crypto/mldsa/src/ml_dsa_core.c:187`
```
unsigned int outlen = CRYPT_SHAKE128_BLOCKSIZE;
    const uint32_t buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;
    uint32_t buf[CRYPT_SHAKE128_BLOCKSIZE / 4];
```
**Issue**: The buffer `buf` is defined as `uint32_t` with size `CRYPT_SHAKE128_BLOCKSIZE / 4`. If `CRYPT_SHAKE128_BLOCKSIZE` is not divisible by 4, the allocated size will be smaller than `CRYPT_SHAKE128_BLOCKSIZE` (due to integer truncation), but `hashMethod->squeeze` is called with `outlen` (the full block size), leading to a heap/stack buffer overflow. While the standard SHAKE128 rate (168) is divisible by 4, this assumption is brittle.
**Fix**:
```
unsigned int outlen = CRYPT_SHAKE128_BLOCKSIZE;
    // Ensure buffer can hold the full output even if not divisible by 4
    const uint32_t buflen = (CRYPT_SHAKE128_BLOCKSIZE + 3) / 4; 
    uint32_t buf[(CRYPT_SHAKE128_BLOCKSIZE + 3) / 4];
```

---
