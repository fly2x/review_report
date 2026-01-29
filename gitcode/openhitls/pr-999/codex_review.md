# Code Review: openHiTLS/openhitls#999
**Reviewer**: CODEX


## High

### Inline definition drops external symbol under C99/C11
`crypto/mldsa/src/ml_dsa_ntt.c:81-87`
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
**Issue**: `MLDSA_PlantardMulReduce` is defined as `inline` in a .c file but referenced from other translation units (e.g., `ml_dsa_core.c`). Under C99/C11 inline semantics this does not emit an external definition, causing undefined references at link time unless compiling with GNU89 inline semantics or LTO.
**Fix**:
```
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


## Medium

### Signed API for Plantard reduce forces implementation-defined conversions
`crypto/mldsa/src/ml_dsa_local.h:99-101`
```
int32_t MLDSA_PlantardMulReduce(int64_t a);
```
**Issue**: The reducer takes `int64_t`, but all new call sites multiply in `uint64_t` (often overflowing INT64_MAX due to `MLDSA_PLANTARD_INV`) and pass the result. Converting a large `uint64_t` to `int64_t` is implementation-defined and can change results across platforms, risking incorrect reductions. Use `uint64_t` in the API/implementation to keep arithmetic defined.
**Fix**:
```
/* ml_dsa_local.h */
int32_t MLDSA_PlantardMulReduce(uint64_t a);

/* ml_dsa_ntt.c */
int32_t MLDSA_PlantardMulReduce(uint64_t a)
{
    uint64_t tmp = a >> MLDSA_PLANTARD_L;
    tmp = (tmp + (1ULL << MLDSA_PLANTARD_ALPHA)) * MLDSA_Q;
    tmp >>= MLDSA_PLANTARD_L;
    return (int32_t)tmp;
}
```

---
