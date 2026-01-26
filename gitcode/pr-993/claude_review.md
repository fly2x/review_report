# Code Review: openHiTLS/openhitls#993
**Reviewer**: CLAUDE


## High

### Static variable causes shared state and potential thread safety issue
`crypto/xmss/src/xmss_tree.c:519-522`
```
void XmssTree_InitCtx(TreeCtx *treeCtx, const CryptXmssCtx *ctx)
{
    ...
    /* Initialize address operations */
    static CryptAdrsOps g_xmssCryptAdrsOps = {0};
    const XmssAdrsOps *xmssOps = XmssAdrs_GetDefaultOps();
    XmssAdrsOps_ToCryptAdrsOps(&g_xmssCryptAdrsOps, xmssOps);
    treeCtx->adrsOps = &g_xmssCryptAdrsOps;
    ...
}
```
**Issue**: The `XmssTree_InitCtx` function uses a static variable `g_xmssCryptAdrsOps` to store address operation function pointers. This causes multiple issues:

1. All `TreeCtx` instances share the same static variable, even though `CryptXmssCtx` has its own `adrsOps` member that was initialized in `CRYPT_XMSS_InitInternal`.

2. The static variable is re-initialized on every call to `XmssTree_InitCtx`, creating unnecessary work and a potential race condition in multi-threaded environments.

3. The `ctx->adrsOps` member in `CryptXmssCtx` is initialized but never used - the code always points to the static variable instead.
**Fix**:
```
void XmssTree_InitCtx(TreeCtx *treeCtx, const CryptXmssCtx *ctx)
{
    ...
    /* Initialize address operations - use ctx's adrsOps that was initialized in CRYPT_XMSS_InitInternal */
    treeCtx->adrsOps = &ctx->adrsOps;
    ...
}
```

---


## Medium

### Inconsistent shift operation (UL vs ULL)
`crypto/xmss/src/xmss_core.c:201`
```
// Line 153 in CRYPT_XMSS_SignInternal:
uint32_t leafIdx = (uint32_t)(index & ((1ULL << hp) - 1));

// Line 201 in CRYPT_XMSS_VerifyInternal:
uint32_t leafIdx = index & ((1UL << hp) - 1);
```
**Issue**: Line 201 uses `1UL` for the shift operation, while line 153 uses `1ULL`. While the current implementation has `hp <= 20` (so no overflow), the inconsistency should be fixed for clarity and future-proofing.
**Fix**:
```
// Use consistent 1ULL for both:
uint32_t leafIdx = index & ((1ULL << hp) - 1);
```

---

### Inconsistent shift operation (UL vs ULL in HyperTree_Sign)
`crypto/xmss/src/xmss_tree.c:380`
```
leafIdxTmp = (uint32_t)(treeIdxTmp & ((1UL << hp) - 1));
```
**Issue**: Line 380 uses `1UL` for the shift operation. While `hp <= 20`, this should be consistent with other uses.
**Fix**:
```
leafIdxTmp = (uint32_t)(treeIdxTmp & ((1ULL << hp) - 1));
```

---


## Low

### Misleading variable name for XMSS hash function table
`crypto/xmss/src/xmss_tree.c:494`
```
/* Static CryptHashFuncs table for XMSS */
static const CryptHashFuncs g_slhdsaCryptHashFuncs = {
```
**Issue**: The static variable `g_slhdsaCryptHashFuncs` is named as if it belongs to SLH-DSA, but it's actually the hash function table for XMSS (in `xmss_tree.c`). This is confusing copy-paste residue.
**Fix**:
```
/* Static CryptHashFuncs table for XMSS */
static const CryptHashFuncs g_xmssCryptHashFuncs = {
```

---

### Inconsistent use of explicit uint64_t cast
`crypto/xmss/src/xmss_tree.c:421`
```
// Line 380:
leafIdxTmp = (uint32_t)(treeIdxTmp & ((1UL << hp) - 1));

// Line 421:
leafIdx = (uint32_t)(treeIdx & (((uint64_t)1 << hp) - 1));
```
**Issue**: Line 421 explicitly casts to `uint64_t`, but line 380 doesn't. This inconsistency should be fixed.
**Fix**:
```
// Line 380:
leafIdxTmp = (uint32_t)(treeIdxTmp & ((1ULL << hp) - 1));

// Line 421:
leafIdx = (uint32_t)(treeIdx & ((1ULL << hp) - 1));
```

---

### Unnecessary uintptr_t cast
`crypto/slh_dsa/src/slh_dsa.c:315`
```
treeCtx->originalCtx = (void *)(uintptr_t)ctx;
```
**Issue**: The cast `(void *)(uintptr_t)ctx` is unnecessary. A direct cast from `const CryptSlhDsaCtx *` to `void *` would work fine.
**Fix**:
```
treeCtx->originalCtx = (void *)ctx;
```

---

### Unnecessary uintptr_t cast
`crypto/xmss/src/xmss_tree.c:523`
```
treeCtx->originalCtx = (void *)(uintptr_t)ctx;
```
**Issue**: Same as above - the cast through `uintptr_t` is unnecessary.
**Fix**:
```
treeCtx->originalCtx = (void *)ctx;
```

---
