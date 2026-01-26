# Code Review: openHiTLS/openhitls#993
**Reviewer**: GEMINI


## Critical

### Thread safety violation in `XmssTree_InitCtx`
`crypto/xmss/src/xmss_tree.c:519`
```
/* Initialize address operations */
    static CryptAdrsOps g_xmssCryptAdrsOps = {0};
    const XmssAdrsOps *xmssOps = XmssAdrs_GetDefaultOps();
    XmssAdrsOps_ToCryptAdrsOps(&g_xmssCryptAdrsOps, xmssOps);
    treeCtx->adrsOps = &g_xmssCryptAdrsOps;
```
**Issue**: The function uses a `static` local variable `g_xmssCryptAdrsOps` which is modified in every call via `XmssAdrsOps_ToCryptAdrsOps`. This creates a data race if multiple threads call `XmssTree_InitCtx` (e.g., during parallel signature verification), potentially corrupting the function pointers and causing crashes or undefined behavior.
**Fix**:
```
/* Initialize address operations */
    /* Store adrsOpsStorage in TreeCtx (needs to be added to TreeCtx struct) */
    /* In crypto/xmss/src/xmss_tree.h: typedef struct { ... CryptAdrsOps adrsOpsStorage; } TreeCtx; */
    
    const XmssAdrsOps *xmssOps = XmssAdrs_GetDefaultOps();
    XmssAdrsOps_ToCryptAdrsOps(&treeCtx->adrsOpsStorage, xmssOps);
    treeCtx->adrsOps = &treeCtx->adrsOpsStorage;
```

---


## Medium

### Potential buffer overflow in `XmssWots_Sign`
`crypto/xmss/src/xmss_wots.c:199`
```
uint32_t adrsLen3 = ctx->adrsOps->getAdrsLen();
    uint8_t skAdrsBuffer[32] = {0};  // Max address size
    void *skAdrs = skAdrsBuffer;
    (void)memcpy_s(skAdrs, adrsLen3, adrs, adrsLen3);
```
**Issue**: `memcpy_s` uses `adrsLen3` (which comes from `getAdrsLen()`) as the destination size limit (`destMax`). `skAdrsBuffer` has a fixed size of 32 bytes. If `adrsLen3` is ever larger than 32, this will cause a stack buffer overflow. The second argument to `memcpy_s` should be the size of the destination buffer.
**Fix**:
```
uint32_t adrsLen3 = ctx->adrsOps->getAdrsLen();
    uint8_t skAdrsBuffer[32] = {0};  // Max address size
    void *skAdrs = skAdrsBuffer;
    (void)memcpy_s(skAdrs, sizeof(skAdrsBuffer), adrs, adrsLen3);
```

---


## Low

### Potential out-of-bounds read in `XmssWots_GeneratePublicKey`
`crypto/xmss/src/xmss_wots.c:133`
```
uint8_t skAdrsBuffer[32] = {0};  // Max address size
    void *skAdrs = skAdrsBuffer;
    (void)memcpy_s(skAdrs, sizeof(skAdrsBuffer), adrs, sizeof(skAdrsBuffer));
```
**Issue**: `memcpy_s` reads `sizeof(skAdrsBuffer)` (32 bytes) from `adrs`. While `XMSS_ADRS_LEN` is currently 32, if `adrs` points to a smaller buffer (e.g., a compressed address of 22 bytes in SLH-DSA), this would read out of bounds. It is safer to use `ctx->adrsOps->getAdrsLen()` for the source size.
**Fix**:
```
uint8_t skAdrsBuffer[32] = {0};  // Max address size
    void *skAdrs = skAdrsBuffer;
    (void)memcpy_s(skAdrs, sizeof(skAdrsBuffer), adrs, ctx->adrsOps->getAdrsLen());
```

---
