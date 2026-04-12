# Code Review: openHiTLS/openhitls#1222
**Reviewer**: CLAUDE


## High

### Integer overflow in MODES_GCM_SIV_Update could cause buffer overflow
`crypto/modes/src/modes_gcm_siv.c:462`
```
uint8_t *nbuf = BSL_SAL_Realloc(modeCtx->msgBuf, modeCtx->msgLen + inLen, modeCtx->msgLen);
```
**Issue**: The calculation `modeCtx->msgLen + inLen` can overflow for very large inputs, causing realloc to allocate less memory than needed. If an attacker can control the input size and trigger multiple Update calls, they could cause a buffer overflow.
**Fix**:
```
// Check for overflow before allocation
if (inLen > UINT32_MAX - modeCtx->msgLen) {
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}
uint8_t *nbuf = BSL_SAL_Realloc(modeCtx->msgBuf, modeCtx->msgLen + inLen, modeCtx->msgLen);
```

---

### Integer overflow in BuildPolyInput could cause buffer underflow
`crypto/modes/src/modes_gcm_siv.c:176`
```
uint32_t total = padAad + padPt + GCM_BLOCKSIZE;
```
**Issue**: The calculation `padAad + padPt + GCM_BLOCKSIZE` can overflow for very large AAD or plaintext lengths, causing malloc to allocate less memory than needed. This could lead to buffer overflow in memcpy_s operations.
**Fix**:
```
// Check for overflow
if (padAad > UINT32_MAX - padPt - GCM_BLOCKSIZE) {
    return CRYPT_INVALID_ARG;
}
uint32_t total = padAad + padPt + GCM_BLOCKSIZE;
```

---


## Medium

### Integer overflow in Pad16Len for inputs near UINT32_MAX
`crypto/modes/src/modes_gcm_siv.c:168`
```
return (len + GCM_BLOCKSIZE - 1u) & ~(GCM_BLOCKSIZE - 1u);
```
**Issue**: The calculation `(len + GCM_BLOCKSIZE - 1u)` can overflow when `len` is close to `UINT32_MAX`, resulting in a smaller value than expected.
**Fix**:
```
if (len > UINT32_MAX - GCM_BLOCKSIZE + 1) {
    // Handle overflow - return error or max valid value
    return UINT32_MAX;  // or return error code via different mechanism
}
return (len + GCM_BLOCKSIZE - 1u) & ~(GCM_BLOCKSIZE - 1u);
```

---

### Tag copied even when encryption fails in GcmSivEncryptFinish
`crypto/modes/src/modes_gcm_siv.c:275-278`
```
if (ctx->msgLen > 0) {
    ret = AesCtrGcmSiv(encKey, encKeyLen, ctr, ctx->msgBuf, ctx->msgLen, ctx->outPtr);
}
(void)memcpy_s(tagBuf, tagLen, tag, ctx->tagLen);
```
**Issue**: If AesCtrGcmSiv fails, the function still copies the tag to the output before returning the error. This could mislead callers who check the tag buffer but not the return value, causing them to use an unencrypted payload with a valid tag.
**Fix**:
```
if (ctx->msgLen > 0) {
    ret = AesCtrGcmSiv(encKey, encKeyLen, ctr, ctx->msgBuf, ctx->msgLen, ctx->outPtr);
    if (ret != CRYPT_SUCCESS) {
        (void)BSL_SAL_CleanseData(authKey, sizeof(authKey));
        (void)BSL_SAL_CleanseData(encKey, sizeof(encKey));
        return ret;
    }
}
(void)memcpy_s(tagBuf, tagLen, tag, ctx->tagLen);
```

---


## Low

### DupCtx copies outPtr pointer from source context
`crypto/modes/src/modes_gcm_siv.c:615-634`
```
struct ModesGcmSivCtx *ctx = BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx));
...
ctx->aadBuf = NULL;
ctx->msgBuf = NULL;
```
**Issue**: The MODES_GCM_SIV_DupCtx function uses BSL_SAL_Dump to copy the entire structure, including the outPtr field. If the source context has outPtr set (pointing to caller's buffer), the duplicated context will also point to the same buffer. This could cause issues if both contexts are used independently.
**Fix**:
```
struct ModesGcmSivCtx *ctx = BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx));
...
ctx->aadBuf = NULL;
ctx->msgBuf = NULL;
ctx->outPtr = NULL;  // Add this line
```

---

### Missing newline at end of file
`crypto/modes/include/crypt_modes_gcm_siv.h:56`
```
#endif /* CRYPT_MODES_GCM_SIV_H */
\ No newline at end of file
```
**Issue**: The file is missing a terminating newline character, which violates POSIX standards and may cause issues with some tools.
**Fix**:
```
#endif /* CRYPT_MODES_GCM_SIV_H */
```

---

### Missing newline at end of file
`crypto/modes/src/modes_gcm_siv.c:644`
```
#endif /* HITLS_CRYPTO_GCM && HITLS_CRYPTO_AES && HITLS_CRYPTO_GHASH */
\ No newline at end of file
```
**Issue**: The file is missing a terminating newline character.
**Fix**:
```
#endif /* HITLS_CRYPTO_GCM && HITLS_CRYPTO_AES && HITLS_CRYPTO_GHASH */
```

---

### Missing newline at end of file
`testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes_gcm_siv.c:176`
```
}
/* END_CASE */
\ No newline at end of file
```
**Issue**: The file is missing a terminating newline character.
**Fix**:
```
}
/* END_CASE */
```

---
