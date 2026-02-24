# Code Review: openHiTLS/sdfp#8
**Reviewer**: CLAUDE


## Critical

### Undefined control command macros causing compilation failure
`demo/sm4_cbc.c:131`
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SM4_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
```
**Issue**: The demo uses CRYPT_CTRL_SM4_SET_KEK_ID and CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK which are not defined in provider.h. The actual macros are CRYPT_CTRL_SET_KEK_ID (110) and CRYPT_CTRL_GEN_DEK_WITH_KEK (111) without the SM4_ prefix.
**Fix**:
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
```

---

### KEK handle destroyed before use causing NULL key handle
`src/sm4_cipher.c:128-151`
```
if (ctx->hKeyHandle != NULL) {
    (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
    ctx->hKeyHandle = NULL;
}

int ret = SDR_OK;
if (ctx->keySource == KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(...);
} else if (key != NULL && keyLen > 0) {
    ret = SDF_DL_ImportKeyWithKEK(...);
}
/* If keySource==KEY_SRC_KEK, key==NULL, hKeyHandle was just destroyed, but not recreated */
```
**Issue**: When using KEK mode with a pre-generated key handle (via CRYPT_CTRL_GEN_DEK_WITH_KEK), calling InitCtx with NULL/0 key parameters destroys the existing hKeyHandle at lines 128-131, but then doesn't recreate it because key==NULL. This causes hKeyHandle to be NULL when EncryptInit/DecryptInit is called at lines 154-160. The test_kek_handle() function in demo/sm4_cbc.c relies on reusing the key handle after GEN_DEK_WITH_KEK.
**Fix**:
```
if (ctx->keySource == KEY_SRC_KEK && key == NULL && ctx->hKeyHandle == NULL) {
    return CRYPT_NULL_INPUT;  /* No key handle available */
}
/* Only destroy if we're going to create a new one */
if ((ctx->keySource == KEY_SRC_RAW) || (key != NULL && keyLen > 0)) {
    if (ctx->hKeyHandle != NULL) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
}
```

---

### KEK handle destroyed before use causing NULL key handle
`src/sm4_gcm.c:136-149`
```
if (ctx->hKeyHandle != NULL) {
    (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
    ctx->hKeyHandle = NULL;
}
...
} else if (key != NULL && keyLen > 0) {
    ret = SDF_DL_ImportKeyWithKEK(...);
}
/* else: hKeyHandle is already set by GEN_KEY ctrl, use it directly */
/* But it was just destroyed above! */
```
**Issue**: Same issue as sm4_cipher.c. When using KEK mode with a pre-generated key handle, calling InitCtx with NULL/0 key destroys the existing hKeyHandle at lines 136-139, but doesn't recreate it for the KEY_SRC_KEK + key==NULL case.
**Fix**:
```
/* Only destroy if we're going to create a new one */
if ((ctx->keySource == GCM_KEY_SRC_RAW) || (key != NULL && keyLen > 0)) {
    if (ctx->hKeyHandle != NULL) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
}
```

---


## High

### Stack buffer with wrapped key not cleansed before return
`src/sm4_cipher.c:247-264`
```
unsigned char tmpBuf[64];
if (wrapBuf == NULL || wrapLen == 0) {
    wrapBuf = tmpBuf;
    wrapLen = sizeof(tmpBuf);
}
...
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, SGD_SM4_ECB,
    ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
/* tmpBuf now contains wrapped key but is not cleansed */
return CRYPT_SUCCESS;
```
**Issue**: When val==NULL, tmpBuf[64] on the stack holds the wrapped key material after SDF_DL_GenerateKeyWithKEK. This sensitive data is not cleared with BSL_SAL_CleanseData before the function returns, potentially leaking wrapped key material on the stack.
**Fix**:
```
unsigned char tmpBuf[64];
if (wrapBuf == NULL || wrapLen == 0) {
    wrapBuf = tmpBuf;
    wrapLen = sizeof(tmpBuf);
}
...
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, SGD_SM4_ECB,
    ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
if (ret == SDR_OK && wrapBuf == tmpBuf) {
    BSL_SAL_CleanseData(tmpBuf, sizeof(tmpBuf));
}
return CRYPT_SUCCESS;
```

---

### Stack buffer with wrapped key not cleansed before return
`src/sm4_gcm.c:327-336`
```
unsigned char tmpBuf[64];
unsigned int  wrapLen = (val != NULL && valLen > 0) ? valLen : sizeof(tmpBuf);
unsigned char *wrapBuf = (val != NULL && valLen > 0) ? (unsigned char *)val : tmpBuf;
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, SGD_SM4_GCM,
    ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
/* tmpBuf contains wrapped key material but is not cleansed */
```
**Issue**: Same issue as sm4_cipher.c. When val==NULL, tmpBuf[64] holds wrapped key material but is not cleared with BSL_SAL_CleanseData before returning.
**Fix**:
```
unsigned char tmpBuf[64];
unsigned int  wrapLen = (val != NULL && valLen > 0) ? valLen : sizeof(tmpBuf);
unsigned char *wrapBuf = (val != NULL && valLen > 0) ? (unsigned char *)val : tmpBuf;
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, SGD_SM4_GCM,
    ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
if (ret == SDR_OK && wrapBuf == tmpBuf) {
    BSL_SAL_CleanseData(tmpBuf, sizeof(tmpBuf));
}
return CRYPT_SUCCESS;
```

---


## Medium

### Inconsistent library format macro usage
`demo/sm4_gcm.c:56`
```
int ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_SO, "SDFProv", provParams, NULL);
```
**Issue**: sm4_gcm.c uses BSL_SAL_LIB_FMT_SO while all other demo files (sm3_hash.c, sm4_cbc.c, sm4_ecb.c, sm2_sign.c, etc.) use BSL_SAL_LIB_FMT_LIBSO. Inconsistency may cause compilation issues if only one macro is defined.
**Fix**:
```
int ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_LIBSO, "SDFProv", provParams, NULL);
```

---

### Wrapped key output not retrievable when val is NULL
`src/sm4_cipher.c:247-264`
```
unsigned int wrapLen = valLen;  /* Input: size of caller's buffer */
unsigned char *wrapBuf = (unsigned char *)val;
unsigned char tmpBuf[64];
if (wrapBuf == NULL || wrapLen == 0) {
    wrapBuf = tmpBuf;
    wrapLen = sizeof(tmpBuf);
}
/* After GenerateKeyWithKEK, wrapLen contains actual size but caller can't access it */
return CRYPT_SUCCESS;  /* Caller has no way to get the wrapped key data or its size */
```
**Issue**: When val==NULL, the wrapped key is written to tmpBuf but there's no way for the caller to retrieve it. The wrappedLen (actual wrapped key size) is not returned to the caller via valLen or any output parameter. This makes the function unusable for getting wrapped key output when passing NULL val.
**Fix**:
```
/* Document that val must not be NULL when output is needed */
/* OR: Add output mechanism for wrapped key size */
```

---


## Low

### Duplicate stdio.h include
`demo/sm4_cbc.c:1-2`
```
#include <stdio.h>
#include <stdio.h>
```
**Issue**: Line 1 and line 2 both include <stdio.h>, which is redundant.
**Fix**:
```
#include <stdio.h>
```

---

### Missing validation in CRYPT_CTRL_SET_AAD for NULL val with zero valLen
`src/sm4_gcm.c:267-279`
```
if (val == NULL && valLen != 0) {
    return CRYPT_INVALID_ARG;
}
if (valLen > SM4_GCM_AAD_MAX) {
    return CRYPT_INVALID_ARG;
}
if (val != NULL && valLen > 0) {
    memcpy(ctx->aad, val, valLen);
}
ctx->aadLen = valLen;  /* Sets aadLen to 0, clearing AAD - this is intentional */
```
**Issue**: The check `if (val == NULL && valLen != 0)` returns error only when val is NULL AND valLen is non-zero. This allows val=NULL with valLen=0 to proceed, which would cause memcpy(NULL, ...) to be called. The condition at line 275 `if (val != NULL && valLen > 0)` prevents the memcpy, but the logic is confusing.
**Fix**:
```
/* The current logic is actually correct - it allows clearing AAD by passing val=NULL, valLen=0 */
/* But the condition could be clearer: */
if (valLen > SM4_GCM_AAD_MAX) {
    return CRYPT_INVALID_ARG;
}
if (val != NULL) {
    if (valLen == 0) {
        return CRYPT_INVALID_ARG;  /* val non-NULL but valLen is 0 */
    }
    memcpy(ctx->aad, val, valLen);
}
ctx->aadLen = valLen;
```

---
