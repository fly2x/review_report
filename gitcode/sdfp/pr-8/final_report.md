# Final Code Review Report
## openHiTLS/sdfp - PR #8

### Summary
- **Total Issues**: 15
- **Critical**: 3
- **High**: 5
- **Medium**: 4
- **Low**: 3
- **Reviewers**: claude, gemini, codex

---


## Critical

### Undefined control command macros causing compilation failure
`demo/sm4_cbc.c:131`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SM4_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
    printf("[kek-handle] SET_KEK_ID failed\n");
    ...
}
int32_t ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```
**Issue**: The demo uses CRYPT_CTRL_SM4_SET_KEK_ID and CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK which are not defined in provider.h. The actual macros are CRYPT_CTRL_SET_KEK_ID (110) and CRYPT_CTRL_GEN_DEK_WITH_KEK (111) without the SM4_ prefix. This will cause compilation to fail.
**Fix**:
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
    printf("[kek-handle] SET_KEK_ID failed\n");
    ...
}
int32_t ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```

---

### KEK handle destroyed before use causing NULL key handle
`src/sm4_cipher.c:128-151`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
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
/* Only destroy if we're going to create a new one */
if ((ctx->keySource == KEY_SRC_RAW) || (key != NULL && keyLen > 0)) {
    if (ctx->hKeyHandle != NULL) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
}

int ret = SDR_OK;
if (ctx->keySource == KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(ctx->hSessionHandle, (unsigned char *)key, keyLen, &ctx->hKeyHandle);
    if (ret != SDR_OK) { BSL_ERR_PUSH_ERROR(ret); return SDFP_ERR_ENCRYPT; }
} else if (key != NULL && keyLen > 0) {
    ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, ctx->sdfAlgId, ctx->kekIndex,
        (unsigned char *)key, keyLen, &ctx->hKeyHandle);
    if (ret != SDR_OK) { BSL_ERR_PUSH_ERROR(ret); return SDFP_ERR_ENCRYPT; }
}
```

---

### KEK handle destroyed before use in GCM mode
`src/sm4_gcm.c:136-149`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
```
/* Destroy old key handle if re-initialising */
if (ctx->hKeyHandle != NULL) {
    (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
    ctx->hKeyHandle = NULL;
}

int ret = SDR_OK;
if (ctx->keySource == GCM_KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(...);
} else if (key != NULL && keyLen > 0) {
    ret = SDF_DL_ImportKeyWithKEK(...);
}
/* else: hKeyHandle is already set by GEN_KEY ctrl, use it directly */
/* But it was just destroyed above! */
```
**Issue**: Same issue as sm4_cipher.c. When using KEK mode with a pre-generated key handle, calling InitCtx with NULL/0 key destroys the existing hKeyHandle at lines 136-139, but doesn't recreate it for the KEY_SRC_KEK + key==NULL case.
**Fix**:
```
/* Destroy old key handle only if a new key is provided for re-initialising */
if ((ctx->keySource == GCM_KEY_SRC_RAW) || (key != NULL && keyLen > 0)) {
    if (ctx->hKeyHandle != NULL) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
}

int ret = SDR_OK;
if (ctx->keySource == GCM_KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(ctx->hSessionHandle, (unsigned char *)key, keyLen, &ctx->hKeyHandle);
    if (ret != SDR_OK) { BSL_ERR_PUSH_ERROR(ret); return SDFP_ERR_ENCRYPT; }
} else if (key != NULL && keyLen > 0) {
    ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, ctx->sdfAlgId, ctx->kekIndex,
        (unsigned char *)key, keyLen, &ctx->hKeyHandle);
    if (ret != SDR_OK) { BSL_ERR_PUSH_ERROR(ret); return SDFP_ERR_ENCRYPT; }
}
```

---


## High

### Stack buffer with wrapped key not cleansed before return
`src/sm4_cipher.c:249-264`
**Reviewers**: CLAUDE | **置信度**: 可信
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
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, ctx->sdfAlgId,
    ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
if (ret == SDR_OK && wrapBuf == tmpBuf) {
    BSL_SAL_CleanseData(tmpBuf, sizeof(tmpBuf));
}
return CRYPT_SUCCESS;
```

---

### Stack buffer with wrapped key not cleansed before return in GCM
`src/sm4_gcm.c:327-336`
**Reviewers**: CLAUDE | **置信度**: 可信
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

### SM3 context becomes unusable after DeInit
`src/sm3_md.c:104-109`
**Reviewers**: GEMINI | **置信度**: 较可信
```
static int32_t CRYPT_SM3_DeInit(void *c)
{
    SDFP_SM3_Ctx *ctx = (SDFP_SM3_Ctx *)c;
    SDFP_SM3_CleanCtx(ctx);
    return CRYPT_SUCCESS;
}
```
**Issue**: CRYPT_SM3_DeInit calls SDFP_SM3_CleanCtx(ctx) which closes hSessionHandle. If the provider attempts to reuse the context after DeInit (which is standard behavior for openHiTLS hash contexts), CRYPT_SM3_InitCtx will reject it with CRYPT_NULL_INPUT because ctx->hSessionHandle is NULL.
**Fix**:
```
static int32_t CRYPT_SM3_DeInit(void *c)
{
    (void)c;
    return CRYPT_SUCCESS;
}
```

---

### SM4 context becomes unusable after DeinitCtx
`src/sm4_cipher.c:216-221`
**Reviewers**: GEMINI | **置信度**: 较可信
```
static int32_t CRYPT_SM4_DeinitCtx(void *c)
{
    SDFP_SM4_Ctx *ctx = (SDFP_SM4_Ctx *)c;
    SDFP_SM4_Clean(ctx);
    return CRYPT_SUCCESS;
}
```
**Issue**: CRYPT_SM4_DeinitCtx calls SDFP_SM4_Clean(ctx), which completely closes hSessionHandle. Because InitCtx checks ctx->hSessionHandle == NULL, any attempt to reuse the context after DeinitCtx (e.g., to re-init with new parameters) will fail with CRYPT_NULL_INPUT.
**Fix**:
```
static int32_t CRYPT_SM4_DeinitCtx(void *c)
{
    SDFP_SM4_Ctx *ctx = (SDFP_SM4_Ctx *)c;
    if (ctx == NULL) {
        return CRYPT_SUCCESS;
    }
    if (ctx->hKeyHandle != NULL && ctx->hSessionHandle != NULL) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
    BSL_SAL_CleanseData(ctx->iv, sizeof(ctx->iv));
    ctx->ivLen = 0;
    ctx->keySource = KEY_SRC_RAW;
    ctx->kekIndex = 0;
    return CRYPT_SUCCESS;
}
```

---

### SM4/GCM symbol loading failures cause provider load to fail
`src/sdf_dl.c:202-209`
**Reviewers**: CODEX | **置信度**: 需评估
```
LOAD_SYM(genKeyWithKek,           SDF_GenerateKeyWithKEK);
LOAD_SYM(importKeyWithKek,        SDF_ImportKeyWithKEK);
LOAD_SYM(authEncInit,             SDF_AuthEncInit);
LOAD_SYM(authEncUpdate,           SDF_AuthEncUpdate);
LOAD_SYM(authEncFinal,            SDF_AuthEncFinal);
LOAD_SYM(authDecInit,             SDF_AuthDecInit);
LOAD_SYM(authDecUpdate,           SDF_AuthDecUpdate);
LOAD_SYM(authDecFinal,            SDF_AuthDecFinal);
```
**Issue**: New SM4/AEAD symbols (SDF_GenerateKeyWithKEK, SDF_ImportKeyWithKEK, SDF_AuthEncInit/Update/Final, SDF_AuthDecInit/Update/Final) are loaded with LOAD_SYM (required). If a device SDK lacks one of these APIs, SDF_DL_Load fails and the whole provider cannot load, regressing existing SM2/RSA functionality.
**Fix**:
```
#define LOAD_SYM_OPTIONAL(field, sdfName) \
    do { g_sdfFunc.field = (typeof(g_sdfFunc.field))dlsym(g_sdfLibHandle, #sdfName); } while (0)

/* Keep provider load compatible when optional SM4/GCM APIs are absent */
LOAD_SYM_OPTIONAL(genKeyWithKek,    SDF_GenerateKeyWithKEK);
LOAD_SYM_OPTIONAL(importKeyWithKek, SDF_ImportKeyWithKEK);
LOAD_SYM_OPTIONAL(authEncInit,      SDF_AuthEncInit);
LOAD_SYM_OPTIONAL(authEncUpdate,    SDF_AuthEncUpdate);
LOAD_SYM_OPTIONAL(authEncFinal,     SDF_AuthEncFinal);
LOAD_SYM_OPTIONAL(authDecInit,      SDF_AuthDecInit);
LOAD_SYM_OPTIONAL(authDecUpdate,    SDF_AuthDecUpdate);
LOAD_SYM_OPTIONAL(authDecFinal,     SDF_AuthDecFinal);
```

---


## Medium

### Hardcoded ECB algorithm ID for KEK import
`src/sm4_cipher.c:145`
**Reviewers**: GEMINI | **置信度**: 可信
```
ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, SGD_SM4_ECB, ctx->kekIndex,
            (unsigned char *)key, keyLen, &ctx->hKeyHandle);
```
**Issue**: The imported key's intended algorithm is ctx->sdfAlgId (which might be SGD_SM4_CBC), but SGD_SM4_ECB is hardcoded. Strict SDF hardware implementations will reject using an ECB key for CBC operations.
**Fix**:
```
ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, ctx->sdfAlgId, ctx->kekIndex,
            (unsigned char *)key, keyLen, &ctx->hKeyHandle);
```

---

### Hardcoded ECB algorithm ID for KEK generation
`src/sm4_cipher.c:258`
**Reviewers**: GEMINI | **置信度**: 可信
```
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, SGD_SM4_ECB,
                ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
```
**Issue**: When generating a key wrapped with KEK, its intended usage algorithm is hardcoded to SGD_SM4_ECB instead of the actual ctx->sdfAlgId (e.g., SGD_SM4_CBC). This limits the generated key from being used with CBC on strict devices.
**Fix**:
```
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, ctx->sdfAlgId,
                ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
```

---

### CRYPT_CTRL_SET_TAGLEN is ignored during encryption final
`src/sm4_gcm.c:215-219`
**Reviewers**: CODEX | **置信度**: 可信
```
unsigned int tagOutLen = SM4_GCM_TAG_MAX;
ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
if (ret == SDR_OK) {
    ctx->tagLen = tagOutLen;
}
```
**Issue**: The ctrl handler stores requested tag length in ctx->tagLen, but GCM_Final always passes SM4_GCM_TAG_MAX to SDF_DL_AuthEncFinal, so caller-requested tag length is not honored.
**Fix**:
```
unsigned int tagOutLen = ctx->tagLen;
ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
if (ret == SDR_OK) {
    if (tagOutLen == 0 || tagOutLen > SM4_GCM_TAG_MAX) {
        return CRYPT_INVALID_ARG;
    }
    ctx->tagLen = tagOutLen;
}
```

---

### Demo can return success even when encryption/decryption fails
`demo/sm4_gcm.c:91-93`
**Reviewers**: CODEX | **置信度**: 可信
```
if (encCtx == NULL) {
    fprintf(stderr, "CipherNewCtx (enc) failed\n");
    goto cleanup;
}
...
if (decLen == ptLen && memcmp(decrypted, plaintext, ptLen) == 0) {
    printf("\n[PASS] Plaintext matches!\n");
} else {
    printf("\n[FAIL] Plaintext mismatch!\n");
}
...
return ret;
```
**Issue**: Several failure branches jump to cleanup without setting ret, and plaintext mismatch only prints [FAIL] but keeps ret==0. The final return ret can report success to CTest even on failure.
**Fix**:
```
if (encCtx == NULL) {
    fprintf(stderr, "CipherNewCtx (enc) failed\n");
    ret = 1;
    goto cleanup;
}
...
if (decCtx == NULL) {
    fprintf(stderr, "CipherNewCtx (dec) failed\n");
    ret = 1;
    goto cleanup;
}
...
if (decLen == ptLen && memcmp(decrypted, plaintext, ptLen) == 0) {
    printf("\n[PASS] Plaintext matches!\n");
} else {
    printf("\n[FAIL] Plaintext mismatch!\n");
    ret = 1;
}
...
return (ret == 0) ? 0 : 1;
```

---


## Low

### Duplicate stdio.h include
`demo/sm4_cbc.c:1-2`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
#include <stdio.h>
#include <stdio.h>
```
**Issue**: Lines 1 and 2 both include <stdio.h>, which is redundant and creates a duplicate include.
**Fix**:
```
#include <stdio.h>
```

---

### Inconsistent library format macro usage
`demo/sm4_gcm.c:56`
**Reviewers**: CLAUDE | **置信度**: 可信
```
int ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_SO, "SDFProv", provParams, NULL);
```
**Issue**: sm4_gcm.c uses BSL_SAL_LIB_FMT_SO while all other demo files (sm3_hash.c, sm4_cbc.c, sm4_ecb.c, sm2_sign.c, etc.) use BSL_SAL_LIB_FMT_LIBSO. Inconsistency may cause compilation issues if only one macro is defined.
**Fix**:
```
int ret = CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_LIBSO, "SDFProv", provParams, NULL);
```

---

### Dead code - unused CRYPT_SM3_DupCtx function
`src/sm3_md.c:111-130`
**Reviewers**: GEMINI | **置信度**: 可信
```
static void *CRYPT_SM3_DupCtx(const void *c)
{
    const SDFP_SM3_Ctx *src = (const SDFP_SM3_Ctx *)c;
    if (src == NULL || src->hSessionHandle == NULL) {
        return NULL;
    }
    /* Duplicate by opening a fresh session; hash state is not cloned */
    SDFP_SM3_Ctx *dst = (SDFP_SM3_Ctx *)BSL_SAL_Calloc(1u, sizeof(SDFP_SM3_Ctx));
    if (dst == NULL) {
        return NULL;
    }
    int ret = SDF_DL_OpenSession(src->hDeviceHandle, &dst->hSessionHandle);
    if (ret != SDR_OK) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(dst);
        return NULL;
    }
    dst->hDeviceHandle = src->hDeviceHandle;
    return dst;
}
```
**Issue**: CRYPT_SM3_DupCtx is defined as a static function but is never added to the g_EalMdSm3 function array, resulting in a compiler warning for unused static function. The implementation returns a fresh, uninitialized session state instead of a true clone, which is misleading.
**Fix**:
```
/* Removed CRYPT_SM3_DupCtx as SDF hash state cannot be cloned and it's unused */
```

---
