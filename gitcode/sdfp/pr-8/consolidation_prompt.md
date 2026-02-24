# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdfp
- PR: #8
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## GEMINI Review

# Code Review: openHiTLS/sdfp#8
**Reviewer**: GEMINI


## Critical

### Compilation failure due to undefined macros
`demo/sm4_cbc.c:131-136`
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SM4_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-handle] SET_KEK_ID failed\n");
        CRYPT_EAL_CipherFreeCtx(ctx);
        return -1;
    }
    int32_t ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```
**Issue**: The macros `CRYPT_CTRL_SM4_SET_KEK_ID` and `CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK` are undefined and will cause a compile-time failure. They must be `CRYPT_CTRL_SET_KEK_ID` and `CRYPT_CTRL_GEN_DEK_WITH_KEK`.
**Fix**:
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-handle] SET_KEK_ID failed\n");
        CRYPT_EAL_CipherFreeCtx(ctx);
        return -1;
    }
    int32_t ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```

---

### Undefined macros for KEK control
`demo/sm4_cbc.c:197-202`
```
if (CRYPT_EAL_CipherCtrl(gen, CRYPT_CTRL_SM4_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-import] SET_KEK_ID failed\n");
        CRYPT_EAL_CipherFreeCtx(gen);
        return -1;
    }
    int32_t ret = CRYPT_EAL_CipherCtrl(gen, CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```
**Issue**: `CRYPT_CTRL_SM4_SET_KEK_ID` and `CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK` are undefined. They must be `CRYPT_CTRL_SET_KEK_ID` and `CRYPT_CTRL_GEN_DEK_WITH_KEK`.
**Fix**:
```
if (CRYPT_EAL_CipherCtrl(gen, CRYPT_CTRL_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-import] SET_KEK_ID failed\n");
        CRYPT_EAL_CipherFreeCtx(gen);
        return -1;
    }
    int32_t ret = CRYPT_EAL_CipherCtrl(gen, CRYPT_CTRL_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```

---

### Undefined macro CRYPT_CTRL_SM4_SET_KEK_ID
`demo/sm4_cbc.c:215-216`
```
if (CRYPT_EAL_CipherCtrl(enc, CRYPT_CTRL_SM4_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-import] enc SET_KEK_ID failed\n");
```
**Issue**: Undefined macro used. Must be `CRYPT_CTRL_SET_KEK_ID`.
**Fix**:
```
if (CRYPT_EAL_CipherCtrl(enc, CRYPT_CTRL_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-import] enc SET_KEK_ID failed\n");
```

---

### Undefined macro CRYPT_CTRL_SM4_SET_KEK_ID
`demo/sm4_cbc.c:242-243`
```
if (CRYPT_EAL_CipherCtrl(dec, CRYPT_CTRL_SM4_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-import] dec SET_KEK_ID failed\n");
```
**Issue**: Undefined macro used. Must be `CRYPT_CTRL_SET_KEK_ID`.
**Fix**:
```
if (CRYPT_EAL_CipherCtrl(dec, CRYPT_CTRL_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
        printf("[kek-import] dec SET_KEK_ID failed\n");
```

---

### Pre-generated KEK handle is unconditionally destroyed during InitCtx
`src/sm4_cipher.c:126-129`
```
if (ctx->hKeyHandle != NULL) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
```
**Issue**: `CRYPT_SM4_InitCtx` unconditionally destroys `ctx->hKeyHandle`. If a handle was pre-generated via `GEN_DEK_WITH_KEK` and `InitCtx` is called with `key == NULL` to reuse it, the handle gets wiped out right before use, causing encryption to fail. The handle should only be destroyed when importing a new key.
**Fix**:
```
if (ctx->hKeyHandle != NULL && key != NULL && keyLen > 0) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
```

---

### Pre-generated KEK handle is unconditionally destroyed during InitCtx
`src/sm4_gcm.c:132-135`
```
/* Destroy old key handle if re-initialising */
    if (ctx->hKeyHandle != NULL) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
```
**Issue**: In `GCM_InitCtx`, `ctx->hKeyHandle` is unconditionally destroyed. If a key handle was pre-generated via the `CRYPT_CTRL_GEN_DEK_WITH_KEK` control and the user invokes `InitCtx` to use it, it will be wiped out before initialization, causing the cipher operation to fail.
**Fix**:
```
/* Destroy old key handle only if a new key is provided for re-initialising */
    if (ctx->hKeyHandle != NULL && key != NULL && keyLen > 0) {
        (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
        ctx->hKeyHandle = NULL;
    }
```

---


## High

### Reusing SM3 context fails after DeInit because session is closed
`src/sm3_md.c:104-109`
```
static int32_t CRYPT_SM3_DeInit(void *c)
{
    SDFP_SM3_Ctx *ctx = (SDFP_SM3_Ctx *)c;
    SDFP_SM3_CleanCtx(ctx);
    return CRYPT_SUCCESS;
}
```
**Issue**: `CRYPT_SM3_DeInit` calls `SDFP_SM3_CleanCtx(ctx)` which closes `hSessionHandle`. If the provider attempts to reuse the context after `DeInit` (which is standard behavior for openHiTLS hash contexts), `CRYPT_SM3_InitCtx` will reject it with `CRYPT_NULL_INPUT` because `ctx->hSessionHandle` is `NULL`.
**Fix**:
```
static int32_t CRYPT_SM3_DeInit(void *c)
{
    (void)c;
    return CRYPT_SUCCESS;
}
```

---

### Context becomes unusable after DeinitCtx closes the session
`src/sm4_cipher.c:219-223`
```
static int32_t CRYPT_SM4_DeinitCtx(void *c)
{
    SDFP_SM4_Ctx *ctx = (SDFP_SM4_Ctx *)c;
    SDFP_SM4_Clean(ctx);
    return CRYPT_SUCCESS;
}
```
**Issue**: `CRYPT_SM4_DeinitCtx` calls `SDFP_SM4_Clean(ctx)`, which completely closes `hSessionHandle`. Because `InitCtx` checks `ctx->hSessionHandle == NULL`, any attempt to reuse the context after `DeinitCtx` (e.g., to re-init with new parameters) will fail with `CRYPT_NULL_INPUT`. It should only destroy the key handle.
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


## Medium

### Hardcoded ECB algorithm ID for KEK import
`src/sm4_cipher.c:142-143`
```
ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, SGD_SM4_ECB, ctx->kekIndex,
            (unsigned char *)key, keyLen, &ctx->hKeyHandle);
```
**Issue**: The imported key's intended algorithm is `ctx->sdfAlgId` (which might be `SGD_SM4_CBC`), but `SGD_SM4_ECB` is hardcoded. Strict SDF hardware implementations will reject using an ECB key for CBC operations.
**Fix**:
```
ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, ctx->sdfAlgId, ctx->kekIndex,
            (unsigned char *)key, keyLen, &ctx->hKeyHandle);
```

---

### Hardcoded ECB algorithm ID for KEK generation
`src/sm4_cipher.c:251-252`
```
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, SGD_SM4_ECB,
                ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
```
**Issue**: When generating a key wrapped with KEK, its intended usage algorithm is hardcoded to `SGD_SM4_ECB` instead of the actual `ctx->sdfAlgId` (e.g., `SGD_SM4_CBC`). This limits the generated key from being used with CBC on strict devices.
**Fix**:
```
int ret = SDF_DL_GenerateKeyWithKEK(ctx->hSessionHandle, 128, ctx->sdfAlgId,
                ctx->kekIndex, wrapBuf, &wrapLen, &ctx->hKeyHandle);
```

---


## Low

### Duplicate include of stdio.h
`demo/sm4_cbc.c:1-2`
```
#include <stdio.h>
#include <stdio.h>
```
**Issue**: `<stdio.h>` is included twice consecutively.
**Fix**:
```
#include <stdio.h>
```

---

### Dead code and unused function CRYPT_SM3_DupCtx
`src/sm3_md.c:111-127`
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
**Issue**: `CRYPT_SM3_DupCtx` is defined as a static function but is never added to the `g_EalMdSm3` function array, resulting in a compiler warning for unused static function. Furthermore, its implementation of returning a fresh, uninitialized session state instead of a true clone is dangerous.
**Fix**:
```
/* Removed CRYPT_SM3_DupCtx as SDF hash state cannot be cloned and it's unused */
```

---


---

## CODEX Review

# Code Review: openHiTLS/sdfp#8
**Reviewer**: CODEX


## High

### KEK handle reuse path is broken by unconditional key destruction
`src/sm4_cipher.c:128-156`
```
if (ctx->hKeyHandle != NULL) {
    (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
    ctx->hKeyHandle = NULL;
}

int ret = SDR_OK;
if (ctx->keySource == KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(ctx->hSessionHandle, (unsigned char *)key, keyLen, &ctx->hKeyHandle);
    ...
} else if (key != NULL && keyLen > 0) {
    ...
    ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, SGD_SM4_ECB, ctx->kekIndex,
        (unsigned char *)key, keyLen, &ctx->hKeyHandle);
}
```
**Issue**: `CRYPT_SM4_InitCtx` validates that a KEK-generated `hKeyHandle` exists, then immediately destroys it before init. When caller uses `GEN_DEK_WITH_KEK` and then `CipherInit(..., NULL, 0, ...)`, no new key is imported and `EncryptInit/DecryptInit` gets a NULL key handle.
**Fix**:
```
bool reuseExistingKekHandle = (ctx->keySource == KEY_SRC_KEK && key == NULL && keyLen == 0);

if (!reuseExistingKekHandle && ctx->hKeyHandle != NULL) {
    (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
    ctx->hKeyHandle = NULL;
}

int ret = SDR_OK;
if (ctx->keySource == KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(ctx->hSessionHandle, (unsigned char *)key, keyLen, &ctx->hKeyHandle);
    if (ret != SDR_OK) { BSL_ERR_PUSH_ERROR(ret); return SDFP_ERR_ENCRYPT; }
} else if (!reuseExistingKekHandle) {
    ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, SGD_SM4_ECB, ctx->kekIndex,
        (unsigned char *)key, keyLen, &ctx->hKeyHandle);
    if (ret != SDR_OK) { BSL_ERR_PUSH_ERROR(ret); return SDFP_ERR_ENCRYPT; }
}
```

---

### GCM KEK-handle init deletes the generated key before use
`src/sm4_gcm.c:135-148`
```
/* Destroy old key handle if re-initialising */
if (ctx->hKeyHandle != NULL) {
    (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
    ctx->hKeyHandle = NULL;
}

int ret = SDR_OK;
if (ctx->keySource == GCM_KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(ctx->hSessionHandle, (unsigned char *)key, keyLen, &ctx->hKeyHandle);
} else if (key != NULL && keyLen > 0) {
    ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, SGD_SM4_GCM, ctx->kekIndex,
        (unsigned char *)key, keyLen, &ctx->hKeyHandle);
}
```
**Issue**: `GCM_InitCtx` has the same handle lifecycle bug as CBC/ECB: it destroys `hKeyHandle` unconditionally, so `GEN_DEK_WITH_KEK` followed by `InitCtx(..., NULL, 0, ...)` cannot work.
**Fix**:
```
bool reuseExistingKekHandle = (ctx->keySource == GCM_KEY_SRC_KEK && key == NULL && keyLen == 0);

if (!reuseExistingKekHandle && ctx->hKeyHandle != NULL) {
    (void)SDF_DL_DestroyKey(ctx->hSessionHandle, ctx->hKeyHandle);
    ctx->hKeyHandle = NULL;
}

int ret = SDR_OK;
if (ctx->keySource == GCM_KEY_SRC_RAW) {
    ret = SDF_DL_ImportKey(ctx->hSessionHandle, (unsigned char *)key, keyLen, &ctx->hKeyHandle);
} else if (!reuseExistingKekHandle) {
    ret = SDF_DL_ImportKeyWithKEK(ctx->hSessionHandle, SGD_SM4_ECB, ctx->kekIndex,
        (unsigned char *)key, keyLen, &ctx->hKeyHandle);
}
```

---

### Demo uses different KEK ctrl IDs than provider implementation
`demo/sm4_cbc.c:131-136`
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SM4_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
    ...
}
int32_t ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```
**Issue**: The demo calls `CRYPT_CTRL_SM4_SET_KEK_ID` / `CRYPT_CTRL_SM4_GEN_DEK_WITH_KEK`, but the provider exports `CRYPT_CTRL_SET_KEK_ID` / `CRYPT_CTRL_GEN_DEK_WITH_KEK` in `provider.h`. This mismatch can fail to compile or call wrong ctrl IDs depending on headers.
**Fix**:
```
if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_KEK_ID, &kekIndex, sizeof(kekIndex)) != CRYPT_SUCCESS) {
    ...
}
int32_t ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GEN_DEK_WITH_KEK, wrapped, wrappedLen);
```

---

### Provider load now hard-fails if any SM4/GCM symbol is missing
`src/sdf_dl.c:202-209`
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
**Issue**: New SM4/AEAD symbols are loaded with `LOAD_SYM` (required). If a device SDK lacks one of these APIs, `SDF_DL_Load` fails and the whole provider cannot load, regressing existing SM2/RSA functionality.
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

### `CRYPT_CTRL_SET_TAGLEN` is ignored during encryption final
`src/sm4_gcm.c:215-218`
```
unsigned int tagOutLen = SM4_GCM_TAG_MAX;
ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
if (ret == SDR_OK) {
    ctx->tagLen = tagOutLen;
}
```
**Issue**: The ctrl handler stores requested tag length in `ctx->tagLen`, but `GCM_Final` always passes `SM4_GCM_TAG_MAX` to `SDF_DL_AuthEncFinal`, so caller-requested tag length is not honored.
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

### Demo can return success even when encryption/decryption flow fails
`demo/sm4_gcm.c:90-93`
```
if (encCtx == NULL) {
    fprintf(stderr, "CipherNewCtx (enc) failed\n");
    goto cleanup;
}
...
if (decCtx == NULL) {
    fprintf(stderr, "CipherNewCtx (dec) failed\n");
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
**Issue**: Several failure branches jump to cleanup without setting `ret`, and plaintext mismatch only prints `[FAIL]` but keeps `ret==0`; final `return ret` can report success to CTest even on failure.
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


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
