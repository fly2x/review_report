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
