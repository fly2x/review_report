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
