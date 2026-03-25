# Final Code Review Report
## openHiTLS/sdfp - PR #9

### Summary
- **Total Issues**: 7
- **Critical**: 1
- **High**: 5
- **Medium**: 1
- **Low**: 0
- **Reviewers**: claude, gemini, codex

---


## Critical

### Buffer overflow in SM4-GCM encryption finalization
`src/sm4/sm4_gcm.c:213-228`
**Reviewers**: GEMINI | **置信度**: 可信
```
unsigned int tmpLen = *outLen;
int ret;
if (ctx->enc) {
    unsigned int tagOutLen = SM4_GCM_TAG_MAX;
    /* Pre-check: ensure the output buffer can hold both ciphertext tail and tag
     * before calling AuthEncFinal, which would write partial data irreversibly. */
    if (*outLen < tagOutLen) {
        return CRYPT_INVALID_ARG;
    }
    /* AuthEncFinal outputs remaining ciphertext bytes into [out, tmpLen) */
    ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
    if (ret == SDR_OK) {
        ctx->tagLen = tagOutLen;
        memcpy(out + tmpLen, ctx->tag, tagOutLen);
        tmpLen += tagOutLen;
    }
```
**Issue**: When calling SDF_DL_AuthEncFinal, tmpLen is initialized to the full buffer capacity (*outLen). The hardware might write up to tmpLen bytes into the out buffer. The code then appends tagOutLen bytes (the GCM authentication tag) starting at out + tmpLen. If the total written length plus the tag length exceeds *outLen, a buffer overflow occurs. The available capacity for AuthEncFinal must be reduced by tagOutLen.
**Fix**:
```
unsigned int tmpLen;
int ret;
if (ctx->enc) {
    unsigned int tagOutLen = SM4_GCM_TAG_MAX;
    /* Pre-check: ensure the output buffer can hold both ciphertext tail and tag
     * before calling AuthEncFinal, which would write partial data irreversibly. */
    if (*outLen < tagOutLen) {
        return CRYPT_INVALID_ARG;
    }
    tmpLen = *outLen - tagOutLen;  /* Reserve space for the tag */
    /* AuthEncFinal outputs remaining ciphertext bytes into [out, tmpLen) */
    ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
    if (ret == SDR_OK) {
        ctx->tagLen = tagOutLen;
        memcpy(out + tmpLen, ctx->tag, tagOutLen);
        tmpLen += tagOutLen;
    }
```

---


## High

### String literal passed as non-const pointer may cause undefined behavior
`src/rsa/rsa_sign.c:117-119`
**Reviewers**: CLAUDE | **置信度**: 可信
```
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : (unsigned char *)DEFAULT_PASS,
        ctx->pass != NULL ? ctx->passLen : DEFAULT_PASS_LEN);
```
**Issue**: When ctx->pass == NULL, the code passes (unsigned char *)DEFAULT_PASS to SDF_DL_GetPrivateKeyAccessRight. DEFAULT_PASS is a string literal defined in provider.h as "#define DEFAULT_PASS \"12345678\"", which is stored in read-only memory. The cast to unsigned char * removes the const qualifier. If the SDF SDK modifies the password buffer, it will cause undefined behavior (segmentation fault or memory corruption).

This is inconsistent with provider.c which properly allocates a heap buffer and copies the default password (lines 209-220).
**Fix**:
```
/* Use a static writable buffer for the default password */
static uint8_t g_defaultPassBuffer[] = "12345678";
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : g_defaultPassBuffer,
        ctx->pass != NULL ? ctx->passLen : sizeof(g_defaultPassBuffer) - 1);
```

---

### String literal passed as non-const pointer may cause undefined behavior
`src/rsa/rsa_pkeycipher.c:158-160`
**Reviewers**: CLAUDE | **置信度**: 可信
```
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : (unsigned char *)DEFAULT_PASS,
        ctx->pass != NULL ? ctx->passLen : DEFAULT_PASS_LEN);
```
**Issue**: When ctx->pass == NULL, the code passes (unsigned char *)DEFAULT_PASS to SDF_DL_GetPrivateKeyAccessRight. DEFAULT_PASS is a string literal stored in read-only memory. The cast to unsigned char * removes the const qualifier. If the SDF SDK modifies the password buffer, it will cause undefined behavior.
**Fix**:
```
/* Use a static writable buffer for the default password */
static uint8_t g_defaultPassBuffer[] = "12345678";
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : g_defaultPassBuffer,
        ctx->pass != NULL ? ctx->passLen : sizeof(g_defaultPassBuffer) - 1);
```

---

### RSA support is silently disabled while RSA callbacks remain exposed
`src/common/sdf_dl.c:183-193`
**Reviewers**: CODEX | **置信度**: 可信
```
/*
 * RSA internal key operations are loaded on demand when an internal RSA
 * key index is configured (not all SDF devices support them).
 */
/* LOAD_SYM(genKeyPairRsa,           SDF_GenerateKeyPair_RSA); */
/* LOAD_SYM(exportSignPubKeyRsa,     SDF_ExportSignPublicKey_RSA); */
/* LOAD_SYM(exportEncPubKeyRsa,      SDF_ExportEncPublicKey_RSA); */
/* LOAD_SYM(intPubKeyOpRsa,          SDF_InternalPublicKeyOperation_RSA); */
/* LOAD_SYM(intPrivKeyOpRsa,         SDF_InternalPrivateKeyOperation_RSA); */
/* LOAD_SYM(extPubKeyOpRsa,          SDF_ExternalPublicKeyOperation_RSA); */
/* LOAD_SYM(extPrivKeyOpRsa,         SDF_ExternalPrivateKeyOperation_RSA); */
```
**Issue**: The loader no longer resolves any RSA symbols (all commented out), but the provider still registers RSA keymgmt/sign/asymcipher callbacks. Every RSA path now reaches wrappers whose function pointers are still NULL and fails with SDFP_ERR_NOT_LOADED at runtime. This creates silent runtime failures for users attempting to use RSA functionality.
**Fix**:
```
LOAD_SYM(genKeyPairRsa,           SDF_GenerateKeyPair_RSA);
LOAD_SYM(exportSignPubKeyRsa,     SDF_ExportSignPublicKey_RSA);
LOAD_SYM(exportEncPubKeyRsa,      SDF_ExportEncPublicKey_RSA);
LOAD_SYM(intPubKeyOpRsa,          SDF_InternalPublicKeyOperation_RSA);
LOAD_SYM(intPrivKeyOpRsa,         SDF_InternalPrivateKeyOperation_RSA);
LOAD_SYM(extPubKeyOpRsa,          SDF_ExternalPublicKeyOperation_RSA);
LOAD_SYM(extPrivKeyOpRsa,         SDF_ExternalPrivateKeyOperation_RSA);
```

---

### Provider unload tears down the process-global RNG even when it did not create it
`src/common/provider.c:95`
**Reviewers**: CODEX | **置信度**: 可信
```
ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES256_CTR, NULL, NULL, NULL, 0);
if (ret != CRYPT_SUCCESS) {
    /* RNG may already be initialized by the application probe it */
    uint8_t probe[4];
    if (CRYPT_EAL_Randbytes(probe, sizeof(probe)) != CRYPT_SUCCESS) {
        BSL_SAL_Free(temp->sdfLibPath);
        BSL_SAL_Free(temp);
        SDF_DL_Unload();
        return SDFP_ERR_OPEN_DEVICE;
    }
}

...

static void CRYPT_EAL_ProvFree(void *provCtx)
{
    ...
    CRYPT_EAL_RandDeinit();
    ...
}
```
**Issue**: ProviderInit explicitly tolerates CRYPT_EAL_RandInit() failing because some other component already initialized the global RNG (lines 170-180), but CRYPT_EAL_ProvFree() always calls CRYPT_EAL_RandDeinit() anyway at line 95. Unloading the provider can therefore deinitialize RNG state that belongs to the application or another provider instance, causing undefined behavior in components that still expect the RNG to be initialized.
**Fix**:
```
/* Add a bool ownsRand to CRYPT_EAL_ProvCtx and only deinit when we created it */
ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES256_CTR, NULL, NULL, NULL, 0);
if (ret == CRYPT_SUCCESS) {
    temp->ownsRand = true;
} else {
    uint8_t probe[4];
    if (CRYPT_EAL_Randbytes(probe, sizeof(probe)) != CRYPT_SUCCESS) {
        BSL_SAL_Free(temp->sdfLibPath);
        BSL_SAL_Free(temp);
        SDF_DL_Unload();
        return SDFP_ERR_OPEN_DEVICE;
    }
}

/* In CRYPT_EAL_ProvFree: */
if (ctx->ownsRand) {
    CRYPT_EAL_RandDeinit();
}
```

---

### Private-key-only signing produces non-standard SM2 hash
`src/sm2/sm2_sign.c:235-253`
**Reviewers**: CODEX | **置信度**: 可信
```
} else {
    /* For external keys without public key, we can't compute Z = SM3(ID || PubKey).
     * Use simple SM3 hash of message instead. This is compatible with the SDF
     * library's ExternalSign_ECC which expects a pre-computed 32-byte hash. */
    ret = SDF_DL_HashInit(ctx->hSessionHandle, SGD_SM3, NULL, ctx->userId, ctx->userIdLen);
    if (ret != SDR_OK) {
        SDFP_LOG(ret);
        return SDFP_ERR_HASH;
    }
    ret = SDF_DL_HashUpdate(ctx->hSessionHandle, (unsigned char *)data, dataLen);
    if (ret != SDR_OK) {
        SDFP_LOG(ret);
        return SDFP_ERR_HASH;
    }
    ret = SDF_DL_HashFinal(ctx->hSessionHandle, tbs, &tbsLen);
    if (ret != SDR_OK) {
        SDFP_LOG(ret);
        return SDFP_ERR_HASH;
    }
}
```
**Issue**: When no public key is present, the fallback signs SM3(msg) instead of the SM2-required SM3(Z || msg) where Z = SM3(ID || PubKey). This silently produces signatures that a compliant SM2 verifier will reject, as the SM2 standard specifically requires computing Z from the public key. The code should either return CRYPT_SM2_NO_PUBKEY error or derive the public key from the private key first.
**Fix**:
```
if (ctx->publicKey == NULL) {
    return CRYPT_SM2_NO_PUBKEY;
}

ret = Sm2ComputeMsgHash(ctx, ctx->publicKey, data, dataLen, tbs, &tbsLen);
if (ret != CRYPT_SUCCESS) {
    SDFP_LOG(ret);
    return ret;
}
```

---


## Medium

### Resource leak of temporary key handle during DEK generation
`src/sm4/sm4_cipher.c:285-292`
**Reviewers**: GEMINI | **置信度**: 可信
```
void *hTmpKey = NULL;
ret = SDF_DL_GenerateKeyWithKEK(hTmpSession, 128, SGD_SM4_ECB,
    ctx->kekIndex, wrapBuf, &wrapLen, &hTmpKey);
(void)SDF_DL_CloseSession(hTmpSession);
```
**Issue**: The code calls SDF_DL_GenerateKeyWithKEK to create a new session key, which yields a hardware key handle (hTmpKey). It then immediately closes hTmpSession without explicitly destroying the generated key handle via SDF_DL_DestroyKey. Although closing the session might implicitly drop session resources in some implementations, it can cause memory or resource leaks inside the HSM or driver on strict SDF device implementations. The key handle must be destroyed properly.
**Fix**:
```
void *hTmpKey = NULL;
ret = SDF_DL_GenerateKeyWithKEK(hTmpSession, 128, SGD_SM4_ECB,
    ctx->kekIndex, wrapBuf, &wrapLen, &hTmpKey);
if (ret == SDR_OK && hTmpKey != NULL) {
    (void)SDF_DL_DestroyKey(hTmpSession, hTmpKey);
}
(void)SDF_DL_CloseSession(hTmpSession);
```

---
