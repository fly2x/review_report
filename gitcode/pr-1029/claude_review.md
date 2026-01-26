# Code Review: openHiTLS/openhitls#1029
**Reviewer**: CLAUDE


## High

### Wrong size used for secure clearing of decrypted private key
`apps/src/app_tls_common.c:331`
```
CRYPT_EAL_PkeyFreeCtx(signKey);
    BSL_SAL_Free(cipher);
    BSL_SAL_ClearFree(plain, cipherLen);
    return encKey;
```
**Issue**: The decrypted private key (`plain`) is cleared using `cipherLen` instead of `plainLen`. The decrypted data length (`plainLen`) is typically smaller than the ciphertext length (`cipherLen`). This means sensitive plaintext private key bytes beyond the actual data may not be cleared, and the operation is using the wrong size parameter, which could leave sensitive key material in memory if `plainLen < cipherLen`.
**Fix**:
```
CRYPT_EAL_PkeyFreeCtx(signKey);
    BSL_SAL_Free(cipher);
    BSL_SAL_ClearFree(plain, plainLen);
    return encKey;
```

---

### Wrong size used for secure clearing of decrypted private key in error path
`apps/src/app_tls_common.c:345`
```
if (plain != NULL) {
        BSL_SAL_ClearFree(plain, cipherLen);
    }
```
**Issue**: Same issue as above - in the error path, `plain` is cleared using `cipherLen` instead of `plainLen`. This is inconsistent and uses the wrong size for secure memory clearing of the sensitive private key material.
**Fix**:
```
if (plain != NULL) {
        BSL_SAL_ClearFree(plain, plainLen);
    }
```

---


## Medium

### Missing NULL check for cipherFile parameter
`apps/src/app_tls_common.c:254`
```
static int32_t ReadEncKeyCipher(const char *cipherFile, uint8_t **cipher, uint32_t *cipherLen)
{
    int32_t ret = BSL_SAL_ReadFile(cipherFile, cipher, cipherLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to read encrypted private key from %s\n", cipherFile);
    }
    return ret;
}
```
**Issue**: The `ReadEncKeyCipher` function passes `cipherFile` directly to `BSL_SAL_ReadFile` and also uses it in the error message with `%s` format specifier without checking if it's NULL. If `cipherFile` is NULL, this could cause undefined behavior in `BSL_SAL_ReadFile` or a crash when printing the error message.
**Fix**:
```
static int32_t ReadEncKeyCipher(const char *cipherFile, uint8_t **cipher, uint32_t *cipherLen)
{
    if (cipherFile == NULL) {
        AppPrintError("Failed to read encrypted private key: file path is NULL\n");
        return BSL_NULL_INPUT;
    }
    int32_t ret = BSL_SAL_ReadFile(cipherFile, cipher, cipherLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to read encrypted private key from %s\n", cipherFile);
    }
    return ret;
}
```

---

### Missing NULL check for provider parameter
`apps/src/app_tls_common.c:283`
```
static CRYPT_EAL_PkeyCtx *CreateSm2PkeyFromPrv(AppProvider *provider, uint8_t *plain, uint32_t plainLen)
{
    CRYPT_EAL_PkeyCtx *encKey = CRYPT_EAL_ProviderPkeyNewCtx(APP_GetCurrent_LibCtx(), CRYPT_PKEY_SM2, 0,
        provider->providerAttr);
```
**Issue**: The `CreateSm2PkeyFromPrv` function does not check if `provider` is NULL before accessing `provider->providerAttr`. If the caller passes NULL provider, this will cause a null pointer dereference and crash.
**Fix**:
```
static CRYPT_EAL_PkeyCtx *CreateSm2PkeyFromPrv(AppProvider *provider, uint8_t *plain, uint32_t plainLen)
{
    if (provider == NULL || plain == NULL || plainLen == 0) {
        AppPrintError("Invalid parameters for creating SM2 pkey from private key\n");
        return NULL;
    }
    CRYPT_EAL_PkeyCtx *encKey = CRYPT_EAL_ProviderPkeyNewCtx(APP_GetCurrent_LibCtx(), CRYPT_PKEY_SM2, 0,
        provider->providerAttr);
```

---

### Missing NULL check for smParam before dereferencing
`apps/src/app_tls_common.c:370`
```
if (!isSignKey && certConfig->smParam->smTag == 1) {
        pkey = LoadEncKeyBySignKey(certConfig);
        if (pkey != NULL) {
            return pkey;
        }
    }
```
**Issue**: The code checks `certConfig->smParam->smTag` without first verifying that `smParam` is not NULL. If `smParam` is NULL, this will cause a null pointer dereference.
**Fix**:
```
if (!isSignKey && certConfig->smParam != NULL && certConfig->smParam->smTag == 1) {
        pkey = LoadEncKeyBySignKey(certConfig);
        if (pkey != NULL) {
            return pkey;
        }
    }
```

---
