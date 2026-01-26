# Code Review: openHiTLS/openhitls#1029
**Reviewer**: GEMINI


## High

### Potential NULL pointer dereference
`apps/src/app_tls_common.c:370`
```
if (!isSignKey && certConfig->smParam->smTag == 1) {
        pkey = LoadEncKeyBySignKey(certConfig);
```
**Issue**: The code dereferences `certConfig->smParam` to access `smTag` without checking if `smParam` is NULL. If `HITLS_APP_SM_MODE` is enabled but `smParam` is not initialized (e.g. in non-SM modes or partial config), this will cause a crash.
**Fix**:
```
if (!isSignKey && certConfig->smParam != NULL && certConfig->smParam->smTag == 1) {
        pkey = LoadEncKeyBySignKey(certConfig);
```

---


## Medium

### Ignored return value of BSL_PARAM_InitValue
`apps/src/app_tls_common.c:292`
```
(void)BSL_PARAM_InitValue(&prvParam[0], CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS,
        (void *)plain, plainLen);
    int32_t ret = CRYPT_EAL_PkeySetPrvEx(encKey, prvParam);
```
**Issue**: The return value of `BSL_PARAM_InitValue` is explicitly cast to void and ignored. If initialization fails (e.g. invalid arguments), `prvParam` will be incorrectly initialized, potentially causing `CRYPT_EAL_PkeySetPrvEx` to fail or behave unpredictably.
**Fix**:
```
if (BSL_PARAM_InitValue(&prvParam[0], CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS,
        (void *)plain, plainLen) != BSL_SUCCESS) {
        AppPrintError("Failed to init private key param\n");
        CRYPT_EAL_PkeyFreeCtx(encKey);
        return NULL;
    }
    int32_t ret = CRYPT_EAL_PkeySetPrvEx(encKey, prvParam);
```

---
