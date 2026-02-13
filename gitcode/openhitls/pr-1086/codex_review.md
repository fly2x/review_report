# Code Review: openHiTLS/openhitls#1086
**Reviewer**: CODEX


## High

### Undefined variable `len` breaks `HITLS_APP_SM_MODE` build
`apps/src/app_utils.c:1102-1107`
```
(void)snprintf(str, sizeof(str), "%d", pid);
if (param->smParam->smTag == 1 && param->randAlgId == CRYPT_RAND_SHA256) {
    param->randAlgId = CRYPT_RAND_SM4_CTR_DF;
}
int32_t ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), param->randAlgId,
    param->provider->providerAttr, (const uint8_t *)str, len, NULL);
```
**Issue**: `len` is still passed to `CRYPT_EAL_ProviderRandInitCtx` after replacing `sprintf_s` with `snprintf`, but `len` is no longer defined. This causes a compile error when `HITLS_APP_SM_MODE` is enabled.
**Fix**:
```
int len = snprintf(str, sizeof(str), "%d", pid);
if (len < 0 || (size_t)len >= sizeof(str)) {
    AppPrintError("Failed to set pid, pid = %d.\n", pid);
    return HITLS_APP_INVALID_ARG;
}
if (param->smParam->smTag == 1 && param->randAlgId == CRYPT_RAND_SHA256) {
    param->randAlgId = CRYPT_RAND_SM4_CTR_DF;
}
int32_t ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), param->randAlgId,
    param->provider->providerAttr, (const uint8_t *)str, (uint32_t)len, NULL);
```

---

### Sensitive key material is wiped with non-guaranteed `memset`
`tls/handshake/common/src/hs_kx.c:436-440`
```
memset(tmpPskPmsBufTmp, 0, MAX_PRE_MASTER_SECRET_SIZE);
...
ERR:
    memset(tmpPskPmsBufTmp, 0, MAX_PRE_MASTER_SECRET_SIZE);
...
memset(keyPara.masterSecret, 0, MASTER_SECRET_LEN);
```
**Issue**: Pre-master/master secret buffers are cleared using `memset`. Compilers may optimize these calls away, leaving secret material in memory after use.
**Fix**:
```
BSL_SAL_CleanseData(tmpPskPmsBufTmp, MAX_PRE_MASTER_SECRET_SIZE);
...
ERR:
    BSL_SAL_CleanseData(tmpPskPmsBufTmp, MAX_PRE_MASTER_SECRET_SIZE);
...
BSL_SAL_CleanseData(keyPara.masterSecret, MASTER_SECRET_LEN);
```

---


## Medium

### PSK buffer cleanup downgraded from secure erase to plain `memset`
`tls/handshake/send/src/send_client_hello.c:330`
```
memset(psk, 0, HS_PSK_MAX_LEN);
...
memset(psk, 0, HS_PSK_MAX_LEN);
...
memset(psk, 0, HS_PSK_MAX_LEN);
```
**Issue**: The temporary `psk` buffer holds secret key material but is cleared with `memset`, which can be optimized out and fail to reliably erase secrets.
**Fix**:
```
BSL_SAL_CleanseData(psk, HS_PSK_MAX_LEN);
...
BSL_SAL_CleanseData(psk, HS_PSK_MAX_LEN);
...
BSL_SAL_CleanseData(psk, HS_PSK_MAX_LEN);
```

---
