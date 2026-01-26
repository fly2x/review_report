# Code Review: openHiTLS/openhitls#1029
**Reviewer**: CODEX


## Medium

### Missing NULL check for smParam in new SM enc-key path
`apps/src/app_tls_common.c:370-374`
```
if (!isSignKey && certConfig->smParam->smTag == 1) {
        pkey = LoadEncKeyBySignKey(certConfig);
        if (pkey != NULL) {
            return pkey;
        }
    }
```
**Issue**: The new SM-mode branch dereferences `certConfig->smParam` without verifying it is non-NULL. If an `APP_CertConfig` is constructed without SM parameters (e.g., SM mode compiled but caller does not set `smParam`), this will crash when loading the encryption key, before falling back to the normal key loader.
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
