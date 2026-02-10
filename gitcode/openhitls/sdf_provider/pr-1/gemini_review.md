# Code Review: openHiTLS/sdf_provider#1
**Reviewer**: GEMINI


## Critical

### Buffer overflow vulnerability in LOG_ERROR
`src/log.c:20`
```
va_start(args, lpFormat);
    vsprintf(log_buf, lpFormat, args);
    va_end(args);
```
**Issue**: The function uses `vsprintf` to write to a fixed-size buffer `log_buf` of 1024 bytes. If the formatted log message exceeds this length, it will cause a buffer overflow, which can lead to crashes or arbitrary code execution.
**Fix**:
```
va_start(args, lpFormat);
    vsnprintf(log_buf, sizeof(log_buf), lpFormat, args);
    va_end(args);
```

---


## High

### Insufficient buffer size for SM2 public key export
`src/sm2_keymgmt.c:421`
```
uint8_t pubkey[32] = {0};
    CRYPT_EAL_ProcessFuncCb processCb = NULL;
    void *args = NULL;
    BSL_Param sm2Params[3] = {0};
    int32_t ret = CRYPT_GetPkeyProcessParams_ex(params, &processCb, &args);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (ctx->KeyIndex != 0 || ctx->PrivateKey != NULL) {
        (void)BSL_PARAM_InitValue(&sm2Params[index], CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvkey, sizeof(prvkey));
        ret = CRYPT_SM2_GetPrvKeyEx(ctx, sm2Params);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        sm2Params[index].valueLen = sm2Params[index].useLen;
        index++;
    }
    if (ctx->KeyIndex != 0 || ctx->PublicKey != NULL) {
        (void)BSL_PARAM_InitValue(&sm2Params[index], CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            pubkey, sizeof(pubkey));
        ret = CRYPT_SM2_GetPubKeyEx(ctx, sm2Params);
```
**Issue**: In `CRYPT_SM2_Export`, the `pubkey` buffer is allocated with 32 bytes, but an uncompressed SM2 public key (0x04 || X || Y) requires 65 bytes. `CRYPT_SM2_GetPubKeyEx` (called via `sm2Params`) checks if the buffer is at least 65 bytes and will fail, making public key export impossible.
**Fix**:
```
uint8_t prvkey[32] = {0};
    uint8_t pubkey[65] = {0};
    CRYPT_EAL_ProcessFuncCb processCb = NULL;
    void *args = NULL;
    BSL_Param sm2Params[3] = {0};
    int32_t ret = CRYPT_GetPkeyProcessParams_ex(params, &processCb, &args);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (ctx->KeyIndex != 0 || ctx->PrivateKey != NULL) {
        (void)BSL_PARAM_InitValue(&sm2Params[index], CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvkey, sizeof(prvkey));
        ret = CRYPT_SM2_GetPrvKeyEx(ctx, sm2Params);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        sm2Params[index].valueLen = sm2Params[index].useLen;
        index++;
    }
    if (ctx->KeyIndex != 0 || ctx->PublicKey != NULL) {
        (void)BSL_PARAM_InitValue(&sm2Params[index], CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            pubkey, sizeof(pubkey));
        ret = CRYPT_SM2_GetPubKeyEx(ctx, sm2Params);
```

---


## Medium

### Memory leak in CRYPT_SM2_Decrypt on error paths
`src/sm2_pkeycipher.c:153`
```
// support key index and external key both
    if (ctx->KeyIndex != 0) {
        ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
                (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
            return CRYPT_SM2_INVALID_PRVKEY;
        }
        ret = SDF_InternalDecrypt_ECC(ctx->hSessionHandle, ctx->KeyIndex, pucEncData, out, outlen);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_InternalDecrypt_ECC error, ret = %08x", ret);
            BSL_SAL_Free(pucEncData);
            return CRYPT_SM2_DECRYPT_FAIL;
        }
        ret = SDF_ReleasePrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_ReleasePrivateKeyAccessRight error, ret = %08x", ret);
            return CRYPT_SM2_INVALID_PRVKEY;
        }
    }
```
**Issue**: `pucEncData` is allocated at the beginning of `CRYPT_SM2_Decrypt` but is not freed if `SDF_GetPrivateKeyAccessRight` or `SDF_ReleasePrivateKeyAccessRight` fails.
**Fix**:
```
// support key index and external key both
    if (ctx->KeyIndex != 0) {
        ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
                (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
            BSL_SAL_Free(pucEncData);
            return CRYPT_SM2_INVALID_PRVKEY;
        }
        ret = SDF_InternalDecrypt_ECC(ctx->hSessionHandle, ctx->KeyIndex, pucEncData, out, outlen);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_InternalDecrypt_ECC error, ret = %08x", ret);
            BSL_SAL_Free(pucEncData);
            return CRYPT_SM2_DECRYPT_FAIL;
        }
        ret = SDF_ReleasePrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_ReleasePrivateKeyAccessRight error, ret = %08x", ret);
            BSL_SAL_Free(pucEncData);
            return CRYPT_SM2_INVALID_PRVKEY;
        }
    }
```

---

### Resource-heavy context creation (Device/Session leak potential)
`src/rsa_keymgmt.c:21`
```
ret = SDF_OpenDevice(&hDeviceHandle);
    if (ret != SDR_OK) {
        LOG_ERROR("SDF_OpenDevice error, ret = %08x", ret);
        BSL_SAL_Free(ctx);
        return NULL;
    }

    ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
    if (ret != SDR_OK) {
        LOG_ERROR("SDF_OpenSession error, ret = %08x", ret);
        SDF_CloseDevice(hDeviceHandle);
        BSL_SAL_Free(ctx);
        return NULL;
    }
```
**Issue**: `CRYPT_RSA_NewCtxEx` opens a new SDF device handle and a new session for every single RSA context created. This is extremely inefficient and can quickly exhaust the hardware's limit on open devices or sessions. Device handles should ideally be shared or managed at the provider level.
**Fix**:
```
/* Implementation should be refactored to manage hDeviceHandle at the Provider context level (src/provider.c) and potentially use a session pool or share sessions across contexts. */
```

---

### Potential NULL pointer dereference in DupCtx
`src/rsa_keymgmt.c:512`
```
if (ctx->hDeviceHandle != NULL) {
        ret = SDF_OpenDevice(&newCtx->hDeviceHandle);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_OpenDevice error, ret = %08x", ret);
            goto ERR;
        }
    }
    if (ctx->hSessionHandle != NULL) {
        ret = SDF_OpenSession(newCtx->hDeviceHandle, &newCtx->hSessionHandle);
```
**Issue**: In `CRYPT_RSA_DupCtx`, `SDF_OpenSession` is called using `newCtx->hDeviceHandle`. If `ctx->hDeviceHandle` was NULL, `newCtx->hDeviceHandle` remains NULL (from `Calloc`), leading to a NULL pointer dereference in `SDF_OpenSession` if `ctx->hSessionHandle` was non-NULL.
**Fix**:
```
if (ctx->hDeviceHandle != NULL) {
        ret = SDF_OpenDevice(&newCtx->hDeviceHandle);
        if (ret != SDR_OK) {
            LOG_ERROR("SDF_OpenDevice error, ret = %08x", ret);
            goto ERR;
        }
    }
    if (ctx->hSessionHandle != NULL && newCtx->hDeviceHandle != NULL) {
        ret = SDF_OpenSession(newCtx->hDeviceHandle, &newCtx->hSessionHandle);
```

---

### Hardcoded default password for private key access
`src/provider.h:9`
```
#define DEFAULT_PASS "12345678"
#define DEFAULT_PASS_LEN strlen(DEFAULT_PASS)
```
**Issue**: `DEFAULT_PASS` is hardcoded as "12345678". This password is used to access private keys in the SDF device. Hardcoding such sensitive information is insecure and should be configurable or provided by the user/application at runtime.
**Fix**:
```
/* Remove hardcoded DEFAULT_PASS and implement a mechanism to pass the key password from the application through the provider context or control APIs. */
```

---

### KeyIndex masquerading as private key data
`src/sm2_keymgmt.c:102`
```
if (memcmp(prv.data, zero, prv.len - 1) == 0) {
        // data with leading 0x00, use it as KeyIndex
        ctx->KeyIndex = prv.data[prv.len - 1];
    }
```
**Issue**: If the provided private key data consists of zeros except for the last byte, it is interpreted as a `KeyIndex`. When exporting this key back, `CRYPT_SM2_GetPrvKeyEx` returns this "fake" private key. This can lead to security issues or interoperability failures if this key is imported into a system that expects real private key bytes.
**Fix**:
```
/* Use a separate parameter type (e.g. CRYPT_PARAM_KEY_INDEX) to specify hardware key indices instead of overloading the private key buffer. */
```

---


## Low

### Use of thread-unsafe localtime function
`src/log.c:24`
```
time(&timep);
    p = localtime(&timep);
```
**Issue**: `localtime` returns a pointer to a static structure which is shared among all threads. In a multi-threaded environment, this can lead to race conditions where the timestamp in the log is corrupted.
**Fix**:
```
struct tm tm_res;
    time(&timep);
    p = localtime_r(&timep, &tm_res);
```

---

### Missing NULL checks for SDF handles in FreeCtx
`src/rsa_keymgmt.c:472`
```
BSL_SAL_Free(ctx->e);
    BSL_SAL_Free(ctx->label.data);
    SDF_CloseSession(ctx->hSessionHandle);
    SDF_CloseDevice(ctx->hDeviceHandle);
    BSL_SAL_Free(ctx);
```
**Issue**: `SDF_CloseSession` and `SDF_CloseDevice` are called without checking if the handles are valid (non-NULL). Depending on the SDF library implementation, passing a NULL handle might cause a crash.
**Fix**:
```
BSL_SAL_Free(ctx->e);
    BSL_SAL_Free(ctx->label.data);
    if (ctx->hSessionHandle != NULL) {
        SDF_CloseSession(ctx->hSessionHandle);
    }
    if (ctx->hDeviceHandle != NULL) {
        SDF_CloseDevice(ctx->hDeviceHandle);
    }
    BSL_SAL_Free(ctx);
```

---

### Inefficient random number generation for RSA padding
`src/rsa_padding.c:686`
```
do {
            // no zero
            ret = SDF_GenerateRandom(ctx->hSessionHandle, 1, ps + i);
            if (ret != SDR_OK) {
                LOG_ERROR("SDF_GenerateRandom error, ret = %08x", ret);
                return CRYPT_EAL_ERR_RAND_NO_WORKING;
            }
        } while (*(ps + i) == 0);
```
**Issue**: In `CRYPT_RSA_SetPkcsV15Type2_ex`, if a byte generated by `SDF_GenerateRandom` is zero, it enters a `do-while` loop that calls `SDF_GenerateRandom` again for just 1 byte. Frequent small calls to hardware random number generators are typically inefficient.
**Fix**:
```
/* It is more efficient to generate a larger block of random bytes and filter out zeros, or use a local PRNG seeded by the hardware RNG. */
```

---
