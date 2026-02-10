# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdf_provider
- PR: #1
- Title: 

## Individual Review Reports

## GEMINI Review

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


---

## CODEX Review

# Code Review: openHiTLS/sdf_provider#1
**Reviewer**: CODEX


## High

### Unbounded vsprintf in LOG_ERROR
`src/log.c:19-20`
```
va_start(args, lpFormat);
vsprintf(log_buf, lpFormat, args);
va_end(args);
```
**Issue**: `vsprintf` writes without bounds into a fixed-size buffer, allowing a long format string to overflow `log_buf` and corrupt memory.
**Fix**:
```
va_start(args, lpFormat);
vsnprintf(log_buf, sizeof(log_buf), lpFormat, args);
va_end(args);
```

---


## Medium

### Missing digest-size zero check can hang MGF1
`src/crypt_util_mgf.c:41-44`
```
uint32_t hashLen = CRYPT_EAL_MdGetDigestSize(id);
if (hashLen > HASH_MAX_MDSIZE) {
    return CRYPT_RSA_ERR_INPUT_VALUE;
}
```
**Issue**: If `CRYPT_EAL_MdGetDigestSize` returns 0 (unsupported/invalid hash), `partLen` stays 0 and the loop never advances, causing an infinite loop.
**Fix**:
```
uint32_t hashLen = CRYPT_EAL_MdGetDigestSize(id);
if (hashLen == 0 || hashLen > HASH_MAX_MDSIZE) {
    return CRYPT_RSA_ERR_INPUT_VALUE;
}
```

---

### `args` may be uninitialized when process args are absent
`src/crypt_util_pkey.c:22-26`
```
BSL_Param *argsParam = BSL_PARAM_FindParam(params, CRYPT_PARAM_PKEY_PROCESS_ARGS);
if (argsParam != NULL) {
    GOTO_ERR_IF_EX(BSL_PARAM_GetPtrValue(argsParam, CRYPT_PARAM_PKEY_PROCESS_ARGS,
        BSL_PARAM_TYPE_CTX_PTR, args, NULL), ret);
}
```
**Issue**: If `CRYPT_PARAM_PKEY_PROCESS_ARGS` isn’t present, `*args` is never initialized and the callback may receive garbage.
**Fix**:
```
if (args != NULL) {
    *args = NULL;
}
BSL_Param *argsParam = BSL_PARAM_FindParam(params, CRYPT_PARAM_PKEY_PROCESS_ARGS);
if (argsParam != NULL) {
    GOTO_ERR_IF_EX(BSL_PARAM_GetPtrValue(argsParam, CRYPT_PARAM_PKEY_PROCESS_ARGS,
        BSL_PARAM_TYPE_CTX_PTR, args, NULL), ret);
}
```

---

### Private key access right not released on error
`src/rsa_sign.c:95-113`
```
ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}
ret = SDF_InternalPrivateKeyOperation_RSA(ctx->hSessionHandle, ctx->KeyIndex,
        pad, padLen, sign, signLen);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_InternalPrivateKeyOperation_RSA error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}
```
**Issue**: If `SDF_InternalPrivateKeyOperation_RSA` fails, the access right is not released, leaving the key in an acquired state.
**Fix**:
```
int accessGranted = 0;
/* ... */
ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}
accessGranted = 1;

ret = SDF_InternalPrivateKeyOperation_RSA(ctx->hSessionHandle, ctx->KeyIndex,
        pad, padLen, sign, signLen);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_InternalPrivateKeyOperation_RSA error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}

EXIT:
if (accessGranted) {
    int32_t rret = SDF_ReleasePrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex);
    if (rret != SDR_OK && ret == CRYPT_SUCCESS) {
        LOG_ERROR("SDF_ReleasePrivateKeyAccessRight error, ret = %08x", rret);
        ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    }
}
```

---

### Private key access right not released on error
`src/rsa_pkeycipher.c:134-154`
```
ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}
ret = SDF_InternalPrivateKeyOperation_RSA(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)data, dataLen, pad, &padLen);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_InternalPrivateKeyOperation_RSA error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}
```
**Issue**: If `SDF_InternalPrivateKeyOperation_RSA` fails, the access right isn’t released, which can leak privileges or lock the key.
**Fix**:
```
int accessGranted = 0;
/* ... */
ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}
accessGranted = 1;

ret = SDF_InternalPrivateKeyOperation_RSA(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)data, dataLen, pad, &padLen);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_InternalPrivateKeyOperation_RSA error, ret = %08x", ret);
    ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    goto EXIT;
}

EXIT:
if (accessGranted) {
    int32_t rret = SDF_ReleasePrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex);
    if (rret != SDR_OK && ret == CRYPT_SUCCESS) {
        LOG_ERROR("SDF_ReleasePrivateKeyAccessRight error, ret = %08x", rret);
        ret = CRYPT_RSA_ERR_INVALID_PRVKEY;
    }
}
```

---

### Private key access right not released on error
`src/sm2_sign.c:88-103`
```
ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
    return CRYPT_SM2_INVALID_PRVKEY;
}
ret = SDF_InternalSign_ECC(ctx->hSessionHandle, ctx->KeyIndex, tbs, tbsLen, &pucSignature);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_InternalSign_ECC error, ret = %08x", ret);
    return CRYPT_SM2_INVALID_PRVKEY;
}
```
**Issue**: On `SDF_InternalSign_ECC` failure, the access right is not released, leaving the key in an acquired state.
**Fix**:
```
int accessGranted = 0;
/* ... */
ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
    return CRYPT_SM2_INVALID_PRVKEY;
}
accessGranted = 1;

ret = SDF_InternalSign_ECC(ctx->hSessionHandle, ctx->KeyIndex, tbs, tbsLen, &pucSignature);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_InternalSign_ECC error, ret = %08x", ret);
    goto EXIT;
}

EXIT:
if (accessGranted) {
    (void)SDF_ReleasePrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex);
}
```

---

### Private key access right not released on error
`src/sm2_pkeycipher.c:153-169`
```
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
```
**Issue**: If `SDF_InternalDecrypt_ECC` fails, the access right is not released, which can leak privileges or lock the key.
**Fix**:
```
int accessGranted = 0;
/* ... */
ret = SDF_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex,
        (unsigned char *)DEFAULT_PASS, DEFAULT_PASS_LEN);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_GetPrivateKeyAccessRight error, ret = %08x", ret);
    return CRYPT_SM2_INVALID_PRVKEY;
}
accessGranted = 1;

ret = SDF_InternalDecrypt_ECC(ctx->hSessionHandle, ctx->KeyIndex, pucEncData, out, outlen);
if (ret != SDR_OK) {
    LOG_ERROR("SDF_InternalDecrypt_ECC error, ret = %08x", ret);
    ret = CRYPT_SM2_DECRYPT_FAIL;
    goto EXIT;
}

EXIT:
if (accessGranted) {
    (void)SDF_ReleasePrivateKeyAccessRight(ctx->hSessionHandle, ctx->KeyIndex);
}
```

---

### SM2 export uses too-small buffer for public key
`src/sm2_keymgmt.c:457-459`
```
uint32_t index = 0;
uint8_t prvkey[32] = {0};
uint8_t pubkey[32] = {0};
```
**Issue**: SM2 uncompressed public keys are 65 bytes, but the export buffer is only 32 bytes, causing `CRYPT_SM2_GetPubKeyEx` to fail.
**Fix**:
```
uint32_t index = 0;
uint8_t prvkey[32] = {0};
uint8_t pubkey[SM2_POINT_COORDINATE_LEN] = {0};
```

---

### RSA key check reports success without validation
`src/rsa_keymgmt.c:584-595`
```
case CRYPT_PKEY_CHECK_KEYPAIR:
    // TODO
    return CRYPT_SUCCESS;
case CRYPT_PKEY_CHECK_PRVKEY:
    // TODO
    return CRYPT_SUCCESS;
```
**Issue**: The check function returns success for keypair/private-key checks but does not actually validate anything, so invalid keys can be treated as valid.
**Fix**:
```
case CRYPT_PKEY_CHECK_KEYPAIR:
case CRYPT_PKEY_CHECK_PRVKEY:
    return CRYPT_NOT_SUPPORT; /* implement real checks before returning success */
```

---

### SM2 key check reports success without validation
`src/sm2_keymgmt.c:301-318`
```
case CRYPT_PKEY_CHECK_KEYPAIR:
    if (pkey1 == NULL || pkey2 == NULL) {
        return CRYPT_NULL_INPUT;
    }
    // TODO
    ret = CRYPT_SUCCESS;
    break;
case CRYPT_PKEY_CHECK_PRVKEY:
    if (pkey1 == NULL) {
        return CRYPT_NULL_INPUT;
    }
    // TODO
    ret = CRYPT_SUCCESS;
    break;
```
**Issue**: The check function returns success for keypair/private-key checks but does not validate the key material, allowing invalid keys to pass.
**Fix**:
```
case CRYPT_PKEY_CHECK_KEYPAIR:
case CRYPT_PKEY_CHECK_PRVKEY:
    return CRYPT_NOT_SUPPORT; /* implement real checks before returning success */
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
