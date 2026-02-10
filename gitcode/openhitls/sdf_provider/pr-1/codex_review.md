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
