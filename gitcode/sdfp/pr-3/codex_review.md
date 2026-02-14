# Code Review: openHiTLS/sdfp#3
**Reviewer**: CODEX


## High

### Agreement handle is cleared even when key generation fails
`src/sm2_keyexch.c:64-69`
```
ret = SDF_DL_GenerateKeyWithECC(selfCtx->hSessionHandle,
        (unsigned char *)peerCtx->userId, peerCtx->userIdLen,
        &sdfPeerPub, &sdfPeerTmpPub,
        selfCtx->hAgreementHandle, &hKeyHandle);
selfCtx->hAgreementHandle = NULL;  /* consumed */
if (ret != SDR_OK) {
    BSL_ERR_PUSH_ERROR(ret);
    return BSL_INTERNAL_EXCEPTION;
}
```
**Issue**: `hAgreementHandle` is nulled before checking `SDF_DL_GenerateKeyWithECC` return status. On failure, the context loses the live handle, which can break retries and leak device-side agreement state.
**Fix**:
```
ret = SDF_DL_GenerateKeyWithECC(selfCtx->hSessionHandle,
        (unsigned char *)peerCtx->userId, peerCtx->userIdLen,
        &sdfPeerPub, &sdfPeerTmpPub,
        selfCtx->hAgreementHandle, &hKeyHandle);
if (ret != SDR_OK) {
    BSL_ERR_PUSH_ERROR(ret);
    return BSL_INTERNAL_EXCEPTION;
}
selfCtx->hAgreementHandle = NULL;  /* consume only on success */
```

---


## Medium

### Uninitialized `ret` is read in error logging path
`src/sm2_sign.c:64-70`
```
int32_t ret;
...
if ((ctx == NULL) || (sign == NULL) || (signLen == NULL) || ((data == NULL) && (dataLen != 0))) {
    BSL_ERR_PUSH_ERROR(ret);
    return CRYPT_NULL_INPUT;
}
if (*signLen < CRYPT_SM2_GetSignLen_ex(ctx)) {
    BSL_ERR_PUSH_ERROR(ret);
    return CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
}
```
**Issue**: `ret` is declared but not initialized before being passed to `BSL_ERR_PUSH_ERROR`, which is undefined behavior in C and can push random error codes.
**Fix**:
```
int32_t ret = CRYPT_SUCCESS;
...
if ((ctx == NULL) || (sign == NULL) || (signLen == NULL) || ((data == NULL) && (dataLen != 0))) {
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return CRYPT_NULL_INPUT;
}
if (*signLen < CRYPT_SM2_GetSignLen_ex(ctx)) {
    BSL_ERR_PUSH_ERROR(CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);
    return CRYPT_SM2_BUFF_LEN_NOT_ENOUGH;
}
```

---

### Uninitialized `ret` used when pushing precondition errors
`src/sm2_keyexch.c:51-57`
```
if (selfCtx->hAgreementHandle == NULL) {
    BSL_ERR_PUSH_ERROR(ret);
    return CRYPT_SM2_NO_PRVKEY;
}
if (peerCtx->PublicKey == NULL || peerCtx->tmpPubKey == NULL) {
    BSL_ERR_PUSH_ERROR(ret);
    return CRYPT_SM2_NO_PUBKEY;
}
```
**Issue**: The function pushes `ret` before `ret` is assigned, causing undefined behavior and non-deterministic error reporting.
**Fix**:
```
if (selfCtx->hAgreementHandle == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_SM2_NO_PRVKEY);
    return CRYPT_SM2_NO_PRVKEY;
}
if (peerCtx->PublicKey == NULL || peerCtx->tmpPubKey == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_SM2_NO_PUBKEY);
    return CRYPT_SM2_NO_PUBKEY;
}
```

---

### Key handle leak on post-SDF allocation failure
`src/sm2_keyexch.c:101-114`
```
ret = SDF_DL_GenerateAgreementDataAndKeyWithECC(..., &hKeyHandle);
if (ret != SDR_OK) {
    BSL_ERR_PUSH_ERROR(ret);
    return BSL_INTERNAL_EXCEPTION;
}

/* Save self public key if not set */
if (selfCtx->PublicKey == NULL) {
    EccPubKey *pubKey = BSL_SAL_Calloc(1u, sizeof(EccPubKey));
    if (pubKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ...
}
EccPubKey *tmpKey = BSL_SAL_Calloc(1u, sizeof(EccPubKey));
if (tmpKey == NULL) {
    return CRYPT_MEM_ALLOC_FAIL;
}
```
**Issue**: The responder path creates `hKeyHandle` first, then allocates `pubKey/tmpKey`. If allocation fails, function returns without cleaning the generated key handle, leaking device resources.
**Fix**:
```
EccPubKey *pubKey = NULL;
EccPubKey *tmpKey = BSL_SAL_Calloc(1u, sizeof(EccPubKey));
if (tmpKey == NULL) {
    return CRYPT_MEM_ALLOC_FAIL;
}
if (selfCtx->PublicKey == NULL) {
    pubKey = BSL_SAL_Calloc(1u, sizeof(EccPubKey));
    if (pubKey == NULL) {
        BSL_SAL_Free(tmpKey);
        return CRYPT_MEM_ALLOC_FAIL;
    }
}

ret = SDF_DL_GenerateAgreementDataAndKeyWithECC(selfCtx->hSessionHandle,
        selfCtx->KeyIndex, 128,
        selfCtx->userId, selfCtx->userIdLen,
        (unsigned char *)peerCtx->userId, peerCtx->userIdLen,
        &sdfSponsorPub, &sdfSponsorTmpPub, &sdfSelfPub, &sdfSelfTmpPub, &hKeyHandle);
if (ret != SDR_OK) {
    BSL_SAL_Free(pubKey);
    BSL_SAL_Free(tmpKey);
    BSL_ERR_PUSH_ERROR(ret);
    return BSL_INTERNAL_EXCEPTION;
}
```

---

### Old key password is freed without zeroization
`src/rsa_keymgmt.c:1085-1089`
```
BSL_SAL_Free(*pass);
*pass = NULL;
*passLen = 0;
```
**Issue**: `SetKeyPass` frees previous password memory directly. This leaves prior secret bytes in heap memory and increases secret exposure risk.
**Fix**:
```
if (*pass != NULL && *passLen > 0) {
    (void)memset(*pass, 0, *passLen);
    BSL_SAL_Free(*pass);
}
*pass = NULL;
*passLen = 0;
```

---

### Old key password is freed without zeroization
`src/sm2_keymgmt.c:516-520`
```
BSL_SAL_Free(*pass);
*pass = NULL;
*passLen = 0;
```
**Issue**: `SetKeyPass` replaces password storage but does not scrub old password contents before free, leaving sensitive data recoverable from heap.
**Fix**:
```
if (*pass != NULL && *passLen > 0) {
    (void)memset(*pass, 0, *passLen);
    BSL_SAL_Free(*pass);
}
*pass = NULL;
*passLen = 0;
```

---
