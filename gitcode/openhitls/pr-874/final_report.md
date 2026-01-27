# Final Code Review Report
## openHiTLS/openhitls - PR #874

### Summary
- **Total Issues**: 11
- **Critical**: 0
- **High**: 1
- **Medium**: 5
- **Low**: 5
- **Reviewers**: claude, gemini, codex

---


## High

### ECDSA public key buffer sized from curve bits, not encoded key length
`crypto/composite/src/composite_encdec.c:292-308`
**Reviewers**: CODEX | **置信度**: 较可信
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
pubLen = BITS_TO_BYTES(pubLen);
uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
...
ret = ctx->tradMethod->getPub(ctx->tradCtx, &param);
```
**Issue**: `CRYPT_CompositeGetEcdsaPubKey` queries `CRYPT_CTRL_GET_BITS` and converts bits to bytes, which yields the curve size (e.g., 32 for P-256) instead of the encoded public key length (e.g., 65 bytes for uncompressed). This under-allocates the buffer, causing `getPub` to fail or truncate, breaking composite ECDSA public key encoding.
**Fix**:
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
RETURN_RET_IF(pub == NULL, CRYPT_MEM_ALLOC_FAIL);
BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
ret = ctx->tradMethod->getPub(ctx->tradCtx, &param);
if (ret != CRYPT_SUCCESS) {
    BSL_SAL_FREE(pub);
    return ret;
}
encode->data = pub;
encode->dataLen = param[0].useLen;
```

---


## Medium

### Provider gating lost due to operator precedence in #if
`crypto/provider/src/default/crypt_default_keymgmt.c:17-22`
**Reviewers**: CODEX | **置信度**: 较可信
```
#if (defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_X25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_ECDH) || defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_PAILLIER) || \
    defined(HITLS_CRYPTO_ELGAMAL) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLKEM) || \
    defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_COMPOSITE) || defined(HITLS_CRYPTO_HYBRIDKEM)) && \
    defined(HITLS_CRYPTO_PROVIDER) || defined(HITLS_CRYPTO_CLASSIC_MCELIECE) || defined(HITLS_CRYPTO_FRODOKEM)
```
**Issue**: `&& defined(HITLS_CRYPTO_PROVIDER)` only applies to the first group; `HITLS_CRYPTO_CLASSIC_MCELIECE` or `HITLS_CRYPTO_FRODOKEM` will include this file even when `HITLS_CRYPTO_PROVIDER` is not set, leading to unintended compilation and potential build failures.
**Fix**:
```
#if (defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_X25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_ECDH) || defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_PAILLIER) || \
    defined(HITLS_CRYPTO_ELGAMAL) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLKEM) || \
    defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_COMPOSITE) || defined(HITLS_CRYPTO_HYBRIDKEM) || \
    defined(HITLS_CRYPTO_CLASSIC_MCELIECE) || defined(HITLS_CRYPTO_FRODOKEM)) && \
    defined(HITLS_CRYPTO_PROVIDER)
```

---

### CRYPT_CompositeSetAlgInfo overwrites contexts without freeing existing ones
`crypto/composite/src/composite.c:249-252`
**Reviewers**: GEMINI | **置信度**: 较可信
```
ctx->pqcMethod = pqcMethod;
ctx->tradMethod = tradMethod;
ctx->pqcCtx = pqcMethod->newCtx();
RETURN_RET_IF((ctx->pqcCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
ctx->tradCtx = tradMethod->newCtx();
```
**Issue**: When `CRYPT_CompositeSetAlgInfo` is called multiple times, it allocates new `pqcCtx`/`tradCtx` without freeing any existing contexts, leaking the previous allocations.
**Fix**:
```
if (ctx->pqcCtx != NULL && ctx->pqcMethod != NULL && ctx->pqcMethod->freeCtx != NULL) {
    ctx->pqcMethod->freeCtx(ctx->pqcCtx);
}
if (ctx->tradCtx != NULL && ctx->tradMethod != NULL && ctx->tradMethod->freeCtx != NULL) {
    ctx->tradMethod->freeCtx(ctx->tradCtx);
}
ctx->pqcCtx = NULL;
ctx->tradCtx = NULL;

ctx->pqcMethod = pqcMethod;
ctx->tradMethod = tradMethod;
ctx->pqcCtx = pqcMethod->newCtx();
RETURN_RET_IF(ctx->pqcCtx == NULL, CRYPT_MEM_ALLOC_FAIL);
ctx->tradCtx = tradMethod->newCtx();
```

---

### CRYPT_CompositeSetAlgInfo leaves ctx->info set on allocation failure
`crypto/composite/src/composite.c:251-258`
**Reviewers**: GEMINI | **置信度**: 较可信
```
ctx->tradCtx = tradMethod->newCtx();
if (ctx->tradCtx == NULL) {
    pqcMethod->freeCtx(ctx->pqcCtx);
    ctx->pqcCtx = NULL;
    return CRYPT_MEM_ALLOC_FAIL;
}
```
**Issue**: If `tradMethod->newCtx()` fails, the function returns `CRYPT_MEM_ALLOC_FAIL` after freeing only `pqcCtx`, but leaves `ctx->info`, `ctx->pqcMethod`, and `ctx->tradMethod` set. This leaves a partially initialized context that can later be misused (e.g., `CRYPT_COMPOSITE_SetPrvKey` will proceed with `info` set but `pqcCtx`/`tradCtx` NULL).
**Fix**:
```
ctx->tradCtx = tradMethod->newCtx();
if (ctx->tradCtx == NULL) {
    ret = CRYPT_MEM_ALLOC_FAIL;
    goto ERR;
}
/* ... */
ERR:
if (ctx->pqcCtx != NULL) { pqcMethod->freeCtx(ctx->pqcCtx); }
if (ctx->tradCtx != NULL) { tradMethod->freeCtx(ctx->tradCtx); }
ctx->pqcCtx = NULL;
ctx->tradCtx = NULL;
ctx->info = NULL;
ctx->pqcMethod = NULL;
ctx->tradMethod = NULL;
return ret;
```

---

### DupCtx leaks duplicated sub-context when one dupCtx fails
`crypto/composite/src/composite.c:162-176`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
    newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
    newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
    if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
}
```
**Issue**: `CRYPT_COMPOSITE_DupCtx` calls both `dupCtx` functions before checking results. If one succeeds and the other fails, `goto ERR` calls `CRYPT_COMPOSITE_FreeCtx(newCtx)` while `newCtx->pqcMethod`/`tradMethod` are still NULL, so the successfully duplicated sub-context is not freed.
**Fix**:
```
newCtx->pqcMethod = ctx->pqcMethod;
newCtx->tradMethod = ctx->tradMethod;
if (newCtx->pqcMethod != NULL && newCtx->tradMethod != NULL) {
    newCtx->pqcCtx = newCtx->pqcMethod->dupCtx(ctx->pqcCtx);
    if (newCtx->pqcCtx == NULL) { BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL); goto ERR; }
    newCtx->tradCtx = newCtx->tradMethod->dupCtx(ctx->tradCtx);
    if (newCtx->tradCtx == NULL) { BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL); goto ERR; }
}
```

---

### SetPrvKey/SetPubKey accept oversized composite keys without validation
`crypto/composite/src/composite.c:432-456`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
ctx->prvKey = (uint8_t *)BSL_SAL_Malloc(prv->len);
...
RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
ctx->pubKey = (uint8_t *)BSL_SAL_Malloc(pub->len);
```
**Issue**: `CRYPT_COMPOSITE_SetPrvKey` and `CRYPT_COMPOSITE_SetPubKey` only check that input length is larger than the PQC portion, but do not cap the total length. Oversized buffers are accepted and passed to the traditional key setters with a length larger than expected, allowing malformed input and potential downstream failures.
**Fix**:
```
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
RETURN_RET_IF(prv->len > ctx->info->pqcPrvkeyLen + ctx->info->tradPrvkeyLen,
              CRYPT_COMPOSITE_KEYLEN_ERROR);

RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
RETURN_RET_IF(pub->len > ctx->info->pqcPubkeyLen + ctx->info->tradPubkeyLen,
              CRYPT_COMPOSITE_KEYLEN_ERROR);
```

---


## Low

### Potential overflow when summing component key lengths
`crypto/composite/src/composite.c:386-388`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
ctx->prvLen = pqcPrv.dataLen + tradPrv.dataLen;
ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
RETURN_RET_IF_ERR(CRYPT_CompositeCreateKeyBuf(ctx), ret);
```
**Issue**: `ctx->prvLen` and `ctx->pubLen` are computed by adding two lengths without overflow checks. If the inputs are malformed or unexpectedly large, the addition can wrap and lead to undersized allocations and memory corruption.
**Fix**:
```
if (pqcPrv.dataLen > UINT32_MAX - tradPrv.dataLen ||
    pqcPub.dataLen > UINT32_MAX - tradPub.dataLen) {
    ret = CRYPT_COMPOSITE_KEYLEN_ERROR;
    goto ERR;
}
ctx->prvLen = pqcPrv.dataLen + tradPrv.dataLen;
ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
```

---

### memcpy_s return values ignored when assembling composite key material
`crypto/composite/src/composite.c:390-393`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
(void)memcpy_s(ctx->prvKey, ctx->prvLen, pqcPrv.data, pqcPrv.dataLen);
(void)memcpy_s(ctx->prvKey + pqcPrv.dataLen, ctx->prvLen - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
(void)memcpy_s(ctx->pubKey, ctx->pubLen, pqcPub.data, pqcPub.dataLen);
(void)memcpy_s(ctx->pubKey + pqcPub.dataLen, ctx->pubLen - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
```
**Issue**: The `memcpy_s` return values are discarded in `CRYPT_COMPOSITE_GenKey`. If any copy fails, the function continues with partially copied key material.
**Fix**:
```
ret = memcpy_s(ctx->prvKey, ctx->prvLen, pqcPrv.data, pqcPrv.dataLen);
GOTO_ERR_IF(ret != EOK, ret);
ret = memcpy_s(ctx->prvKey + pqcPrv.dataLen, ctx->prvLen - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
GOTO_ERR_IF(ret != EOK, ret);
ret = memcpy_s(ctx->pubKey, ctx->pubLen, pqcPub.data, pqcPub.dataLen);
GOTO_ERR_IF(ret != EOK, ret);
ret = memcpy_s(ctx->pubKey + pqcPub.dataLen, ctx->pubLen - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
GOTO_ERR_IF(ret != EOK, ret);
```

---

### Ed25519 public key length control call return ignored
`crypto/composite/src/composite_encdec.c:330-335`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
uint32_t pubLen = 0;
ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen));
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```
**Issue**: `CRYPT_CompositeGetEd25519PubKey` ignores the return value from `ctrl`, so an error is silently masked and treated as “not supported,” complicating debugging and error handling.
**Fix**:
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```

---

### Passing pointer-to-array instead of element pointer to setPrv/setPub
`crypto/composite/src/composite_encdec.c:439-441`
**Reviewers**: GEMINI | **置信度**: 较可信
```
RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, &rsaParam), ret);
RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &rsaParam), ret);
...
RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &rsaParam), ret);
```
**Issue**: `&rsaParam` is a pointer to an array (`BSL_Param (*)[N]`), not a `BSL_Param *`. This is a type mismatch and may compile with warnings or lead to incorrect pointer arithmetic in the callee.
**Fix**:
```
RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, rsaParam), ret);
RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, rsaParam), ret);
```

---

### Missing error push on allocation failure in ParsePkcs8key
`crypto/codecskey/src/crypt_decoder_composite.c:82-85`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
if (pctx == NULL) {
    return CRYPT_MEM_ALLOC_FAIL;
}
```
**Issue**: When `CRYPT_COMPOSITE_NewCtxEx` fails, the function returns `CRYPT_MEM_ALLOC_FAIL` without pushing the error code, unlike other error paths.
**Fix**:
```
CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
if (pctx == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
    return CRYPT_MEM_ALLOC_FAIL;
}
```

---
