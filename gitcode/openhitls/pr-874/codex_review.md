# Code Review: openHiTLS/openhitls#874
**Reviewer**: CODEX


## Medium

### ECDSA public key length derived from bits causes under-allocation
`crypto/composite/src/composite_encdec.c:292-299`
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
pubLen = BITS_TO_BYTES(pubLen);
uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
...
BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
```
**Issue**: `CRYPT_CTRL_GET_BITS` returns curve size (e.g., 256/384), not the encoded public key size (e.g., 65/97 bytes for uncompressed). Converting bits to bytes under-allocates the buffer and makes `getPub` fail or truncate, breaking composite public key encoding.
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


## Low

### Ed25519 public key length lookup ignores error return
`crypto/composite/src/composite_encdec.c:330-335`
```
uint32_t pubLen = 0;
ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen));
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```
**Issue**: The return value of `ctrl` is ignored. If the control call fails, the function returns `CRYPT_EAL_ALG_NOT_SUPPORT`, masking real errors and making debugging and error handling incorrect.
**Fix**:
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```

---

### Preprocessor condition loses HITLS_CRYPTO_PROVIDER gating
`crypto/provider/src/default/crypt_default_keymgmt.c:16-22`
```
#if (defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_X25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_ECDH) || defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_PAILLIER) || \
    defined(HITLS_CRYPTO_ELGAMAL) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLKEM) || \
    defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_COMPOSITE) || defined(HITLS_CRYPTO_HYBRIDKEM)) && \
    defined(HITLS_CRYPTO_PROVIDER) || defined(HITLS_CRYPTO_CLASSIC_MCELIECE) || defined(HITLS_CRYPTO_FRODOKEM)
```
**Issue**: Missing parentheses change precedence so the file is compiled when `HITLS_CRYPTO_CLASSIC_MCELIECE` or `HITLS_CRYPTO_FRODOKEM` are set even if `HITLS_CRYPTO_PROVIDER` is not defined, causing unintended compilation and potential build failures.
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
