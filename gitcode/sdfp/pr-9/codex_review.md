# Code Review: openHiTLS/sdfp#9
**Reviewer**: CODEX


## High

### RSA support is silently disabled while RSA callbacks remain exposed
`src/common/sdf_dl.c:183-193`
```
/*
     * RSA internal key operations are loaded on demand when an internal RSA
     * key index is configured (not all SDF devices support them).
     */
    /* LOAD_SYM(genKeyPairRsa,           SDF_GenerateKeyPair_RSA); */
    /* LOAD_SYM(exportSignPubKeyRsa,     SDF_ExportSignPublicKey_RSA); */
    /* LOAD_SYM(exportEncPubKeyRsa,      SDF_ExportEncPublicKey_RSA); */
    /* LOAD_SYM(intPubKeyOpRsa,          SDF_InternalPublicKeyOperation_RSA); */
    /* LOAD_SYM(intPrivKeyOpRsa,         SDF_InternalPrivateKeyOperation_RSA); */
    /* LOAD_SYM(extPubKeyOpRsa,          SDF_ExternalPublicKeyOperation_RSA); */
    /* LOAD_SYM(extPrivKeyOpRsa,         SDF_ExternalPrivateKeyOperation_RSA); */
```
**Issue**: The loader no longer resolves any RSA symbols, but the provider still registers RSA keymgmt/sign/asymcipher callbacks. Every RSA path now reaches wrappers whose function pointers are still NULL and fails with `SDFP_ERR_NOT_LOADED` at runtime.
**Fix**:
```
LOAD_SYM(genKeyPairRsa,           SDF_GenerateKeyPair_RSA);
    LOAD_SYM(exportSignPubKeyRsa,     SDF_ExportSignPublicKey_RSA);
    LOAD_SYM(exportEncPubKeyRsa,      SDF_ExportEncPublicKey_RSA);
    LOAD_SYM(intPubKeyOpRsa,          SDF_InternalPublicKeyOperation_RSA);
    LOAD_SYM(intPrivKeyOpRsa,         SDF_InternalPrivateKeyOperation_RSA);
    LOAD_SYM(extPubKeyOpRsa,          SDF_ExternalPublicKeyOperation_RSA);
    LOAD_SYM(extPrivKeyOpRsa,         SDF_ExternalPrivateKeyOperation_RSA);
```

---

### SM4-GCM tag handling no longer matches the AEAD provider contract
`src/sm4/sm4_gcm.c:200-307`
```
if (ctx->enc) {
        unsigned int tagOutLen = SM4_GCM_TAG_MAX;
        ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
        if (ret == SDR_OK) {
            ctx->tagLen = tagOutLen;
            memcpy(out + tmpLen, ctx->tag, tagOutLen);
            tmpLen += tagOutLen;
        }
    } else {
        ret = SDF_DL_AuthDecFinal(ctx->hSessionHandle, out, &tmpLen);
    }

    ...

        case CRYPT_CTRL_GET_TAG:
            if (val == NULL || valLen == 0 || valLen > SM4_GCM_TAG_MAX || !ctx->enc) {
                return CRYPT_INVALID_ARG;
            }
            uint32_t copyLen = (valLen < ctx->tagLen) ? valLen : ctx->tagLen;
            memcpy(val, ctx->tag, copyLen);
            return CRYPT_SUCCESS;

        case 112:
            if (val == NULL || valLen == 0 || valLen > SM4_GCM_TAG_MAX) {
                return CRYPT_INVALID_ARG;
            }
            memcpy(ctx->tag, val, valLen);
            ctx->tagLen = valLen;
            return CRYPT_SUCCESS;
```
**Issue**: The implementation only computes/stores the authentication tag in `SDFP_SM4_GCM_Final()` and appends it to the ciphertext buffer there, while `CRYPT_CTRL_GET_TAG` merely copies `ctx->tag`. Any caller that uses the normal AEAD flow of `Update` followed by `GET_TAG` gets a zero/stale tag. Decryption is also tied to a provider-private `112` control instead of the public tag flow, so the provider is no longer drop-in compatible with generic AEAD callers.
**Fix**:
```
/* Add a finalized flag in SDFP_SM4_GCM_Ctx and finalize AEAD from GET_TAG. */
static int32_t SDFP_SM4_GCM_Final(void *c, uint8_t *out, uint32_t *outLen)
{
    (void)c;
    if (out == NULL || outLen == NULL) {
        return CRYPT_NULL_INPUT;
    }
    *outLen = 0; /* AEAD tag is returned via GET_TAG, not appended here */
    return CRYPT_SUCCESS;
}

case CRYPT_CTRL_SET_TAG:
    if (val == NULL || valLen == 0 || valLen > SM4_GCM_TAG_MAX) {
        return CRYPT_INVALID_ARG;
    }
    memcpy(ctx->tag, val, valLen);
    ctx->tagLen = valLen;
    return CRYPT_SUCCESS;

case CRYPT_CTRL_GET_TAG: {
    if (val == NULL || valLen == 0 || valLen > SM4_GCM_TAG_MAX) {
        return CRYPT_INVALID_ARG;
    }
    if (!ctx->started) {
        int32_t initRet = SDFP_SM4_GCM_SdfInit(ctx);
        if (initRet != CRYPT_SUCCESS) {
            return initRet;
        }
    }
    if (!ctx->finalized) {
        unsigned int lastLen = 0;
        unsigned int tagOutLen = ctx->tagLen;
        int ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, NULL, &lastLen, ctx->tag, &tagOutLen);
        if (ret != SDR_OK || lastLen != 0) {
            return SDFP_ERR_ENCRYPT;
        }
        ctx->tagLen = tagOutLen;
        ctx->finalized = true;
    }
    memcpy(val, ctx->tag, ctx->tagLen);
    return CRYPT_SUCCESS;
}
```

---


## Medium

### Provider unload tears down the process-global RNG even when it did not create it
`src/common/provider.c:95`
```
CRYPT_EAL_RandDeinit();

    ...

    ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES256_CTR, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        /* RNG may already be initialized by the application probe it */
        uint8_t probe[4];
        if (CRYPT_EAL_Randbytes(probe, sizeof(probe)) != CRYPT_SUCCESS) {
            BSL_SAL_Free(temp->sdfLibPath);
            BSL_SAL_Free(temp);
            SDF_DL_Unload();
            return SDFP_ERR_OPEN_DEVICE;
        }
    }
```
**Issue**: `ProviderInit` now explicitly tolerates `CRYPT_EAL_RandInit()` failing because some other component already initialized the global RNG, but `CRYPT_EAL_ProvFree()` always calls `CRYPT_EAL_RandDeinit()` anyway. Unloading the provider can therefore deinitialize RNG state that belongs to the application or another provider instance.
**Fix**:
```
/* Add a bool ownsRand to CRYPT_EAL_ProvCtx and only deinit when we created it. */
ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES256_CTR, NULL, NULL, NULL, 0);
if (ret == CRYPT_SUCCESS) {
    temp->ownsRand = true;
} else {
    uint8_t probe[4];
    if (CRYPT_EAL_Randbytes(probe, sizeof(probe)) != CRYPT_SUCCESS) {
        BSL_SAL_Free(temp->sdfLibPath);
        BSL_SAL_Free(temp);
        SDF_DL_Unload();
        return SDFP_ERR_OPEN_DEVICE;
    }
}

...

if (ctx->ownsRand) {
    CRYPT_EAL_RandDeinit();
}
```

---

### SM2 signing no longer works for imported internal key indices
`src/sm2/sm2_sign.c:151-157`
```
if (ctx->privateKey == NULL) {
        return CRYPT_SM2_NO_PRVKEY;
    }
    ECCrefPrivateKey sdfPrv = {0};
    EccPrvKeyToSdf(ctx->privateKey, &sdfPrv);
    ret = SDF_DL_ExternalSign_ECC(ctx->hSessionHandle, SGD_SM2_1, &sdfPrv,
            (unsigned char *)data, dataLen, &pucSignature);

    ...

    if (ctx->privateKey == NULL) {
        return CRYPT_SM2_NO_PRVKEY;
    }
```
**Issue**: The refactor removed the `keyIndex` path from signing and now hard-requires an external private key object. That breaks contexts imported through `CRYPT_CTRL_KEY_INDEX`, even though `sm2_keymgmt.c` still accepts and exports those internal-key parameters.
**Fix**:
```
if (ctx->keyIndex >= 0) {
        ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
            ctx->pass != NULL ? ctx->pass : (unsigned char *)DEFAULT_PASS,
            ctx->pass != NULL ? ctx->passLen : DEFAULT_PASS_LEN);
        if (ret != SDR_OK) {
            return SDFP_ERR_GET_PRIV_ACCESS;
        }
        ret = SDF_DL_InternalSign_ECC(ctx->hSessionHandle, ctx->keyIndex,
            (unsigned char *)data, dataLen, &pucSignature);
        (void)SDF_DL_ReleasePrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex);
        if (ret != SDR_OK) {
            return SDFP_ERR_SIGN;
        }
    } else {
        if (ctx->privateKey == NULL) {
            return CRYPT_SM2_NO_PRVKEY;
        }
        ECCrefPrivateKey sdfPrv = {0};
        EccPrvKeyToSdf(ctx->privateKey, &sdfPrv);
        ret = SDF_DL_ExternalSign_ECC(ctx->hSessionHandle, SGD_SM2_1, &sdfPrv,
            (unsigned char *)data, dataLen, &pucSignature);
        (void)memset(&sdfPrv, 0, sizeof(sdfPrv));
        if (ret != SDR_OK) {
            return SDFP_ERR_SIGN;
        }
    }
```

---

### Private-key-only signing now produces a non-standard SM2 hash
`src/sm2/sm2_sign.c:235-253`
```
} else {
        /* For external keys without public key, we can't compute Z = SM3(ID || PubKey).
         * Use simple SM3 hash of message instead. This is compatible with the SDF
         * library's ExternalSign_ECC which expects a pre-computed 32-byte hash. */
        ret = SDF_DL_HashInit(ctx->hSessionHandle, SGD_SM3, NULL, ctx->userId, ctx->userIdLen);
        if (ret != SDR_OK) {
            SDFP_LOG(ret);
            return SDFP_ERR_HASH;
        }
        ret = SDF_DL_HashUpdate(ctx->hSessionHandle, (unsigned char *)data, dataLen);
        if (ret != SDR_OK) {
            SDFP_LOG(ret);
            return SDFP_ERR_HASH;
        }
        ret = SDF_DL_HashFinal(ctx->hSessionHandle, tbs, &tbsLen);
        if (ret != SDR_OK) {
            SDFP_LOG(ret);
            return SDFP_ERR_HASH;
        }
    }
```
**Issue**: When no public key is present, the new fallback signs `SM3(msg)` instead of the SM2-required `SM3(Z || msg)`. That silently produces signatures that a compliant SM2 verifier will reject, instead of returning the previous `CRYPT_SM2_NO_PUBKEY` error or deriving the public key first.
**Fix**:
```
if (ctx->publicKey == NULL) {
        return CRYPT_SM2_NO_PUBKEY;
    }

    ret = Sm2ComputeMsgHash(ctx, ctx->publicKey, data, dataLen, tbs, &tbsLen);
    if (ret != CRYPT_SUCCESS) {
        SDFP_LOG(ret);
        return ret;
    }
```

---
