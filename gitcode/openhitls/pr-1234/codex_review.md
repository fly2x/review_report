# Code Review: openHiTLS/openhitls#1234
**Reviewer**: CODEX


## High

### DecryptInit reports success after decryption context setup fails
`pki/cms/src/hitls_cms_envelopeddata.c:3413-3420`
```
ret = SetDecryCtx(envData);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_ClearFree(envData->streamKey, envData->streamKeyLen);
        envData->streamKey = NULL;
        envData->streamKeyLen = 0;
    }
    envData->state = HITLS_CMS_DECRYPT_INIT;
    return HITLS_PKI_SUCCESS;
```
**Issue**: `EnvelopedData_DecryptInit()` clears the CEK when `SetDecryCtx()` fails, but then still marks the object as initialized and returns success. Callers will continue with a half-initialized decrypt state and only fail later in `Update`/`Final`.
**Fix**:
```
ret = SetDecryCtx(envData);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_ClearFree(envData->streamKey, envData->streamKeyLen);
        envData->streamKey = NULL;
        envData->streamKeyLen = 0;
        return ret;
    }
    envData->state = HITLS_CMS_DECRYPT_INIT;
    return HITLS_PKI_SUCCESS;
```

---


## Medium

### Generator emits EnvelopedData with an empty RecipientInfos set
`pki/cms/src/hitls_cms_envelopeddata.c:2614-2619`
```
uint32_t count = (uint32_t)BSL_LIST_COUNT(list);
    if (count == 0) {
        encode->buff = NULL;
        encode->len = 0;
        encode->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET;
        return HITLS_PKI_SUCCESS;
    }
```
**Issue**: RFC 5652 requires `RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo`. This code returns success for `count == 0`, so one-shot and streaming encryption can generate an invalid CMS object that nobody can decrypt and that `ParseRecipientList()` rejects.
**Fix**:
```
uint32_t count = (uint32_t)BSL_LIST_COUNT(list);
    if (count == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
        return HITLS_CMS_ERR_INVALID_PARAM;
    }
```

---

### KEM KEK derivation ignores the CMS provider context
`pki/cms/src/hitls_cms_envelopeddata.c:881-883`
```
uint8_t *kek = NULL;
    ret = DeriveKek(kemri->libCtx, kemri->attrName, kemri, sharedSecret, sharedSecretLen, &kek);
    BSL_SAL_CleanseData(sharedSecret, sizeof(sharedSecret));
```
**Issue**: `EncryptCekForKemri()` derives the KEK from `kemri->libCtx` and `kemri->attrName`, but those runtime fields are never populated when KEM recipients are created or parsed. ML-KEM EnvelopedData therefore falls back to a NULL/default provider context and breaks non-default-provider flows.
**Fix**:
```
static void CMS_SetRecipientRuntimeCtx(CMS_RecipientInfo *recip, CMS_EnvelopedData *envData)
{
    if (recip->type == CMS_RECIPIENT_TYPE_KEMRI && recip->d.kemri != NULL) {
        recip->d.kemri->libCtx = envData->libCtx;
        recip->d.kemri->attrName = envData->attrName;
    }
}

/* Call this after creating or parsing each recipient. */
```

---

### Parser accepts IV-based content-encryption algorithms without parameters
`pki/cms/src/hitls_cms_envelopeddata.c:2018-2028`
```
if (asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].len > 0) {
        item->algParams = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
        if (item->algParams == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        item->algParams->data = asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].buff;
        item->algParams->dataLen = asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].len;
    } else {
        item->algParams = NULL;
    }
```
**Issue**: For algorithms such as AES-CBC, `AlgorithmIdentifier.parameters` carries the IV and is required. This branch silently accepts a missing parameter block and leaves `item->algParams = NULL`, so malformed input is only rejected later, or worse, is decrypted with a NULL/zero-length IV.
**Fix**:
```
uint32_t ivLen = 0;
    int32_t infoRet = CRYPT_EAL_CipherGetInfo((CRYPT_CIPHER_AlgId)cid, CRYPT_INFO_IV_LEN, &ivLen);
    bool needIv = (infoRet == CRYPT_SUCCESS && ivLen > 0);

    if (needIv) {
        if (asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].tag == BSL_ASN1_TAG_EMPTY ||
            asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].len != ivLen) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
            return HITLS_CMS_ERR_PARSE_TYPE;
        }
    }

    if (asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].tag != BSL_ASN1_TAG_EMPTY) {
        item->algParams = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
        if (item->algParams == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        item->algParams->data =
            asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].buff;
        item->algParams->dataLen =
            asnArr[HITLS_CMS_ENCRYCONTENTINFO_CONTENTENCRYALG_PARAM_IDX].len;
    }
```

---

### Decrypt final trusts CRYPT_PARAM_DECODE_BUFFER_DATA without type checking
`pki/cms/src/hitls_cms_envelopeddata.c:3612-3618`
```
const BSL_Param *p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_BUFFER_DATA);
        if (p == NULL || p->value == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
            return HITLS_CMS_ERR_NULL_POINTER;
        }
        BSL_Buffer *output = (BSL_Buffer *)p->value;
        return EnvelopedData_DecryptFinal(cms, output);
```
**Issue**: The decrypt-final path only checks that `p->value` is non-NULL and then casts it to `BSL_Buffer *`. A caller can pass the right key with the wrong `valueType` or `valueLen` and trigger an invalid cast and write into unrelated memory.
**Fix**:
```
const BSL_Param *p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_BUFFER_DATA);
        if (p == NULL || p->value == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
            return HITLS_CMS_ERR_NULL_POINTER;
        }
        if (p->valueType != BSL_PARAM_TYPE_CTX_PTR || p->valueLen != sizeof(BSL_Buffer)) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
            return HITLS_CMS_ERR_INVALID_PARAM;
        }
        BSL_Buffer *output = (BSL_Buffer *)p->value;
        return EnvelopedData_DecryptFinal(cms, output);
```

---

### EnvelopedData feature omits required crypto and X509 dependencies
`cmake/hitls_define_dependencies.cmake:583`
```
hitls_define_dependency(HITLS_PKI_CMS_ENVELOPEDDATA     DEPS HITLS_PKI_CMS HITLS_BSL_ASN1)
```
**Issue**: `hitls_cms_envelopeddata.c` now uses X509 cert/CRL parse/generate helpers, HKDF, cipher code, RSA key transport, and ML-KEM, but the feature dependency only enables `HITLS_PKI_CMS` and `HITLS_BSL_ASN1`. Feature combinations that turn on `HITLS_PKI_CMS_ENVELOPEDDATA` without those subfeatures can build into missing symbols or a nonfunctional binary.
**Fix**:
```
hitls_define_dependency(HITLS_PKI_CMS_ENVELOPEDDATA     DEPS HITLS_PKI_CMS HITLS_BSL_ASN1
    HITLS_PKI_X509_CRL_GEN HITLS_PKI_X509_CRL_PARSE
    HITLS_PKI_X509_CRT_GEN HITLS_PKI_X509_CRT_PARSE
    HITLS_CRYPTO_CIPHER HITLS_CRYPTO_AES HITLS_CRYPTO_HKDF
    HITLS_CRYPTO_RSA_ENCRYPT HITLS_CRYPTO_RSA_DECRYPT HITLS_CRYPTO_RSAES_PKCSV15
    HITLS_CRYPTO_MLKEM
)
```

---
