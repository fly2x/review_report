# Code Review: openHiTLS/openhitls#1206
**Reviewer**: CODEX


## High

### Unchecked length arithmetic can under-allocate cipher buffers
`pki/cms/src/hitls_cms_envelopeddata.c:294-295`
```
uint32_t ciphertextLen = plaintext->dataLen + blockSize;
uint8_t *ciphertext = BSL_SAL_Malloc(ciphertextLen);

uint32_t maxPlaintextLen = encInfo->encryptedContent.dataLen + blockSize;
uint8_t *plaintextData = BSL_SAL_Malloc(maxPlaintextLen);

uint32_t newDataLen = input->dataLen + blockSize;
uint32_t totalLen = currentLen + newDataLen;
uint8_t *newBuf = BSL_SAL_Realloc(envData->encryptedContentInfo.encryptedContent.data, totalLen, currentLen);

uint32_t maxOutLen = input->dataLen + blockSize;
uint32_t totalOutLen = curOutLen + maxOutLen;

uint32_t newOutLen = curOutLen + accDataLen;
uint8_t *newBuf = BSL_SAL_Realloc(output->data, newOutLen, curOutLen);

uint32_t totalLen = currentLen + blockSize;
uint8_t *newBuf = BSL_SAL_Realloc(output->data, totalLen, currentLen);
```
**Issue**: Several new one-shot and streaming paths add attacker-controlled lengths in `uint32_t` and allocate with the wrapped result. If any `dataLen + blockSize` or `currentLen + ...` addition overflows, the subsequent `CRYPT_EAL_CipherUpdate`/`CRYPT_EAL_CipherFinal` call writes past the end of the heap buffer.
**Fix**:
```
/* Apply this pattern before every size addition in these paths. */
if (plaintext->dataLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
    return BSL_ASN1_ERR_LEN_OVERFLOW;
}
uint32_t ciphertextLen = plaintext->dataLen + blockSize;

if (input->dataLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
    return BSL_ASN1_ERR_LEN_OVERFLOW;
}
uint32_t newDataLen = input->dataLen + blockSize;
if (currentLen > UINT32_MAX - newDataLen) {
    BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
    return BSL_ASN1_ERR_LEN_OVERFLOW;
}
uint32_t totalLen = currentLen + newDataLen;

if (curOutLen > UINT32_MAX - accDataLen) {
    BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_LEN_OVERFLOW);
    return BSL_ASN1_ERR_LEN_OVERFLOW;
}
uint32_t newOutLen = curOutLen + accDataLen;
```

---


## Medium

### DecryptInit returns success after cipher setup failure
`pki/cms/src/hitls_cms_envelopeddata.c:2443-2450`
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
**Issue**: `SetDecryCtx` errors are ignored. On failure the code clears the CEK, but still marks the object as `HITLS_CMS_DECRYPT_INIT` and returns success. Callers therefore get a “successful” decrypt context with no key and no cipher state, and the original failure is lost.
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

### EnvelopedData generation accepts an empty RecipientInfos set
`pki/cms/src/hitls_cms_envelopeddata.c:564-576`
```
if ((cms->dataType != BSL_CID_PKCS7_ENVELOPEDDATA) || (plaintext == NULL && recipCerts == NULL)) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}

bool allVersion0 = true;
recip = BSL_LIST_GET_FIRST(envData->recipientInfos);
while (recip != NULL) {
    if (!(recip->type == CMS_RECIPIENT_TYPE_KTRI && recip->d.ktri != NULL && recip->d.ktri->version == 0)) {
        allVersion0 = false;
        break;
    }
    recip = BSL_LIST_GET_NEXT(envData->recipientInfos);
}
if (allVersion0) {
    envData->version = 0; // version 0
    return HITLS_PKI_SUCCESS;
}
```
**Issue**: RFC 5652 requires `RecipientInfos` to contain at least one recipient, but the new code never enforces that. Both one-shot and streaming encryption can succeed with zero recipients, and `GetEnvDataVersion` even treats the empty list as `allVersion0`, producing an invalid, undecryptable CMS object.
**Fix**:
```
if (envData->recipientInfos == NULL || BSL_LIST_COUNT(envData->recipientInfos) == 0) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}

/* Only version 0 when there is at least one recipient and all are KTRI v0. */
if (envData->originatorInfo == NULL && envData->unprotectedAttrs == NULL &&
    BSL_LIST_COUNT(envData->recipientInfos) > 0) {
    bool allVersion0 = true;
    for (CMS_RecipientInfo *recip = BSL_LIST_GET_FIRST(envData->recipientInfos);
         recip != NULL; recip = BSL_LIST_GET_NEXT(envData->recipientInfos)) {
        if (!(recip->type == CMS_RECIPIENT_TYPE_KTRI && recip->d.ktri != NULL && recip->d.ktri->version == 0)) {
            allVersion0 = false;
            break;
        }
    }
    if (allVersion0) {
        envData->version = 0;
        return HITLS_PKI_SUCCESS;
    }
}
```

---

### Final decrypt path trusts output parameter without validating its type
`pki/cms/src/hitls_cms_envelopeddata.c:2642-2648`
```
const BSL_Param *p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_BUFFER_DATA);
if (p == NULL || p->value == NULL) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
    return HITLS_CMS_ERR_NULL_POINTER;
}
BSL_Buffer *output = (BSL_Buffer *)p->value;
return EnvelopedData_DecryptFinal(cms, output);
```
**Issue**: Unlike the other parameter extractors in this file, this branch only checks `p->value != NULL` and then casts it to `BSL_Buffer *`. If the caller passes `CRYPT_PARAM_DECODE_BUFFER_DATA` with the wrong `valueType` or `valueLen`, `EnvelopedData_DecryptFinal` dereferences unrelated memory.
**Fix**:
```
const BSL_Param *p = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_DECODE_BUFFER_DATA);
if (p == NULL || p->value == NULL ||
    p->valueType != BSL_PARAM_TYPE_CTX_PTR || p->valueLen != sizeof(BSL_Buffer)) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
BSL_Buffer *output = (BSL_Buffer *)p->value;
return EnvelopedData_DecryptFinal(cms, output);
```

---
