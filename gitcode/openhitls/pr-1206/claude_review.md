# Code Review: openHiTLS/openhitls#1206
**Reviewer**: CLAUDE


## High

### Integer overflow in ciphertext length calculation
`pki/cms/src/hitls_cms_envelopeddata.c:294`
```
uint32_t ciphertextLen = plaintext->dataLen + blockSize;
uint8_t *ciphertext = BSL_SAL_Malloc(ciphertextLen);
```
**Issue**: uint32_t ciphertextLen = plaintext->dataLen + blockSize; can overflow if plaintext->dataLen is close to UINT32_MAX, leading to buffer under-allocation and potential heap overflow.
**Fix**:
```
if (blockSize > UINT32_MAX - plaintext->dataLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t ciphertextLen = plaintext->dataLen + blockSize;
uint8_t *ciphertext = BSL_SAL_Malloc(ciphertextLen);
```

---

### Integer overflow in plaintext length calculation
`pki/cms/src/hitls_cms_envelopeddata.c:776`
```
uint32_t maxPlaintextLen = encInfo->encryptedContent.dataLen + blockSize;
uint8_t *plaintextData = BSL_SAL_Malloc(maxPlaintextLen);
```
**Issue**: uint32_t maxPlaintextLen = encInfo->encryptedContent.dataLen + blockSize; can overflow, leading to buffer under-allocation and potential heap overflow during decryption.
**Fix**:
```
if (blockSize > UINT32_MAX - encInfo->encryptedContent.dataLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t maxPlaintextLen = encInfo->encryptedContent.dataLen + blockSize;
uint8_t *plaintextData = BSL_SAL_Malloc(maxPlaintextLen);
```

---

### Integer overflow in streaming encrypt update buffer allocation
`pki/cms/src/hitls_cms_envelopeddata.c:2233-2234`
```
uint32_t newDataLen = input->dataLen + blockSize;
uint32_t totalLen = currentLen + newDataLen;
uint8_t *newBuf = BSL_SAL_Realloc(envData->encryptedContentInfo.encryptedContent.data, totalLen, currentLen);
```
**Issue**: Multiple unchecked additions that can overflow: uint32_t newDataLen = input->dataLen + blockSize; uint32_t totalLen = currentLen + newDataLen;
**Fix**:
```
if (blockSize > UINT32_MAX - input->dataLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t newDataLen = input->dataLen + blockSize;
if (newDataLen > UINT32_MAX - currentLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t totalLen = currentLen + newDataLen;
```

---

### Integer overflow in streaming decrypt update buffer allocation
`pki/cms/src/hitls_cms_envelopeddata.c:2483-2484`
```
uint32_t maxOutLen = input->dataLen + blockSize;
uint32_t totalOutLen = curOutLen + maxOutLen;
```
**Issue**: Multiple unchecked additions that can overflow: uint32_t maxOutLen = input->dataLen + blockSize; uint32_t totalOutLen = curOutLen + maxOutLen;
**Fix**:
```
if (blockSize > UINT32_MAX - input->dataLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t maxOutLen = input->dataLen + blockSize;
if (maxOutLen > UINT32_MAX - curOutLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t totalOutLen = curOutLen + maxOutLen;
```

---

### Integer overflow in FinalizeEncry buffer reallocation
`pki/cms/src/hitls_cms_envelopeddata.c:2268`
```
uint32_t totalLen = currentLen + blockSize;
uint8_t *newBuf = BSL_SAL_Realloc(envData->encryptedContentInfo.encryptedContent.data, totalLen, currentLen);
```
**Issue**: uint32_t totalLen = currentLen + blockSize; can overflow, leading to heap corruption.
**Fix**:
```
if (blockSize > UINT32_MAX - currentLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t totalLen = currentLen + blockSize;
```

---

### Integer overflow in DecryptFinal buffer reallocation
`pki/cms/src/hitls_cms_envelopeddata.c:2568`
```
uint32_t totalLen = currentLen + blockSize;
uint8_t *newBuf = BSL_SAL_Realloc(output->data, totalLen, currentLen);
```
**Issue**: uint32_t totalLen = currentLen + blockSize; can overflow, leading to heap corruption.
**Fix**:
```
if (blockSize > UINT32_MAX - currentLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t totalLen = currentLen + blockSize;
```

---

### Integer overflow in TransferAccumulatedData buffer reallocation
`pki/cms/src/hitls_cms_envelopeddata.c:2512`
```
uint32_t newOutLen = curOutLen + accDataLen;
uint8_t *newBuf = BSL_SAL_Realloc(output->data, newOutLen, curOutLen);
```
**Issue**: uint32_t newOutLen = curOutLen + accDataLen; can overflow, leading to heap corruption.
**Fix**:
```
if (accDataLen > UINT32_MAX - curOutLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_PARAM);
    return HITLS_CMS_ERR_INVALID_PARAM;
}
uint32_t newOutLen = curOutLen + accDataLen;
```

---


## Medium

### Potential null pointer dereference in BufferEquals
`pki/cms/src/hitls_cms_envelopeddata.c:631-640`
```
static bool BufferEquals(const BSL_Buffer *a, const BSL_Buffer *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->dataLen != b->dataLen) {
        return false;
    }
    return memcmp(a->data, b->data, a->dataLen) == 0;
}
```
**Issue**: The function checks if struct pointers a and b are NULL, but not if a->data or b->data are NULL before calling memcmp. memcmp with NULL pointers is undefined behavior.
**Fix**:
```
static bool BufferEquals(const BSL_Buffer *a, const BSL_Buffer *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->dataLen != b->dataLen) {
        return false;
    }
    if (a->data == NULL || b->data == NULL) {
        return a->dataLen == 0;
    }
    return memcmp(a->data, b->data, a->dataLen) == 0;
}
```

---

### Potential null pointer dereference in MatchRecipientIdByData
`pki/cms/src/hitls_cms_envelopeddata.c:669-677`
```
BSL_Buffer certSerial = {0};
ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &certSerial, sizeof(BSL_Buffer));
if (ret != HITLS_PKI_SUCCESS) {
    return false;
}
return BufferEquals(serialNumber, &certSerial);
```
**Issue**: The function calls BufferEquals with pointers whose data fields may be NULL if HITLS_X509_CertCtrl fails or returns data with NULL pointers.
**Fix**:
```
BSL_Buffer certSerial = {0};
ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SERIALNUM, &certSerial, sizeof(BSL_Buffer));
if (ret != HITLS_PKI_SUCCESS) {
    return false;
}
if (certSerial.data == NULL) {
    return false;
}
return BufferEquals(serialNumber, &certSerial);
```

---
