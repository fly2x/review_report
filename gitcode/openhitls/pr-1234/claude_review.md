# Code Review: openHiTLS/openhitls#1234
**Reviewer**: CLAUDE


## High

### Integer overflow in DecryptContentCore allocation
`pki/cms/src/hitls_cms_envelopeddata.c:1265`
```
uint32_t maxPlaintextLen = encInfo->encryptedContent.dataLen + blockSize;
uint8_t *plaintextData = BSL_SAL_Malloc(maxPlaintextLen);
```
**Issue**: When decrypting CMS EnvelopedData, the code adds blockSize to encryptedContent.dataLen without checking for overflow. An attacker could craft a CMS message with encryptedContent.dataLen close to UINT32_MAX, causing integer overflow and allocating a buffer that is too small, leading to heap buffer overflow during decryption.
**Fix**:
```
if (encInfo->encryptedContent.dataLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t maxPlaintextLen = encInfo->encryptedContent.dataLen + blockSize;
uint8_t *plaintextData = BSL_SAL_Malloc(maxPlaintextLen);
```

---

### Integer overflow in EnvelopedData_DecryptUpdate
`pki/cms/src/hitls_cms_envelopeddata.c:3454-3455`
```
uint32_t maxOutLen = input->dataLen + blockSize;
uint32_t totalOutLen = curOutLen + maxOutLen;
```
**Issue**: The code adds blockSize to input->dataLen and then adds curOutLen without checking for overflow. An attacker could provide large input data sizes to cause integer overflow, leading to undersized buffer allocation and heap overflow.
**Fix**:
```
if (input->dataLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t maxOutLen = input->dataLen + blockSize;
if (curOutLen > UINT32_MAX - maxOutLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t totalOutLen = curOutLen + maxOutLen;
```

---

### Integer overflow in TransferAccumulatedData
`pki/cms/src/hitls_cms_envelopeddata.c:3482`
```
uint32_t newOutLen = curOutLen + accDataLen;
```
**Issue**: The code adds curOutLen and accDataLen without checking for overflow, which could lead to undersized buffer allocation.
**Fix**:
```
if (curOutLen > UINT32_MAX - accDataLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t newOutLen = curOutLen + accDataLen;
```

---


## Medium

### Integer overflow in EnvelopedData_EncryptUpdate
`pki/cms/src/hitls_cms_envelopeddata.c:3204-3205`
```
uint32_t newDataLen = input->dataLen + blockSize;
uint32_t totalLen = currentLen + newDataLen;
```
**Issue**: The code adds blockSize to input->dataLen and then adds currentLen without checking for overflow. While this is in the encryption path (not parsing), it could still cause issues with very large inputs.
**Fix**:
```
if (input->dataLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t newDataLen = input->dataLen + blockSize;
if (currentLen > UINT32_MAX - newDataLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t totalLen = currentLen + newDataLen;
```

---

### Integer overflow in EncryptContentCore
`pki/cms/src/hitls_cms_envelopeddata.c:347`
```
uint32_t ciphertextLen = plaintext->dataLen + blockSize;
```
**Issue**: The code adds blockSize to plaintext->dataLen without checking for overflow. While this is in the encryption path, it could cause issues with very large plaintext inputs.
**Fix**:
```
if (plaintext->dataLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t ciphertextLen = plaintext->dataLen + blockSize;
```

---

### Potential buffer underflow in ParseRecipientList
`pki/cms/src/hitls_cms_envelopeddata.c:1947-1948`
```
buff += valueLen;
buffLen -= valueLen;
```
**Issue**: The code subtracts valueLen from buffLen without verifying that valueLen <= buffLen. If BSL_ASN1_DecodeLen returns a valid valueLen but valueLen > buffLen, this would cause unsigned integer underflow.
**Fix**:
```
if (valueLen > buffLen) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
buff += valueLen;
buffLen -= valueLen;
```

---


## Low

### Integer overflow in FinalizeEncry
`pki/cms/src/hitls_cms_envelopeddata.c:3238`
```
uint32_t totalLen = currentLen + blockSize;
```
**Issue**: The code adds blockSize to currentLen without checking for overflow.
**Fix**:
```
if (currentLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t totalLen = currentLen + blockSize;
```

---

### Integer overflow in EnvelopedData_DecryptFinal
`pki/cms/src/hitls_cms_envelopeddata.c:3538`
```
uint32_t totalLen = currentLen + blockSize;
```
**Issue**: The code adds blockSize to currentLen without checking for overflow.
**Fix**:
```
if (currentLen > UINT32_MAX - blockSize) {
    BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
    return HITLS_CMS_ERR_INVALID_DATA;
}
uint32_t totalLen = currentLen + blockSize;
```

---
