# Code Review: openHiTLS/openhitls#1206
**Reviewer**: GEMINI


## High

### Masked error in EnvelopedData_DecryptInit allows invalid state
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
**Issue**: If SetDecryCtx fails during stream decryption initialization, the error code is saved in `ret` and streamKey is freed, but the function ignores the failure and proceeds to transition the context state to HITLS_CMS_DECRYPT_INIT and unconditionally returns HITLS_PKI_SUCCESS. This will lead to subsequent updates failing on an uninitialized cipher context and potential null pointer dereferences or crashes when relying on stream decryption.
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
