# Code Review: openHiTLS/openhitls#1234
**Reviewer**: GEMINI


## High

### Memory leak on reallocation failure in EnvelopedData_DecryptUpdate
`pki/cms/src/hitls_cms_envelopeddata.c:3455-3461`
```
if (output->data == NULL) {
        output->data = BSL_SAL_Malloc(totalOutLen);
    } else {
        output->data = BSL_SAL_Realloc(output->data, totalOutLen, curOutLen);
    }
    if (output->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
```
**Issue**: When updating the decryption state, `output->data` is passed directly to `BSL_SAL_Realloc` and the result is assigned back to `output->data`. If the reallocation fails (returns `NULL`), the original `output->data` is overwritten with `NULL` without freeing it, leading to a memory leak of the previously accumulated decrypted data.
**Fix**:
```
uint8_t *newBuf;
    if (output->data == NULL) {
        newBuf = BSL_SAL_Malloc(totalOutLen);
    } else {
        newBuf = BSL_SAL_Realloc(output->data, totalOutLen, curOutLen);
    }
    if (newBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
```

---
