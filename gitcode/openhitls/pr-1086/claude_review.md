# Code Review: openHiTLS/openhitls#1086
**Reviewer**: CLAUDE


## High

### Incorrect offset increment in Uint8ToHex after snprintf conversion
`tls/cm/src/conn_create.c:835`
```
int n = snprintf((char *)&destBuf[offsetTemp], (destMaxSize - offsetTemp), "%02x", srcBuf[i]);
if (n < 0 || (size_t)n >= (destMaxSize - offsetTemp)) {
    ...
}
offsetTemp += (size_t)n;
```
**Issue**: The original code used `offsetTemp += sizeof(uint16_t)` (which is 2) because sprintf_s with "%02x" always writes 2 hex digits. The new code uses the actual snprintf return value. However, if snprintf returns a value other than 2 (e.g., due to truncation or error), the subsequent buffer positioning could be incorrect. The validation check catches some cases but the logic is fragile.
**Fix**:
```
int n = snprintf((char *)&destBuf[offsetTemp], (destMaxSize - offsetTemp), "%02x", srcBuf[i]);
if (n < 0 || n != 2 || (size_t)n >= (destMaxSize - offsetTemp)) {
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16481, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "snprintf fail", 0, 0, 0, 0);
    return HITLS_INVALID_INPUT;
}
offsetTemp += 2;  // Each hex byte is exactly 2 characters
```

---


## Medium

### Missing buffer length validation in BSL_LOG_GetVersion
`bsl/log/src/log.c:41`
```
uint32_t len = (uint32_t)strlen(g_openHiTLSVersion);

memcpy(version, g_openHiTLSVersion, len);
```
**Issue**: The memcpy_s bounds check was removed. The original code verified that the actual string length fits in the caller's buffer. The new code relies only on HITLS_VERSION_LEN check. If g_openHiTLSVersion contains a longer string than expected (e.g., due to a build configuration issue), this could cause buffer overflow. While the function checks *versionLen >= HITLS_VERSION_LEN, this doesn't guarantee strlen(g_openHiTLSVersion) <= *versionLen.
**Fix**:
```
uint32_t len = (uint32_t)strlen(g_openHiTLSVersion);
if (len > *versionLen) {
    return BSL_MEMCPY_FAIL;
}
memcpy(version, g_openHiTLSVersion, len);
*versionLen = len;
return BSL_SUCCESS;
```

---

### HS_CombineRandom loses defensive error handling
`tls/handshake/common/src/hs_common.c:207-208`
```
if ((randomSize == 0u) || (destSize < randomSize * 2)) {
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RANDOM_SIZE_ERR);
    return HITLS_MSG_HANDLE_RANDOM_SIZE_ERR;
}
memcpy(dest, random1, randomSize);
memcpy(&dest[randomSize], random2, randomSize);
```
**Issue**: The memcpy_s error checking was removed. While the function has an initial check (destSize < randomSize * 2), the old code provided defensive programming with explicit error returns on memcpy failure. The new code silently continues on any error, potentially propagating corrupted data.
**Fix**:
```
if ((randomSize == 0u) || (destSize < randomSize * 2)) {
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RANDOM_SIZE_ERR);
    return HITLS_MSG_HANDLE_RANDOM_SIZE_ERR;
}
// Add explicit check even though we verified above
if (destSize < randomSize * 2) {
    BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
    return HITLS_MEMCPY_FAIL;
}
memcpy(dest, random1, randomSize);
memcpy(&dest[randomSize], random2, randomSize);
return HITLS_SUCCESS;
```

---

### strncpy usage without null termination guarantee in OptPrint
`apps/src/app_opt.c:407-408`
```
size_t nameLen = strlen(opt->name);
if (nameLen < sizeof(start) - pos - 1) {
    strncpy(&start[pos], opt->name, nameLen + 1);
    pos += (int)nameLen;
}
```
**Issue**: The code checks `nameLen < sizeof(start) - pos - 1` then uses `strncpy(&start[pos], opt->name, nameLen + 1)`. strncpy does not guarantee null termination if the source is longer than count. Here count is `nameLen + 1` but source is `opt->name` with length `nameLen`, so strncpy will copy the null terminator. However, the bounds check uses `nameLen < sizeof(start) - pos - 1` which means `nameLen <= sizeof(start) - pos - 2`, leaving room for the null. But using `nameLen + 1` as count is confusing and error-prone.
**Fix**:
```
size_t nameLen = strlen(opt->name);
if (nameLen > sizeof(start) - pos - 2) {
    // Skip this option name - buffer too small
} else {
    memcpy(&start[pos], opt->name, nameLen);
    pos += (int)nameLen;
}
```

---

### Removed bounds check in UpdateEncStdin cache handling
`apps/src/app_enc.c:793-795`
```
if (cacheLen + readLen > MAX_BUFSIZE + BUF_READABLE_BLOCK) {
    AppPrintError("enc: Buffer overflow detected\n");
    return HITLS_APP_COPY_ARGS_FAILED;
}
(void)memcpy(cacheArea + cacheLen, readBuf, readLen);
```
**Issue**: The original code had `cacheLen + readLen <= MAX_BUFSIZE + BUF_READABLE_BLOCK` check before the memcpy_s. The new code removed this validation. While there's an earlier overflow check, removing the defensive check makes the code less robust.
**Fix**:
```
if (cacheLen + readLen > MAX_BUFSIZE + BUF_READABLE_BLOCK) {
    AppPrintError("enc: Buffer overflow detected\n");
    return HITLS_APP_COPY_ARGS_FAILED;
}
if (readLen > MAX_BUFSIZE + BUF_READABLE_BLOCK - cacheLen) {
    AppPrintError("enc: Buffer overflow detected\n");
    return HITLS_APP_COPY_ARGS_FAILED;
}
memcpy(cacheArea + cacheLen, readBuf, readLen);
```

---

### Removed bounds check in UpdateEncStdin memcpy for cache rotation
`apps/src/app_enc.c:809`
```
memcpy(cacheArea, cacheArea + readableLen, BUF_SAFE_BLOCK);
```
**Issue**: The original code verified `BUF_SAFE_BLOCK <= MAX_BUFSIZE + BUF_READABLE_BLOCK - BUF_SAFE_BLOCK` via memcpy_s. The new code does not validate this constant relationship. If BUF_SAFE_BLOCK is incorrectly defined, this could overflow.
**Fix**:
```
if (BUF_SAFE_BLOCK > MAX_BUFSIZE + BUF_READABLE_BLOCK) {
    AppPrintError("enc: Invalid block size configuration\n");
    return HITLS_APP_COPY_ARGS_FAILED;
}
memcpy(cacheArea, cacheArea + readableLen, BUF_SAFE_BLOCK);
```

---


## Low

### Removed output validation from Int2Hex function
`apps/src/app_enc.c:130`
```
static int32_t Int2Hex(int32_t num, char *hexBuf)
{
    (void)snprintf(hexBuf, REC_HEX_BUF_LENGTH + 1, "%08X", num);
    return HITLS_APP_SUCCESS;
}
```
**Issue**: The original code verified that snprintf_s wrote exactly REC_HEX_BUF_LENGTH characters by checking strlen(hexBuf) != REC_HEX_BUF_LENGTH. The new code with standard snprintf doesn't validate the output. If num is an invalid value (e.g., very large negative number causing more than 8 hex digits), the output could be malformed without error detection.
**Fix**:
```
static int32_t Int2Hex(int32_t num, char *hexBuf)
{
    int ret = snprintf(hexBuf, REC_HEX_BUF_LENGTH + 1, "%08X", num);
    if (ret < 0 || ret > REC_HEX_BUF_LENGTH) {
        AppPrintError("enc: error in uint to hex.\n");
        return HITLS_APP_ENCODE_FAIL;
    }
    return HITLS_APP_SUCCESS;
}
```

---

### IsSpecialLabel has incorrect condition logic after snprintf_s replacement
`tls/handshake/common/src/hs_common.c:718-719`
```
if (labelLen != 0 && useLabelLen <= sizeof(labelBuf)) {
    memcpy(labelBuf, label, useLabelLen);
} else if (labelLen != 0) {
    return true;
}
```
**Issue**: The original code used memcpy_s error return to detect if the label was too long. The new condition `useLabelLen <= sizeof(labelBuf)` causes the function to return true (indicating special label) when the label fits in the buffer. This is semantically incorrect - the function should return true (meaning "need special handling") when the label is too long, not when it fits.
**Fix**:
```
if (labelLen != 0) {
    if (useLabelLen > sizeof(labelBuf) - 1) {
        return true;  // Label too long, needs special handling
    }
    memcpy(labelBuf, label, useLabelLen);
}
```

---
