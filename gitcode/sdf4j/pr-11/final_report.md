# Final Code Review Report
## openHiTLS/sdf4j - PR #11

### Summary
- **Total Issues**: 12
- **Critical**: 4
- **High**: 1
- **Medium**: 3
- **Low**: 4
- **Reviewers**: claude, gemini, codex

---


## Critical

### Plaintext password logging in access-right calls
`sdf4j/src/main/native/src/sdf_jni_device.c:227-290`
**Reviewers**: GEMINI | **置信度**: 较可信
```
ULONG pwd_len = pwd ? strlen(pwd) : 0;
SDF_JNI_LOG("SDF_GetPrivateKeyAccessRight: pwd='%s', pwd_len=%lu",
            pwd ? pwd : "(null)", (unsigned long)pwd_len);
...
ULONG pwd_len = pwd ? strlen(pwd) : 0;
SDF_JNI_LOG("SDF_GetKEKAccessRight: pwd='%s', pwd_len=%lu",
            pwd ? pwd : "(null)", (unsigned long)pwd_len);
```
**Issue**: Both access-right JNI functions log the full password string in plaintext, leaking sensitive credentials to logs.
**Fix**:
```
ULONG pwd_len = pwd ? strlen(pwd) : 0;
SDF_JNI_LOG("SDF_GetPrivateKeyAccessRight: pwd='***', pwd_len=%lu",
            (unsigned long)pwd_len);
...
ULONG pwd_len = pwd ? strlen(pwd) : 0;
SDF_JNI_LOG("SDF_GetKEKAccessRight: pwd='***', pwd_len=%lu",
            (unsigned long)pwd_len);
```

---

### AuthEncFinal uses user-sized buffer, risking heap overflow
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1114-1142`
**Reviewers**: GEMINI | **置信度**: 较可信
```
/* Convert pucEncData to native buffer */
BYTE *output_buf = NULL;
ULONG output_len = 0;
if (pucEncData != NULL) {
    output_len = (*env)->GetArrayLength(env, pucEncData);
    output_buf = (BYTE*)malloc(output_len);
    ...
    (*env)->GetByteArrayRegion(env, pucEncData, 0, output_len, (jbyte*)output_buf);
}
...
LONG ret = g_sdf_functions.SDF_AuthEncFinal(
    (HANDLE)sessionHandle,
    output_buf,
    &output_len,
    tag_buf,
    &tag_len
);
```
**Issue**: Output buffer size is derived from Java input array length and the code copies input bytes even though the buffer is output-only. If the caller passes a small array, the native SDF_AuthEncFinal can write beyond the allocated buffer.
**Fix**:
```
/* Allocate a safe output buffer for final block + padding */
ULONG output_len = 128; /* or block_size + max padding */
BYTE *output_buf = (BYTE*)malloc(output_len);
if (output_buf == NULL) {
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
/* Do not copy from pucEncData; this is output-only */
LONG ret = g_sdf_functions.SDF_AuthEncFinal(
    (HANDLE)sessionHandle,
    output_buf,
    &output_len,
    tag_buf,
    &tag_len
);
```

---

### Unbounded ECC byte array copies overflow fixed-size buffers
`sdf4j/src/main/native/src/type_conversion.c:319-399`
**Reviewers**: CODEX | **置信度**: 较可信
```
jsize len = (*env)->GetArrayLength(env, x_array);
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_cipher->x);
...
jsize len = (*env)->GetArrayLength(env, x_array);
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
...
jsize len = (*env)->GetArrayLength(env, r_array);
(*env)->GetByteArrayRegion(env, r_array, 0, len, (jbyte*)native_sig->r);
```
**Issue**: Java-provided ECC arrays are copied into fixed-size native buffers without clamping to `ECCref_MAX_LEN` (and ECCSignature is not zeroed). Oversized inputs can corrupt memory.
**Fix**:
```
/* ECCCipher x/y */
jsize len = (*env)->GetArrayLength(env, x_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_cipher->x);

/* ECCPublicKey x/y */
jsize len = (*env)->GetArrayLength(env, x_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);

/* ECCSignature */
memset(native_sig, 0, sizeof(ECCSignature));
jsize len = (*env)->GetArrayLength(env, r_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, r_array, 0, len, (jbyte*)native_sig->r);
```

---

### ECC private key copy can overflow native buffer
`sdf4j/src/main/native/src/type_conversion.c:617-628`
**Reviewers**: CODEX | **置信度**: 较可信
```
/* k */
jbyteArray k_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                         g_jni_cache.eccPrivateKey.k);
if (k_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, k_array);
    (*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
}
```
**Issue**: `java_to_native_ECCPrivateKey` copies the full Java array into `native_key->K` without clamping or zeroing, risking buffer overflow and leaving uninitialized bytes.
**Fix**:
```
memset(native_key, 0, sizeof(ECCrefPrivateKey));
native_key->bits = (*env)->GetIntField(env, java_key, g_jni_cache.eccPrivateKey.bits);

jbyteArray k_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                         g_jni_cache.eccPrivateKey.k);
if (k_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, k_array);
    if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
}
```

---


## High

### ECCCipher L field can exceed allocated C buffer length
`sdf4j/src/main/native/src/type_conversion.c:344-348`
**Reviewers**: GEMINI | **置信度**: 较可信
```
/* L - cipher data length */
native_cipher->L = (ULONG)l_value;
if (native_cipher->L == 0 && c_len > 0) {
    native_cipher->L = c_len;
}
```
**Issue**: `native_cipher->L` is set from Java without validating against the allocated `C` length. A larger `L` can cause over-reads in downstream native operations.
**Fix**:
```
if (l_value > c_len) {
    SDF_LOG_ERROR("java_to_native_ECCCipher_alloc", "Invalid L: exceeds C length");
    free(native_cipher);
    return NULL;
}
native_cipher->L = (ULONG)l_value;
if (native_cipher->L == 0 && c_len > 0) {
    native_cipher->L = c_len;
}
```

---


## Medium

### Null unboxing in device close guard causes NPE
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:173-176`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
if (gDevHandle == 0 || deviceHandle != gDevHandle) {
    return;
}
```
**Issue**: `gDevHandle` is a `Long`. The guard `gDevHandle == 0` auto-unboxes and throws `NullPointerException` when `gDevHandle` is null (e.g., close before open or after prior close).
**Fix**:
```
if (gDevHandle == null || deviceHandle != gDevHandle.longValue()) {
    return;
}
```

---

### ConcurrentModificationException while closing session keys
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:229-234`
**Reviewers**: CODEX | **置信度**: 较可信
```
for (Long keyHandle : sessionResource.keys) {
    sessionResource.removeKey(keyHandle);
    SDF_DestroyKey_Native(sessionHandle, keyHandle);
}
```
**Issue**: The loop iterates `sessionResource.keys` and removes from the same set inside the loop, which can throw `ConcurrentModificationException` and leave keys undisposed.
**Fix**:
```
for (Long keyHandle : new java.util.HashSet<>(sessionResource.keys)) {
    sessionResource.removeKey(keyHandle);
    SDF_DestroyKey_Native(sessionHandle, keyHandle);
}
```

---

### Session creation assumes device resource initialized
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:204-208`
**Reviewers**: CODEX | **置信度**: 较可信
```
long handle = SDF_OpenSessionNative(deviceHandle);
// 创建 SessionResource 并注册到 gDevResource 和 gSessResource
SessionResource sessionResource = new SessionResource(handle);
gSessResource.put(handle, sessionResource);
```
**Issue**: `SessionResource` relies on `gDevResource` being non-null. If `SDF_OpenSession` is called when the device is not open, the native call succeeds but Java then throws `NullPointerException`, leaking the native session handle.
**Fix**:
```
if (gDevHandle == null || gDevResource == null || deviceHandle != gDevHandle.longValue()) {
    throw new IllegalStateException("Device not opened");
}
long handle = SDF_OpenSessionNative(deviceHandle);
SessionResource sessionResource = new SessionResource(handle);
gSessResource.put(handle, sessionResource);
```

---


## Low

### DeviceResource.finalize may throw NPE on null handle
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:68-71`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
@Override
protected void finalize() throws Throwable {
    try {
        SDF_CloseDevice(gDevHandle);
    } finally {
        super.finalize();
    }
}
```
**Issue**: `finalize()` unconditionally passes `gDevHandle` to `SDF_CloseDevice`. If `gDevHandle` is null, auto-unboxing throws `NullPointerException` and skips cleanup.
**Fix**:
```
@Override
protected void finalize() throws Throwable {
    try {
        Long handle = gDevHandle;
        if (handle != null) {
            SDF_CloseDevice(handle.longValue());
        }
    } finally {
        super.finalize();
    }
}
```

---

### SessionResource.finalize aborts on first key destruction error
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:100-103`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
for (Long keyHandle : keys) {
        SDF_DestroyKey_Native(sessionHandle, keyHandle);
}
```
**Issue**: If `SDF_DestroyKey_Native` throws for one key, the loop stops and remaining keys are not destroyed.
**Fix**:
```
for (Long keyHandle : new java.util.HashSet<>(keys)) {
    try {
        SDF_DestroyKey_Native(sessionHandle, keyHandle);
    } catch (Exception ignored) {
        // continue cleanup
    }
}
```

---

### Decrypt logs plaintext before checking return code
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:303-308`
**Reviewers**: CODEX | **置信度**: 较可信
```
LONG ret = g_sdf_functions.SDF_Decrypt(...);

SDF_JNI_LOG("SDF_Decrypt: output_len=%lu", data_len);
SDF_LOG_HEX("SDF_Decrypt plaintext", data_buf, data_len);
```
**Issue**: Plaintext is logged unconditionally even when decryption fails, which can log uninitialized data or partial plaintext.
**Fix**:
```
LONG ret = g_sdf_functions.SDF_Decrypt(...);

if (ret == SDR_OK) {
    SDF_JNI_LOG("SDF_Decrypt: output_len=%lu", data_len);
    SDF_LOG_HEX("SDF_Decrypt plaintext", data_buf, data_len);
}
```

---

### Wrong log tag in InternalEncrypt_ECC error path
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:229-232`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
if (data_buf == NULL) {
    SDF_LOG_ERROR("SDF_ExternalEncrypt_ECC", "GetPrimitiveArrayCritical failed");
    throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
    return NULL;
}
```
**Issue**: The error log uses the external-encrypt tag inside `JNI_SDF_InternalEncrypt_ECC`, making logs misleading.
**Fix**:
```
if (data_buf == NULL) {
    SDF_LOG_ERROR("SDF_InternalEncrypt_ECC", "GetPrimitiveArrayCritical failed");
    throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
    return NULL;
}
```

---
