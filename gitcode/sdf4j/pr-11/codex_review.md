# Code Review: openHiTLS/sdf4j#11
**Reviewer**: CODEX


## Critical

### Missing bounds checks when copying ECC byte arrays
`sdf4j/src/main/native/src/type_conversion.c:319-399`
```
if (x_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, x_array);
    (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_cipher->x);
}
...
if (x_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, x_array);
    (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
}
...
if (r_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, r_array);
    (*env)->GetByteArrayRegion(env, r_array, 0, len, (jbyte*)native_sig->r);
}
```
**Issue**: Java-provided arrays are copied into fixed-size ECC buffers without clamping to `ECCref_MAX_LEN`. This enables out-of-bounds writes (memory corruption) if the Java arrays are longer than the native fields. Additionally, ECCSignature is no longer zeroed before partial copies.
**Fix**:
```
/* ECCCipher x */
if (x_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, x_array);
    if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_cipher->x);
}

/* ECCPublicKey x */
if (x_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, x_array);
    if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
}

/* ECCSignature */
memset(native_sig, 0, sizeof(ECCSignature));
if (r_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, r_array);
    if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, r_array, 0, len, (jbyte*)native_sig->r);
}
```

---


## High

### ECC private key copy can overflow native buffer
`sdf4j/src/main/native/src/type_conversion.c:617-628`
```
jbyteArray k_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                         g_jni_cache.eccPrivateKey.k);
if (k_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, k_array);
    (*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
}
```
**Issue**: `java_to_native_ECCPrivateKey` copies the full Java array length into `native_key->K` without clamping to `ECCref_MAX_LEN`, and it no longer zeroes the struct. This can overflow the fixed-size buffer and leave uninitialized bytes.
**Fix**:
```
memset(native_key, 0, sizeof(ECCrefPrivateKey));
if (k_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, k_array);
    if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
}
```

---


## Medium

### Null unboxing in device close guard
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:173-176`
```
if (gDevHandle == 0 || deviceHandle != gDevHandle) {
    return;
}
```
**Issue**: `gDevHandle` is a `Long`. The comparison `gDevHandle == 0` auto-unboxes; when `gDevHandle` is `null` (e.g., close called before open or after a previous close), this throws `NullPointerException` instead of a safe no-op.
**Fix**:
```
if (gDevHandle == null || deviceHandle != gDevHandle.longValue()) {
    return;
}
```

---

### ConcurrentModificationException while closing session keys
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:229-234`
```
for (Long keyHandle : sessionResource.keys) {
    sessionResource.removeKey(keyHandle);
    SDF_DestroyKey_Native(sessionHandle, keyHandle);
}
```
**Issue**: The code iterates `sessionResource.keys` and removes from the same set inside the loop, which triggers `ConcurrentModificationException` and may leave keys undisposed.
**Fix**:
```
for (Long keyHandle : new java.util.HashSet<>(sessionResource.keys)) {
    sessionResource.removeKey(keyHandle);
    SDF_DestroyKey_Native(sessionHandle, keyHandle);
}
```

---

### Session tracking NPE if device resource not initialized
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:92-95`
```
SessionResource(long sessionHandle) {
    this.sessionHandle = sessionHandle;
    gDevResource.addSession(sessionHandle);
}
```
**Issue**: `SessionResource` assumes `gDevResource` is non-null. If `SDF_OpenSession` is called without a prior `SDF_OpenDevice` on this instance (or after device close), this throws `NullPointerException` after the native session is opened, leaking the native session handle.
**Fix**:
```
SessionResource(long sessionHandle) {
    if (gDevResource == null) {
        throw new IllegalStateException("Device not opened");
    }
    this.sessionHandle = sessionHandle;
    gDevResource.addSession(sessionHandle);
}
```

---


## Low

### Decrypt logs plaintext before checking return code
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:303-309`
```
LONG ret = g_sdf_functions.SDF_Decrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                        algID, (BYTE*)iv_buf, (BYTE*)enc_data_buf, enc_data_len,
                                        data_buf, &data_len);

SDF_JNI_LOG("SDF_Decrypt: output_len=%lu", data_len);
SDF_LOG_HEX("SDF_Decrypt plaintext", data_buf, data_len);
```
**Issue**: Plaintext is logged unconditionally before verifying `ret == SDR_OK`, which can log uninitialized data or partial plaintext when decryption/authentication fails.
**Fix**:
```
LONG ret = g_sdf_functions.SDF_Decrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                        algID, (BYTE*)iv_buf, (BYTE*)enc_data_buf, enc_data_len,
                                        data_buf, &data_len);

if (ret == SDR_OK) {
    SDF_JNI_LOG("SDF_Decrypt: output_len=%lu", data_len);
    SDF_LOG_HEX("SDF_Decrypt plaintext", data_buf, data_len);
}
```

---
