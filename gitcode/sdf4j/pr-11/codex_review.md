# Code Review: openHiTLS/sdf4j#11
**Reviewer**: CODEX


## Critical

### Buffer overflow in ECC conversions (missing length clamps)
`sdf4j/src/main/native/src/type_conversion.c:300-449`
```
jsize len = (*env)->GetArrayLength(env, x_array);
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
...
jsize len = (*env)->GetArrayLength(env, y_array);
(*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_key->y);
```
**Issue**: The new code copies Java byte arrays directly into fixed-size ECC buffers without clamping to `ECCref_MAX_LEN`. If Java supplies longer arrays, this writes past the end of `ECCrefPublicKey`, `ECCSignature`, and `ECCCipher` fields, causing memory corruption.
**Fix**:
```
jsize len = (*env)->GetArrayLength(env, x_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);

len = (*env)->GetArrayLength(env, y_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_key->y);
```

---

### Buffer overflow in ECC private key conversion
`sdf4j/src/main/native/src/type_conversion.c:667-678`
```
jsize len = (*env)->GetArrayLength(env, k_array);
(*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
```
**Issue**: `java_to_native_ECCPrivateKey` copies the Java `k` array into a fixed-size `ECCrefPrivateKey.K` buffer without clamping. Oversized input overflows the native struct.
**Fix**:
```
memset(native_key, 0, sizeof(ECCrefPrivateKey));
jsize len = (*env)->GetArrayLength(env, k_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
```

---


## High

### Build break: undefined variable keyHandle
`sdf4j/src/main/native/src/sdf_jni_keygen.c:662-668`
```
SDF_LOG_EXIT("SDF_ImportKey", ret);
SDF_JNI_LOG("SDF_ImportKey: keyHandle=0x%lX", (unsigned long)keyHandle);
return (jlong)key_handle;
```
**Issue**: The new `SDF_ImportKey` JNI method logs `keyHandle`, but the variable is named `key_handle`. This is a compile error.
**Fix**:
```
SDF_LOG_EXIT("SDF_ImportKey", ret);
SDF_JNI_LOG("SDF_ImportKey: keyHandle=0x%lX", (unsigned long)key_handle);
return (jlong)key_handle;
```

---

### Double ReleasePrimitiveArrayCritical on aad_buf
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:960-967`
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
```
**Issue**: `aad_buf` is released twice in `JNI_SDF_AuthDec`, which can corrupt JNI state or crash the JVM.
**Fix**:
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
```

---

### Invalid free() of pinned JNI array
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1229-1236`
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
if (aad_buf != NULL) free(aad_buf);
```
**Issue**: `aad_buf` is obtained via `GetPrimitiveArrayCritical` and must be released via `ReleasePrimitiveArrayCritical`. Calling `free(aad_buf)` is undefined behavior and can crash.
**Fix**:
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
```

---

### Invalid free() on GetPrimitiveArrayCritical buffers
`sdf4j/src/main/native/src/sdf_jni_util.c:405-448`
```
if (iv_buf == NULL) {
    free(key_buf);
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
if (enc_buf == NULL) {
    free(key_buf);
    if (iv_buf) free(iv_buf);
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
free(key_buf);
if (iv_buf) free(iv_buf);
free(enc_buf);
```
**Issue**: `key_buf`, `iv_buf`, and `enc_buf` are obtained via `GetPrimitiveArrayCritical` but are freed with `free(...)`. This is invalid and can cause memory corruption or JVM crashes, including in error paths.
**Fix**:
```
if (iv_buf == NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
if (enc_buf == NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
(*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
if (iv_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
}
(*env)->ReleasePrimitiveArrayCritical(env, encData, enc_buf, JNI_ABORT);
```

---


## Medium

### NullPointerException on CloseDevice when gDevHandle is null
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:181-184`
```
if (deviceHandle != gDevHandle) {
    return;
}
```
**Issue**: `deviceHandle != gDevHandle` auto-unboxes `gDevHandle`. If `SDF_CloseDevice` is called before `SDF_OpenDevice` or after a close, `gDevHandle` is null and this throws a NullPointerException instead of behaving as a no-op or clean error.
**Fix**:
```
if (gDevHandle == null || deviceHandle != gDevHandle.longValue()) {
    return;
}
```

---

### OpenSession can throw NPE when device resource is missing
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:216-221`
```
long handle = SDF_OpenSessionNative(deviceHandle);
// 创建 SessionResource 并注册到 gDevResource 和 gSessResource
SessionResource sessionResource = new SessionResource(handle);
gSessResource.put(handle, sessionResource);
```
**Issue**: `SessionResource` uses `gDevResource.addSession(...)` but `gDevResource` is only set in `SDF_OpenDevice`. Calling `SDF_OpenSession` without an open device (or after closing) now throws a NullPointerException instead of a controlled `SDFException`.
**Fix**:
```
if (gDevResource == null) {
    throw new SDFException(SDR_INARGERR);
}
long handle = SDF_OpenSessionNative(deviceHandle);
SessionResource sessionResource = new SessionResource(handle);
gSessResource.put(handle, sessionResource);
```

---
