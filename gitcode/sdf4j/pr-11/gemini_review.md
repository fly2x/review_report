# Code Review: openHiTLS/sdf4j#11
**Reviewer**: GEMINI


## Critical

### Invalid free of JNI primitive array
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1296`
```
if (ret != SDR_OK) {
        if (output_buf != NULL) free(output_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }
```
**Issue**: In `JNI_SDF_AuthEncFinal`, if the native `SDF_AuthEncFinal` fails (returns non-SDR_OK), the code attempts to `free(output_buf)`. However, `output_buf` was obtained using `GetPrimitiveArrayCritical`, which may point to a pinned Java object or a copy managed by the JVM. Calling `free()` on it will corrupt the heap allocator and crash the JVM.
**Fix**:
```
if (ret != SDR_OK) {
        if (output_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, pucEncData, output_buf, JNI_ABORT);
        }
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }
```

---

### Double release of JNI primitive array
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1045`
```
if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
    if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
```
**Issue**: In `JNI_SDF_AuthDec`, the `aad_buf` (Additional Authenticated Data) is released twice using `ReleasePrimitiveArrayCritical` in the success cleanup path. This leads to undefined behavior, potentially corrupting JVM memory or crashing.
**Fix**:
```
if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
```

---


## High

### Thread-unsafe resource management
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:57`
```
private Long gDevHandle = null;
    private DeviceResource gDevResource = null;
    private java.util.Map<Long, SessionResource> gSessResource = new java.util.HashMap<>();
```
**Issue**: The `SDF` class introduces instance-level state (`gSessResource` HashMap, `gDevResource` object) to track sessions and keys. These collections are accessed and modified by multiple methods (`SDF_OpenSession`, `SDF_CloseSession`, `SDF_GenerateKey...`) without any synchronization. If a single `SDF` instance is shared across threads (common for hardware device wrappers), this will lead to `ConcurrentModificationException` or state corruption (e.g., tracking leaks, double-frees).
**Fix**:
```
private Long gDevHandle = null;
    private DeviceResource gDevResource = null;
    private java.util.Map<Long, SessionResource> gSessResource = new java.util.concurrent.ConcurrentHashMap<>();
    
    // Also ensure DeviceResource.sessions access is thread-safe, e.g., use Collections.synchronizedSet or ConcurrentHashMap.newKeySet()
```

---

### JVM Garbage Collector blocking
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:94`
```
jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    // ...
    LONG ret = g_sdf_functions.SDF_EncryptUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)data_buf,
        // ...
    );
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
```
**Issue**: The code uses `GetPrimitiveArrayCritical` to access byte arrays. This function temporarily disables the JVM Garbage Collector. Inside the critical region, the code calls `malloc` (which can lock) and, more importantly, calls the underlying SDF hardware library functions (`g_sdf_functions.SDF_EncryptUpdate`, etc.). If the hardware device or driver blocks or takes a significant amount of time (e.g., high load, hardware fault), the entire JVM GC will be paused, potentially causing the whole Java application to stall or become unresponsive.
**Fix**:
```
/* Prefer GetByteArrayRegion / SetByteArrayRegion for potentially blocking operations */
    jbyte *data_buf = (jbyte*)malloc(data_len);
    if (data_buf == NULL) { ... }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, data_buf);
    
    LONG ret = g_sdf_functions.SDF_EncryptUpdate(..., (BYTE*)data_buf, ...);
    
    free(data_buf);
```

---


## Medium

### Potential buffer overflow in Envelope Exchange
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:345`
```
ULONG out_len = in_cipher->L;
    ECCCipher *out_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + out_len);
```
**Issue**: `JNI_SDF_ExchangeDigitEnvelopeBaseOnECC` allocates the output buffer based solely on the input cipher length (`in_cipher->L`). If the operation results in a larger ciphertext (e.g., due to key wrapping overhead, padding, or format differences), `SDF_ExchangeDigitEnvelopeBaseOnECC` will write past the allocated buffer.
**Fix**:
```
/* Ensure buffer is large enough for potential expansion. 
       Consult SDF spec for maximum expansion. typically ECCref_MAX_CIPHER_LEN or similar constant */
    ULONG out_len = in_cipher->L + 128; // Add safety margin
    ECCCipher *out_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + out_len);
    out_cipher->L = out_len; // Tell native lib the max buffer size if possible, otherwise rely on sufficient alloc
```

---
