# Code Review: openHiTLS/sdf4j#20
**Reviewer**: CODEX


## Critical

### Out-of-bounds read when copying nested ECCCipher
`sdf4j/src/main/native/src/type_conversion.c:698-704`
```
if (temp_cts != NULL) {
    c_len = (jsize)temp_cts->L;
}
...
size_t alloc_size = sizeof(HybridCipher) + c_len;
...
memcpy(&native_cipher->ct_s, temp_cts, sizeof(ECCCipher) + c_len);
```
**Issue**: `c_len` is taken from `temp_cts->L` (user-controlled Java field), not from the actual allocated `temp_cts` buffer size. If `L` is larger than `c[]` length, `memcpy` reads past `temp_cts`, causing native memory corruption/crash.
**Fix**:
```
jsize c_len = 0;
if (cts_obj != NULL) {
    jbyteArray c_array = (jbyteArray)(*env)->GetObjectField(env, cts_obj, g_jni_cache.eccCipher.c);
    if (c_array != NULL) {
        c_len = (*env)->GetArrayLength(env, c_array);
    }

    temp_cts = java_to_native_ECCCipher_alloc(env, cts_obj);
    if (temp_cts == NULL) {
        return NULL;
    }

    /* Keep length consistent with actual copied buffer size */
    if (temp_cts->L > (ULONG)c_len) {
        temp_cts->L = (ULONG)c_len;
    }
}

size_t alloc_size = sizeof(HybridCipher) + (size_t)c_len;
...
if (temp_cts != NULL) {
    memcpy(&native_cipher->ct_s, temp_cts, sizeof(ECCCipher) + (size_t)c_len);
    free(temp_cts);
}
```

---


## High

### Unvalidated L1 length can desynchronize payload size
`sdf4j/src/main/native/src/type_conversion.c:711`
```
native_cipher->L1 = (ULONG)(*env)->GetLongField(env, java_cipher, g_jni_cache.hybridCipher.l1);
...
if (ctm_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, ctm_array);
    if (len > HYBRIDENCref_MAX_LEN) len = HYBRIDENCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, ctm_array, 0, len, (jbyte*)native_cipher->ct_m);
}
```
**Issue**: `L1` is copied directly from Java (`GetLongField`) and can be negative/oversized relative to `ct_m`. This can make native code pass an invalid length to the SDF library and trigger out-of-bounds reads on `ct_m`.
**Fix**:
```
ULONG l1 = 0;
if (ctm_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, ctm_array);
    if (len > HYBRIDENCref_MAX_LEN) len = HYBRIDENCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, ctm_array, 0, len, (jbyte*)native_cipher->ct_m);
    l1 = (ULONG)len;
}
native_cipher->L1 = l1;
```

---

### Signature length accepts negative/oversized values
`sdf4j/src/main/native/src/type_conversion.c:784-790`
```
if (l_value > HYBRIDSIGref_MAX_LEN) l_value = HYBRIDSIGref_MAX_LEN;
native_sig->L = (ULONG)l_value;

if (sig_m_array != NULL) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
}
```
**Issue**: `l_value` is not validated for `< 0` and not bounded by `sigM` array length. Casting negative values to `ULONG` produces huge lengths; `GetByteArrayRegion` can throw, and `native_sig->L` can carry unsafe size into native verify API.
**Fix**:
```
jsize sig_len = 0;
if (sig_m_array != NULL) {
    sig_len = (*env)->GetArrayLength(env, sig_m_array);
}

if (l_value < 0) {
    free(native_sig);
    return NULL;
}
if (l_value > sig_len) l_value = sig_len;
if (l_value > HYBRIDSIGref_MAX_LEN) l_value = HYBRIDSIGref_MAX_LEN;

native_sig->L = (ULONG)l_value;
if (sig_m_array != NULL && l_value > 0) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
}
```

---

### Unbounded ct_s length can trigger over-read during Java conversion
`sdf4j/src/main/native/src/sdf_jni_hybrid.c:125`
```
jobject result = native_to_java_HybridCipher(env, cipher, cipher->ct_s.L, key_handle);
```
**Issue**: `cipher->ct_s.L` is trusted directly. If device/library returns a larger value than allocated `HYBRIDENCref_ECC_MAX_LEN`, conversion code reads beyond `cipher` buffer.
**Fix**:
```
ULONG ct_s_len = cipher->ct_s.L;
if (ct_s_len > HYBRIDENCref_ECC_MAX_LEN) {
    ct_s_len = HYBRIDENCref_ECC_MAX_LEN;
}
jobject result = native_to_java_HybridCipher(env, cipher, ct_s_len, key_handle);
```

---

### No upper bound on sig_m_len before copying fixed buffer
`sdf4j/src/main/native/src/type_conversion.c:749-753`
```
if (sig_m_len > 0) {
    jbyteArray sig_m_array = (*env)->NewByteArray(env, sig_m_len);
    if (sig_m_array != NULL) {
        (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
        (*env)->SetObjectField(env, obj, g_jni_cache.hybridSignature.sigM, sig_m_array);
    }
}
```
**Issue**: `sig_m_len` is used directly to allocate/copy from `native_sig->sig_m` (fixed-size array). Oversized length causes out-of-bounds read of native memory.
**Fix**:
```
if (sig_m_len > HYBRIDSIGref_MAX_LEN) {
    sig_m_len = HYBRIDSIGref_MAX_LEN;
}
if (sig_m_len > 0) {
    jbyteArray sig_m_array = (*env)->NewByteArray(env, (jsize)sig_m_len);
    if (sig_m_array != NULL) {
        (*env)->SetByteArrayRegion(env, sig_m_array, 0, (jsize)sig_m_len, (jbyte*)native_sig->sig_m);
        (*env)->SetObjectField(env, obj, g_jni_cache.hybridSignature.sigM, sig_m_array);
    }
}
```

---


## Medium

### setCtM does not keep L1 in sync and stores mutable external buffer
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java:45-50`
```
public void setCtM(byte[] ctM) {
    if (ctM == null) {
        throw new IllegalArgumentException("cipher value cannot be null");
    }
    this.ctM = ctM;
}
```
**Issue**: `setCtM` assigns caller array directly and does not update `l1`. This allows stale/invalid length values to propagate into JNI and also lets external mutation change internal state unexpectedly.
**Fix**:
```
public void setCtM(byte[] ctM) {
    if (ctM == null) {
        throw new IllegalArgumentException("cipher value cannot be null");
    }
    int len = Math.min(ctM.length, HYBRIDENCref_MAX_LEN);
    this.ctM = Arrays.copyOf(ctM, len);
    this.l1 = len;
}
```

---


## Low

### Duplicate cache initialization leaks global references
`sdf4j/src/main/native/src/jni_cache.c:325-333`
```
if (init_common_class_cache(env) != JNI_TRUE) {
    jni_cache_cleanup(env);
    return JNI_FALSE;
}

if (init_common_class_cache(env) != JNI_TRUE) {
    jni_cache_cleanup(env);
    return JNI_FALSE;
}
```
**Issue**: `init_common_class_cache(env)` is called twice consecutively. The second call overwrites already-created global refs and leaks the first set until cleanup.
**Fix**:
```
if (init_common_class_cache(env) != JNI_TRUE) {
    jni_cache_cleanup(env);
    return JNI_FALSE;
}
```

---
