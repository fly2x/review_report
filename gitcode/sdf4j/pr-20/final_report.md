# Final Code Review Report
## openHiTLS/sdf4j - PR #20

### Summary
- **Total Issues**: 10
- **Critical**: 2
- **High**: 5
- **Medium**: 2
- **Low**: 1
- **Reviewers**: claude, gemini, codex

---


## Critical

### Buffer overflow - insufficient allocation for post-quantum KEM ciphertext
`sdf4j/src/main/native/src/sdf_jni_hybrid.c:15`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
#define HYBRIDENCref_ECC_MAX_LEN 141
...
HybridCipher *cipher = (HybridCipher*)malloc(sizeof(HybridCipher) + HYBRIDENCref_ECC_MAX_LEN);
```
**Issue**: HYBRIDENCref_ECC_MAX_LEN is defined as 141 bytes, which is insufficient for post-quantum KEM algorithms like MLKEM-1024 that produce ciphertexts up to 1568 bytes. When SDF_GenerateKeyWithEPK_Hybrid is called with hybrid algorithms (e.g., SGD_HYBRID_ENV_SM2_MLKEM_1024), the SDF library will write beyond the allocated buffer, causing memory corruption.
**Fix**:
```
#define HYBRIDENC_MAX_ECC_CIPHER_LEN 2048  /* Large enough for MLKEM-1024 (1568) + overhead */
...
HybridCipher *cipher = (HybridCipher*)malloc(sizeof(HybridCipher) + HYBRIDENC_MAX_ECC_CIPHER_LEN);
if (cipher == NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, publicKey, pub_key_buf, JNI_ABORT);
    THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for cipher");
    return NULL;
}
memset(cipher, 0, sizeof(HybridCipher) + HYBRIDENC_MAX_ECC_CIPHER_LEN);
```

---

### Out-of-bounds read when copying nested ECCCipher
`sdf4j/src/main/native/src/type_conversion.c:696-704`
**Reviewers**: CODEX | **置信度**: 可信
```
temp_cts = java_to_native_ECCCipher_alloc(env, cts_obj);
if (temp_cts != NULL) {
    c_len = (jsize)temp_cts->L;
}
...
size_t alloc_size = sizeof(HybridCipher) + c_len;
...
memcpy(&native_cipher->ct_s, temp_cts, sizeof(ECCCipher) + c_len);
```
**Issue**: c_len is taken from temp_cts->L (user-controlled Java field), not from the actual allocated buffer size. If Java's ECCCipher.L field is larger than the actual c[] array length, memcpy at line 727 reads beyond temp_cts buffer, causing memory corruption.
**Fix**:
```
jbyteArray c_array = (jbyteArray)(*env)->GetObjectField(env, cts_obj, g_jni_cache.eccCipher.c);
jsize actual_c_len = (c_array != NULL) ? (*env)->GetArrayLength(env, c_array) : 0;
temp_cts = java_to_native_ECCCipher_alloc(env, cts_obj);
if (temp_cts == NULL) {
    return NULL;
}
/* Use the actual array length, not the L field from Java */
c_len = actual_c_len;
/* Also ensure L field reflects actual buffer size */
if (temp_cts->L > (ULONG)c_len) {
    temp_cts->L = (ULONG)c_len;
}
```

---


## High

### Unbounded ct_s length can trigger buffer over-read
`sdf4j/src/main/native/src/sdf_jni_hybrid.c:125`
**Reviewers**: CODEX | **置信度**: 可信
```
jobject result = native_to_java_HybridCipher(env, cipher, cipher->ct_s.L, key_handle);
```
**Issue**: cipher->ct_s.L from SDF library is trusted directly without bounds checking. If the device returns an L value larger than the allocated HYBRIDENCref_ECC_MAX_LEN, native_to_java_HybridCipher will read beyond the cipher buffer.
**Fix**:
```
ULONG ct_s_len = cipher->ct_s.L;
if (ct_s_len > HYBRIDENCref_ECC_MAX_LEN) {
    ct_s_len = HYBRIDENCref_ECC_MAX_LEN;
}
jobject result = native_to_java_HybridCipher(env, cipher, ct_s_len, key_handle);
```

---

### ArrayIndexOutOfBoundsException - sig_m array access without length validation
`sdf4j/src/main/native/src/type_conversion.c:784-790`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
if (l_value > HYBRIDSIGref_MAX_LEN) l_value = HYBRIDSIGref_MAX_LEN;
native_sig->L = (ULONG)l_value;

if (sig_m_array != NULL) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
}
```
**Issue**: l_value from Java object's L field is used to read from sig_m_array without verifying the actual array length. If L > sig_m_array.length, GetByteArrayRegion will throw a Java exception. Also, l_value is not validated for negative values.
**Fix**:
```
jsize actual_array_len = (sig_m_array != NULL) ? (*env)->GetArrayLength(env, sig_m_array) : 0;
if (l_value < 0) {
    free(native_sig);
    return NULL;
}
if (l_value > HYBRIDSIGref_MAX_LEN || l_value > actual_array_len) {
    l_value = (l_value > actual_array_len) ? actual_array_len : HYBRIDSIGref_MAX_LEN;
}
native_sig->L = (ULONG)l_value;

if (sig_m_array != NULL && l_value > 0) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
}
```

---

### No upper bound on sig_m_len before copying from fixed buffer
`sdf4j/src/main/native/src/type_conversion.c:749-752`
**Reviewers**: CODEX | **置信度**: 可信
```
if (sig_m_len > 0) {
    jbyteArray sig_m_array = (*env)->NewByteArray(env, sig_m_len);
    if (sig_m_array != NULL) {
        (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
```
**Issue**: sig_m_len parameter is used directly to allocate/copy from native_sig->sig_m (fixed-size array of HYBRIDSIGref_MAX_LEN). If caller passes oversized length, SetByteArrayRegion reads beyond the native buffer.
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

### Unvalidated L1 length can desynchronize payload size
`sdf4j/src/main/native/src/type_conversion.c:711`
**Reviewers**: CODEX | **置信度**: 较可信
```
native_cipher->L1 = (ULONG)(*env)->GetLongField(env, java_cipher, g_jni_cache.hybridCipher.l1);

/* ct_m */
jbyteArray ctm_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                          g_jni_cache.hybridCipher.ctM);
if (ctm_array != NULL) {
    jsize len = (*env)->GetArrayLength(env, ctm_array);
    if (len > HYBRIDENCref_MAX_LEN) len = HYBRIDENCref_MAX_LEN;
    (*env)->GetByteArrayRegion(env, ctm_array, 0, len, (jbyte*)native_cipher->ct_m);
}
```
**Issue**: L1 is copied directly from Java GetLongField without validation. If L1 is negative or inconsistent with ct_m array length, invalid size may be passed to SDF library. The ct_m array uses GetArrayLength but L1 is not synchronized.
**Fix**:
```
jbyteArray ctm_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                          g_jni_cache.hybridCipher.ctM);
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

### Wrong package declaration - test will not compile
`sdf4j/src/test/java/org/openhitls/sdf4j/HybridAlgorithmTest.java:13`
**Reviewers**: CLAUDE | **置信度**: 可信
```
package org.openhitls.sdf4j.examples;
```
**Issue**: File is at org/openhitls/sdf4j/HybridAlgorithmTest.java but declares package org.openhitls.sdf4j.examples. This mismatch causes compilation failure.
**Fix**:
```
package org.openhitls.sdf4j;
```

---


## Medium

### Duplicate function call - redundant cache initialization
`sdf4j/src/main/native/src/jni_cache.c:325-333`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
if (init_common_class_cache(env) != JNI_TRUE) {
    jni_cache_cleanup(env);
    return JNI_FALSE;
}

if (init_common_class_cache(env) != JNI_TRUE) {
    jni_cache_cleanup(env);
    return JNI_FALSE;
}
g_jni_cache.initialized = true;
```
**Issue**: init_common_class_cache(env) is called twice consecutively. The second call overwrites global references from the first call, leaking memory until cleanup.
**Fix**:
```
if (init_common_class_cache(env) != JNI_TRUE) {
    jni_cache_cleanup(env);
    return JNI_FALSE;
}
g_jni_cache.initialized = true;
```

---

### setCtM does not keep L1 in sync and stores mutable external buffer
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java:45-50`
**Reviewers**: CODEX | **置信度**: 较可信
```
public void setCtM(byte[] ctM) {
    if (ctM == null) {
        throw new IllegalArgumentException("cipher value cannot be null");
    }
    this.ctM = ctM;
}
```
**Issue**: setCtM assigns caller array directly without copying and does not update l1. This allows external mutation and stale/invalid length values to propagate into JNI.
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

### Misleading comment - sigM is not a MAC value
`sdf4j/src/test/java/org/openhitls/sdf4j/HybridAlgorithmTest.java:204`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
assertNotNull("MAC值不应为null", signature.getSigM());
```
**Issue**: Comment says "MAC值不应为null" (MAC value should not be null) but sigM is the post-quantum signature component (e.g., ML-DSA signature), not a MAC.
**Fix**:
```
assertNotNull("后量子签名值不应为null", signature.getSigM());
// or
assertNotNull("Post-quantum signature should not be null", signature.getSigM());
```

---
