# Code Review: openHiTLS/sdf4j#20
**Reviewer**: CLAUDE


## Critical

### Buffer overflow - insufficient allocation for post-quantum KEM ciphertext
`sdf4j/src/main/native/src/sdf_jni_hybrid.c:104`
```
#define HYBRIDENCref_ECC_MAX_LEN 141
...
HybridCipher *cipher = (HybridCipher*)malloc(sizeof(HybridCipher) + HYBRIDENCref_ECC_MAX_LEN);
```
**Issue**: The allocation `sizeof(HybridCipher) + HYBRIDENCref_ECC_MAX_LEN` uses only 141 bytes for the ECCCipher flexible array (ct_s.C[]). Post-quantum algorithms like MLKEM-1024 produce ciphertexts up to 1568 bytes. When SDF_GenerateKeyWithEPK_Hybrid is called with algorithms like SGD_HYBRID_ENV_SM2_MLKEM_1024, it will write beyond the allocated buffer, causing memory corruption.
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


## High

### ArrayIndexOutOfBoundsException - unchecked array access
`sdf4j/src/main/native/src/type_conversion.c:787-790`
```
/* L - sig value length */
if (l_value > HYBRIDSIGref_MAX_LEN) l_value = HYBRIDSIGref_MAX_LEN;
native_sig->L = (ULONG)l_value;

/* sig_m  */
if (sig_m_array != NULL) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
}
```
**Issue**: The code uses `l_value` (from Java object's l field) to read from `sig_m_array` without verifying the actual array length. If the Java object has l > sig_m_array.length, GetByteArrayRegion will throw a Java exception, causing unexpected JNI behavior.
**Fix**:
```
/* L - sig value length */
jsize actual_array_len = (sig_m_array != NULL) ? (*env)->GetArrayLength(env, sig_m_array) : 0;
if (l_value > HYBRIDSIGref_MAX_LEN || l_value > actual_array_len) {
    l_value = (l_value > actual_array_len) ? actual_array_len : HYBRIDSIGref_MAX_LEN;
}
native_sig->L = (ULONG)l_value;

/* sig_m  */
if (sig_m_array != NULL && l_value > 0) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
}
```

---

### Wrong package declaration - test will not compile
`sdf4j/src/test/java/org/openhitls/sdf4j/HybridAlgorithmTest.java:13`
```
package org.openhitls.sdf4j.examples;
```
**Issue**: The file is located at `sdf4j/src/test/java/org/openhitls/sdf4j/HybridAlgorithmTest.java` but declares `package org.openhitls.sdf4j.examples;`. This mismatch will cause compilation failure.
**Fix**:
```
package org.openhitls.sdf4j;
```

---


## Medium

### Duplicate function call - code redundancy
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
    g_jni_cache.initialized = true;
```
**Issue**: The `init_common_class_cache(env)` function is called twice consecutively (lines 325 and 330). This is redundant code - the second call serves no purpose since the first call already initialized the cache.
**Fix**:
```
if (init_common_class_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }
    g_jni_cache.initialized = true;
```

---


## Low

### Misleading comment - sigM is not a MAC value
`sdf4j/src/test/java/org/openhitls/sdf4j/HybridAlgorithmTest.java:204`
```
assertNotNull("MAC值不应为null", signature.getSigM());
```
**Issue**: The comment says "MAC值不应为null" (MAC value should not be null) but `sigM` is actually the post-quantum signature component (e.g., ML-DSA signature), not a MAC.
**Fix**:
```
assertNotNull("后量子签名值不应为null", signature.getSigM());
// or
assertNotNull("Post-quantum signature should not be null", signature.getSigM());
```

---
