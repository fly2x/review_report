# Code Review: openHiTLS/sdf4j#23
**Reviewer**: GEMINI


## Critical

### Uninitialized pointer `ct_m` in dynamically allocated `HybridCipher`
`sdf4j/src/main/native/src/sdf_jni_hybrid.c:104-110`
```
HybridCipher *cipher = (HybridCipher*)malloc(sizeof(HybridCipher) + HYBRIDENCref_ECC_FIXED_LEN + 
        HYBRIDENCref_MAX_LEN);
    if (cipher == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKey, pub_key_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for cipher");
        return NULL;
    }
```
**Issue**: The PR updates `HybridCipher` so that `ct_m` is a pointer instead of an inline array. In `JNI_SDF_GenerateKeyWithEPK_Hybrid`, memory is allocated for the struct and the data buffers, but the `ct_m` pointer is never initialized to point to the allocated data section. When the underlying SDF library writes the ciphertext to `cipher->ct_m`, it will write to a garbage, uninitialized pointer, leading to a segmentation fault or memory corruption.
**Fix**:
```
HybridCipher *cipher = (HybridCipher*)malloc(sizeof(HybridCipher) + HYBRIDENCref_ECC_FIXED_LEN + 
        HYBRIDENCref_MAX_LEN);
    if (cipher == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKey, pub_key_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for cipher");
        return NULL;
    }
    cipher->ct_m = (BYTE*)cipher + sizeof(HybridCipher) + HYBRIDENCref_ECC_FIXED_LEN;
```

---

### Uninitialized pointer `sig_m` in dynamically allocated `HybridSignature`
`sdf4j/src/main/native/src/sdf_jni_hybrid.c:152-157`
```
HybridSignature *signature = (HybridSignature*)malloc(sizeof(HybridSignature) + HYBRIDSIGref_MAX_LEN);
    if (signature == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for signature");
        return NULL;
    }
```
**Issue**: The PR updates `HybridSignature` so that `sig_m` is a pointer instead of an inline array. In `JNI_SDF_InternalSign_Composite`, memory is allocated to hold the struct and the signature data, but the `sig_m` pointer is not assigned. When the underlying SDF function attempts to write the signature to `signature->sig_m`, it will dereference an uninitialized pointer and crash the JVM.
**Fix**:
```
HybridSignature *signature = (HybridSignature*)malloc(sizeof(HybridSignature) + HYBRIDSIGref_MAX_LEN);
    if (signature == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for signature");
        return NULL;
    }
    signature->sig_m = (BYTE*)signature + sizeof(HybridSignature);
```

---


## High

### Heap buffer over-read during `ECCCipher` copy
`sdf4j/src/main/native/src/type_conversion.c:823-826`
```
/* ct_s */
    if (temp_cts != NULL) {
        memcpy(&native_cipher->ct_s, temp_cts, sizeof(ECCCipher) + HYBRIDENCref_ECC_FIXED_LEN);
        free(temp_cts);
    }
```
**Issue**: In `java_to_native_HybridCipher_alloc`, `temp_cts` is dynamically allocated based on the length of the `C` byte array from the Java object. However, the modified `memcpy` hardcodes reading `sizeof(ECCCipher) + HYBRIDENCref_ECC_FIXED_LEN` (32 extra bytes) from `temp_cts`. If the Java object provided fewer than 32 bytes for the flexible array, this `memcpy` will read out of bounds from the heap, potentially crashing or leaking memory.
**Fix**:
```
/* ct_s */
    if (temp_cts != NULL) {
        size_t copy_len = temp_cts->L < HYBRIDENCref_ECC_FIXED_LEN ? temp_cts->L : HYBRIDENCref_ECC_FIXED_LEN;
        memcpy(&native_cipher->ct_s, temp_cts, sizeof(ECCCipher) + copy_len);
        free(temp_cts);
    }
```

---
