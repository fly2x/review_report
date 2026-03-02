# Code Review: openHiTLS/sdf4j#21
**Reviewer**: GEMINI


## High

### Null reference passed to ECCCipher constructor for empty cipher
`sdf4j/src/main/native/src/type_conversion.c:243-251`
```
jbyteArray c_array = NULL;
    if (cipher_len > 0) {
        c_array = (*env)->NewByteArray(env, cipher_len);
        if (c_array == NULL) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, c_array, 0, cipher_len, (jbyte*)&native_cipher->C);
    }
```
**Issue**: When `cipher_len` is 0, `c_array` is initialized to `NULL` and not allocated. It is then passed to the `ECCCipher` parameterized constructor. Since the Java constructor throws an `IllegalArgumentException` if the `c` array is null, this will cause a pending JNI exception and failure in the native call when attempting to create an `ECCCipher` object with an empty ciphertext.
**Fix**:
```
jbyteArray c_array = (*env)->NewByteArray(env, cipher_len);
    if (c_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    if (cipher_len > 0) {
        (*env)->SetByteArrayRegion(env, c_array, 0, cipher_len, (jbyte*)&native_cipher->C);
    }
```

---

### Buffer over-read vulnerability in HybridCipher serialization
`sdf4j/src/main/native/src/type_conversion.c:727-728`
```
/* ctM byte array */
    jsize ctm_len = (jsize)native_cipher->L1;
    jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
```
**Issue**: The bounds check `if (ctm_len > HYBRIDENCref_MAX_LEN)` was removed. If a hardware device or mock returns a `HybridCipher` structure with an `L1` value larger than `HYBRIDENCref_MAX_LEN` (1576 bytes), `SetByteArrayRegion` will read past the bounds of the fixed-size `ct_m` array, exposing adjacent uninitialized or sensitive native memory to the Java application.
**Fix**:
```
/* ctM byte array */
    jsize ctm_len = (jsize)native_cipher->L1;
    if (ctm_len > HYBRIDENCref_MAX_LEN) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Ciphertext length exceeds maximum");
        return NULL;
    }
    jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
```

---

### Buffer over-read and potential Null reference in HybridSignature serialization
`sdf4j/src/main/native/src/type_conversion.c:812-820`
```
/* sigM byte array */
    jbyteArray sig_m_array = NULL;
    if (sig_m_len > 0) {
        sig_m_array = (*env)->NewByteArray(env, sig_m_len);
        if (sig_m_array == NULL) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to new byte array");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
    }
```
**Issue**: The bounds check `if (sig_m_len > HYBRIDSIGref_MAX_LEN)` was removed. If `sig_m_len` exceeds `HYBRIDSIGref_MAX_LEN`, an out-of-bounds read will occur when `SetByteArrayRegion` accesses `native_sig->sig_m`. Additionally, if `sig_m_len` is exactly `0`, `sig_m_array` remains `NULL`, which will crash the Java `HybridSignature` constructor via an `IllegalArgumentException`.
**Fix**:
```
/* sigM byte array */
    if (sig_m_len > HYBRIDSIGref_MAX_LEN) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Signature length exceeds maximum");
        return NULL;
    }
    jbyteArray sig_m_array = (*env)->NewByteArray(env, sig_m_len);
    if (sig_m_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to new byte array");
        return NULL;
    }
    if (sig_m_len > 0) {
        (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
    }
```

---
