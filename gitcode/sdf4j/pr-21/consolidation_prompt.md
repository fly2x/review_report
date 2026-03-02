# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdf4j
- PR: #21
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/sdf4j#21
**Reviewer**: CLAUDE


## Critical

### Integer overflow when converting ULONG to jsize
`sdf4j/src/main/native/src/type_conversion.c:725-734`
```
jsize ctm_len = (jsize)native_cipher->L1;
    jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
```
**Issue**: cipher_len is ULONG (unsigned long) but is cast to jsize (signed int). If cipher_len exceeds INT_MAX, it will overflow and cause a negative value, potentially leading to buffer allocation issues.
**Fix**:
```
jsize ctm_len = (jsize)native_cipher->L1;
    if (native_cipher->L1 > INT_MAX || native_cipher->L1 > HYBRIDENCref_MAX_LEN) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Cipher length exceeds maximum");
        return NULL;
    }
    jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
```

---


## High

### Getter returns direct reference to internal array allowing modification
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPublicKey.java:86-92`
```
public byte[] getX() {
        return x;  // Returns direct reference
    }
```
**Issue**: The getX() and getY() methods return direct references to internal arrays instead of defensive copies. This allows callers to modify the internal state of cryptographic objects, breaking encapsulation and potentially causing security vulnerabilities.
**Fix**:
```
public byte[] getX() {
        return x != null ? Arrays.copyOf(x, x.length) : null;
    }
```

---

### Getter returns direct reference to internal array allowing modification
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPrivateKey.java:72-76`
```
public byte[] getK() {
        return k;  // Returns direct reference to sensitive key material
    }
```
**Issue**: The getK() method returns a direct reference to the private key array, allowing callers to modify the key material.
**Fix**:
```
public byte[] getK() {
        return k != null ? Arrays.copyOf(k, k.length) : null;
    }
```

---

### Getter returns direct reference to internal array allowing modification
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCSignature.java:40-46`
```
public byte[] getR() {
        return r;  // Returns direct reference
    }
```
**Issue**: The getR() and getS() methods return direct references to internal arrays, allowing callers to modify signature values.
**Fix**:
```
public byte[] getR() {
        return r != null ? Arrays.copyOf(r, r.length) : null;
    }
```

---

### Getter returns direct reference to internal array allowing modification
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java:47-61`
```
public byte[] getX() {
        return x;  // Returns direct reference
    }
```
**Issue**: The getX(), getY(), getM(), and getC() methods return direct references to internal arrays, allowing callers to modify ciphertext data.
**Fix**:
```
public byte[] getX() {
        return x != null ? Arrays.copyOf(x, x.length) : null;
    }
```

---

### Getter returns direct reference to internal array allowing modification
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPublicKey.java:83-95`
```
public byte[] getM() {
        return m;  // Returns direct reference to modulus
    }
```
**Issue**: The getM() and getE() methods return direct references to internal arrays, allowing callers to modify public key material.
**Fix**:
```
public byte[] getM() {
        return m != null ? Arrays.copyOf(m, m.length) : null;
    }
```

---

### Getter returns direct reference to internal array allowing modification
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:75-135`
```
public byte[] getD() {
        return d;  // Returns direct reference to private exponent
    }
```
**Issue**: The getM(), getE(), getD(), getPrime(), getPexp(), and getCoef() methods return direct references to internal arrays, exposing private key material to modification.
**Fix**:
```
public byte[] getD() {
        return d != null ? Arrays.copyOf(d, d.length) : null;
    }
```

---

### Missing null validation in setters for sensitive key material
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:82-88`
```
public void setM(byte[] m) {
        this.m = m;  // No null check
    }
```
**Issue**: The setM(), setE(), setD(), setPrime(), setPexp(), and setCoef() methods do not validate null input, potentially allowing null key material to be set.
**Fix**:
```
public void setM(byte[] m) {
        if (m == null) {
            throw new IllegalArgumentException("Modulus cannot be null");
        }
        this.m = m;
    }
```

---

### Missing null validation in setters for key material
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPublicKey.java:84-90`
```
public void setM(byte[] m) {
        if (m == null) {
            throw new IllegalArgumentException("Modulus cannot be null");
        }
        this.m = m;  // No null check was removed
    }
```
**Issue**: The setM() and setE() methods do not validate null input.
**Fix**:
```
public void setM(byte[] m) {
        if (m == null) {
            throw new IllegalArgumentException("Modulus cannot be null");
        }
        if (m.length > RSA_MAX_LEN) {
            throw new IllegalArgumentException("Modulus too large");
        }
        this.m = m;
    }
```

---

### Direct array exposure for algorithm abilities
`sdf4j/src/main/java/org/openhitls/sdf4j/types/DeviceInfo.java:56-63`
```
public long[] getAsymAlgAbility() {
        return asymAlgAbility;  // Direct reference
    }
```
**Issue**: getAsymAlgAbility() returns direct reference to internal array.
**Fix**:
```
public long[] getAsymAlgAbility() {
        return asymAlgAbility != null ? Arrays.copyOf(asymAlgAbility, asymAlgAbility.length) : null;
    }
```

---

### Resource leak - sponsor_id_buf not released on error path
`sdf4j/src/main/native/src/sdf_jni_keygen.c:408-423`
```
jbyte *sponsor_id_buf = (*env)->GetPrimitiveArrayCritical(env, sponsorID, NULL);
    if (sponsor_id_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }
    
    /* 转换发起方ECC公钥 */
    ECCrefPublicKey sponsor_pub_key, sponsor_tmp_pub_key;
    
    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return NULL;
    }
    if (!java_to_native_ECCPublicKey(env, sponsorTmpPublicKey, &sponsor_tmp_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return NULL;
    }
```
**Issue**: If java_to_native_ECCPublicKey fails after allocating sponsor_id_buf, the buffer is not released.
**Fix**:
```
/* 转换发起方ECC公钥 */
    ECCrefPublicKey sponsor_pub_key, sponsor_tmp_pub_key;
    
    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return NULL;
    }
    if (!java_to_native_ECCPublicKey(env, sponsorTmpPublicKey, &sponsor_tmp_pub_key)) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return NULL;
    }

    /* 转换发起方ID */
    jsize sponsor_id_len = (*env)->GetArrayLength(env, sponsorID);
    jbyte *sponsor_id_buf = (*env)->GetPrimitiveArrayCritical(env, sponsorID, NULL);
    if (sponsor_id_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }
```

---

### Validation uses stale l1 value in setCtM
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java:72-79`
```
public void setCtM(byte[] ctM) {
        if (ctM == null || this.l1 > ctM.length) {  // this.l1 might be stale
            throw new IllegalArgumentException("cipher value is invalid");
        }
        this.ctM = ctM;
    }
```
**Issue**: When setCtM is called, it checks this.l1 against the new array, but this.l1 may have been set previously. The check should happen after the new l1 is set, or validation should be coordinated.
**Fix**:
```
public void setCtM(byte[] ctM) {
        if (ctM == null) {
            throw new IllegalArgumentException("cipher value cannot be null");
        }
        this.ctM = ctM;
    }
    
    public void setL1(long l1) {
        if (l1 < 0) {
            throw new IllegalArgumentException("Ciphertext length cannot be negative");
        }
        if (ctM != null && l1 > ctM.length) {
            throw new IllegalArgumentException("l1 cannot exceed ctM length");
        }
        this.l1 = l1;
    }
```

---

### Validation uses stale l value in setSigM
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridSignature.java:64-70`
```
public void setSigM(byte[] sigM) {
        if (sigM == null || this.l > sigM.length) {  // this.l might be stale
            throw new IllegalArgumentException("signature value is invalid");
        }
        this.sigM = sigM;
    }
```
**Issue**: When setSigM is called, it checks this.l which may be stale from previous usage.
**Fix**:
```
public void setSigM(byte[] sigM) {
        if (sigM == null) {
            throw new IllegalArgumentException("signature value cannot be null");
        }
        this.sigM = sigM;
    }
    
    public void setL(int l) {
        if (l < 0) {
            throw new IllegalArgumentException("Signature length cannot be negative");
        }
        if (sigM != null && l > sigM.length) {
            throw new IllegalArgumentException("l cannot exceed sigM length");
        }
        this.l = l;
    }
```

---

### Direct reference to sensitive encrypted key material
`sdf4j/src/main/java/org/openhitls/sdf4j/types/KeyEncryptionResult.java:51-55`
```
public byte[] getEncryptedKey() {
        return encryptedKey;  // Direct reference
    }
```
**Issue**: getEncryptedKey() returns direct reference to internal array containing encrypted key material.
**Fix**:
```
public byte[] getEncryptedKey() {
        return encryptedKey != null ? Arrays.copyOf(encryptedKey, encryptedKey.length) : null;
    }
```

---

### Direct reference to sensitive ciphertext data
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java:45-49`
```
public byte[] getCtM() {
        return ctM;  // Direct reference
    }
```
**Issue**: getCtM() returns direct reference to internal array containing PQC ciphertext.
**Fix**:
```
public byte[] getCtM() {
        return ctM != null ? Arrays.copyOf(ctM, ctM.length) : null;
    }
```

---

### Direct reference to signature data
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridSignature.java:53-57`
```
public byte[] getSigM() {
        return sigM;  // Direct reference
    }
```
**Issue**: getSigM() returns direct reference to internal array containing signature data.
**Fix**:
```
public byte[] getSigM() {
        return sigM != null ? Arrays.copyOf(sigM, sigM.length) : null;
    }
```

---


## Medium

### Missing null check in asymAlgAbility setter
`sdf4j/src/main/java/org/openhitls/sdf4j/types/DeviceInfo.java:49-53`
```
public DeviceInfo() {
        // asymAlgAbility no longer initialized
    }
    
    public long[] getAsymAlgAbility() {
        return asymAlgAbility;  // Could return null
    }
```
**Issue**: The setAsymAlgAbility() method checks for null but getAsymAlgAbility() returns the array directly without null check, potentially causing NPE when accessed via default constructor.
**Fix**:
```
public DeviceInfo() {
        this.asymAlgAbility = new long[2];
    }
```

---

### Constructor accepts 2D array without proper validation
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:96-104`
```
public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                         byte[][] prime, byte[][] pexp, byte[] coef) {
        // ... null check for bits
        this.prime = prime;  // No validation of array dimensions
        this.pexp = pexp;
```
**Issue**: The constructor accepts prime and pexp arrays without validating they have exactly 2 elements or that each element has correct length.
**Fix**:
```
public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                         byte[][] prime, byte[][] pexp, byte[] coef) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        if (prime == null || prime.length != 2) {
            throw new IllegalArgumentException("Prime array must have exactly 2 elements");
        }
        // ... similar for pexp
        this.prime = prime;
```

---

### Resource leak - data_buf not released on error path
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:68-73`
```
jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return;
    }
    
    ECCSignature native_sig = {0};
    if(!java_to_native_ECCSignature(env, signature, &native_sig)) {
        return;  // Leak: data_buf not released
    }
```
**Issue**: If java_to_native_ECCSignature fails after data_buf is allocated, data_buf is not released.
**Fix**:
```
ECCSignature native_sig = {0};
    if(!java_to_native_ECCSignature(env, signature, &native_sig)) {
        return;
    }
    
    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return;
    }
```

---

### Inconsistent validation - allows zero-length cipher
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java:69-77`
```
if (l < 0 || l > c.length) {
        throw new IllegalArgumentException("l is invalid");
    }
```
**Issue**: The validation allows l to be 0 even when c is non-empty, which is semantically incorrect.
**Fix**:
```
if (l < 0 || l > c.length) {
        throw new IllegalArgumentException("l is invalid");
    }
    if (l == 0 && c.length > 0) {
        throw new IllegalArgumentException("l cannot be zero when c is non-empty");
    }
```

---

### Missing validation for sig_m_len in native_to_java_HybridSignature
`sdf4j/src/main/native/src/type_conversion.c:816-820`
```
/* sigM byte array */
    jbyteArray sig_m_array = NULL;
    if (sig_m_len > 0) {
        sig_m_array = (*env)->NewByteArray(env, sig_m_len);
```
**Issue**: sig_m_len is not validated against HYBRIDSIGref_MAX_LEN before being used for array creation.
**Fix**:
```
/* sigM byte array */
    jbyteArray sig_m_array = NULL;
    if (sig_m_len > HYBRIDSIGref_MAX_LEN) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Signature M length exceeds maximum");
        return NULL;
    }
    if (sig_m_len > 0) {
        sig_m_array = (*env)->NewByteArray(env, sig_m_len);
```

---

### Removed upper bound validation for bits field
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPublicKey.java:56-63`
```
public void setBits(int bits) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;  // No upper bound check
    }
```
**Issue**: The setBits() method no longer validates that bits <= RSA_MAX_BITS, allowing invalid key sizes to be set.
**Fix**:
```
public void setBits(int bits) {
        if (bits <= 0 || bits > RSA_MAX_BITS) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
    }
```

---

### Removed upper bound validation for bits field
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPublicKey.java:62-68`
```
public void setBits(int bits) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;  // No upper bound check
    }
```
**Issue**: The setBits() method no longer validates that bits <= ECC_MAX_BITS (512).
**Fix**:
```
public void setBits(int bits) {
        if (bits <= 0 || bits > 512) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
    }
```

---

### Inconsistent error handling order - critical conversions happen before memory allocation
`sdf4j/src/main/native/src/sdf_jni_keygen.c:393-410`
```
/* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    jbyte *response_id_buf = (*env)->GetPrimitiveArrayCritical(env, responseID, NULL);
    if (response_id_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return 0;
    }

    /* 转换responsePublicKey */
    ECCrefPublicKey response_pub_key;
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return 0;
    }
```
**Issue**: Converting responsePublicKey/responseTmpPublicKey should happen BEFORE allocating critical memory (response_id_buf) to avoid needing to release on error.
**Fix**:
```
/* 转换responsePublicKey */
    ECCrefPublicKey response_pub_key;
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return 0;
    }

    ECCrefPublicKey response_tmp_pub_key;
    if (!java_to_native_ECCPublicKey(env, responseTmpPublicKey, &response_tmp_pub_key)) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert tmp public key");
        return 0;
    }

    /* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    jbyte *response_id_buf = (*env)->GetPrimitiveArrayCritical(env, responseID, NULL);
    if (response_id_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return 0;
    }
```

---


---

## CODEX Review

# Code Review: openHiTLS/sdf4j#21
**Reviewer**: CODEX


## High

### Unbounded `L1` causes out-of-bounds read when exporting `HybridCipher`
`sdf4j/src/main/native/src/type_conversion.c:754-760`
```
jsize ctm_len = (jsize)native_cipher->L1;
jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
if (ctm_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ctM array");
    return NULL;
}
(*env)->SetByteArrayRegion(env, ctm_array, 0, ctm_len, (jbyte*)native_cipher->ct_m);
```
**Issue**: `native_cipher->L1` is used directly as copy length for `ct_m` without enforcing `HYBRIDENCref_MAX_LEN`. If a device/library returns an oversized `L1`, JNI reads past the fixed `ct_m` buffer and copies invalid memory into Java.
**Fix**:
```
jsize ctm_len = (jsize)native_cipher->L1;
if (native_cipher->L1 > HYBRIDENCref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridCipher L1 exceeds 1576");
    return NULL;
}
jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
if (ctm_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ctM array");
    return NULL;
}
(*env)->SetByteArrayRegion(env, ctm_array, 0, ctm_len, (jbyte*)native_cipher->ct_m);
```

---

### Hybrid signature conversion can read past native buffer and pass invalid null arg
`sdf4j/src/main/native/src/type_conversion.c:840-853`
```
jbyteArray sig_m_array = NULL;
if (sig_m_len > 0) {
    sig_m_array = (*env)->NewByteArray(env, sig_m_len);
    if (sig_m_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to new byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
}

jobject obj = (*env)->NewObject(env, g_jni_cache.hybridSignature.cls,
                                g_jni_cache.hybridSignature.ctor,
                                ecc_sig_obj, (jint)native_sig->L, sig_m_array);
```
**Issue**: `sig_m_len` is not bounded to `HYBRIDSIGref_MAX_LEN` before copy, so oversized lengths can read past `native_sig->sig_m`. Also, when `sig_m_len == 0`, `sig_m_array` stays `NULL`, but the new Java constructor requires non-null `sigM`, causing constructor failure.
**Fix**:
```
if (sig_m_len > HYBRIDSIGref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridSignature L exceeds 4636");
    return NULL;
}

jbyteArray sig_m_array = (*env)->NewByteArray(env, (jsize)sig_m_len); /* non-null even when 0 */
if (sig_m_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to new byte array");
    return NULL;
}
if (sig_m_len > 0) {
    (*env)->SetByteArrayRegion(env, sig_m_array, 0, (jsize)sig_m_len, (jbyte*)native_sig->sig_m);
}

jobject obj = (*env)->NewObject(env, g_jni_cache.hybridSignature.cls,
                                g_jni_cache.hybridSignature.ctor,
                                ecc_sig_obj, (jint)sig_m_len, sig_m_array);
```

---

### Incomplete `l_value` validation allows invalid copy length in `java_to_native_HybridSignature_alloc`
`sdf4j/src/main/native/src/type_conversion.c:885-895`
```
if (l_value > HYBRIDSIGref_MAX_LEN) {
    free(native_sig);
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "cipher len exceeds 4636");
    return NULL;
}
native_sig->L = (ULONG)l_value;

/* sig_m  */
if (sig_m_array != NULL) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
}
```
**Issue**: Only `l_value > HYBRIDSIGref_MAX_LEN` is checked. Negative values and values larger than `sig_m_array` length are not rejected before `GetByteArrayRegion`, which can produce runtime JNI exceptions and propagate inconsistent `native_sig->L`.
**Fix**:
```
if (l_value < 0 || l_value > HYBRIDSIGref_MAX_LEN) {
    free(native_sig);
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridSignature length is invalid");
    return NULL;
}

jsize sig_m_len = (sig_m_array != NULL) ? (*env)->GetArrayLength(env, sig_m_array) : 0;
if ((jsize)l_value > sig_m_len) {
    free(native_sig);
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridSignature length exceeds sigM array length");
    return NULL;
}

native_sig->L = (ULONG)l_value;
if (sig_m_array != NULL && l_value > 0) {
    (*env)->GetByteArrayRegion(env, sig_m_array, 0, (jsize)l_value, (jbyte*)native_sig->sig_m);
}
```

---


## Medium

### Removal of `L` fallback creates ECC cipher length regression
`sdf4j/src/main/native/src/type_conversion.c:365-370`
```
/* L - cipher data length */
native_cipher->L = (ULONG)l_value;
/* C - cipher data (now properly allocated) */
if (c_array != NULL && c_len > 0) {
    (*env)->GetByteArrayRegion(env, c_array, 0, c_len, (jbyte*)native_cipher->C);
}
```
**Issue**: `native_cipher->L` is now taken only from Java field `l`; when callers populate `c` but leave `l` at default 0 (legacy/common setter usage), JNI sends zero-length ciphertext to SDF even though bytes are present, causing decryption/import failures.
**Fix**:
```
/* L - cipher data length */
native_cipher->L = (ULONG)l_value;
if (native_cipher->L == 0 && c_len > 0) {
    native_cipher->L = (ULONG)c_len;  /* keep compatibility with setC-only usage */
}
if ((ULONG)c_len < native_cipher->L) {
    free(native_cipher);
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "ECCCipher L exceeds C length");
    return NULL;
}

/* C - cipher data */
if (c_array != NULL && c_len > 0) {
    (*env)->GetByteArrayRegion(env, c_array, 0, c_len, (jbyte*)native_cipher->C);
}
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
