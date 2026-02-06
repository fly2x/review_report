# Code Review: openHiTLS/sdf4j#13
**Reviewer**: GEMINI


## Medium

### Code Duplication in RSA Public Key Conversion
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:366`
```
/* 转换公钥 */
    RSArefPublicKey native_key;
    memset(&native_key, 0, sizeof(RSArefPublicKey));

    jclass key_class = (*env)->GetObjectClass(env, publicKey);
    
    /* 获取bits字段 */
    jfieldID bits_fid = (*env)->GetFieldID(env, key_class, "bits", "I");
    if (bits_fid == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000001, "Cannot get bits field");
        return NULL;
    }
    native_key.bits = (*env)->GetIntField(env, publicKey, bits_fid);

    /* 获取m字段 */
    jfieldID m_fid = (*env)->GetFieldID(env, key_class, "m", "[B");
    if (m_fid != NULL) {
        jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, m_fid);
        if (m_array != NULL) {
            jsize m_len = (*env)->GetArrayLength(env, m_array);
            if (m_len > RSAref_MAX_LEN) m_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, m_array, 0, m_len, (jbyte*)native_key.m);
        }
    }

    /* 获取e字段 */
    jfieldID e_fid = (*env)->GetFieldID(env, key_class, "e", "[B");
    if (e_fid != NULL) {
        jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, e_fid);
        if (e_array != NULL) {
            jsize e_len = (*env)->GetArrayLength(env, e_array);
            if (e_len > RSAref_MAX_LEN) e_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, e_array, 0, e_len, (jbyte*)native_key.e);
        }
    }
```
**Issue**: The function `JNI_SDF_ExternalPublicKeyOperation_RSA` manually converts the Java RSA public key to the native `RSArefPublicKey` structure. This duplicates the logic already implemented in `java_to_native_RSAPublicKey` (declared in `type_conversion.h`), increasing maintenance burden and the risk of inconsistencies (e.g., if the helper function is updated to handle edge cases).
**Fix**:
```
/* 转换公钥 */
    RSArefPublicKey native_key;
    if (!java_to_native_RSAPublicKey(env, publicKey, &native_key)) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return NULL;
    }
```

---


## Low

### Incorrect Error Message in JNI_SDF_GenerateKeyPair_RSA
`sdf4j/src/main/native/src/sdf_jni_util.c:46`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_GenerateKeyPair_RSA` fails. This is misleading as the operation is key generation, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate RSA key pair");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_GenerateKeyPair_ECC
`sdf4j/src/main/native/src/sdf_jni_util.c:97`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_GenerateKeyPair_ECC` fails. This is misleading as the operation is key generation, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate ECC key pair");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalPrivateKeyOperation_RSA
`sdf4j/src/main/native/src/sdf_jni_util.c:170`
```
if (ret != SDR_OK) {
        free(output_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalPrivateKeyOperation_RSA` fails. This is misleading as the operation is RSA private key operation, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(output_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform RSA private key operation");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalSign_ECC
`sdf4j/src/main/native/src/sdf_jni_util.c:225`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalSign_ECC` fails. This is misleading as the operation is ECC signing, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to sign with external private key");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalDecrypt_ECC
`sdf4j/src/main/native/src/sdf_jni_util.c:284`
```
if (ret != SDR_OK) {
        free(ecc_cipher);
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalDecrypt_ECC` fails. This is misleading as the operation is ECC decryption, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(ecc_cipher);
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to decrypt with external private key");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyEncrypt
`sdf4j/src/main/native/src/sdf_jni_util.c:375`
```
if (ret != SDR_OK) {
        free(enc_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyEncrypt` fails. This is misleading as the operation is symmetric encryption, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(enc_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform symmetric encryption");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyDecrypt
`sdf4j/src/main/native/src/sdf_jni_util.c:465`
```
if (ret != SDR_OK) {
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyDecrypt` fails. This is misleading as the operation is symmetric decryption, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform symmetric decryption");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyEncryptInit
`sdf4j/src/main/native/src/sdf_jni_util.c:524`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyEncryptInit` fails. This is misleading as the operation is symmetric encryption initialization, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize symmetric encryption");
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyDecryptInit
`sdf4j/src/main/native/src/sdf_jni_util.c:577`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyDecryptInit` fails. This is misleading as the operation is symmetric decryption initialization, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize symmetric decryption");
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyHMACInit
`sdf4j/src/main/native/src/sdf_jni_util.c:612`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyHMACInit` fails. While HMAC is related to hash, the message should be more specific to the initialization failure.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize HMAC operation");
    }
```

---
