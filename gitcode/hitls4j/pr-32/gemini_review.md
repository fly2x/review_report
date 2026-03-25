# Code Review: openHiTLS/hitls4j#32
**Reviewer**: GEMINI


## High

### Missing NULL check after GetStringUTFChars in frodoKemCreateContext
`src/main/native/crypto_native_jni.c:3329-3333`
```
(JNIEnv *env, jclass cls, jstring jparameterSet) {
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    int paramId = getFrodoKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
```
**Issue**: The JNI function `GetStringUTFChars` can return NULL if the JVM runs out of memory. If it returns NULL, passing it to `strcmp` in `getFrodoKemParamId` will cause a segmentation fault and crash the JVM.
**Fix**:
```
(JNIEnv *env, jclass cls, jstring jparameterSet) {
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return 0;
    }
    int paramId = getFrodoKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
```

---

### Missing NULL check after GetStringUTFChars in frodoKemGenerateKeyPair
`src/main/native/crypto_native_jni.c:3359-3363`
```
int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    int paramId = getFrodoKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);

    getFrodoKemKeySizes(paramId, &publicKeySize, &privateKeySize);
```
**Issue**: `GetStringUTFChars` can return NULL. Passing NULL to `getFrodoKemParamId` will result in a segmentation fault.
**Fix**:
```
int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return NULL;
    }
    int paramId = getFrodoKemParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);

    getFrodoKemKeySizes(paramId, &publicKeySize, &privateKeySize);
```

---

### Missing NULL check after GetByteArrayElements for encapsulate key in frodoKemSetKeys
`src/main/native/crypto_native_jni.c:3449-3453`
```
CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_FRODOKEM;
        pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
        pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
```
**Issue**: `GetByteArrayElements` can return NULL on out-of-memory. Using this NULL pointer or passing it to `ReleaseByteArrayElements` will cause undefined behavior or crash the JVM.
**Fix**:
```
CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_FRODOKEM;
        pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
        if (pubKey.key.kemEk.data == NULL) {
            return;
        }
        pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
```

---

### Missing NULL check after GetByteArrayElements for decapsulate key in frodoKemSetKeys
`src/main/native/crypto_native_jni.c:3464-3468`
```
CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_FRODOKEM;
        privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
        privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
```
**Issue**: `GetByteArrayElements` can return NULL on out-of-memory. Using this NULL pointer or passing it to `ReleaseByteArrayElements` will cause undefined behavior or crash the JVM.
**Fix**:
```
CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_FRODOKEM;
        privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
        if (privKey.key.kemDk.data == NULL) {
            return;
        }
        privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
```

---

### Missing NULL check after GetStringUTFChars in mcelieceCreateContext
`src/main/native/crypto_native_jni.c:3662-3667`
```
JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    int paramId = getMcElieceParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
```
**Issue**: `GetStringUTFChars` can return NULL. Passing NULL to `getMcElieceParamId` will result in a segmentation fault.
**Fix**:
```
JNIEXPORT jlong JNICALL Java_org_openhitls_crypto_core_CryptoNative_mcelieceCreateContext
  (JNIEnv *env, jclass cls, jstring jparameterSet) {
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return 0;
    }
    int paramId = getMcElieceParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);
    if (paramId == -1) {
```

---

### Missing NULL check after GetStringUTFChars in mcelieceGenerateKeyPair
`src/main/native/crypto_native_jni.c:3693-3697`
```
int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    int paramId = getMcElieceParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);

    getMcElieceKeySizes(paramId, &publicKeySize, &privateKeySize);
```
**Issue**: `GetStringUTFChars` can return NULL. Passing NULL to `getMcElieceParamId` will result in a segmentation fault.
**Fix**:
```
int publicKeySize;
    int privateKeySize;
    const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
    if (parameterSet == NULL) {
        return NULL;
    }
    int paramId = getMcElieceParamId(parameterSet);
    (*env)->ReleaseStringUTFChars(env, jparameterSet, parameterSet);

    getMcElieceKeySizes(paramId, &publicKeySize, &privateKeySize);
```

---

### Missing NULL check after GetByteArrayElements for encapsulate key in mcelieceSetKeys
`src/main/native/crypto_native_jni.c:3783-3787`
```
CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_MCELIECE;
        pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
        pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
```
**Issue**: `GetByteArrayElements` can return NULL on out-of-memory. Using this NULL pointer or passing it to `ReleaseByteArrayElements` will cause undefined behavior or crash the JVM.
**Fix**:
```
CRYPT_EAL_PkeyPub pubKey;
        memset(&pubKey, 0, sizeof(CRYPT_EAL_PkeyPub));
        pubKey.id = CRYPT_PKEY_MCELIECE;
        pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
        if (pubKey.key.kemEk.data == NULL) {
            return;
        }
        pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);

        ret = CRYPT_EAL_PkeySetPub(pkey, &pubKey);
```

---

### Missing NULL check after GetByteArrayElements for decapsulate key in mcelieceSetKeys
`src/main/native/crypto_native_jni.c:3798-3802`
```
CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_MCELIECE;
        privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
        privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
```
**Issue**: `GetByteArrayElements` can return NULL on out-of-memory. Using this NULL pointer or passing it to `ReleaseByteArrayElements` will cause undefined behavior or crash the JVM.
**Fix**:
```
CRYPT_EAL_PkeyPrv privKey;
        memset(&privKey, 0, sizeof(CRYPT_EAL_PkeyPrv));
        privKey.id = CRYPT_PKEY_MCELIECE;
        privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
        if (privKey.key.kemDk.data == NULL) {
            return;
        }
        privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);

        ret = CRYPT_EAL_PkeySetPrv(pkey, &privKey);
```

---


## Medium

### Incorrect exception type thrown for short buffers
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:80-87`
```
@Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws InvalidParameterException {
        byte[] secret = engineGenerateSecret();
        if (sharedSecret.length - offset < secret.length) {
            throw new IllegalStateException("Insufficient space in sharedSecret array");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }
```
**Issue**: When generating a secret into an existing array that is too small, the implementation throws `IllegalStateException`. According to the JCE contract for `KeyAgreementSpi.engineGenerateSecret(byte[], int)`, a `javax.crypto.ShortBufferException` must be thrown in this case to allow calling applications to handle the size dynamically.
**Fix**:
```
@Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, javax.crypto.ShortBufferException {
        byte[] secret = engineGenerateSecret();
        if (sharedSecret.length - offset < secret.length) {
            throw new javax.crypto.ShortBufferException("Insufficient space in sharedSecret array");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }
```

---

### Incorrect exception type thrown for short buffers
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:116-123`
```
@Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws InvalidParameterException {
        byte[] secret = engineGenerateSecret();
        if (sharedSecret.length - offset < secret.length) {
            throw new IllegalStateException("Insufficient space in sharedSecret array");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }
```
**Issue**: When generating a secret into an existing array that is too small, the implementation throws `IllegalStateException`. According to the JCE contract for `KeyAgreementSpi.engineGenerateSecret(byte[], int)`, a `javax.crypto.ShortBufferException` must be thrown in this case to allow calling applications to handle the size dynamically.
**Fix**:
```
@Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, javax.crypto.ShortBufferException {
        byte[] secret = engineGenerateSecret();
        if (sharedSecret.length - offset < secret.length) {
            throw new javax.crypto.ShortBufferException("Insufficient space in sharedSecret array");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }
```

---
