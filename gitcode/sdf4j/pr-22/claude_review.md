# Code Review: openHiTLS/sdf4j#22
**Reviewer**: CLAUDE


## High

### Context freed before error check in sm4EncryptFinal
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:365-371`
```
LONG ret = g_sdf_functions.SDF_EncryptFinal(ctx->session_handle, output, &outputLen);

    ctx->initialized = 0;
    free(ctx);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 encrypt final failed");
        return NULL;
    }
```
**Issue**: The context is freed (free(ctx)) before checking the return value of SDF_EncryptFinal. If the operation fails, the context is freed and then an exception is thrown. The Java side still has a reference to the freed context handle, and if cleanup code (like finalize() or explicit cleanup) calls sm4Free again, it will cause a double-free vulnerability.
**Fix**:
```
LONG ret = g_sdf_functions.SDF_EncryptFinal(ctx->session_handle, output, &outputLen);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 encrypt final failed");
        free(ctx);
        return NULL;
    }

    ctx->initialized = 0;
    free(ctx);

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    return result;
```

---

### Context freed before error check in sm4DecryptFinal
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:522-528`
```
LONG ret = g_sdf_functions.SDF_DecryptFinal(ctx->session_handle, output, &outputLen);

    ctx->initialized = 0;
    free(ctx);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 decrypt final failed");
        return NULL;
    }
```
**Issue**: Same issue as sm4EncryptFinal. The context is freed before checking the return value, leading to potential double-free if error handling code attempts to clean up.
**Fix**:
```
LONG ret = g_sdf_functions.SDF_DecryptFinal(ctx->session_handle, output, &outputLen);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 decrypt final failed");
        free(ctx);
        return NULL;
    }

    ctx->initialized = 0;
    free(ctx);

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    return result;
```

---

### sm2Sign modifies caller's private key array
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:117-122`
```
ERR:
    /* Clear sensitive data in JNI buffer before releasing */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
```
**Issue**: After memset(privKeyBytes, 0, ...) to clear sensitive data, ReleaseByteArrayElements is called with mode 0 which copies back to the original array. This writes zeros to the caller's original private key array, causing unexpected data corruption.
**Fix**:
```
ERR:
    /* Clear sensitive data in JNI buffer before releasing */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
```

---

### sm2Decrypt modifies caller's private key array
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:264-269`
```
ERR:
    /* 清除敏感数据 */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
```
**Issue**: Same issue as sm2Sign - zeros are written to the caller's original array due to using ReleaseByteArrayElements with mode 0 after memset.
**Fix**:
```
ERR:
    /* 清除敏感数据 */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
```

---


## Medium

### Memory leak in SM3MessageDigest.engineDigest
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:69-71`
```
byte[] result = SDFJceNative.sm3Final(ctx);
        ctx = 0;
        initialized = false;
```
**Issue**: After calling sm3Final, the native context (allocated by sm3Init with malloc) is never freed. The ctx is set to 0 but sm3Free is never called, causing a memory leak for each digest operation.
**Fix**:
```
byte[] result = SDFJceNative.sm3Final(ctx);
        SDFJceNative.sm3Free(ctx);
        ctx = 0;
        initialized = false;
```

---

### SM2PrivateKey doesn't clone key bytes, allowing external modification
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java:33`
```
public SM2PrivateKey(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        this.keyBytes = keyBytes;
    }

    @Override
    public byte[] getEncoded() {
        return keyBytes;
    }
```
**Issue**: The constructor assigns the keyBytes reference directly without cloning. This allows external code to modify the internal key state. Additionally, getEncoded() returns the internal array directly, and destroy() zeros the array which affects the caller's original array if they passed it directly to the constructor.
**Fix**:
```
public SM2PrivateKey(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        this.keyBytes = keyBytes.clone();
    }

    @Override
    public byte[] getEncoded() {
        return keyBytes.clone();
    }
```

---


## Low

### sm3Free doesn't clear sensitive data before freeing
`sdf4j-jce/src/main/native/src/sdf_jce_sm3.c:192-193`
```
SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    free(ctx);
```
**Issue**: The sm3Free function frees the context without clearing potentially sensitive data. For consistency with sm4Free which does memset before free, sm3Free should also clear the context.
**Fix**:
```
SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(SM3Context));
    free(ctx);
```

---

### SM2PublicKey getX/getY return internal arrays without cloning
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PublicKey.java:36-37`
```
public byte[] getX() {
        return x;
    }

    public byte[] getY() {
        return y;
    }
```
**Issue**: The getX() and getY() methods return the internal byte arrays directly without cloning, allowing external modification of the key's internal state.
**Fix**:
```
public byte[] getX() {
        return x.clone();
    }

    public byte[] getY() {
        return y.clone();
    }
```

---

### SM2ParameterSpec.getUserId returns internal array without cloning
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/spec/SM2ParameterSpec.java:81`
```
public byte[] getUserId() {
        return userId;
    }
```
**Issue**: The getUserId() method returns the internal userId array directly without cloning, allowing external modification.
**Fix**:
```
public byte[] getUserId() {
        return userId.clone();
    }
```

---

### SM2Cipher.engineSetPadding accepts unsupported padding mode
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:237`
```
@Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding) && !"PKCS1Padding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("SM2 only supports NoPadding");
        }
    }
```
**Issue**: The engineSetPadding method accepts "PKCS1Padding" but the comment says SM2 only supports NoPadding. This is misleading and the method should throw an exception for unsupported padding.
**Fix**:
```
@Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("SM2 only supports NoPadding");
        }
    }
```

---

### sm2Verify doesn't check signature length
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:195-201`
```
jsize xLen = (*env)->GetArrayLength(env, publicKeyX);
    jsize yLen = (*env)->GetArrayLength(env, publicKeyY);
    if (xLen != SM2_KEY_BYTES || yLen != SM2_KEY_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "SM2 public key/signature length is invalid");
        return JNI_FALSE;
    }
```
**Issue**: The sm2Verify function checks publicKeyX and publicKeyY lengths but doesn't validate the signature array length. A malformed signature could cause out-of-bounds read when accessing sigBytes.
**Fix**:
```
jsize xLen = (*env)->GetArrayLength(env, publicKeyX);
    jsize yLen = (*env)->GetArrayLength(env, publicKeyY);
    jsize sigLen = (*env)->GetArrayLength(env, signature);
    if (xLen != SM2_KEY_BYTES || yLen != SM2_KEY_BYTES || sigLen != SM2_SIGNATURE_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "SM2 public key/signature length is invalid");
        return JNI_FALSE;
    }
```

---
