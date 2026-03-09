# Final Code Review Report
## openHiTLS/sdf4j - PR #22

### Summary
- **Total Issues**: 15
- **Critical**: 2
- **High**: 4
- **Medium**: 6
- **Low**: 3
- **Reviewers**: claude, gemini, codex

---


## Critical

### SM2 JNI functions copy fixed-size buffers without validating Java array lengths
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:198-240`
**Reviewers**: CODEX | **置信度**: 可信
```
jbyte *xBytes = (*env)->GetByteArrayElements(env, publicKeyX, NULL);
jbyte *yBytes = (*env)->GetByteArrayElements(env, publicKeyY, NULL);
...
ECCrefPublicKey eccPubKey;
memset(&eccPubKey, 0, sizeof(eccPubKey));
eccPubKey.bits = SM2_KEY_BITS;
memcpy(eccPubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES, xBytes, SM2_KEY_BYTES);
memcpy(eccPubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES, yBytes, SM2_KEY_BYTES);
```
**Issue**: The sm2Verify function (and other SM2 JNI functions) performs memcpy operations on Java byte arrays before checking their actual lengths. If a malicious or buggy caller provides short arrays (publicKeyX, publicKeyY, signature), the code will read past the array boundary, causing memory corruption or crash.
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

jbyte *xBytes = (*env)->GetByteArrayElements(env, publicKeyX, NULL);
jbyte *yBytes = (*env)->GetByteArrayElements(env, publicKeyY, NULL);
...
ECCrefPublicKey eccPubKey;
memset(&eccPubKey, 0, sizeof(eccPubKey));
eccPubKey.bits = SM2_KEY_BITS;
memcpy(eccPubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES, xBytes, SM2_KEY_BYTES);
memcpy(eccPubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES, yBytes, SM2_KEY_BYTES);
```

---

### SM4 JNI functions copy IV without validating length
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:98-100`
**Reviewers**: CODEX | **置信度**: 可信
```
if (ivBytes && mode != SM4_MODE_ECB) {
    memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
}
```
**Issue**: The sm4Encrypt and sm4Decrypt functions copy 16 bytes from the IV array using memcpy without first verifying the Java array is actually 16 bytes long. Passing a short IV causes out-of-bounds memory read.
**Fix**:
```
if (iv != NULL) {
    jsize ivLen = (*env)->GetArrayLength(env, iv);
    if (ivLen != SM4_IV_LENGTH) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "IV must be 16 bytes");
        goto ERR;
    }
}

if (ivBytes && mode != SM4_MODE_ECB) {
    memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
}
```

---


## High

### SM2PublicKey.getX() and getY() return internal arrays directly
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PublicKey.java:68-74`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
public byte[] getX() {
    return x;
}

public byte[] getY() {
    return y;
}
```
**Issue**: The getX() and getY() methods return the internal x and y arrays directly instead of defensive copies. This allows callers to modify the public key coordinates externally, which is a security vulnerability.
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

### SM2PrivateKey constructor stores reference and getEncoded() returns internal array
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java:29-34`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
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
**Issue**: The constructor stores the caller's array reference directly (not a copy), and getEncoded() returns the internal array. Callers can modify the private key material, and destroy() will zero the original caller's array unexpectedly.
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

### SM4-MAC uses HMAC API instead of SDF MAC API and ignores IV
`sdf4j-jce/src/main/native/src/sdf_jce_mac.c:25-88`
**Reviewers**: CODEX | **置信度**: 可信
```
CHECK_FUNCTION_RET(SDF_ExternalKeyHMACInit, env, "SDF_ExternalKeyHMACInit", NULL);
CHECK_FUNCTION_RET(SDF_HMACUpdate, env, "SDF_HMACUpdate", NULL);
CHECK_FUNCTION_RET(SDF_HMACFinal, env, "SDF_HMACFinal", NULL);
...
BYTE ivCopy[SM4_IV_LENGTH] = {0};
if (ivBytes) {
    memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
}
LONG ret = g_sdf_functions.SDF_ExternalKeyHMACInit(
    g_session_handle, SGD_SM4_MAC, (BYTE *)keyBytes, SM4_KEY_LENGTH);
```
**Issue**: The sm4Mac function uses SDF_ExternalKeyHMACInit/SDF_HMACUpdate/SDF_HMACFinal instead of the proper SDF MAC APIs (SDF_ImportKey/SDF_CalculateMAC). The IV parameter is copied but never used, meaning SM4-MAC does not perform the advertised SM4 CBC-MAC operation.
**Fix**:
```
CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", NULL);
CHECK_FUNCTION_RET(SDF_CalculateMAC, env, "SDF_CalculateMAC", NULL);
CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", NULL);
...
HANDLE keyHandle = 0;
LONG ret = g_sdf_functions.SDF_ImportKey(
    g_session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
if (ret != SDR_OK) {
    throw_jce_exception(env, (int)ret, "SM4 MAC import key failed");
    goto ERR;
}

ret = g_sdf_functions.SDF_CalculateMAC(
    g_session_handle, keyHandle, SGD_SM4_MAC, ivCopy,
    (BYTE *)dataBytes, (ULONG)dataLen, mac, &macLen);

g_sdf_functions.SDF_DestroyKey(g_session_handle, keyHandle);
```

---

### Provider uses single global SDF session for all operations
`sdf4j-jce/src/main/native/src/sdf_jce_init.c:18-21`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
HANDLE g_device_handle = NULL;
HANDLE g_session_handle = NULL;
int g_sdf_initialized = 0;
...
ret = g_sdf_functions.SDF_OpenSession(g_device_handle, &g_session_handle);
```
**Issue**: The JCE provider opens one session (g_session_handle) once and stores it globally for the JVM lifetime. Since SDF hash/MAC/encrypt-init state is session-scoped, concurrent operations will interfere with each other, and stateful operations race on the same hardware session.
**Fix**:
```
HANDLE g_device_handle = NULL;
int g_sdf_initialized = 0;

int sdf_jce_open_session(HANDLE *session) {
    return g_sdf_functions.SDF_OpenSession(g_device_handle, session);
}

void sdf_jce_close_session(HANDLE session) {
    if (session != NULL && g_sdf_functions.SDF_CloseSession != NULL) {
        g_sdf_functions.SDF_CloseSession(session);
    }
}

/* Stateful operations (SM3, streaming SM4, MAC) should open their own session
 * in init and close it in final/free instead of reusing a global session. */
```

---


## Medium

### sm2SignWithIndex accepts PIN parameter but never uses it
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:151-170`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
if (pin != NULL) {
    pinLen = (*env)->GetArrayLength(env, pin);
    pinStr = (char *)malloc((size_t)(pinLen + 1));
    ...
    (*env)->GetByteArrayRegion(env, pin, 0, pinLen, (jbyte *)pinStr);
    pinStr[pinLen] = '\0';
}

ECCSignature signature = {0};
...
LONG ret = g_sdf_functions.SDF_InternalSign_ECC(g_session_handle, (ULONG)keyIndex, (BYTE *)dataBytes,
    (ULONG)dataLen, &signature);
```
**Issue**: The sm2SignWithIndex function allocates and copies the PIN parameter, but never uses it for authorization. On devices requiring SDF_GetPrivateKeyAccessRight, this API will fail with access-denied errors while misleading callers into thinking the PIN was honored.
**Fix**:
```
CHECK_FUNCTION_RET(SDF_GetPrivateKeyAccessRight, env,
                   "SDF_GetPrivateKeyAccessRight", NULL);
CHECK_FUNCTION_RET(SDF_ReleasePrivateKeyAccessRight, env,
                   "SDF_ReleasePrivateKeyAccessRight", NULL);

int accessGranted = 0;
if (pinStr != NULL) {
    ret = g_sdf_functions.SDF_GetPrivateKeyAccessRight(
        g_session_handle, (ULONG)keyIndex, pinStr, (ULONG)strlen(pinStr));
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Get private key access right failed");
        goto ERR;
    }
    accessGranted = 1;
}

ret = g_sdf_functions.SDF_InternalSign_ECC(
    g_session_handle, (ULONG)keyIndex, (BYTE *)dataBytes, (ULONG)dataLen, &signature);

ERR:
if (accessGranted) {
    g_sdf_functions.SDF_ReleasePrivateKeyAccessRight(g_session_handle, (ULONG)keyIndex);
}
```

---

### Streaming SM4 contexts leak imported key handles
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:20-25`
**Reviewers**: CODEX | **置信度**: 可信
```
typedef struct {
    int mode;
    int encrypt;
    BYTE iv[SM4_IV_LENGTH];
    int initialized;
} SM4Context;
...
HANDLE keyHandle = 0;
LONG ret = g_sdf_functions.SDF_ImportKey(
    g_session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
...
ctx->initialized = 1;
return (jlong)(uintptr_t)ctx;
```
**Issue**: sm4EncryptInit and sm4DecryptInit import a device key handle, but the handle is neither stored in SM4Context nor destroyed on success. Every streaming init leaks a device key handle until the session is torn down.
**Fix**:
```
typedef struct {
    int mode;
    int encrypt;
    BYTE iv[SM4_IV_LENGTH];
    HANDLE keyHandle;
    int initialized;
} SM4Context;

ctx->keyHandle = 0;
ret = g_sdf_functions.SDF_ImportKey(
    g_session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &ctx->keyHandle);
...
ret = g_sdf_functions.SDF_EncryptInit(
    g_session_handle, ctx->keyHandle, algId, ctx->iv, SM4_IV_LENGTH);

...

if (ctx->keyHandle != 0) {
    g_sdf_functions.SDF_DestroyKey(g_session_handle, ctx->keyHandle);
    ctx->keyHandle = 0;
}
free(ctx);
```

---

### Provider shutdown() is no-op and never releases native device/session
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFProvider.java:84-86`
**Reviewers**: CODEX | **置信度**: 可信
```
/**
 * Shutdown the provider and release resources.
 * Resources are automatically released when JVM unloads the native library.
 */
public void shutdown() {
    // No-op - resources are cleaned up in JNI_OnUnload
}
```
**Issue**: The shutdown() method is documented as a resource-release hook but is a no-op. The native device and session stay open until the JNI library is unloaded at JVM shutdown, leaking scarce hardware resources in long-running processes.
**Fix**:
```
/**
 * Shutdown the provider and release resources.
 */
public void shutdown() {
    NativeLoader.shutdown();
}

final class NativeLoader {
    private static native void shutdown();
}
```

---

### CBC/CTR decryption generates random IV when none supplied
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:131-142`
**Reviewers**: CODEX | **置信度**: 可信
```
if (params != null) {
    if (params instanceof IvParameterSpec) {
        this.iv = ((IvParameterSpec) params).getIV();
    } else {
        throw new InvalidAlgorithmParameterException("Unsupported parameter type");
    }
} else if (cipherMode != MODE_ECB) {
    // Generate random IV for non-ECB modes
    this.iv = new byte[BLOCK_SIZE];
    SecureRandom rng = (random != null) ? random : new SecureRandom();
    rng.nextBytes(this.iv);
}
```
**Issue**: For every non-ECB mode, engineInit generates a random IV when params==null, regardless of encryption or decryption mode. A caller who forgets to supply the IV for decryption gets garbage plaintext instead of an immediate error.
**Fix**:
```
if (params != null) {
    if (!(params instanceof IvParameterSpec)) {
        throw new InvalidAlgorithmParameterException("Unsupported parameter type");
    }
    this.iv = ((IvParameterSpec) params).getIV();
    if (this.iv == null || this.iv.length != BLOCK_SIZE) {
        throw new InvalidAlgorithmParameterException("IV must be 16 bytes");
    }
} else if (cipherMode != MODE_ECB) {
    if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
        throw new InvalidAlgorithmParameterException("IV required for decryption");
    }
    this.iv = new byte[BLOCK_SIZE];
    SecureRandom rng = (random != null) ? random : new SecureRandom();
    rng.nextBytes(this.iv);
}
```

---

### Integration test helper swallows non-SDF exceptions
`sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceIntegrationTest.java:75-86`
**Reviewers**: CODEX | **置信度**: 可信
```
private void handleSdfException(Exception e, String testName) throws Exception {
    if (e instanceof SDFJceException) {
        SDFJceException sdfEx = (SDFJceException) e;
        if (sdfEx.getErrorCode() == SDFJceErrorCode.SDR_NOTSUPPORT) {
            System.out.println("[跳过] " + testName + ": 操作不支持");
            Assume.assumeTrue(testName + " not supported", false);
            return;
        }
        System.err.println("[错误] " + testName + ": " + e.getMessage());
        throw e;
    }
}
```
**Issue**: The handleSdfException helper catches Exception but only rethrows SDFJceException. Any AssertionError, SignatureException, ProviderException, or plain RuntimeException is silently ignored, so tests return green even when they actually fail.
**Fix**:
```
private void handleSdfException(Exception e, String testName) throws Exception {
    if (e instanceof SDFJceException) {
        SDFJceException sdfEx = (SDFJceException) e;
        if (sdfEx.getErrorCode() == SDFJceErrorCode.SDR_NOTSUPPORT) {
            System.out.println("[跳过] " + testName + ": 操作不支持");
            Assume.assumeTrue(testName + " not supported", false);
            return;
        }
        System.err.println("[错误] " + testName + ": " + e.getMessage());
    }
    throw e;
}
```

---

### Example test helper swallows non-SDF exceptions
`sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceExamples.java:45-56`
**Reviewers**: CODEX | **置信度**: 可信
```
private void handleSdfException(Exception e, String testName) throws Exception {
    if (e instanceof SDFJceException) {
        SDFJceException sdfEx = (SDFJceException) e;
        if (sdfEx.getErrorCode() == SDFJceErrorCode.SDR_NOTSUPPORT) {
            System.out.println("[跳过] " + testName + ": 操作不支持");
            Assume.assumeTrue(testName + " not supported", false);
            return;
        }
        System.err.println("[错误] " + testName + ": " + e.getMessage());
        throw e;
    }
}
```
**Issue**: The example suite has the same bug as the integration suite: handleSdfException catches Exception but only rethrows SDFJceException. Example regressions can fail internally and still report success.
**Fix**:
```
private void handleSdfException(Exception e, String testName) throws Exception {
    if (e instanceof SDFJceException) {
        SDFJceException sdfEx = (SDFJceException) e;
        if (sdfEx.getErrorCode() == SDFJceErrorCode.SDR_NOTSUPPORT) {
            System.out.println("[跳过] " + testName + ": 操作不支持");
            Assume.assumeTrue(testName + " not supported", false);
            return;
        }
        System.err.println("[错误] " + testName + ": " + e.getMessage());
    }
    throw e;
}
```

---


## Low

### Documentation omits required SM2ParameterSpec for signing
`sdf4j-jce/README.md:61-67`
**Reviewers**: CODEX | **置信度**: 可信
```
// SM2 签名（遵循 GM/T 0009-2012 标准）
KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
KeyPair keyPair = kpg.generateKeyPair();
Signature signer = Signature.getInstance("SM3withSM2", "SDF");
signer.initSign(keyPair.getPrivate());
signer.update("Hello".getBytes());
byte[] signature = signer.sign();
```
**Issue**: The README shows SM3withSM2 signing without setting SM2ParameterSpec. The implementation explicitly requires the public key to compute Z value, so following the documented snippet throws SignatureException at runtime.
**Fix**:
```
// SM2 签名（遵循 GM/T 0009-2012 标准）
KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
KeyPair keyPair = kpg.generateKeyPair();
Signature signer = Signature.getInstance("SM3withSM2", "SDF");
signer.initSign(keyPair.getPrivate());
signer.setParameter(new SM2ParameterSpec((SM2PublicKey) keyPair.getPublic()));
signer.update("Hello".getBytes());
byte[] signature = signer.sign();
```

---

### SM3MessageDigest.engineReset() may free already-freed context
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:38-44`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
@Override
protected void engineReset() {
    if (ctx != 0) {
        SDFJceNative.sm3Free(ctx);
        ctx = 0;
    }
    initialized = false;
}
```
**Issue**: The engineReset() method calls sm3Free(ctx) and sets ctx=0. While engineDigest() also frees the context and sets ctx=0, if there were an exception path that didn't set ctx=0, double-free could occur. However, the JNI layer should handle this safely.
**Fix**:
```
@Override
protected void engineReset() {
    if (ctx != 0) {
        SDFJceNative.sm3Free(ctx);
        ctx = 0;
    }
    initialized = false;
}
```

---

### loadLibraryFromResources() always re-extracts and doesn't clean up old temp files
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java:98-102`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
// Extract the library (always re-extract to ensure using latest version)
Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

// Load the extracted library
System.load(tempLib.toAbsolutePath().toString());
```
**Issue**: The method always re-extracts the library to temp directory. Old temp files remain and could accumulate. Multiple JVMs using this simultaneously could race on the temp file.
**Fix**:
```
// Extract the library (always re-extract to ensure using latest version)
Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

// Load the extracted library
System.load(tempLib.toAbsolutePath().toString());

// Clean up on JVM exit
tempLib.toFile().deleteOnExit();
```

---
