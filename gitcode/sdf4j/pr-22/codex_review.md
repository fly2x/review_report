# Code Review: openHiTLS/sdf4j#22
**Reviewer**: CODEX


## High

### SM2 JNI entry points copy fixed-size buffers without validating Java array lengths
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:206-228`
```
memcpy(eccPubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES, xBytes, SM2_KEY_BYTES);
memcpy(eccPubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES, yBytes, SM2_KEY_BYTES);
memcpy(eccSig.r + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes, SM2_KEY_BYTES);
memcpy(eccSig.s + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes + SM2_KEY_BYTES, SM2_KEY_BYTES);

memcpy(eccPrivKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES, privKeyBytes, SM2_KEY_BYTES);
```
**Issue**: Several SM2 native methods memcpy 32-byte and 64-byte fields out of Java byte arrays before checking that the arrays are actually that long. A short `publicKeyX`, `publicKeyY`, `signature`, or `privateKey` passed to `SDFJceNative` can make the JNI code read past the JVM-managed buffer and crash the process.
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

jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
if (privKeyLen != SM2_KEY_BYTES) {
    throw_exception(env, "java/lang/IllegalArgumentException",
                    "Private key must be 32 bytes");
    return NULL;
}

/* Apply the same length checks in sm2Encrypt/sm2Decrypt/sm2DecryptWithIndex
 * before every fixed-size memcpy. */
```

---

### Short IVs cause out-of-bounds reads in SM4 native methods
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:98-100`
```
if (ivBytes && mode != SM4_MODE_ECB) {
    memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
}

if (ivBytes) {
    memcpy(ctx->iv, ivBytes, SM4_IV_LENGTH);
}
```
**Issue**: The SM4 JNI layer copies 16 bytes from `ivBytes` whenever an IV is present, but it never verifies that the Java `iv` array is actually 16 bytes long. Passing a short IV from Java reaches a raw `memcpy` and can read past the array boundary.
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

/* Apply the same ivLen check in sm4Encrypt, sm4Decrypt,
 * sm4EncryptInit, and sm4DecryptInit. */
```

---

### Internal SM2 operations ignore the supplied PIN completely
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:151-170`
```
if (pin != NULL) {
    pinLen = (*env)->GetArrayLength(env, pin);
    pinStr = (char *)malloc((size_t)(pinLen + 1));
    ...
    (*env)->GetByteArrayRegion(env, pin, 0, pinLen, (jbyte *)pinStr);
    pinStr[pinLen] = '\0';
}

LONG ret = g_sdf_functions.SDF_InternalSign_ECC(g_session_handle, (ULONG)keyIndex,
    (BYTE *)dataBytes, (ULONG)dataLen, &signature);
```
**Issue**: `sm2SignWithIndex` and `sm2DecryptWithIndex` allocate and copy the caller's PIN, but never use it to acquire private-key access rights. On devices that require `SDF_GetPrivateKeyAccessRight`, these APIs will fail with access-denied errors while misleading callers into thinking the PIN was honored.
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

### SM4-MAC is wired to the HMAC API and ignores the IV
`sdf4j-jce/src/main/native/src/sdf_jce_mac.c:30-32`
```
CHECK_FUNCTION_RET(SDF_ExternalKeyHMACInit, env, "SDF_ExternalKeyHMACInit", NULL);
CHECK_FUNCTION_RET(SDF_HMACUpdate, env, "SDF_HMACUpdate", NULL);
CHECK_FUNCTION_RET(SDF_HMACFinal, env, "SDF_HMACFinal", NULL);

BYTE ivCopy[SM4_IV_LENGTH] = {0};
...
if (ivBytes) {
    memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
}

LONG ret = g_sdf_functions.SDF_ExternalKeyHMACInit(
    g_session_handle, SGD_SM4_MAC, (BYTE *)keyBytes, SM4_KEY_LENGTH);
```
**Issue**: The new `SM4-MAC` implementation does not call the SDF MAC API at all. It initializes `SDF_ExternalKeyHMACInit`/`SDF_HMACUpdate`/`SDF_HMACFinal` with `SGD_SM4_MAC`, and the copied IV is never passed anywhere. That means `Mac.getInstance("SM4-MAC")` is not performing the advertised SM4 CBC-MAC operation.
**Fix**:
```
CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", NULL);
CHECK_FUNCTION_RET(SDF_CalculateMAC, env, "SDF_CalculateMAC", NULL);
CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", NULL);

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

### The provider uses a single global SDF session for all operations
`sdf4j-jce/src/main/native/src/sdf_jce_init.c:18-21`
```
HANDLE g_device_handle = NULL;
HANDLE g_session_handle = NULL;
int g_sdf_initialized = 0;
...
ret = g_sdf_functions.SDF_OpenSession(g_device_handle, &g_session_handle);
...
g_sdf_initialized = 1;
```
**Issue**: The PR opens one session once and stores it in `g_session_handle` for the lifetime of the JVM. SDF hash/MAC/encrypt-init state is session-scoped, so independent JCA objects will trample each other's in-flight state and concurrent callers race on the same hardware session.
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

### Streaming SM4 contexts leak imported key handles
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:20-25`
```
typedef struct {
    int mode;
    int encrypt;
    BYTE iv[SM4_IV_LENGTH];
    int initialized;
} SM4Context;

HANDLE keyHandle = 0;
LONG ret = g_sdf_functions.SDF_ImportKey(
    g_session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
...
ctx->initialized = 1;
return (jlong)(uintptr_t)ctx;
```
**Issue**: `sm4EncryptInit` and `sm4DecryptInit` import a device key handle, but the handle is neither stored in `SM4Context` nor destroyed on success. The `Final` and `Free` paths only free the heap context, so every streaming init leaks a device key handle until the session is torn down.
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

### Provider shutdown never releases the native device/session
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFProvider.java:81-86`
```
/**
 * Shutdown the provider and release resources.
 * Resources are automatically released when JVM unloads the native library.
 */
public void shutdown() {
    // No-op - resources are cleaned up in JNI_OnUnload
}
```
**Issue**: `shutdown()` is documented as a resource-release hook, but it is a no-op. In practice the native device and session stay open until the JNI library is unloaded at JVM shutdown, which leaks scarce hardware resources in long-running processes.
**Fix**:
```
public void shutdown() {
    NativeLoader.shutdown();
}

final class NativeLoader {
    private static native void shutdown();
}
```

---

### CBC/CTR decryption silently invents a random IV when none is supplied
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:131-142`
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
**Issue**: For every non-ECB mode, `engineInit` generates a random IV whenever `params == null`, regardless of whether the cipher is being initialized for encryption or decryption. A caller who forgets to supply the IV for decrypt gets garbage plaintext instead of an immediate error.
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

### SM2PrivateKey exposes and aliases mutable private-key material
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java:29-33`
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
**Issue**: The constructor stores the caller's array directly, and `getEncoded()` returns the internal array directly. Any caller holding either reference can modify the live private key in place, zero it unexpectedly, or observe subsequent mutations.
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

### Integration helper swallows non-SDF exceptions and lets broken tests pass
`sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceIntegrationTest.java:75-85`
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
**Issue**: Every integration test catches `Exception` and delegates to `handleSdfException`, but the helper only acts on `SDFJceException`. Any `AssertionError`, `SignatureException`, `ProviderException`, or plain `RuntimeException` is silently ignored, so the test method returns green even though it actually failed.
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

### Example tests also suppress unexpected failures
`sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceExamples.java:45-55`
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
**Issue**: The example suite has the same helper bug as the integration suite: it catches `Exception` everywhere, but only rethrows `SDFJceException`. That means example regressions can fail internally and still report success, defeating the point of shipping them as executable documentation.
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

### The documented SM2 signing flow omits the required public-key parameter
`sdf4j-jce/README.md:61-67`
```
// SM2 签名（遵循 GM/T 0009-2012 标准）
KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
KeyPair keyPair = kpg.generateKeyPair();
Signature signer = Signature.getInstance("SM3withSM2", "SDF");
signer.initSign(keyPair.getPrivate());
signer.update("Hello".getBytes());
byte[] signature = signer.sign();
```
**Issue**: The README shows `SM3withSM2` signing without ever setting `SM2ParameterSpec`. The implementation in this PR explicitly requires the public key to compute `Z`, so following the documented snippet throws `SignatureException` at runtime instead of producing a signature.
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
