# Code Review: openHiTLS/sdf4j#22
**Reviewer**: CODEX


## High

### Provider constructors eagerly initialize hardware and ignore the explicit path argument
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFProvider.java:52-69`
```
public SDFProvider() {
    super(PROVIDER_NAME, VERSION, INFO);
    registerAlgorithms();
    // Trigger native library loading, which auto-initializes SDF via SDF_LIBRARY_PATH
    ensureNativeLoaded();
}

/**
 * Create provider with SDF library path (backward compatibility).
 * <p>
 * Note: The libraryPath parameter is ignored. SDF library is now initialized
 * automatically via the SDF_LIBRARY_PATH environment variable.
 *
 * @param libraryPath ignored, use SDF_LIBRARY_PATH environment variable instead
 */
public SDFProvider(String libraryPath) {
    this();
}
```
**Issue**: `SDFProvider()` immediately calls into native initialization, so simple provider registration fails on machines without a configured SDF device/library. The new `SDFProviderTest` suite reproduces this: `mvn -pl sdf4j-jce -Dtest=SDFProviderTest test` fails before any cryptographic operation is requested. At the same time, `SDFProvider(String libraryPath)` claims backward compatibility but discards `libraryPath`, so existing callers that passed a path directly no longer work unless they also set external properties or environment variables.
**Fix**:
```
public SDFProvider() {
    this(null);
}

public SDFProvider(String libraryPath) {
    super(PROVIDER_NAME, VERSION, INFO);
    if (libraryPath != null && !libraryPath.trim().isEmpty()) {
        System.setProperty("sdf.library.path", libraryPath.trim());
    }
    registerAlgorithms();
}
```

---

### Native library is extracted to a predictable shared temp path
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java:98-106`
```
Path baseDir = Paths.get(System.getProperty("java.io.tmpdir"), "sdf4j-jce-native");
Files.createDirectories(baseDir);
Path tempLib = baseDir.resolve(platform + "-" + libraryFileName);

// Extract the library (always re-extract to ensure using latest version)
Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

// Load the extracted library
System.load(tempLib.toAbsolutePath().toString());
```
**Issue**: The bridge library is always written to `${java.io.tmpdir}/sdf4j-jce-native/<platform>-libsdf4j-jce.so`. On a multi-user system, that predictable shared path lets another local user pre-create or replace the file and get arbitrary native code loaded into the JVM. The existing core loader avoids this by using a fresh temp directory per load.
**Fix**:
```
Path tempDir = Files.createTempDirectory("sdf4j-jce-native-");
Path tempLib = Files.createTempFile(tempDir, LIBRARY_NAME + "-", ".so");

Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);
tempLib.toFile().deleteOnExit();
tempDir.toFile().deleteOnExit();

System.load(tempLib.toAbsolutePath().toString());
```

---

### `sm4DecryptInit` returns a live context even after native init fails
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:466-522`
```
ret = g_sdf_functions.SDF_DecryptInit(ctx->session_handle, keyHandle, algId, (BYTE *)ivBytes, (ivBytes ? SM4_IV_LENGTH : 0));
if (ret != SDR_OK) {
    g_sdf_functions.SDF_DestroyKey(ctx->session_handle, keyHandle);
    throw_jce_exception(env, (int)ret, "SM4 decrypt init failed");
}

(*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

ctx->initialized = 1;
return (jlong)(uintptr_t)ctx;
```
**Issue**: When `SDF_DecryptInit` fails, the function throws an exception but still falls through, marks the context initialized, and returns it to Java. The caller then proceeds with a half-initialized context whose key handle may already have been destroyed. This turns a clean initialization failure into follow-on decryption errors and use-after-destroy behavior.
**Fix**:
```
jsize keyLen = (*env)->GetArrayLength(env, key);
if (keyLen != SM4_KEY_LENGTH) {
    throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
    return 0;
}

jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
if (keyBytes == NULL) {
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
    return 0;
}

jbyte *ivBytes = NULL;
if (iv != NULL) {
    jsize ivLen = (*env)->GetArrayLength(env, iv);
    if (ivLen != SM4_IV_LENGTH) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "IV must be 16 bytes");
        return 0;
    }
    ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
    if (ivBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
        return 0;
    }
}

ret = g_sdf_functions.SDF_DecryptInit(
    ctx->session_handle, keyHandle, algId, (BYTE *)ivBytes, (ivBytes ? SM4_IV_LENGTH : 0));
if (ret != SDR_OK) {
    g_sdf_functions.SDF_DestroyKey(ctx->session_handle, keyHandle);
    throw_jce_exception(env, (int)ret, "SM4 decrypt init failed");
    goto ERR;
}

(*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

ctx->initialized = 1;
return (jlong)(uintptr_t)ctx;
```

---

### Public native update APIs trust caller-controlled offsets and lengths
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:393-405`
```
jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
ULONG outputBufLen = (ULONG)(len + SM4_BLOCK_SIZE);
BYTE *output = (BYTE *)malloc((size_t)outputBufLen);

LONG ret = g_sdf_functions.SDF_EncryptUpdate(ctx->session_handle, (BYTE *)(dataBytes + offset), (ULONG)len,
    output, &outputLen);
```
**Issue**: `sm4EncryptUpdate` and `sm4DecryptUpdate` do raw pointer arithmetic with `dataBytes + offset` but never verify that `offset` and `len` are within the Java array bounds. Because `SDFJceNative` is a public API, a bad caller can drive these methods into out-of-bounds native reads and crash the JVM.
**Fix**:
```
jsize dataLen = (*env)->GetArrayLength(env, data);
if (offset < 0 || len < 0 || offset > dataLen || dataLen - offset < len) {
    throw_exception(env, "java/lang/ArrayIndexOutOfBoundsException", "offset/len out of bounds");
    return NULL;
}

jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
if (dataBytes == NULL) {
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
    return NULL;
}

LONG ret = g_sdf_functions.SDF_EncryptUpdate(
    ctx->session_handle, (BYTE *)(dataBytes + offset), (ULONG)len, output, &outputLen);
```

---


## Medium

### DER parser accepts signatures with trailing garbage
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/DERCodec.java:71-99`
```
int length = in.readLength();
if (in.available() < length) {
    throw new IllegalArgumentException("DER length mismatch");
}

// INTEGER r
if (in.readTag() != 0x02) {
    throw new IllegalArgumentException("Expected INTEGER for r");
}
int rLength = in.readLength();
byte[] rBytes = in.readBytes(rLength);

// INTEGER s
if (in.readTag() != 0x02) {
    throw new IllegalArgumentException("Expected INTEGER for s");
}
int sLength = in.readLength();
byte[] sBytes = in.readBytes(sLength);
```
**Issue**: `derToRaw` only checks `in.available() < length`, then parses two INTEGERs and returns without verifying that the SEQUENCE length matched exactly or that no bytes remain. A blob like `valid_signature || attacker_controlled_suffix` is therefore accepted as a valid SM2 signature encoding, which is not DER-canonical and can cause signature-format bypasses between layers.
**Fix**:
```
int length = in.readLength();
if (length != in.available()) {
    throw new IllegalArgumentException("DER length mismatch");
}

if (in.readTag() != 0x02) {
    throw new IllegalArgumentException("Expected INTEGER for r");
}
int rLength = in.readLength();
byte[] rBytes = in.readBytes(rLength);

if (in.readTag() != 0x02) {
    throw new IllegalArgumentException("Expected INTEGER for s");
}
int sLength = in.readLength();
byte[] sBytes = in.readBytes(sLength);

if (in.available() != 0) {
    throw new IllegalArgumentException("Trailing data after DER signature");
}
```

---

### Cipher sessions are leaked until GC runs
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:64-78`
```
public SM4Cipher() {
    this.sessionHandle = SDFJceNative.openSession();
    if (sessionHandle == 0) {
        throw new IllegalStateException("Failed to open SDF session");
    }
    this.cipherMode = MODE_CBC;
}

@Override
protected void finalize() throws Throwable {
    try {
        cleanup();
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
        }
    } finally {
        super.finalize();
    }
}
```
**Issue**: Every `SM4Cipher` instance opens a device session in its constructor and only closes it from `finalize()`. JCE code tends to create many short-lived cipher instances, and hardware session counts are limited; under load this will exhaust the device long before the GC decides to run. The test suite already has to force `System.gc()` to release sessions, which is a clear sign the lifecycle is wrong.
**Fix**:
```
protected long sessionHandle;

@Override
protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
    cleanup();
    this.sessionHandle = SDFJceNative.openSession();
    if (sessionHandle == 0) {
        throw new InvalidKeyException("Failed to open SDF session");
    }
    this.opmode = opmode;
    this.key = key.getEncoded();
    ...
}

protected void cleanup() {
    if (key != null) {
        Arrays.fill(key, (byte) 0);
        key = null;
    }
    if (iv != null) {
        Arrays.fill(iv, (byte) 0);
        iv = null;
    }
    if (ctx != 0) {
        SDFJceNative.sm4Free(ctx);
        ctx = 0;
    }
    if (sessionHandle != 0) {
        SDFJceNative.closeSession(sessionHandle);
        sessionHandle = 0;
    }
}
```

---
