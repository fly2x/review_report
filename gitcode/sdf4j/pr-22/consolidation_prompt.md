# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdf4j
- PR: #22
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/sdf4j#22
**Reviewer**: CLAUDE


## High

### Missing IV length validation in sm4EncryptInit
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:224-238`
```
jbyte *ivBytes = NULL;
if (iv != NULL) {
    jsize ivLen = (*env)->GetArrayLength(env, iv);
    if (ivLen != SM4_IV_LENGTH) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "IV must be 16 bytes");
        return 0;
    }
    ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
}
```
**Issue**: When iv parameter is non-NULL, the code checks IV length in decryptInit but not in encryptInit. This could lead to buffer over-read if an incorrectly sized IV is passed.
**Fix**:
```
jbyte *ivBytes = NULL;
jsize ivLen = 0;
if (iv != NULL) {
    ivLen = (*env)->GetArrayLength(env, iv);
    if (ivLen != SM4_IV_LENGTH) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "IV must be 16 bytes");
        return 0;
    }
    ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
}
```

---


## Medium

### SM2PublicKey exposes internal key arrays
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PublicKey.java:65-68`
```
public byte[] getX() {
    return x;
}

public byte[] getY() {
    return y;
}
```
**Issue**: getX() and getY() methods return the internal byte arrays directly instead of clones, allowing external code to modify the key material.
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

### DERCodec copyToFixedBuffer has incorrect truncation logic
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/DERCodec.java:173-193`
```
if (srcLen > fixedLen) {
    // 截断高位，因为interger的编码在高bit=0的时候会增加00, 导致编码长度是33
    System.arraycopy(src, srcLen - fixedLen, dest, offset, fixedLen);
}
```
**Issue**: When srcLen > fixedLen (32 bytes), the code truncates from the end. However, for properly encoded DER integers, when high bit is 0 and there's a leading 0x00 byte (making 33 bytes), this would truncate the wrong byte (the 0x00 prefix should be removed, not trailing bytes).
**Fix**:
```
if (srcLen > fixedLen) {
    // If first byte is 0x00 (sign byte for positive integers with high bit set), skip it
    if (src[0] == 0 && srcLen == fixedLen + 1) {
        System.arraycopy(src, 1, dest, offset, fixedLen);
    } else {
        throw new IllegalArgumentException("Integer value too large for " + fixedLen + " bytes");
    }
}
```

---

### sm3Update lacks null data array check
`sdf4j-jce/src/main/native/src/sdf_jce_sm3.c:90-97`
```
SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
if (ctx == NULL || !ctx->initialized) {
    throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
    return;
}

jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
```
**Issue**: The function doesn't check if data is NULL before calling GetByteArrayElements. If an empty byte array is passed, GetByteArrayElements could return NULL, leading to null pointer dereference.
**Fix**:
```
SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
if (ctx == NULL || !ctx->initialized) {
    throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
    return;
}

if (data == NULL) {
    throw_exception(env, "java/lang/NullPointerException", "data is null");
    return;
}

jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
if (dataBytes == NULL) {
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte array");
    return;
}
```

---

### SM4Cipher uses deprecated finalize() for cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:531-562`
```
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
**Issue**: The finalize() method is deprecated and unreliable. Resources may not be released properly. The class should implement AutoCloseable instead.
**Fix**:
```
public void close() {
    cleanup();
    if (sessionHandle != 0) {
        SDFJceNative.closeSession(sessionHandle);
        sessionHandle = 0;
    }
}

@Override
@Deprecated
protected void finalize() throws Throwable {
    try {
        close();
    } finally {
        super.finalize();
    }
}
```

---

### SM3MessageDigest uses deprecated finalize() for cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:97-107`
```
@Override
protected void finalize() throws Throwable {
    try {
        cleanupContext();
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
        }
    } finally {
        super.finalize();
    }
}
```
**Issue**: The finalize() method is deprecated and unreliable. Resources may not be released properly. The class should extend a cleanup pattern.
**Fix**:
```
@Override
@Deprecated
protected void finalize() throws Throwable {
    try {
        cleanupContext();
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
        }
    } finally {
        super.finalize();
    }
}
```

---

### SM2Signature uses deprecated finalize() for cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:175-183`
```
@Override
protected void finalize() throws Throwable {
    try {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
        }
    } finally {
        super.finalize();
    }
}
```
**Issue**: The finalize() method is deprecated and unreliable. Session resources may leak.
**Fix**:
```
@Override
@Deprecated
protected void finalize() throws Throwable {
    try {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
        }
    } finally {
        super.finalize();
    }
}
```

---

### SM2KeyPairGenerator uses deprecated finalize() for cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM2KeyPairGenerator.java:73-81`
```
@Override
protected void finalize() throws Throwable {
    try {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
        }
    } finally {
        super.finalize();
    }
}
```
**Issue**: The finalize() method is deprecated and unreliable. Session resources may leak.
**Fix**:
```
@Override
@Deprecated
protected void finalize() throws Throwable {
    try {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
        }
    } finally {
        super.finalize();
    }
}
```

---


## Low

### hexToBytes doesn't validate input length
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/SM2Util.java:151-157`
```
private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                             + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
}
```
**Issue**: The method assumes the hex string has even length. If an odd-length string is passed, it will throw IndexOutOfBoundsException instead of a more descriptive error.
**Fix**:
```
private static byte[] hexToBytes(String hex) {
    if (hex == null) {
        throw new IllegalArgumentException("Hex string cannot be null");
    }
    if (hex.length() % 2 != 0) {
        throw new IllegalArgumentException("Hex string must have even length");
    }
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        int high = Character.digit(hex.charAt(i), 16);
        int low = Character.digit(hex.charAt(i + 1), 16);
        if (high == -1 || low == -1) {
            throw new IllegalArgumentException("Invalid hex string: " + hex);
        }
        data[i / 2] = (byte) ((high << 4) + low);
    }
    return data;
}
```

---

### Maven forkCount changed from 0 to 1
`pom.xml:65`
```
<forkCount>1</forkCount>
```
**Issue**: Changing forkCount from 0 (no fork) to 1 (forked process) may cause issues with stateful providers like JCE providers where provider registration needs to be shared.
**Fix**:
```
<forkCount>0</forkCount>
```

---

### Loaded flag visibility issue in double-checked locking
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java:59`
```
public static synchronized void load() {
    if (loaded) {
        return;
    }
```
**Issue**: The `loaded` flag is checked outside the synchronized block without proper volatile semantics. While volatile is declared, the double-check pattern could still have visibility issues on some JVMs.
**Fix**:
```
private static volatile boolean loaded = false;

public static void load() {
    if (loaded) {
        return;
    }
    synchronized (NativeLoader.class) {
        if (loaded) {
            return;
        }
        // ... loading logic
    }
}
```

---


---

## GEMINI Review

# Code Review: openHiTLS/sdf4j#22
**Reviewer**: GEMINI


## Critical

### Resource Leak: SDF Sessions exhausted due to per-instance allocation
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:64-67`
```
public SM4Cipher() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
```
**Issue**: `SDFJceNative.openSession()` is called in the constructor, tying the SDF session lifecycle to the Java object lifecycle, relying on `finalize()` to close the session. Cryptographic hardware devices typically have a strict limit on concurrent sessions (e.g., 256 or 1024). Since `Cipher` objects are instantiated frequently and their garbage collection is non-deterministic (and `finalize` is deprecated/unreliable), this design will quickly exhaust device sessions, leading to application-wide cryptographic failures.
**Fix**:
```
// Implement a shared session pool, or defer session opening until strictly necessary and release promptly.
    // Example for delayed initialization:
    public SM4Cipher() {
        this.cipherMode = MODE_CBC;
        // Do not open session in the constructor. Obtain it during engineInit/engineUpdate from a pool or per-operation.
    }
```

---


## High

### Insecure Temporary File Creation for Native Library
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java:99-101`
```
Path baseDir = Paths.get(System.getProperty("java.io.tmpdir"), "sdf4j-jce-native");
            Files.createDirectories(baseDir);
            Path tempLib = baseDir.resolve(platform + "-" + libraryFileName);
```
**Issue**: The native library is extracted to a predictable directory name in `java.io.tmpdir`. In a shared temporary directory like `/tmp` on Unix systems, a malicious user can pre-create this directory or use symlinks. This leads to a Time-of-Check to Time-of-Use (TOCTOU) race condition where an attacker can replace the `.so` file between `Files.copy` and `System.load`, potentially achieving arbitrary code execution within the JVM process.
**Fix**:
```
Path baseDir = Files.createTempDirectory("sdf4j-jce-native-");
            baseDir.toFile().deleteOnExit();
            Path tempLib = baseDir.resolve(platform + "-" + libraryFileName);
```

---

### Missing NULL check after GetByteArrayElements in sm4EncryptInit
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:313-317`
```
jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    jsize keyLen = (*env)->GetArrayLength(env, key);
    if (keyLen != SM4_KEY_LENGTH) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
        return 0;
    }
```
**Issue**: `GetByteArrayElements` can return NULL if it fails to allocate memory (e.g., OutOfMemoryError). If it returns NULL, a JNI exception is scheduled, but C execution continues. The NULL pointer `keyBytes` will subsequently be dereferenced by `SDF_ImportKey` or passed to `ReleaseByteArrayElements`, causing a segmentation fault and crashing the entire JVM process instead of throwing a catchable Java exception.
**Fix**:
```
jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        return 0;
    }
    jsize keyLen = (*env)->GetArrayLength(env, key);
    if (keyLen != SM4_KEY_LENGTH) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
        return 0;
    }
```

---

### Missing NULL check after GetByteArrayElements in sm4EncryptUpdate
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:393-397`
```
jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    ULONG outputBufLen = (ULONG)(len + SM4_BLOCK_SIZE);
    BYTE *output = (BYTE *)malloc((size_t)outputBufLen);
    if (output == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
```
**Issue**: `GetByteArrayElements` can return NULL on OutOfMemoryError. The C code fails to verify the return value and subsequently dereferences the NULL `dataBytes` pointer in `SDF_EncryptUpdate` via `dataBytes + offset` and attempts to release it via `ReleaseByteArrayElements`. This will cause a segmentation fault, crashing the JVM.
**Fix**:
```
jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        return NULL;
    }
    ULONG outputBufLen = (ULONG)(len + SM4_BLOCK_SIZE);
    BYTE *output = (BYTE *)malloc((size_t)outputBufLen);
    if (output == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
```

---


---

## CODEX Review

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
