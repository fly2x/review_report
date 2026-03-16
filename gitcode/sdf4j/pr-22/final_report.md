# Final Code Review Report
## openHiTLS/sdf4j - PR #22

### Summary
- **Total Issues**: 14
- **Critical**: 2
- **High**: 4
- **Medium**: 7
- **Low**: 1
- **Reviewers**: claude, gemini, codex

---


## Critical

### SDF session resource exhaustion due to per-instance allocation
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:64-68:64-68`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
public SM4Cipher() {
    this.sessionHandle = SDFJceNative.openSession();
    if (sessionHandle == 0) {
        throw new IllegalStateException("Failed to open SDF session");
    }
    this.cipherMode = MODE_CBC;
}
```
**Issue**: SDF sessions are opened in the constructor and only closed via finalize(). Cryptographic hardware devices have strict limits on concurrent sessions (e.g., 256). JCE code creates many short-lived Cipher instances, and garbage collection is non-deterministic. Under load, this will exhaust device sessions, causing application-wide cryptographic failures.
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
    // ... rest of init logic
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

### Insecure predictable temporary file extraction path
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java:98-106:98-106`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
Path baseDir = Paths.get(System.getProperty("java.io.tmpdir"), "sdf4j-jce-native");
Files.createDirectories(baseDir);
Path tempLib = baseDir.resolve(platform + "-" + libraryFileName);

Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);
System.load(tempLib.toAbsolutePath().toString());
```
**Issue**: The native library is extracted to a predictable directory ${java.io.tmpdir}/sdf4j-jce-native/. On multi-user systems, a malicious user can pre-create this directory or replace the .so file, leading to TOCTOU race conditions and potential arbitrary code execution within the JVM process.
**Fix**:
```
Path baseDir = Files.createTempDirectory("sdf4j-jce-native-");
baseDir.toFile().deleteOnExit();
Path tempLib = baseDir.resolve(libraryFileName);

Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);
System.load(tempLib.toAbsolutePath().toString());
```

---


## High

### sm4DecryptInit returns context after native init fails
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:466-516:466-516`
**Reviewers**: CODEX | **置信度**: 可信
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
**Issue**: When SDF_DecryptInit fails at line 507-510, the function throws an exception but continues to mark ctx->initialized = 1 and returns the context. The caller then proceeds with a half-initialized context whose key handle was already destroyed. This turns a clean init failure into follow-on errors.
**Fix**:
```
ret = g_sdf_functions.SDF_DecryptInit(ctx->session_handle, keyHandle, algId, (BYTE *)ivBytes, (ivBytes ? SM4_IV_LENGTH : 0));
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

### Provider constructor eagerly initializes hardware and ignores path argument
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFProvider.java:52-69:52-69`
**Reviewers**: CODEX | **置信度**: 可信
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
**Issue**: SDFProvider() immediately calls into native initialization, so simple provider registration fails on machines without a configured SDF device/library. The SDFProvider(String libraryPath) constructor claims backward compatibility but discards libraryPath, breaking existing callers that passed a path directly.
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

### Missing bounds check on offset/len parameters
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:393-405:393-405`
**Reviewers**: CODEX | **置信度**: 可信
```
jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
ULONG outputBufLen = (ULONG)(len + SM4_BLOCK_SIZE);
BYTE *output = (BYTE *)malloc((size_t)outputBufLen);
if (output == NULL) {
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate output buffer");
    return NULL;
}
ULONG outputLen = outputBufLen;
jbyteArray result = NULL;

LONG ret = g_sdf_functions.SDF_EncryptUpdate(ctx->session_handle, (BYTE *)(dataBytes + offset), (ULONG)len,
    output, &outputLen);
```
**Issue**: sm4EncryptUpdate and sm4DecryptUpdate perform raw pointer arithmetic with dataBytes + offset but never verify that offset and len are within array bounds. A malicious caller can drive these methods into out-of-bounds reads and crash the JVM.
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
ULONG outputBufLen = (ULONG)(len + SM4_BLOCK_SIZE);
```

---

### Missing NULL check after GetByteArrayElements in sm4DecryptInit
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:483-492:483-492`
**Reviewers**: GEMINI | **置信度**: 可信
```
jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;

SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
```
**Issue**: GetByteArrayElements can return NULL on OutOfMemoryError. The code at line 483 fails to verify keyBytes before using it, which will cause a segmentation fault when dereferenced.
**Fix**:
```
jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
if (keyBytes == NULL) {
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
    return 0;
}
jbyte *ivBytes = NULL;
if (iv != NULL) {
    ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
    if (ivBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
        return 0;
    }
}
```

---


## Medium

### DER parser accepts signatures with trailing garbage
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/DERCodec.java:59-100:59-100`
**Reviewers**: CODEX | **置信度**: 可信
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
**Issue**: derToRaw only checks that the available bytes are >= length, then parses two INTEGERs and returns without verifying no bytes remain. A blob like valid_signature || attacker_controlled_suffix is accepted, which is not DER-canonical.
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

### copyToFixedBuffer has incorrect truncation logic
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/DERCodec.java:163-178:163-178`
**Reviewers**: CLAUDE | **置信度**: 可信
```
private static void copyToFixedBuffer(byte[] src, byte[] dest, int offset) {
    int srcLen = src.length;
    int fixedLen = 32;

    if (srcLen > fixedLen) {
        // 截断高位，因为interger的编码在高bit=0的时候会增加00, 导致编码长度是33
        System.arraycopy(src, srcLen - fixedLen, dest, offset, fixedLen);
    } else {
        // 前导零填充
        int padLen = fixedLen - srcLen;
        for (int i = 0; i < padLen; i++) {
            dest[offset + i] = 0;
        }
        System.arraycopy(src, 0, dest, offset + padLen, srcLen);
    }
}
```
**Issue**: When srcLen > fixedLen (32 bytes), the code truncates from the end. For properly encoded DER integers with a 0x00 prefix byte (making 33 bytes), this would truncate the wrong byte - the 0x00 prefix should be removed, not trailing bytes.
**Fix**:
```
private static void copyToFixedBuffer(byte[] src, byte[] dest, int offset) {
    int srcLen = src.length;
    int fixedLen = 32;

    if (srcLen > fixedLen) {
        // If first byte is 0x00 (sign byte for positive integers with high bit set), skip it
        if (src[0] == 0 && srcLen == fixedLen + 1) {
            System.arraycopy(src, 1, dest, offset, fixedLen);
        } else {
            throw new IllegalArgumentException("Integer value too large for " + fixedLen + " bytes");
        }
    } else {
        // 前导零填充
        int padLen = fixedLen - srcLen;
        for (int i = 0; i < padLen; i++) {
            dest[offset + i] = 0;
        }
        System.arraycopy(src, 0, dest, offset + padLen, srcLen);
    }
}
```

---

### SM2PublicKey exposes internal key arrays
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PublicKey.java:68-74:68-74`
**Reviewers**: CLAUDE | **置信度**: 可信
```
public byte[] getX() {
    return x;
}

public byte[] getY() {
    return y;
}
```
**Issue**: getX() and getY() methods return the internal byte arrays directly instead of defensive copies, allowing external code to modify the key material.
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

### SM4Cipher uses deprecated finalize() for cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:523-532:523-532`
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: The finalize() method is deprecated and unreliable. Combined with the session resource leak issue, resources may not be released properly. The class should implement AutoCloseable for deterministic cleanup.
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

### SM3MessageDigest uses deprecated finalize() for session cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:100-110:100-110`
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: The finalize() method is deprecated and unreliable. Session resources may leak since each SM3MessageDigest instance opens its own SDF session in the constructor.
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

### SM2Signature uses deprecated finalize() for session cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:174-183:174-183`
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: The finalize() method is deprecated and unreliable. Session resources may leak since each SM2Signature instance opens its own SDF session in the constructor.
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

### SM2KeyPairGenerator uses deprecated finalize() for session cleanup
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM2KeyPairGenerator.java:72-81:72-81`
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: The finalize() method is deprecated and unreliable. Session resources may leak since each SM2KeyPairGenerator instance opens its own SDF session in the constructor.
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
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/SM2Util.java:151-159:151-159`
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: The hexToBytes method assumes the hex string has even length. If an odd-length string is passed, it will throw IndexOutOfBoundsException instead of a more descriptive error.
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
