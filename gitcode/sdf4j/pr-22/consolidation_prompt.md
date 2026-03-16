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

### Private key material exposure through getEncoded()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java:45`
```
@Override
    public byte[] getEncoded() {
        return keyBytes;
    }
```
**Issue**: The getEncoded() method returns the internal keyBytes array directly instead of a clone. This allows external code to modify the private key material, which is a security vulnerability.
**Fix**:
```
@Override
    public byte[] getEncoded() {
        return keyBytes.clone();
    }
```

---


## Medium

### Public key coordinates exposed without cloning
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PublicKey.java:64-68`
```
public byte[] getX() {
        return x;
    }

    public byte[] getY() {
        return y;
    }
```
**Issue**: The getX() and getY() methods return the internal x and y arrays directly without cloning. This allows external code to modify the public key coordinates.
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

### Native library extracted to temp directory without restrictive permissions
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java:94-98`
```
// Extract the library (always re-extract to ensure using latest version)
            Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

            // Load the extracted library
            System.load(tempLib.toAbsolutePath().toString());
```
**Issue**: The loadLibraryFromResources() method extracts the native library to /tmp/sdf4j-jce-native without setting restrictive file permissions. On multi-user systems, another user could potentially replace the library before it's loaded.
**Fix**:
```
// Extract the library (always re-extract to ensure using latest version)
            Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

            // Set restrictive permissions (owner read-only)
            try {
                Files.setPosixFilePermissions(tempLib, PosixFilePermissions.fromString("r--------"));
            } catch (UnsupportedOperationException e) {
                // Not a POSIX system, skip
            }

            // Load the extracted library
            System.load(tempLib.toAbsolutePath().toString());
```

---

### Resource cleanup relies on finalize() which is unreliable
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:531-543`
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
**Issue**: The sessionHandle is only cleaned up in finalize(), which is not guaranteed to run and may run arbitrarily late. This can lead to resource leaks. There should be an explicit close() method or implement AutoCloseable.
**Fix**:
```
// Implement AutoCloseable for explicit resource management
    public void close() {
        cleanup();
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Resource cleanup relies on finalize() which is unreliable
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:178-186`
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
**Issue**: The sessionHandle is only cleaned up in finalize(). This class should implement AutoCloseable to provide explicit resource cleanup.
**Fix**:
```
public void close() {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Silent truncation of signature values in copyToFixedBuffer
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/DERCodec.java:196-209`
```
private static void copyToFixedBuffer(byte[] src, byte[] dest, int offset) {
        int srcLen = src.length;
        int fixedLen = 32;

        if (srcLen > fixedLen) {
            // 截断高位
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
**Issue**: The copyToFixedBuffer function silently truncates data if srcLen > 32 bytes. This could lead to incorrect signature verification or encoding issues without any error indication.
**Fix**:
```
private static void copyToFixedBuffer(byte[] src, byte[] dest, int offset) {
        int srcLen = src.length;
        int fixedLen = 32;

        if (srcLen > fixedLen) {
            // Truncation indicates invalid signature - throw exception
            throw new IllegalArgumentException("Signature component too large: " + srcLen + " bytes");
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

### Resource cleanup relies on finalize()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:104-115`
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
**Issue**: Like other JCE classes, this class uses finalize() for cleanup. Implementing AutoCloseable would provide better resource management.
**Fix**:
```
public void close() {
        cleanupContext();
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Resource cleanup relies on finalize()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM2KeyPairGenerator.java:73-80`
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
**Issue**: This class uses finalize() for session cleanup. The sessionHandle should be explicitly closable.
**Fix**:
```
public void close() {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Resource cleanup relies on finalize()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:206-213`
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
**Issue**: SM2Cipher also uses finalize() for session cleanup.
**Fix**:
```
public void close() {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Resource cleanup relies on finalize()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/random/SDFSecureRandom.java:57-64`
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
**Issue**: SDFSecureRandom uses finalize() for session cleanup. This is particularly problematic since SecureRandom instances are often long-lived.
**Fix**:
```
public void close() {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Resource cleanup relies on finalize()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM4KeyGenerator.java:65-72`
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
**Issue**: SM4KeyGenerator uses finalize() for session cleanup.
**Fix**:
```
public void close() {
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Resource cleanup relies on finalize()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java:94-102`
```
@Override
    protected void finalize() throws Throwable {
        try {
            cleanupKey();
            if (sessionHandle != 0) {
                SDFJceNative.closeSession(sessionHandle);
            }
        } finally {
            super.finalize();
        }
    }
```
**Issue**: HmacSM3 uses finalize() for session cleanup.
**Fix**:
```
public void close() {
        cleanupKey();
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---

### Resource cleanup relies on finalize()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java:119-128`
```
@Override
    protected void finalize() throws Throwable {
        try {
            cleanupKey();
            if (sessionHandle != 0) {
                SDFJceNative.closeSession(sessionHandle);
            }
        } finally {
            super.finalize();
        }
    }
```
**Issue**: SM4Mac uses finalize() for session cleanup.
**Fix**:
```
public void close() {
        cleanupKey();
        if (sessionHandle != 0) {
            SDFJceNative.closeSession(sessionHandle);
            sessionHandle = 0;
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
```

---


## Low

### Potential race condition in initialization check
`sdf4j-jce/src/main/native/src/sdf_jce_init.c:28-36`
```
int sdf_jce_initialize(const char *library_path) {
    if (g_sdf_initialized) {
        /* 检查句柄是否有效（简单检查：不为NULL）*/
        if (g_device_handle != NULL) {
            return SDR_OK;  // 已初始化且句柄有效
        }
        /* 句柄无效，先清理 */
        sdf_jce_cleanup();
    }
```
**Issue**: The g_sdf_initialized flag is checked before checking g_device_handle validity, but the flag is set after successful initialization. Between the check and the set, another thread could see an inconsistent state.
**Fix**:
```
int sdf_jce_initialize(const char *library_path) {
    /* Use mutex to protect initialization */
    static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&init_mutex);

    if (g_sdf_initialized) {
        /* 检查句柄是否有效（简单检查：不为NULL）*/
        if (g_device_handle != NULL) {
            pthread_mutex_unlock(&init_mutex);
            return SDR_OK;  // 已初始化且句柄有效
        }
        /* 句柄无效，先清理 */
        sdf_jce_cleanup();
    }
    /* ... rest of function ... */
    pthread_mutex_unlock(&init_mutex);
```

---

### Memory leak when strdup fails in SetLibraryPath
`sdf4j-jce/src/main/native/src/sdf_jce_register.c:175-187`
```
/* 获取并保存新路径 */
    const char *path_str = (*env)->GetStringUTFChars(env, path, NULL);
    if (path_str != NULL) {
        g_library_path = strdup(path_str);
        (*env)->ReleaseStringUTFChars(env, path, path_str);
    }
```
**Issue**: When GetStringUTFChars succeeds but strdup fails, the code returns without freeing the string from GetStringUTFChars, causing a memory leak.
**Fix**:
```
/* 获取并保存新路径 */
    const char *path_str = (*env)->GetStringUTFChars(env, path, NULL);
    if (path_str != NULL) {
        g_library_path = strdup(path_str);
        (*env)->ReleaseStringUTFChars(env, path, path_str);
        if (g_library_path == NULL) {
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate library path");
        }
    }
```

---

### forkCount changed from 0 to 1 may affect test behavior
`pom.xml:65`
```
-                        <!-- 禁用fork，在Maven主进程中运行测试，避免surefire临时文件 -->
-                        <forkCount>0</forkCount>
+                        <forkCount>1</forkCount>
```
**Issue**: The forkCount is changed from 0 (no fork, run in Maven process) to 1 (fork new process). The original comment stated this was to "avoid surefire temporary files" and use "system class loader". This change may break tests that relied on the previous behavior.
**Fix**:
```
Keep the original forkCount=0 behavior if tests depend on running in the Maven process with system class loader. If the change is intentional, add a comment explaining why the change was made and what the implications are.
```

---


---

## GEMINI Review

# Code Review: openHiTLS/sdf4j#22
**Reviewer**: GEMINI


## High

### Cipher context is not implicitly reset for updates
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:232-236`
```
if (ctx == 0) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
```
**Issue**: The JCE `Cipher` specification requires the cipher to be implicitly reset after `doFinal`. Since `doFinalStreaming` frees the context and sets `ctx = 0`, a subsequent `update` call will incorrectly throw an `IllegalStateException` instead of re-initializing the context.
**Fix**:
```
if (ctx == 0) {
            initStreamingContext();
        }

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
```

---

### Cipher context is not implicitly reset for doFinal
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:326-331`
```
private byte[] doFinalStreaming() throws IllegalBlockSizeException, BadPaddingException {
        if (ctx == 0) {
            throw new IllegalStateException("Cipher not initialized");
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
```
**Issue**: The JCE `Cipher` specification requires the cipher to be implicitly reset after `doFinal`. A subsequent `doFinal` call will incorrectly throw an `IllegalStateException` because `ctx` is 0. Re-initializing the context lazily allows subsequent operations without explicit re-initialization.
**Fix**:
```
private byte[] doFinalStreaming() throws IllegalBlockSizeException, BadPaddingException {
        if (ctx == 0) {
            initStreamingContext();
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
```

---

### Key handle leak in SM4 streaming operations
`sdf4j-jce/src/main/native/include/jce_common.h:63-69`
```
/* SM4上下文 */
typedef struct {
    int mode;
    int encrypt;
    BYTE iv[SM4_IV_LENGTH];
    int initialized;
    HANDLE session_handle;  /* Session handle for this crypto operation */
} SM4Context;
```
**Issue**: The imported symmetric key handle is not stored in `SM4Context`, meaning it is never destroyed when the streaming encryption/decryption context is freed. This causes a memory and resource leak on the SDF cryptographic hardware device.
**Fix**:
```
/* SM4上下文 */
typedef struct {
    int mode;
    int encrypt;
    BYTE iv[SM4_IV_LENGTH];
    int initialized;
    HANDLE session_handle;  /* Session handle for this crypto operation */
    HANDLE key_handle;      /* Key handle for this crypto operation */
} SM4Context;
```

---

### Missing key handle storage in SM4 encrypt init
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:349-354`
```
ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key failed");
        goto ERR;
    }

    ret = g_sdf_functions.SDF_EncryptInit(
```
**Issue**: The successfully imported key handle must be stored in the context so it can be destroyed later.
**Fix**:
```
ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key failed");
        goto ERR;
    }
    ctx->key_handle = keyHandle;

    ret = g_sdf_functions.SDF_EncryptInit(
```

---

### Missing key handle storage in SM4 decrypt init
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:509-514`
```
ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key failed");
        goto ERR;
    }

    ret = g_sdf_functions.SDF_DecryptInit(ctx->session_handle, keyHandle, algId, ctx->iv, SM4_IV_LENGTH);
```
**Issue**: The successfully imported key handle must be stored in the context so it can be destroyed later.
**Fix**:
```
ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key failed");
        goto ERR;
    }
    ctx->key_handle = keyHandle;

    ret = g_sdf_functions.SDF_DecryptInit(ctx->session_handle, keyHandle, algId, ctx->iv, SM4_IV_LENGTH);
```

---

### Missing SDF_DestroyKey in SM4 free
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:636-641`
```
SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(SM4Context));
    free(ctx);
```
**Issue**: The imported key handle must be destroyed to free hardware device resources when the cipher context is closed.
**Fix**:
```
SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    if (ctx->key_handle != NULL && g_sdf_functions.SDF_DestroyKey != NULL) {
        g_sdf_functions.SDF_DestroyKey(ctx->session_handle, ctx->key_handle);
    }

    memset(ctx, 0, sizeof(SM4Context));
    free(ctx);
```

---


## Medium

### Race condition in native library extraction
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java:99-106`
```
Path baseDir = Paths.get(System.getProperty("java.io.tmpdir"), "sdf4j-jce-native");
            Files.createDirectories(baseDir);
            Path tempLib = baseDir.resolve(platform + "-" + libraryFileName);

            // Extract the library (always re-extract to ensure using latest version)
            Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

            // Load the extracted library
            System.load(tempLib.toAbsolutePath().toString());

            // Clean up on JVM exit
            tempLib.toFile().deleteOnExit();
```
**Issue**: Using a static temporary file name can cause concurrent write conflicts and corrupted native libraries if multiple JVMs initialize the provider simultaneously.
**Fix**:
```
Path baseDir = Paths.get(System.getProperty("java.io.tmpdir"), "sdf4j-jce-native");
            Files.createDirectories(baseDir);
            Path tempLib = Files.createTempFile(baseDir, platform + "-", "-" + libraryFileName);

            // Extract the library
            Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

            // Load the extracted library
            System.load(tempLib.toAbsolutePath().toString());

            // Clean up on JVM exit
            tempLib.toFile().deleteOnExit();
```

---

### engineGetOutputSize ignores buffered data size
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:74-81`
```
@Override
    protected int engineGetOutputSize(int inputLen) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            // SM2 ciphertext: 0x04(1) + C1_X(32) + C1_Y(32) + C2(plaintext) + C3(32) = 97 + plaintext
            return inputLen + 97;
        } else {
            // Plaintext is ciphertext - 97 bytes overhead (1 + 32 + 32 + 32)
            return Math.max(0, inputLen - 97);
        }
    }
```
**Issue**: According to the CipherSpi contract, `engineGetOutputSize` must account for any data currently held in the internal buffer. Failing to include `buffer.size()` can cause the caller to allocate too small an output array.
**Fix**:
```
@Override
    protected int engineGetOutputSize(int inputLen) {
        int totalLen = inputLen + (buffer != null ? buffer.size() : 0);
        if (opmode == Cipher.ENCRYPT_MODE) {
            // SM2 ciphertext: 0x04(1) + C1_X(32) + C1_Y(32) + C2(plaintext) + C3(32) = 97 + plaintext
            return totalLen + 97;
        } else {
            // Plaintext is ciphertext - 97 bytes overhead (1 + 32 + 32 + 32)
            return Math.max(0, totalLen - 97);
        }
    }
```

---

### engineGetOutputSize ignores buffered data size
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:118-135`
```
@Override
    protected int engineGetOutputSize(int inputLen) {
        if (isAeadMode()) {
            int tagBytes = gcmTagLenBits / 8;
            if (opmode == Cipher.ENCRYPT_MODE) {
                return inputLen + tagBytes;
            } else {
                return Math.max(0, inputLen - tagBytes);
            }
        }
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (paddingMode == PADDING_PKCS5) {
                return ((inputLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            }
            return inputLen;
        } else {
            return inputLen;
        }
    }
```
**Issue**: According to the CipherSpi contract, `engineGetOutputSize` must account for any data currently held in the internal buffer. Failing to include `buffer.size()` can cause the caller to allocate too small an output array.
**Fix**:
```
@Override
    protected int engineGetOutputSize(int inputLen) {
        int totalLen = inputLen + (buffer != null ? buffer.size() : 0);
        if (isAeadMode()) {
            int tagBytes = gcmTagLenBits / 8;
            if (opmode == Cipher.ENCRYPT_MODE) {
                return totalLen + tagBytes;
            } else {
                return Math.max(0, totalLen - tagBytes);
            }
        }
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (paddingMode == PADDING_PKCS5) {
                return ((totalLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            }
            return totalLen;
        } else {
            return totalLen;
        }
    }
```

---


## Low

### Incorrect exception type for empty plaintext in SM2 encrypt
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:224-229`
```
if (plainLen == 0) {
        (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "plain len is invalid");
        return NULL;
    }
```
**Issue**: When `plainLen` is 0, the code throws `OutOfMemoryError` instead of `IllegalArgumentException`, which is misleading for developers trying to debug.
**Fix**:
```
if (plainLen == 0) {
        (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "plain len is invalid");
        return NULL;
    }
```

---


---

## CODEX Review

# Code Review: openHiTLS/sdf4j#22
**Reviewer**: CODEX


## High

### Native library is loaded from a predictable shared temp path
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
**Issue**: The bridge library is always extracted to `/tmp/sdf4j-jce-native/<platform>-libsdf4j-jce.so` and then loaded with `System.load()`. That predictable, shared location makes the load path vulnerable to local file-replacement/race attacks, so a malicious user on the same host can potentially get arbitrary native code loaded into the JVM.
**Fix**:
```
Path baseDir = Files.createTempDirectory("sdf4j-jce-",
        java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
Path tempLib = Files.createTempFile(baseDir, LIBRARY_NAME + "-", ".so");
Files.setPosixFilePermissions(tempLib,
        java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));

Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);
System.load(tempLib.toRealPath().toString());
```

---

### Decrypt init reads past Java key and IV buffers
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:488-505`
```
jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;

SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
...
if (ivBytes) {
    memcpy(ctx->iv, ivBytes, SM4_IV_LENGTH);
}

algId = sm4_mode_to_alg_id(mode);

ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
```
**Issue**: `sm4DecryptInit` pulls raw pointers for `key` and `iv` and immediately copies/imports 16 bytes without first checking the Java array lengths. Because `SM4Cipher.engineInit()` also accepts any `IvParameterSpec`, a short key or IV reaches this code path and causes out-of-bounds JNI reads inside the JVM process.
**Fix**:
```
jsize keyLen = (*env)->GetArrayLength(env, key);
if (keyLen != SM4_KEY_LENGTH) {
    throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
    return 0;
}
jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);

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

---

### SM2 private key state is externally mutable
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java:29-48`
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
**Issue**: The constructor keeps the caller's byte array by reference, and `getEncoded()` returns the same internal array. Any code holding either array can modify the live private key in place, which breaks key immutability and exposes secret material to accidental or hostile mutation.
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


## Medium

### Streaming SM4 initialization leaks imported key handles
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:349-366`
```
ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
if (ret != SDR_OK) {
    throw_jce_exception(env, (int)ret, "SM4 import key failed");
    goto ERR;
}

ret = g_sdf_functions.SDF_EncryptInit(
    ctx->session_handle, keyHandle, algId, ctx->iv, SM4_IV_LENGTH);
...
ctx->initialized = 1;
return (jlong)(uintptr_t)ctx;
```
**Issue**: Both streaming init paths import an SM4 key, pass the returned handle into `SDF_EncryptInit`/`SDF_DecryptInit`, and then drop the handle on success. Since the handle is not stored in `SM4Context` and never destroyed in `sm4Free` or the final paths, repeated cipher initializations leak device-side key objects until the session is exhausted.
**Fix**:
```
ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
if (ret != SDR_OK) {
    throw_jce_exception(env, (int)ret, "SM4 import key failed");
    goto ERR;
}

ret = g_sdf_functions.SDF_DecryptInit(ctx->session_handle, keyHandle, algId, ctx->iv, SM4_IV_LENGTH);
...
ctx->initialized = 1;
return (jlong)(uintptr_t)ctx;
```

---

### Provider construction now requires working hardware configuration and discards the explicit path argument
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFProvider.java:52-68`
```
public SDFProvider() {
    super(PROVIDER_NAME, VERSION, INFO);
    registerAlgorithms();
    // Trigger native library loading, which auto-initializes SDF via SDF_LIBRARY_PATH
    ensureNativeLoaded();
}

public SDFProvider(String libraryPath) {
    this();
}
```
**Issue**: The default constructor eagerly calls `NativeLoader.load()`, so simply registering the provider now fails if the device library is not already configured. On top of that, `SDFProvider(String libraryPath)` ignores its argument entirely. This breaks provider-only use cases and makes the new `SDFProviderTest` fail immediately.
**Fix**:
```
public SDFProvider() {
    super(PROVIDER_NAME, VERSION, INFO);
    registerAlgorithms();
}

public SDFProvider(String libraryPath) {
    this();
    if (libraryPath != null && !libraryPath.isEmpty()) {
        System.setProperty("sdf.library.path", libraryPath);
    }
}
```

---

### GCM tag length from GCMParameterSpec is accepted but not actually supported
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:172-178`
```
GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
this.iv = gcmSpec.getIV();
this.gcmTagLenBits = gcmSpec.getTLen();
```
**Issue**: The cipher accepts any `GCMParameterSpec` tag length and uses it to size buffers and split the tag on decrypt, but the native bridge always generates and expects a fixed 16-byte tag. Requests for 96/104/112/120-bit tags therefore produce wrong `getOutputSize()` calculations on encrypt and broken authentication on decrypt.
**Fix**:
```
int tagBytes = gcmTagLenBits / 8;
...
byte[] ciphertext = new byte[data.length - tagBytes];
byte[] tag = new byte[tagBytes];
...
byte[] plaintext = SDFJceNative.sm4AuthDec(sessionHandle, cipherMode, key, iv,
        aad.length > 0 ? aad : null, tag, ciphertext);
```

---

### DER parser normalizes malformed signatures instead of rejecting them
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/DERCodec.java:71-95`
```
int length = in.readLength();
if (in.available() < length) {
    throw new IllegalArgumentException("DER length mismatch");
}
...
byte[] raw = new byte[64];
copyToFixedBuffer(rBytes, raw, 0);
copyToFixedBuffer(sBytes, raw, 32);
```
**Issue**: `derToRaw()` only checks that at least the declared SEQUENCE length remains, so trailing garbage is accepted, and `copyToFixedBuffer()` silently truncates oversized INTEGER encodings to 32 bytes. That means malformed DER input can be transformed into a different `(r,s)` pair instead of being rejected as invalid.
**Fix**:
```
if (srcLen > fixedLen) {
    // 截断高位
    System.arraycopy(src, srcLen - fixedLen, dest, offset, fixedLen);
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
