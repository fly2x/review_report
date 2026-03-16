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
