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
