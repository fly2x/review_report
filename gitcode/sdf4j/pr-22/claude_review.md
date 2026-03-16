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
