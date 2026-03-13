# Code Review: openHiTLS/sdf4j#22
**Reviewer**: CODEX


## High

### sm2Verify reads past short signature buffers
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:146-171`
```
jsize xLen = (*env)->GetArrayLength(env, publicKeyX);
jsize yLen = (*env)->GetArrayLength(env, publicKeyY);
if (xLen != SM2_KEY_BYTES || yLen != SM2_KEY_BYTES) {
    throw_exception(env, "java/lang/IllegalArgumentException",
                    "SM2 public key/signature length is invalid");
    return JNI_FALSE;
}

jbyte *sigBytes = (*env)->GetByteArrayElements(env, signature, NULL);
...
memcpy(eccSig.r + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes, SM2_KEY_BYTES);
memcpy(eccSig.s + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes + SM2_KEY_BYTES, SM2_KEY_BYTES);
```
**Issue**: The native verifier only validates the public-key coordinates. It then copies 64 bytes from `signature` unconditionally. A caller can pass a shorter `byte[]` to `SDFJceNative.sm2Verify(...)`, which makes the JNI code read past the Java array and can crash the JVM or feed adjacent memory into signature verification.
**Fix**:
```
jsize xLen = (*env)->GetArrayLength(env, publicKeyX);
jsize yLen = (*env)->GetArrayLength(env, publicKeyY);
jsize sigLen = (*env)->GetArrayLength(env, signature);
if (xLen != SM2_KEY_BYTES || yLen != SM2_KEY_BYTES || sigLen != SM2_SIGNATURE_BYTES) {
    throw_exception(env, "java/lang/IllegalArgumentException",
                    "Public key must be 32 bytes and signature must be 64 bytes");
    return JNI_FALSE;
}

jbyte *xBytes = (*env)->GetByteArrayElements(env, publicKeyX, NULL);
jbyte *yBytes = (*env)->GetByteArrayElements(env, publicKeyY, NULL);
jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
jbyte *sigBytes = (*env)->GetByteArrayElements(env, signature, NULL);
if (xBytes == NULL || yBytes == NULL || dataBytes == NULL || sigBytes == NULL) {
    if (xBytes) (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
    if (yBytes) (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
    if (dataBytes) (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    if (sigBytes) (*env)->ReleaseByteArrayElements(env, signature, sigBytes, JNI_ABORT);
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
    return JNI_FALSE;
}
```

---

### sm2Decrypt copies 32 bytes from an unchecked private-key array
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:279-298`
```
jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
jbyte *privKeyBytes = (*env)->GetByteArrayElements(env, privateKey, NULL);
...
ECCrefPrivateKey eccPrivKey;
memset(&eccPrivKey, 0, sizeof(eccPrivKey));
eccPrivKey.bits = SM2_KEY_BITS;
memcpy(eccPrivKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES, privKeyBytes, SM2_KEY_BYTES);
```
**Issue**: `sm2Decrypt` never verifies that `privateKey` is 32 bytes long before copying it into `ECCrefPrivateKey`. Passing a shorter array causes an out-of-bounds native read, which can crash the JVM or use unrelated memory as key material.
**Fix**:
```
jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
if (privKeyLen != SM2_KEY_BYTES) {
    throw_exception(env, "java/lang/IllegalArgumentException", "Private key must be 32 bytes");
    return NULL;
}

jbyte *privKeyBytes = (*env)->GetByteArrayElements(env, privateKey, NULL);
jbyte *cipherBytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
if (privKeyBytes == NULL || cipherBytes == NULL) {
    if (privKeyBytes) {
        memset(privKeyBytes, 0, (size_t)privKeyLen);
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
    }
    if (cipherBytes) (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
    return NULL;
}
```

---

### SM4 streaming init reads past short key or IV arrays
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:243-265`
```
jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;
...
if (ivBytes) {
    memcpy(ctx->iv, ivBytes, SM4_IV_LENGTH);
}
...
LONG ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
```
**Issue**: Both `sm4EncryptInit` and `sm4DecryptInit` import a fixed 16-byte key and copy a fixed 16-byte IV without checking the Java array lengths first. Direct callers of the public `SDFJceNative` streaming API can trigger native out-of-bounds reads with undersized buffers.
**Fix**:
```
jsize keyLen = (*env)->GetArrayLength(env, key);
if (keyLen != SM4_KEY_LENGTH) {
    throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
    return 0;
}
if (iv != NULL && (*env)->GetArrayLength(env, iv) != SM4_IV_LENGTH) {
    throw_exception(env, "java/lang/IllegalArgumentException", "IV must be 16 bytes");
    return 0;
}

jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;
if (keyBytes == NULL || (iv != NULL && ivBytes == NULL)) {
    if (keyBytes) (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
    return 0;
}
```

---


## Medium

### Provider registration hard-fails without a live SDF library
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFProvider.java:52-57`
```
public SDFProvider() {
    super(PROVIDER_NAME, VERSION, INFO);
    registerAlgorithms();
    // Trigger native library loading, which auto-initializes SDF via SDF_LIBRARY_PATH
    ensureNativeLoaded();
}
```
**Issue**: Constructing the provider immediately loads the native bridge and initializes the SDF device. That means simple provider discovery and registration fail on machines without hardware or a configured library. The new `SDFProviderTest` already errors on a clean checkout for this reason.
**Fix**:
```
public SDFProvider() {
    super(PROVIDER_NAME, VERSION, INFO);
    registerAlgorithms();
}

// Let the SPI implementations trigger NativeLoader.load() on first real use.
```

---

### SM2PrivateKey exposes mutable private-key state
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java:29-48`
```
public SM2PrivateKey(byte[] keyBytes) {
    if (keyBytes == null || keyBytes.length != 32) {
        throw new IllegalArgumentException("Key must be 32 bytes");
    }
    this.keyBytes = keyBytes;
}
...
@Override
public byte[] getEncoded() {
    return keyBytes;
}
```
**Issue**: The constructor stores the caller's array directly, and `getEncoded()` returns the same internal array. Any caller can mutate or zero the private key after construction, which can silently corrupt later signatures and leak key state across code paths.
**Fix**:
```
public SM2PrivateKey(byte[] keyBytes) {
    if (keyBytes == null || keyBytes.length != 32) {
        throw new IllegalArgumentException("Key must be 32 bytes");
    }
    this.keyBytes = Arrays.copyOf(keyBytes, keyBytes.length);
}

@Override
public byte[] getEncoded() {
    return keyBytes.clone();
}
```

---

### SM2 output-size calculation is off by one byte
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:72-79`
```
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
**Issue**: The native code produces `C1_X || C1_Y || C3 || C2`, which has 96 bytes of overhead. `engineGetOutputSize()` assumes a nonexistent leading `0x04` byte and uses 97 instead. For decryption, `Cipher.getOutputSize()` underestimates by one byte, so `doFinal(input, output, off)` can throw `ShortBufferException` even when the caller allocates the advertised size.
**Fix**:
```
protected int engineGetOutputSize(int inputLen) {
    final int overhead = 96; // C1_X(32) + C1_Y(32) + C3(32)
    if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
        return inputLen + overhead;
    }
    return Math.max(0, inputLen - overhead);
}
```

---

### SM2 cipher advertises unsupported PKCS1Padding
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:60-63`
```
@Override
protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    if (!"NoPadding".equalsIgnoreCase(padding) && !"PKCS1Padding".equalsIgnoreCase(padding)) {
        throw new NoSuchPaddingException("SM2 only supports NoPadding");
    }
}
```
**Issue**: `engineSetPadding()` accepts `PKCS1Padding`, but the implementation never applies any PKCS#1-style formatting. `Cipher.getInstance("SM2/ECB/PKCS1Padding", "SDF")` therefore behaves like raw SM2 while claiming a padding mode it does not implement.
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

### DER signature parsing accepts malformed encodings
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
...
if (srcLen > fixedLen) {
    // 截断高位
    System.arraycopy(src, srcLen - fixedLen, dest, offset, fixedLen);
}
```
**Issue**: `derToRaw()` only rejects lengths that are too short, not extra trailing data, and `copyToFixedBuffer()` silently truncates oversized INTEGERs. That means malformed signatures with trailing bytes or non-canonical 33-byte integers are normalized into the same raw `r || s` value instead of being rejected.
**Fix**:
```
int length = in.readLength();
if (in.available() != length) {
    throw new IllegalArgumentException("DER length mismatch");
}
...
validateDerInteger(rBytes);
validateDerInteger(sBytes);
if (in.available() != 0) {
    throw new IllegalArgumentException("Trailing DER data");
}
byte[] raw = new byte[64];
copyToFixedBuffer(rBytes, raw, 0);
copyToFixedBuffer(sBytes, raw, 32);

private static void validateDerInteger(byte[] value) {
    if (value.length == 0 || value.length > 33) {
        throw new IllegalArgumentException("Invalid INTEGER length");
    }
    if (value.length == 33 && value[0] != 0) {
        throw new IllegalArgumentException("INTEGER too large");
    }
    if (value.length > 1 && value[0] == 0 && (value[1] & 0x80) == 0) {
        throw new IllegalArgumentException("Non-canonical INTEGER encoding");
    }
}

private static void copyToFixedBuffer(byte[] src, byte[] dest, int offset) {
    validateDerInteger(src);
    int start = (src.length == 33) ? 1 : 0;
    int srcLen = src.length - start;
    System.arraycopy(src, start, dest, offset + (32 - srcLen), srcLen);
}
```

---
