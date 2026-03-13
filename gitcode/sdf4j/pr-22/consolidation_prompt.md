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

### Context freed before error check in sm4EncryptFinal
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:365-371`
```
LONG ret = g_sdf_functions.SDF_EncryptFinal(ctx->session_handle, output, &outputLen);

    ctx->initialized = 0;
    free(ctx);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 encrypt final failed");
        return NULL;
    }
```
**Issue**: The context is freed (free(ctx)) before checking the return value of SDF_EncryptFinal. If the operation fails, the context is freed and then an exception is thrown. The Java side still has a reference to the freed context handle, and if cleanup code (like finalize() or explicit cleanup) calls sm4Free again, it will cause a double-free vulnerability.
**Fix**:
```
LONG ret = g_sdf_functions.SDF_EncryptFinal(ctx->session_handle, output, &outputLen);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 encrypt final failed");
        free(ctx);
        return NULL;
    }

    ctx->initialized = 0;
    free(ctx);

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    return result;
```

---

### Context freed before error check in sm4DecryptFinal
`sdf4j-jce/src/main/native/src/sdf_jce_sm4.c:522-528`
```
LONG ret = g_sdf_functions.SDF_DecryptFinal(ctx->session_handle, output, &outputLen);

    ctx->initialized = 0;
    free(ctx);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 decrypt final failed");
        return NULL;
    }
```
**Issue**: Same issue as sm4EncryptFinal. The context is freed before checking the return value, leading to potential double-free if error handling code attempts to clean up.
**Fix**:
```
LONG ret = g_sdf_functions.SDF_DecryptFinal(ctx->session_handle, output, &outputLen);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 decrypt final failed");
        free(ctx);
        return NULL;
    }

    ctx->initialized = 0;
    free(ctx);

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    return result;
```

---

### sm2Sign modifies caller's private key array
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:117-122`
```
ERR:
    /* Clear sensitive data in JNI buffer before releasing */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
```
**Issue**: After memset(privKeyBytes, 0, ...) to clear sensitive data, ReleaseByteArrayElements is called with mode 0 which copies back to the original array. This writes zeros to the caller's original private key array, causing unexpected data corruption.
**Fix**:
```
ERR:
    /* Clear sensitive data in JNI buffer before releasing */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
```

---

### sm2Decrypt modifies caller's private key array
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:264-269`
```
ERR:
    /* 清除敏感数据 */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
```
**Issue**: Same issue as sm2Sign - zeros are written to the caller's original array due to using ReleaseByteArrayElements with mode 0 after memset.
**Fix**:
```
ERR:
    /* 清除敏感数据 */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
```

---


## Medium

### Memory leak in SM3MessageDigest.engineDigest
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:69-71`
```
byte[] result = SDFJceNative.sm3Final(ctx);
        ctx = 0;
        initialized = false;
```
**Issue**: After calling sm3Final, the native context (allocated by sm3Init with malloc) is never freed. The ctx is set to 0 but sm3Free is never called, causing a memory leak for each digest operation.
**Fix**:
```
byte[] result = SDFJceNative.sm3Final(ctx);
        SDFJceNative.sm3Free(ctx);
        ctx = 0;
        initialized = false;
```

---

### SM2PrivateKey doesn't clone key bytes, allowing external modification
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java:33`
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
**Issue**: The constructor assigns the keyBytes reference directly without cloning. This allows external code to modify the internal key state. Additionally, getEncoded() returns the internal array directly, and destroy() zeros the array which affects the caller's original array if they passed it directly to the constructor.
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


## Low

### sm3Free doesn't clear sensitive data before freeing
`sdf4j-jce/src/main/native/src/sdf_jce_sm3.c:192-193`
```
SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    free(ctx);
```
**Issue**: The sm3Free function frees the context without clearing potentially sensitive data. For consistency with sm4Free which does memset before free, sm3Free should also clear the context.
**Fix**:
```
SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(SM3Context));
    free(ctx);
```

---

### SM2PublicKey getX/getY return internal arrays without cloning
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PublicKey.java:36-37`
```
public byte[] getX() {
        return x;
    }

    public byte[] getY() {
        return y;
    }
```
**Issue**: The getX() and getY() methods return the internal byte arrays directly without cloning, allowing external modification of the key's internal state.
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

### SM2ParameterSpec.getUserId returns internal array without cloning
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/spec/SM2ParameterSpec.java:81`
```
public byte[] getUserId() {
        return userId;
    }
```
**Issue**: The getUserId() method returns the internal userId array directly without cloning, allowing external modification.
**Fix**:
```
public byte[] getUserId() {
        return userId.clone();
    }
```

---

### SM2Cipher.engineSetPadding accepts unsupported padding mode
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:237`
```
@Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding) && !"PKCS1Padding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("SM2 only supports NoPadding");
        }
    }
```
**Issue**: The engineSetPadding method accepts "PKCS1Padding" but the comment says SM2 only supports NoPadding. This is misleading and the method should throw an exception for unsupported padding.
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

### sm2Verify doesn't check signature length
`sdf4j-jce/src/main/native/src/sdf_jce_sm2.c:195-201`
```
jsize xLen = (*env)->GetArrayLength(env, publicKeyX);
    jsize yLen = (*env)->GetArrayLength(env, publicKeyY);
    if (xLen != SM2_KEY_BYTES || yLen != SM2_KEY_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "SM2 public key/signature length is invalid");
        return JNI_FALSE;
    }
```
**Issue**: The sm2Verify function checks publicKeyX and publicKeyY lengths but doesn't validate the signature array length. A malformed signature could cause out-of-bounds read when accessing sigBytes.
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
```

---


---

## CODEX Review

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
