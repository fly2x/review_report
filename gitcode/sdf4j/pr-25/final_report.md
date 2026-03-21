# Final Code Review Report
## openHiTLS/sdf4j - PR #25

### Summary
- **Total Issues**: 15
- **Critical**: 0
- **High**: 7
- **Medium**: 6
- **Low**: 2
- **Reviewers**: claude, gemini, codex

---


## High

### Resource leak and JCE contract violation in engineSign()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:130-143`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
```
// Calculate Z value according to GM/T 0009-2012
byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());

// Calculate e = SM3(Z || M)
byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

// Sign the hash e (returns r||s format, 64 bytes)
try {
    byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
    return DERCodec.rawToDer(rawSignature);
} finally {
    releaseSession();
}
```
**Issue**: Two issues: (1) The try-finally block only wraps sm2Sign(), not calculateZ() or calculateE(). If those methods throw exceptions, releaseSession() won't be called, leaking the SDF session handle. (2) After successful signing, releaseSession() sets sessionHandle to 0. The JCE Signature contract allows reuse without re-initialization, but subsequent engineSign() calls will use sessionHandle=0, causing SM2Util.calculateZ() and calculateE() to fail.
**Fix**:
```
try {
    // Calculate Z value according to GM/T 0009-2012
    byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());
    // Calculate e = SM3(Z || M)
    byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);
    // Sign the hash e (returns r||s format, 64 bytes)
    byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
    return DERCodec.rawToDer(rawSignature);
} finally {
    releaseSession();
}
```

---

### Resource leak and JCE contract violation in engineVerify()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:155-169`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
```
// Calculate Z value according to GM/T 0009-2012
byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());

// Calculate e = SM3(Z || M)
byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

// Convert signature to raw format (r||s, 64 bytes) from DER format
byte[] rawSignature = DERCodec.derToRaw(sigBytes);

// Verify the signature (expects r||s format, 64 bytes)
try {
    return SDFJceNative.sm2Verify(sessionHandle, publicKey.getX(), publicKey.getY(), e, rawSignature);
} finally {
    releaseSession();
}
```
**Issue**: Two issues: (1) The try-finally block only wraps sm2Verify(). If calculateZ(), calculateE(), or derToRaw() throw exceptions, releaseSession() won't be called, leaking the SDF session handle. (2) After successful verification, sessionHandle is set to 0. Subsequent engineVerify() calls on the same Signature instance will fail with sessionHandle=0.
**Fix**:
```
try {
    // Calculate Z value according to GM/T 0009-2012
    byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());
    // Calculate e = SM3(Z || M)
    byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);
    // Convert signature to raw format (r||s, 64 bytes) from DER format
    byte[] rawSignature = DERCodec.derToRaw(sigBytes);
    // Verify the signature (expects r||s format, 64 bytes)
    return SDFJceNative.sm2Verify(sessionHandle, publicKey.getX(), publicKey.getY(), e, rawSignature);
} finally {
    releaseSession();
}
```

---

### JCE contract violation: Mac instance unusable after doFinal()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java:92-99`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
@Override
protected byte[] engineDoFinal() {
    byte[] data = buffer.toByteArray();
    buffer.reset();
    try {
        return SDFJceNative.hmacSm3(sessionHandle, key, data);
    } finally {
        releaseSession();
    }
}
```
**Issue**: engineDoFinal() unconditionally calls releaseSession(), setting sessionHandle to 0. The JCE Mac contract allows reuse of a Mac instance after doFinal() without re-initialization (buffer is reset). Subsequent engineDoFinal() calls will invoke hmacSm3() with sessionHandle=0, causing failure.
**Fix**:
```
@Override
protected byte[] engineDoFinal() {
    acquireSession();
    byte[] data = buffer.toByteArray();
    buffer.reset();
    try {
        return SDFJceNative.hmacSm3(sessionHandle, key, data);
    } finally {
        releaseSession();
    }
}
```

---

### JCE contract violation: Mac instance unusable after doFinal()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java:114-121`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
@Override
protected byte[] engineDoFinal() {
    byte[] data = buffer.toByteArray();
    buffer.reset();
    try {
        return SDFJceNative.sm4Mac(sessionHandle, key, iv, data);
    } finally {
        releaseSession();
    }
}
```
**Issue**: engineDoFinal() unconditionally calls releaseSession(), setting sessionHandle to 0. The JCE Mac contract allows reuse after doFinal() without re-initialization. Subsequent engineDoFinal() calls will invoke sm4Mac() with sessionHandle=0, causing failure.
**Fix**:
```
@Override
protected byte[] engineDoFinal() {
    acquireSession();
    byte[] data = buffer.toByteArray();
    buffer.reset();
    try {
        return SDFJceNative.sm4Mac(sessionHandle, key, iv, data);
    } finally {
        releaseSession();
    }
}
```

---

### JCE contract violation: Cipher instance unusable after doFinal()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:174-189`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
try {
    if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
        if (publicKey == null) {
            throw new IllegalStateException("Public key not set");
        }
        // Native layer outputs GM/T format: 0x04 || C1 || C3 || C2
        return SDFJceNative.sm2Encrypt(sessionHandle, publicKey.getX(), publicKey.getY(), data);
    } else {
        if (privateKey == null) {
            throw new IllegalStateException("Private key not set");
        }
        // Native layer expects GM/T format: 0x04 || C1 || C3 || C2
        return SDFJceNative.sm2Decrypt(sessionHandle, privateKey.getKeyBytes(), data);
    }
} finally {
    releaseSession();
}
```
**Issue**: engineDoFinal() calls releaseSession() in the finally block, setting sessionHandle to 0. The JCE Cipher contract allows reusing an initialized cipher instance for multiple operations. Subsequent doFinal() calls will invoke sm2Encrypt() or sm2Decrypt() with sessionHandle=0, causing failure.
**Fix**:
```
acquireSession();
try {
    if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
        if (publicKey == null) {
            throw new IllegalStateException("Public key not set");
        }
        return SDFJceNative.sm2Encrypt(sessionHandle, publicKey.getX(), publicKey.getY(), data);
    } else {
        if (privateKey == null) {
            throw new IllegalStateException("Private key not set");
        }
        return SDFJceNative.sm2Decrypt(sessionHandle, privateKey.getKeyBytes(), data);
    }
} finally {
    releaseSession();
}
```

---

### JCE contract violation: AEAD cipher unusable after doFinal()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:377-407`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
try {
    if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
        if (data.length == 0) {
            throw new IllegalBlockSizeException("SM4 GCM/CCM does not support empty plaintext");
        }
        // sm4AuthEnc returns ciphertext || tag directly
        byte[] result = SDFJceNative.sm4AuthEnc(sessionHandle, cipherMode, key, iv,
                aad.length > 0 ? aad : null, data);
        if (result == null) {
            throw new IllegalBlockSizeException("AuthEnc returned null");
        }
        return result;
    } else {
        // Decrypt: input is ciphertext || tag
        if (data.length < tagBytes) {
            throw new BadPaddingException("Input too short for GCM tag");
        }
        byte[] ciphertext = new byte[data.length - tagBytes];
        byte[] tag = new byte[tagBytes];
        System.arraycopy(data, 0, ciphertext, 0, ciphertext.length);
        System.arraycopy(data, ciphertext.length, tag, 0, tagBytes);

        byte[] plaintext = SDFJceNative.sm4AuthDec(sessionHandle, cipherMode, key, iv,
                aad.length > 0 ? aad : null, tag, ciphertext);
        if (plaintext == null) {
            throw new AEADBadTagException("GCM authentication failed");
        }
        return plaintext;
    }
} finally {
    releaseSession();
}
```
**Issue**: doFinalAead() calls releaseSession() in the finally block. For GCM/CCM modes, acquireSession() is only called in engineInit(). After the first doFinal(), subsequent operations will use sessionHandle=0, causing sm4AuthEnc() or sm4AuthDec() to fail.
**Fix**:
```
acquireSession();
try {
    if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
        if (data.length == 0) {
            throw new IllegalBlockSizeException("SM4 GCM/CCM does not support empty plaintext");
        }
        byte[] result = SDFJceNative.sm4AuthEnc(sessionHandle, cipherMode, key, iv,
                aad.length > 0 ? aad : null, data);
        if (result == null) {
            throw new IllegalBlockSizeException("AuthEnc returned null");
        }
        return result;
    } else {
        if (data.length < tagBytes) {
            throw new BadPaddingException("Input too short for GCM tag");
        }
        byte[] ciphertext = new byte[data.length - tagBytes];
        byte[] tag = new byte[tagBytes];
        System.arraycopy(data, 0, ciphertext, 0, ciphertext.length);
        System.arraycopy(data, ciphertext.length, tag, 0, tagBytes);

        byte[] plaintext = SDFJceNative.sm4AuthDec(sessionHandle, cipherMode, key, iv,
                aad.length > 0 ? aad : null, tag, ciphertext);
        if (plaintext == null) {
            throw new AEADBadTagException("GCM authentication failed");
        }
        return plaintext;
    }
} finally {
    releaseSession();
}
```

---

### JCE contract violation: MessageDigest unusable after digest()
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:88-103`
**Reviewers**: GEMINI, CODEX | **置信度**: 较可信
```
@Override
protected byte[] engineDigest() {
    try {
        if (!initialized) {
            // Empty input: need a session for the one-shot call
            acquireSession();
            return SDFJceNative.sm3Digest(sessionHandle, new byte[0]);
        }
        byte[] result = SDFJceNative.sm3Final(ctx);
        SDFJceNative.sm3Free(ctx);
        ctx = 0;
        initialized = false;
        return result;
    } finally {
        releaseSession();
    }
}
```
**Issue**: engineDigest() calls releaseSession() in the finally block. After the first digest() call, the sessionHandle is set to 0. Subsequent digest() calls will fail when trying to use the session. The MessageDigest SPI allows reuse after digest().
**Fix**:
```
@Override
protected byte[] engineDigest() {
    acquireSession();
    try {
        if (!initialized) {
            return SDFJceNative.sm3Digest(sessionHandle, new byte[0]);
        }
        byte[] result = SDFJceNative.sm3Final(ctx);
        SDFJceNative.sm3Free(ctx);
        ctx = 0;
        initialized = false;
        return result;
    } finally {
        releaseSession();
    }
}
```

---


## Medium

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:49`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
protected long sessionHandle;
```
**Issue**: sessionHandle is accessed from multiple methods (acquireSession, releaseSession, doFinal) without proper synchronization. While JCE Cipher objects are not required to be thread-safe, the lack of volatile can cause memory visibility issues between constructor and other methods, especially in concurrent scenarios where the object might be shared improperly.
**Fix**:
```
protected volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:43`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
private long sessionHandle;
```
**Issue**: sessionHandle should be volatile for proper memory visibility between constructor, acquireSession(), and releaseSession().
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java:31`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
private long sessionHandle;
```
**Issue**: sessionHandle should be volatile for proper memory visibility.
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java:34`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
private long sessionHandle;
```
**Issue**: sessionHandle should be volatile for proper memory visibility.
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:26`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
private long sessionHandle;
```
**Issue**: sessionHandle should be volatile for proper memory visibility between constructor and other methods.
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:38`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
private long sessionHandle;
```
**Issue**: sessionHandle should be volatile for proper memory visibility between constructor and other methods.
**Fix**:
```
private volatile long sessionHandle;
```

---


## Low

### Missing null check on bytes parameter
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/random/SDFSecureRandom.java:40-48`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
if (bytes == null || bytes.length == 0) {
    return;
}
byte[] random = SDFJceNative.generateRandom(sessionHandle, bytes.length);
if (random == null) {
    throw new IllegalStateException("Failed to generate random bytes: native call returned null");
}
System.arraycopy(random, 0, bytes, 0, bytes.length);
```
**Issue**: The null check on line 41-43 checks `bytes == null` but the check `bytes.length == 0` in the same condition could potentially throw NPE if bytes is null. However, looking at the actual code flow, the check `bytes == null || bytes.length == 0` uses short-circuit evaluation, so if bytes is null, bytes.length is never evaluated. This is actually a false positive - the code is correct.

---

### Deprecated Maven javadoc parameter
`script/build_with_simulator.sh:68`
**Reviewers**: CLAUDE | **置信度**: 可信
```
mvn javadoc:javadoc -pl sdf4j -Dadditionalparam=-Xwerror || exit 1
```
**Issue**: The -Dadditionalparam flag is deprecated in Maven Javadoc Plugin 3.0+. Use -DadditionalOptions instead for forward compatibility.
**Fix**:
```
mvn javadoc:javadoc -pl sdf4j -DadditionalOptions=-Xwerror || exit 1
```

---
