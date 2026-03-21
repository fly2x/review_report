# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdf4j
- PR: #25
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/sdf4j#25
**Reviewer**: CLAUDE


## High

### Resource leak in engineSign() when pre-sign operations fail
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:130-143`
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
**Issue**: The try-finally block only wraps the sm2Sign() call. If calculateZ() or calculateE() throw exceptions (lines 131, 134), releaseSession() will not be called, leaking the SDF session handle.
**Fix**:
```
// Calculate Z value according to GM/T 0009-2012
// Calculate e = SM3(Z || M)
// Sign the hash e (returns r||s format, 64 bytes)
try {
    byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());
    byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);
    byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
    return DERCodec.rawToDer(rawSignature);
} finally {
    releaseSession();
}
```

---

### Resource leak in engineVerify() when pre-verify operations fail
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:155-169`
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
**Issue**: The try-finally block only wraps the sm2Verify() call. If calculateZ() (line 156), calculateE() (line 159), or derToRaw() (line 162) throw exceptions, releaseSession() will not be called, leaking the SDF session handle.
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


## Medium

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:49`
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
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:44`
```
private long sessionHandle;
```
**Issue**: Same as SM4Cipher - sessionHandle should be volatile for proper memory visibility between constructor, acquireSession(), and releaseSession().
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java:33`
```
private long sessionHandle;
```
**Issue**: Same as SM4Cipher - sessionHandle should be volatile for proper memory visibility.
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java:36`
```
private long sessionHandle;
```
**Issue**: Same as SM4Cipher - sessionHandle should be volatile for proper memory visibility.
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java:27`
```
private long sessionHandle;
```
**Issue**: Same as SM4Cipher - sessionHandle should be volatile for proper memory visibility.
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing volatile on sessionHandle for thread safety
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:39`
```
private long sessionHandle;
```
**Issue**: Same as SM4Cipher - sessionHandle should be volatile for proper memory visibility.
**Fix**:
```
private volatile long sessionHandle;
```

---

### Missing null check on random byte array before use
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/random/SDFSecureRandom.java:43-50`
```
byte[] random = SDFJceNative.generateRandom(sessionHandle, bytes.length);
if (random == null) {
    throw new IllegalStateException("Failed to generate random bytes: native call returned null");
}
System.arraycopy(random, 0, bytes, 0, bytes.length);
```
**Issue**: The null check is done on 'bytes' but SDFJceNative.generateRandom could return null, which would cause NullPointerException in System.arraycopy.
**Fix**:
```
if (bytes == null) {
    return;
}
byte[] random = SDFJceNative.generateRandom(sessionHandle, bytes.length);
if (random == null) {
    throw new IllegalStateException("Failed to generate random bytes: native call returned null");
}
System.arraycopy(random, 0, bytes, 0, bytes.length);
```

---


## Low

### Deprecated Maven javadoc parameter
`script/build_with_simulator.sh:68`
```
mvn javadoc:javadoc -pl sdf4j -Dadditionalparam=-Xwerror || exit 1
```
**Issue**: The -Dadditionalparam flag is deprecated in Maven Javadoc Plugin 3.0+. Use -DadditionalOptions instead for forward compatibility.
**Fix**:
```
mvn javadoc:javadoc -pl sdf4j -DadditionalOptions=-Xwerror || exit 1
```

---


---

## GEMINI Review

# Code Review: openHiTLS/sdf4j#25
**Reviewer**: GEMINI


## High

### JCE contract violation: session closed in doFinal prevents cipher reuse
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:165-184`
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
**Issue**: `releaseSession()` is called in the `finally` block of `engineDoFinal()`. Because `acquireSession()` is only called in `engineInit()`, subsequent `update()` or `doFinal()` operations on the same cipher instance will use `sessionHandle = 0`, leading to exceptions. The JCE `CipherSpi` contract requires instances to be reusable for multiple operations after a single `engineInit()`.
**Fix**:
```
acquireSession();
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

---

### JCE contract violation: session closed in AEAD doFinal prevents cipher reuse
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:377-407`
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
**Issue**: `releaseSession()` is called in `doFinalAead()`, but `acquireSession()` is not called upon reentry, causing subsequent AEAD encryption/decryption operations on the reused cipher instance to fail with `sessionHandle = 0`.
**Fix**:
```
acquireSession();
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

---

### JCE contract violation: session closed in doFinal prevents MAC reuse
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java:95-101`
```
try {
            return SDFJceNative.hmacSm3(sessionHandle, key, data);
        } finally {
            releaseSession();
        }
```
**Issue**: `engineDoFinal()` unconditionally releases the session handle. The standard Mac contract allows reuse of a Mac instance without reinitialization. The next time `engineDoFinal()` is invoked, `sessionHandle` will be `0`, causing the native invocation to fail.
**Fix**:
```
acquireSession();
        try {
            return SDFJceNative.hmacSm3(sessionHandle, key, data);
        } finally {
            releaseSession();
        }
```

---

### JCE contract violation: session closed in doFinal prevents MAC reuse
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java:117-123`
```
try {
            return SDFJceNative.sm4Mac(sessionHandle, key, iv, data);
        } finally {
            releaseSession();
        }
```
**Issue**: The Mac session is released in `engineDoFinal()`, invalidating the instance for subsequent operations that do not call `engineInit()`. Missing `acquireSession()` before doing native MAC operations.
**Fix**:
```
acquireSession();
        try {
            return SDFJceNative.sm4Mac(sessionHandle, key, iv, data);
        } finally {
            releaseSession();
        }
```

---

### Null sessionHandle crash during SM2Signature sign reuse
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:134-143`
```
byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

        // Sign the hash e (returns r||s format, 64 bytes)
        try {
            byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
            // Convert to DER format for compatibility with Bouncy Castle and other providers
            return DERCodec.rawToDer(rawSignature);
        } finally {
            releaseSession();
        }
```
**Issue**: `engineSign()` unconditionally calls `releaseSession()`. On a subsequent signing operation (reuse), `SM2Util.calculateE(sessionHandle, ...)` will be called with `sessionHandle = 0`, causing an exception before it even attempts native signing.
**Fix**:
```
acquireSession();
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

        // Sign the hash e (returns r||s format, 64 bytes)
        try {
            byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
            // Convert to DER format for compatibility with Bouncy Castle and other providers
            return DERCodec.rawToDer(rawSignature);
        } finally {
            releaseSession();
        }
```

---

### Null sessionHandle crash during SM2Signature verify reuse
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:159-170`
```
// SM2 requires hashing the data with user ID (Z)
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

        // Convert DER signature to raw r||s format
        byte[] rawSignature = DERCodec.derToRaw(sigBytes);

        // Verify the signature (expects r||s format, 64 bytes)
        try {
            return SDFJceNative.sm2Verify(sessionHandle, publicKey.getX(), publicKey.getY(), e, rawSignature);
        } finally {
            releaseSession();
        }
```
**Issue**: Similar to `engineSign()`, `engineVerify()` releases the session handle. If the signature instance is reused without reinitialization, `SM2Util.calculateE()` will be executed with `sessionHandle = 0`.
**Fix**:
```
acquireSession();
        // SM2 requires hashing the data with user ID (Z)
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

        // Convert DER signature to raw r||s format
        byte[] rawSignature = DERCodec.derToRaw(sigBytes);

        // Verify the signature (expects r||s format, 64 bytes)
        try {
            return SDFJceNative.sm2Verify(sessionHandle, publicKey.getX(), publicKey.getY(), e, rawSignature);
        } finally {
            releaseSession();
        }
```

---


---

## CODEX Review

# Code Review: openHiTLS/sdf4j#25
**Reviewer**: CODEX


## Medium

### HMAC instance becomes unusable after the first `doFinal()`
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java:92-99`
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
**Issue**: `engineInit()` is the only place that reopens the SDF session, but `engineDoFinal()` now always closes it. The same `Mac` instance can still accept more `update()` calls after `doFinal()`, yet the next `engineDoFinal()` will invoke `hmacSm3()` with `sessionHandle == 0` and fail.
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

### SM4 MAC state is broken after one `doFinal()`
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java:114-121`
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
**Issue**: `engineDoFinal()` closes the session, but no later path reopens it unless the caller performs another `init()`. Reusing the same `Mac` object with the same key after one successful `doFinal()` will call `sm4Mac()` with a zero session handle.
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

### `sign()` and `verify()` close the session without reopening it
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java:130-168`
```
// Calculate Z value according to GM/T 0009-2012
byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());

// Calculate e = SM3(Z || M)
byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

// Sign the hash e (returns r||s format, 64 bytes)
try {
    byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
    // Convert to DER format for compatibility with Bouncy Castle and other providers
    return DERCodec.rawToDer(rawSignature);
} finally {
    releaseSession();
}
...
// Calculate Z value according to GM/T 0009-2012
byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());

// Calculate e = SM3(Z || M)
byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

try {
    return SDFJceNative.sm2Verify(sessionHandle, publicKey.getX(), publicKey.getY(), e, rawSignature);
} finally {
    releaseSession();
}
```
**Issue**: After the first successful `sign()` or `verify()`, `releaseSession()` sets `sessionHandle` to `0`. A later call on the same initialized `Signature` object uses that dead handle in `SM2Util.calculateZ()`, `SM2Util.calculateE()`, and `sm2Sign()/sm2Verify()`, so repeat operations fail even though the object still holds the key material and buffered state.
**Fix**:
```
@Override
protected byte[] engineSign() throws SignatureException {
    if (!forSigning || privateKey == null) {
        throw new SignatureException("Not initialized for signing");
    }
    if (publicKey == null) {
        throw new SignatureException(
            "Public key required for SM2 signature. " +
            "Use setParameter(SM2ParameterSpec) to provide the public key before signing.");
    }

    byte[] dataBytes = data.toByteArray();
    data.reset();

    acquireSession();
    try {
        byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);
        byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
        return DERCodec.rawToDer(rawSignature);
    } finally {
        releaseSession();
    }
}

@Override
protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (forSigning || publicKey == null) {
        throw new SignatureException("Not initialized for verification");
    }

    byte[] dataBytes = data.toByteArray();
    data.reset();
    byte[] rawSignature = DERCodec.derToRaw(sigBytes);

    acquireSession();
    try {
        byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);
        return SDFJceNative.sm2Verify(sessionHandle, publicKey.getX(), publicKey.getY(), e, rawSignature);
    } finally {
        releaseSession();
    }
}
```

---

### SM2 cipher cannot be used again after one `doFinal()`
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java:174-189`
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
**Issue**: `engineDoFinal()` now closes the session in a `finally` block, but nothing reopens it before the next encryption/decryption attempt. A caller that reuses the same initialized `Cipher` instance will buffer input normally and then pass `sessionHandle == 0` to `sm2Encrypt()` or `sm2Decrypt()`.
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

### GCM/CCM mode loses its session after the first `doFinal()`
`sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java:377-407`
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
**Issue**: `doFinalAead()` closes the session every time, but AEAD mode does not recreate it anywhere except `engineInit()`. After one GCM/CCM operation, later `updateAAD()`/`update()` calls still succeed because they only buffer bytes, but the next `doFinalAead()` reaches `sm4AuthEnc()`/`sm4AuthDec()` with `sessionHandle == 0`.
**Fix**:
```
private byte[] doFinalAead() throws IllegalBlockSizeException, BadPaddingException {
    byte[] data = buffer.toByteArray();
    byte[] aad = aadBuffer.toByteArray();
    buffer.reset();
    aadBuffer.reset();

    int tagBytes = gcmTagLenBits / 8;
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
