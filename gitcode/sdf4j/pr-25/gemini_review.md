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
