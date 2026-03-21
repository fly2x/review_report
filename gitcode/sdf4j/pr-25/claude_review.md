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
