# Code Review: openHiTLS/hitls4j#32
**Reviewer**: CLAUDE


## High

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/FrodoKEMPrivateKeyImpl.java:13-14`
```
public FrodoKEMPrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor `FrodoKEMPrivateKeyImpl(byte[] encoded)` stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability. The Spec classes (FrodoKEMPrivateKeySpec) do clone the array, creating an inconsistent security model.
**Fix**:
```
public FrodoKEMPrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/FrodoKEMPublicKeyImpl.java:13-14`
```
public FrodoKEMPublicKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor `FrodoKEMPublicKeyImpl(byte[] encoded)` stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability.
**Fix**:
```
public FrodoKEMPublicKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/McEliecePrivateKeyImpl.java:13-14`
```
public McEliecePrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor `McEliecePrivateKeyImpl(byte[] encoded)` stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability.
**Fix**:
```
public McEliecePrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/McEliecePublicKeyImpl.java:13-14`
```
public McEliecePublicKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor `McEliecePublicKeyImpl(byte[] encoded)` stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability.
**Fix**:
```
public McEliecePublicKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Bounds check vulnerable to integer underflow
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:113-114`
```
if (sharedSecret.length - offset < secret.length) {
    throw new IllegalStateException("Insufficient space in sharedSecret array");
}
System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
```
**Issue**: The bounds check `sharedSecret.length - offset < secret.length` can underflow if `offset` is negative or very large (close to Integer.MAX_VALUE), potentially allowing a buffer overflow or negative indexing in System.arraycopy.
**Fix**:
```
if (offset < 0 || sharedSecret.length - offset < secret.length) {
    throw new InvalidParameterException("Invalid offset or insufficient space");
}
System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
```

---

### Bounds check vulnerable to integer underflow
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:113-114`
```
if (sharedSecret.length - offset < secret.length) {
    throw new IllegalStateException("Insufficient space in sharedSecret array");
}
System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
```
**Issue**: The bounds check `sharedSecret.length - offset < secret.length` can underflow if `offset` is negative or very large, potentially allowing a buffer overflow or negative indexing.
**Fix**:
```
if (offset < 0 || sharedSecret.length - offset < secret.length) {
    throw new InvalidParameterException("Invalid offset or insufficient space");
}
System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
```

---


## Medium

### Ciphertext not cleared after use, potential key material leak
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:97-100`
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;  // Cleared after use
    return result;
}
```
**Issue**: In `engineGenerateSecret()`, the shared key is cleared after use (`sharedKey = null`), but the ciphertext field is not cleared. The ciphertext contains cryptographic material that should be cleared from memory after use to prevent potential leakage.
**Fix**:
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;
    // Also clear ciphertext after encapsulation
    if (ciphertext != null) {
        Arrays.fill(ciphertext, (byte) 0);
        ciphertext = null;
    }
    return result;
}
```

---

### Ciphertext not cleared after use, potential key material leak
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:97-100`
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;  // Cleared after use
    return result;
}
```
**Issue**: In `engineGenerateSecret()`, the shared key is cleared after use but the ciphertext field is not. The ciphertext contains cryptographic material that should be cleared from memory after use.
**Fix**:
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;
    // Also clear ciphertext after encapsulation
    if (ciphertext != null) {
        Arrays.fill(ciphertext, (byte) 0);
        ciphertext = null;
    }
    return result;
}
```

---

### setKeys method does not validate key parameters
`src/main/java/org/openhitls/crypto/core/pqc/FrodoKEMImpl.java:24-27`
```
void setKeys(byte[] encapKey, byte[] decapKey) {
    this.encapKey = encapKey;
    this.decapKey = decapKey;
    CryptoNative.frodoKemSetKeys(nativeContext, encapKey, decapKey);
}
```
**Issue**: The `setKeys` method does not validate that the encapKey and decapKey parameters are non-null before using them. This could lead to unexpected behavior or NullPointerException when the native methods are called.
**Fix**:
```
void setKeys(byte[] encapKey, byte[] decapKey) {
    this.encapKey = encapKey;
    this.decapKey = decapKey;
    // Native methods handle null keys appropriately - setting only non-null keys
    CryptoNative.frodoKemSetKeys(nativeContext, 
        encapKey != null ? encapKey : new byte[0], 
        decapKey != null ? decapKey : new byte[0]);
}
```

---

### setKeys method does not validate key parameters
`src/main/java/org/openhitls/crypto/core/pqc/McElieceImpl.java:24-27`
```
void setKeys(byte[] encapKey, byte[] decapKey) {
    this.encapKey = encapKey;
    this.decapKey = decapKey;
    CryptoNative.mcelieceSetKeys(nativeContext, encapKey, decapKey);
}
```
**Issue**: The `setKeys` method does not validate that the encapKey and decapKey parameters are non-null before using them. While the native code may handle null parameters, this should be explicitly validated.
**Fix**:
```
void setKeys(byte[] encapKey, byte[] decapKey) {
    this.encapKey = encapKey;
    this.decapKey = decapKey;
    // Native methods handle null keys appropriately
    CryptoNative.mcelieceSetKeys(nativeContext, 
        encapKey != null ? encapKey : new byte[0], 
        decapKey != null ? decapKey : new byte[0]);
}
```

---


## Low

### Missing null check in constructor could allow null ciphertext
`src/main/java/org/openhitls/crypto/jce/key/FrodoKEMCiphertextKey.java:11-13`
```
public FrodoKEMCiphertextKey(byte[] ciphertext) {
    this.ciphertext = ciphertext != null ? ciphertext.clone() : null;
}
```
**Issue**: The constructor accepts null ciphertext and stores it without validation. While `getEncoded()` handles null by returning null, allowing null ciphertext in the constructor could lead to unexpected behavior in cryptographic operations.
**Fix**:
```
public FrodoKEMCiphertextKey(byte[] ciphertext) {
    if (ciphertext == null) {
        throw new IllegalArgumentException("Ciphertext cannot be null");
    }
    this.ciphertext = ciphertext.clone();
}
```

---

### Missing null check in constructor could allow null ciphertext
`src/main/java/org/openhitls/crypto/jce/key/McElieceCiphertextKey.java:11-13`
```
public McElieceCiphertextKey(byte[] ciphertext) {
    this.ciphertext = ciphertext != null ? ciphertext.clone() : null;
}
```
**Issue**: The constructor accepts null ciphertext and stores it without validation. Allowing null ciphertext could lead to unexpected behavior in cryptographic operations.
**Fix**:
```
public McElieceCiphertextKey(byte[] ciphertext) {
    if (ciphertext == null) {
        throw new IllegalArgumentException("Ciphertext cannot be null");
    }
    this.ciphertext = ciphertext.clone();
}
```

---

### malloc without size validation could cause integer overflow
`src/main/native/crypto_native_jni.c:3362-3366`
```
pubKey.key.kemEk.data = malloc(publicKeySize);
pubKey.key.kemEk.len = publicKeySize;
if (pubKey.key.kemEk.data == NULL) {
```
**Issue**: In `frodoKemGenerateKeyPair`, the code allocates memory using `malloc(publicKeySize)` and `malloc(privateKeySize)` without validating these sizes. While the sizes come from constants in this code path, defensive programming suggests checking for unreasonable sizes.
**Fix**:
```
if (publicKeySize == 0 || publicKeySize > 10485760) {  // 10MB sanity limit
    throwException(env, ILLEGAL_STATE_EXCEPTION, "Invalid public key size");
    return NULL;
}
pubKey.key.kemEk.data = malloc(publicKeySize);
pubKey.key.kemEk.len = publicKeySize;
if (pubKey.key.kemEk.data == NULL) {
```

---

### Missing validation of parameter name in constructor
`src/main/java/org/openhitls/crypto/jce/spec/FrodoKEMGenParameterSpec.java:10-12`
```
public FrodoKEMGenParameterSpec(String name) {
    this.name = name;
}
```
**Issue**: The `FrodoKEMGenParameterSpec` constructor accepts any string without validating it's a valid FrodoKEM parameter set name. This allows creation of invalid parameter specs that will fail later.
**Fix**:
```
public FrodoKEMGenParameterSpec(String name) {
    if (name == null) {
        throw new NullPointerException("name cannot be null");
    }
    if (!name.matches("^FrodoKEM-(640|976|1344)-(SHAKE|AES)$")) {
        throw new IllegalArgumentException("Invalid FrodoKEM parameter set: " + name);
    }
    this.name = name;
}
```

---

### Missing validation of parameter name in constructor
`src/main/java/org/openhitls/crypto/jce/spec/McElieceGenParameterSpec.java:10-12`
```
public McElieceGenParameterSpec(String name) {
    this.name = name;
}
```
**Issue**: The `McElieceGenParameterSpec` constructor accepts any string without validating it's a valid McEliece parameter set name.
**Fix**:
```
public McElieceGenParameterSpec(String name) {
    if (name == null) {
        throw new NullPointerException("name cannot be null");
    }
    if (!name.matches("^McEliece-(6688128|6688128f|6688128pc|6688128pcf|6960119|6960119f|6960119pc|6960119pcf|8192128|8192128f|8192128pc|8192128pcf)$")) {
        throw new IllegalArgumentException("Invalid McEliece parameter set: " + name);
    }
    this.name = name;
}
```

---
