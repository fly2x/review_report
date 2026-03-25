# Final Code Review Report
## openHiTLS/hitls4j - PR #32

### Summary
- **Total Issues**: 28
- **Critical**: 0
- **High**: 18
- **Medium**: 4
- **Low**: 6
- **Reviewers**: claude, gemini, codex

---


## High

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/FrodoKEMPrivateKeyImpl.java:11-14`
**Reviewers**: CLAUDE | **置信度**: 可信
```
public FrodoKEMPrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability. The same pattern exists in the public key constructor and both McEliece key classes.
**Fix**:
```
public FrodoKEMPrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/FrodoKEMPublicKeyImpl.java:11-14`
**Reviewers**: CLAUDE | **置信度**: 可信
```
public FrodoKEMPublicKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability.
**Fix**:
```
public FrodoKEMPublicKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/McEliecePrivateKeyImpl.java:11-14`
**Reviewers**: CLAUDE | **置信度**: 可信
```
public McEliecePrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability.
**Fix**:
```
public McEliecePrivateKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Key constructor stores direct reference to encoded array without cloning
`src/main/java/org/openhitls/crypto/jce/key/McEliecePublicKeyImpl.java:11-14`
**Reviewers**: CLAUDE | **置信度**: 可信
```
public McEliecePublicKeyImpl(byte[] encoded) {
    this.encoded = encoded;  // Direct reference - not cloned
    this.params = null;
}
```
**Issue**: The constructor stores a direct reference to the input array instead of cloning it. This allows external code to modify the key material after the key object is created, which is a security vulnerability.
**Fix**:
```
public McEliecePublicKeyImpl(byte[] encoded) {
    this.encoded = encoded != null ? encoded.clone() : null;
    this.params = null;
}
```

---

### Missing NULL check after GetStringUTFChars in frodoKemCreateContext
`src/main/native/crypto_native_jni.c:3330-3332`
**Reviewers**: GEMINI | **置信度**: 可信
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
int paramId = getFrodoKemParamId(parameterSet);
```
**Issue**: The JNI function GetStringUTFChars can return NULL if the JVM runs out of memory. If it returns NULL, passing it to getFrodoKemParamId (which uses strcmp) will cause a segmentation fault and crash the JVM. The same pattern exists in mcelieceCreateContext.
**Fix**:
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
if (parameterSet == NULL) {
    return 0;
}
int paramId = getFrodoKemParamId(parameterSet);
```

---

### Missing NULL check after GetStringUTFChars in frodoKemGenerateKeyPair
`src/main/native/crypto_native_jni.c:3361-3363`
**Reviewers**: GEMINI | **置信度**: 可信
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
int paramId = getFrodoKemParamId(parameterSet);
```
**Issue**: GetStringUTFChars can return NULL on out-of-memory. Passing NULL to getFrodoKemParamId will result in a segmentation fault. The same issue exists in mcelieceGenerateKeyPair.
**Fix**:
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
if (parameterSet == NULL) {
    return NULL;
}
int paramId = getFrodoKemParamId(parameterSet);
```

---

### Missing NULL check after GetByteArrayElements for encapsulate key in frodoKemSetKeys
`src/main/native/crypto_native_jni.c:3450-3451`
**Reviewers**: GEMINI | **置信度**: 可信
```
pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);
```
**Issue**: GetByteArrayElements can return NULL on out-of-memory. Using this NULL pointer or passing it to ReleaseByteArrayElements will cause undefined behavior or crash the JVM. The same issue exists in mcelieceSetKeys for both encapsulation and decapsulation keys.
**Fix**:
```
pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
if (pubKey.key.kemEk.data == NULL) {
    return;
}
pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);
```

---

### Missing NULL check after GetByteArrayElements for decapsulate key in frodoKemSetKeys
`src/main/native/crypto_native_jni.c:3465-3466`
**Reviewers**: GEMINI | **置信度**: 可信
```
privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);
```
**Issue**: GetByteArrayElements can return NULL on out-of-memory. Using this NULL pointer will cause undefined behavior or crash the JVM. The same issue exists in mcelieceSetKeys.
**Fix**:
```
privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
if (privKey.key.kemDk.data == NULL) {
    return;
}
privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);
```

---

### Missing NULL check after GetStringUTFChars in mcelieceCreateContext
`src/main/native/crypto_native_jni.c:3664-3666`
**Reviewers**: GEMINI | **置信度**: 可信
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
int paramId = getMcElieceParamId(parameterSet);
```
**Issue**: GetStringUTFChars can return NULL. Passing NULL to getMcElieceParamId will result in a segmentation fault.
**Fix**:
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
if (parameterSet == NULL) {
    return 0;
}
int paramId = getMcElieceParamId(parameterSet);
```

---

### Missing NULL check after GetStringUTFChars in mcelieceGenerateKeyPair
`src/main/native/crypto_native_jni.c:3695-3697`
**Reviewers**: GEMINI | **置信度**: 可信
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
int paramId = getMcElieceParamId(parameterSet);
```
**Issue**: GetStringUTFChars can return NULL. Passing NULL to getMcElieceParamId will result in a segmentation fault.
**Fix**:
```
const char *parameterSet = (*env)->GetStringUTFChars(env, jparameterSet, NULL);
if (parameterSet == NULL) {
    return NULL;
}
int paramId = getMcElieceParamId(parameterSet);
```

---

### Missing NULL check after GetByteArrayElements for encapsulate key in mcelieceSetKeys
`src/main/native/crypto_native_jni.c:3784-3785`
**Reviewers**: GEMINI | **置信度**: 可信
```
pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);
```
**Issue**: GetByteArrayElements can return NULL on out-of-memory. Using this NULL pointer will cause undefined behavior or crash the JVM.
**Fix**:
```
pubKey.key.kemEk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jencapKey, NULL);
if (pubKey.key.kemEk.data == NULL) {
    return;
}
pubKey.key.kemEk.len = (*env)->GetArrayLength(env, jencapKey);
```

---

### Missing NULL check after GetByteArrayElements for decapsulate key in mcelieceSetKeys
`src/main/native/crypto_native_jni.c:3799-3800`
**Reviewers**: GEMINI | **置信度**: 可信
```
privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);
```
**Issue**: GetByteArrayElements can return NULL on out-of-memory. Using this NULL pointer will cause undefined behavior or crash the JVM.
**Fix**:
```
privKey.key.kemDk.data = (uint8_t *)(*env)->GetByteArrayElements(env, jdecapKey, NULL);
if (privKey.key.kemDk.data == NULL) {
    return;
}
privKey.key.kemDk.len = (*env)->GetArrayLength(env, jdecapKey);
```

---

### Bounds check vulnerable to integer underflow
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:115`
**Reviewers**: CLAUDE | **置信度**: 可信
```
if (sharedSecret.length - offset < secret.length) {
    throw new IllegalStateException("Insufficient space in sharedSecret array");
}
System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
```
**Issue**: The bounds check `sharedSecret.length - offset < secret.length` can underflow if `offset` is negative or very large (close to Integer.MAX_VALUE), potentially allowing a buffer overflow or negative indexing in System.arraycopy. The same issue exists in McElieceKeyAgreement.
**Fix**:
```
if (offset < 0 || sharedSecret.length - offset < secret.length) {
    throw new InvalidParameterException("Invalid offset or insufficient space");
}
System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
```

---

### Bounds check vulnerable to integer underflow
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:118`
**Reviewers**: CLAUDE | **置信度**: 可信
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

### KeyFactory treats raw bytes as PKCS#8/X.509 without parsing
`src/main/java/org/openhitls/crypto/jce/key/factory/FrodoKEMKeyFactory.java:26-31`
**Reviewers**: CODEX | **置信度**: 可信
```
} else if (keySpec instanceof PKCS8EncodedKeySpec) {
    try {
        return new FrodoKEMPrivateKeyImpl(((PKCS8EncodedKeySpec) keySpec).getEncoded());
    } catch (Exception e) {
        throw new InvalidKeySpecException("Invalid PKCS8EncodedKeySpec for FrodoKEM private key", e);
    }
}
...
} else if (keySpec instanceof X509EncodedKeySpec) {
    try {
        return new FrodoKEMPublicKeyImpl(((X509EncodedKeySpec) keySpec).getEncoded());
    } catch (Exception e) {
        throw new InvalidKeySpecException("Invalid X509EncodedKeySpec for FrodoKEM public key", e);
    }
}
...
if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
}
...
if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
}
```
**Issue**: The KeyFactory accepts PKCS8EncodedKeySpec and X509EncodedKeySpec, but never parses or validates any ASN.1 wrapper. It just copies the byte array and later re-exports the same bytes as if they were standard encodings. This breaks interoperability with code that expects real PKCS#8 or SubjectPublicKeyInfo data. The same issue exists in McElieceKeyFactory.
**Fix**:
```
@Override
protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof FrodoKEMPrivateKeySpec) {
        FrodoKEMPrivateKeySpec spec = (FrodoKEMPrivateKeySpec) keySpec;
        return new FrodoKEMPrivateKeyImpl(spec.getParams(), spec.getEncoded());
    }
    if (keySpec instanceof PKCS8EncodedKeySpec) {
        throw new InvalidKeySpecException(
                "PKCS#8 encoding is not implemented for FrodoKEM keys; use FrodoKEMPrivateKeySpec");
    }
    throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
}

@Override
protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof FrodoKEMPublicKeySpec) {
        FrodoKEMPublicKeySpec spec = (FrodoKEMPublicKeySpec) keySpec;
        return new FrodoKEMPublicKeyImpl(spec.getParams(), spec.getEncoded());
    }
    if (keySpec instanceof X509EncodedKeySpec) {
        throw new InvalidKeySpecException(
                "X.509 encoding is not implemented for FrodoKEM keys; use FrodoKEMPublicKeySpec");
    }
    throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
}

@Override
protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
    if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)
            || keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
        throw new InvalidKeySpecException(
                "Standard X.509/PKCS#8 encodings are not implemented for FrodoKEM keys");
    }
    // existing FrodoKEMPublicKeySpec / FrodoKEMPrivateKeySpec handling stays here
}
```

---

### KeyFactory treats raw bytes as PKCS#8/X.509 without parsing
`src/main/java/org/openhitls/crypto/jce/key/factory/McElieceKeyFactory.java:26-31`
**Reviewers**: CODEX | **置信度**: 可信
```
} else if (keySpec instanceof PKCS8EncodedKeySpec) {
    try {
        return new McEliecePrivateKeyImpl(((PKCS8EncodedKeySpec) keySpec).getEncoded());
    } catch (Exception e) {
        throw new InvalidKeySpecException("Invalid PKCS8EncodedKeySpec for Classic McEliece private key", e);
    }
}
...
} else if (keySpec instanceof X509EncodedKeySpec) {
    try {
        return new McEliecePublicKeyImpl(((X509EncodedKeySpec) keySpec).getEncoded());
    } catch (Exception e) {
        throw new InvalidKeySpecException("Invalid X509EncodedKeySpec for Classic McEliece public key", e);
    }
}
...
if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
}
...
if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
}
```
**Issue**: The KeyFactory accepts PKCS8EncodedKeySpec and X509EncodedKeySpec, but never parses or validates any ASN.1 wrapper. It just copies the byte array and later re-exports the same bytes as if they were standard encodings.
**Fix**:
```
@Override
protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof McEliecePrivateKeySpec) {
        McEliecePrivateKeySpec spec = (McEliecePrivateKeySpec) keySpec;
        return new McEliecePrivateKeyImpl(spec.getParams(), spec.getEncoded());
    }
    if (keySpec instanceof PKCS8EncodedKeySpec) {
        throw new InvalidKeySpecException(
                "PKCS#8 encoding is not implemented for Classic McEliece keys; use McEliecePrivateKeySpec");
    }
    throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
}

@Override
protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof McEliecePublicKeySpec) {
        McEliecePublicKeySpec spec = (McEliecePublicKeySpec) keySpec;
        return new McEliecePublicKeyImpl(spec.getParams(), spec.getEncoded());
    }
    if (keySpec instanceof X509EncodedKeySpec) {
        throw new InvalidKeySpecException(
                "X.509 encoding is not implemented for Classic McEliece keys; use McEliecePublicKeySpec");
    }
    throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
}

@Override
protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
    if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)
            || keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
        throw new InvalidKeySpecException(
                "Standard X.509/PKCS#8 encodings are not implemented for Classic McEliece keys");
    }
    // existing McEliecePublicKeySpec / McEliecePrivateKeySpec handling stays here
}
```

---

### Test suite uses incorrect provider name
`src/test/java/org/openhitls/crypto/jce/pqc/FrodoKEMTest.java:44`
**Reviewers**: CODEX | **置信度**: 可信
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", "HiTls4j");
KeyAgreement senderAgreement = KeyAgreement.getInstance("FrodoKEM", "HiTls4j");
KeyAgreement receiverAgreement = KeyAgreement.getInstance("FrodoKEM", "HiTls4j");
```
**Issue**: These calls request provider "HiTls4j", but the provider is registered as "HITLS4J" (case-sensitive). Every getInstance(..., "HiTls4j") call will throw NoSuchProviderException and the tests will fail. The same issue exists in McElieceTest.
**Fix**:
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
KeyAgreement senderAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
KeyAgreement receiverAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
```

---

### Test suite uses incorrect provider name
`src/test/java/org/openhitls/crypto/jce/pqc/McElieceTest.java:40`
**Reviewers**: CODEX | **置信度**: 可信
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Classic-McEliece", "HiTls4j");
KeyAgreement senderAgreement = KeyAgreement.getInstance("Classic-McEliece", "HiTls4j");
KeyAgreement receiverAgreement = KeyAgreement.getInstance("Classic-McEliece", "HiTls4j");
```
**Issue**: The test requests provider "HiTls4j" instead of the registered "HITLS4J". Because provider lookup is case-sensitive, the test will fail with NoSuchProviderException.
**Fix**:
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
KeyAgreement senderAgreement = KeyAgreement.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
KeyAgreement receiverAgreement = KeyAgreement.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
```

---


## Medium

### Missing null check on key parameters causes NullPointerException
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:52-55`
**Reviewers**: CODEX | **置信度**: 可信
```
} else if (frodoKemPrivateKey != null) {
    parameterSet = frodoKemPrivateKey.getParams().getName();
} else if (frodoKemPublicKey != null) {
    parameterSet = frodoKemPublicKey.getParams().getName();
}
```
**Issue**: The init method assumes every FrodoKEM key carries a non-null FrodoKEMParameterSpec. Keys created from the PKCS8EncodedKeySpec/X509EncodedKeySpec constructors have params=null, causing a NullPointerException instead of a proper InvalidKeyException. The same issue exists in McElieceKeyAgreement.
**Fix**:
```
FrodoKEMParameterSpec keyParams = null;
if (frodoKemPrivateKey != null) {
    keyParams = frodoKemPrivateKey.getParams();
} else if (frodoKemPublicKey != null) {
    keyParams = frodoKemPublicKey.getParams();
}

if (params != null) {
    parameterSet = params.getName();
    if (keyParams != null && !parameterSet.equals(keyParams.getName())) {
        throw new InvalidKeyException("Key parameter set does not match the supplied FrodoKEM parameters");
    }
} else if (keyParams != null) {
    parameterSet = keyParams.getName();
} else {
    throw new InvalidKeyException("FrodoKEM key is missing parameter metadata");
}
```

---

### Missing null check on key parameters causes NullPointerException
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:55-58`
**Reviewers**: CODEX | **置信度**: 可信
```
} else if (mcEliecePrivateKey != null) {
    parameterSet = mcEliecePrivateKey.getParams().getName();
} else if (mcEliecePublicKey != null) {
    parameterSet = mcEliecePublicKey.getParams().getName();
}
```
**Issue**: The init method dereferences getParams() without checking for null. Keys constructed from the encoded-key paths have params=null, causing a NullPointerException instead of a checked InvalidKeyException.
**Fix**:
```
McElieceParameterSpec keyParams = null;
if (mcEliecePrivateKey != null) {
    keyParams = mcEliecePrivateKey.getParams();
} else if (mcEliecePublicKey != null) {
    keyParams = mcEliecePublicKey.getParams();
}

if (params != null) {
    parameterSet = params.getName();
    if (keyParams != null && !parameterSet.equals(keyParams.getName())) {
        throw new InvalidKeyException("Key parameter set does not match the supplied Classic McEliece parameters");
    }
} else if (keyParams != null) {
    parameterSet = keyParams.getName();
} else {
    throw new InvalidKeyException("Classic McEliece key is missing parameter metadata");
}
```

---

### Incorrect exception type thrown for short buffers
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:116`
**Reviewers**: GEMINI | **置信度**: 可信
```
if (sharedSecret.length - offset < secret.length) {
    throw new IllegalStateException("Insufficient space in sharedSecret array");
}
```
**Issue**: When generating a secret into an existing array that is too small, the implementation throws IllegalStateException. According to the JCE contract for KeyAgreementSpi.engineGenerateSecret(byte[], int), a javax.crypto.ShortBufferException must be thrown to allow calling applications to handle the size dynamically. The same issue exists in McElieceKeyAgreement.
**Fix**:
```
if (sharedSecret.length - offset < secret.length) {
    throw new javax.crypto.ShortBufferException("Insufficient space in sharedSecret array");
}
```

---

### Incorrect exception type thrown for short buffers
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:119`
**Reviewers**: GEMINI | **置信度**: 可信
```
if (sharedSecret.length - offset < secret.length) {
    throw new IllegalStateException("Insufficient space in sharedSecret array");
}
```
**Issue**: When generating a secret into an existing array that is too small, the implementation throws IllegalStateException. According to the JCE contract for KeyAgreementSpi.engineGenerateSecret(byte[], int), a javax.crypto.ShortBufferException must be thrown.
**Fix**:
```
if (sharedSecret.length - offset < secret.length) {
    throw new javax.crypto.ShortBufferException("Insufficient space in sharedSecret array");
}
```

---


## Low

### Ciphertext not cleared after use, potential key material leak
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:97-100`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;  // Cleared after use
    return result;
}
```
**Issue**: In engineGenerateSecret(), the shared key is cleared after use but the ciphertext field is not. The ciphertext contains cryptographic material that should be cleared from memory after use to prevent potential leakage.
**Fix**:
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;
    if (ciphertext != null) {
        Arrays.fill(ciphertext, (byte) 0);
        ciphertext = null;
    }
    return result;
}
```

---

### Ciphertext not cleared after use, potential key material leak
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:100-103`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;  // Cleared after use
    return result;
}
```
**Issue**: In engineGenerateSecret(), the shared key is cleared after use but the ciphertext field is not. The ciphertext contains cryptographic material that should be cleared from memory after use.
**Fix**:
```
if (sharedKey != null) {
    byte[] result = sharedKey;
    sharedKey = null;
    if (ciphertext != null) {
        Arrays.fill(ciphertext, (byte) 0);
        ciphertext = null;
    }
    return result;
}
```

---

### Missing null check in constructor could allow null ciphertext
`src/main/java/org/openhitls/crypto/jce/key/FrodoKEMCiphertextKey.java:8-10`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
public FrodoKEMCiphertextKey(byte[] ciphertext) {
    this.ciphertext = ciphertext != null ? ciphertext.clone() : null;
}
```
**Issue**: The constructor accepts null ciphertext and stores it without validation. While getEncoded() handles null by returning null, allowing null ciphertext could lead to unexpected behavior in cryptographic operations.
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
`src/main/java/org/openhitls/crypto/jce/key/McElieceCiphertextKey.java:8-10`
**Reviewers**: CLAUDE | **置信度**: 较可信
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

### Missing validation of parameter name in constructor
`src/main/java/org/openhitls/crypto/jce/spec/FrodoKEMGenParameterSpec.java:8-10`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
public FrodoKEMGenParameterSpec(String name) {
    this.name = name;
}
```
**Issue**: The constructor accepts any string without validating it's a valid FrodoKEM parameter set name. This allows creation of invalid parameter specs that will fail later.
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
`src/main/java/org/openhitls/crypto/jce/spec/McElieceGenParameterSpec.java:8-10`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
public McElieceGenParameterSpec(String name) {
    this.name = name;
}
```
**Issue**: The constructor accepts any string without validating it's a valid McEliece parameter set name.
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
