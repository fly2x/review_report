# Code Review: openHiTLS/hitls4j#32
**Reviewer**: CODEX


## High

### KeyFactory treats raw FrodoKEM bytes as PKCS#8/X.509 without parsing
`src/main/java/org/openhitls/crypto/jce/key/factory/FrodoKEMKeyFactory.java:22-31`
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
**Issue**: The new key factory accepts `PKCS8EncodedKeySpec` and `X509EncodedKeySpec`, but it never parses or validates any ASN.1 wrapper. It just copies the byte array into a provider key object and later re-exports the same bytes as if they were standard encodings. That makes `KeyFactory` accept malformed input as a key and breaks interoperability with any code that expects real PKCS#8 or SubjectPublicKeyInfo data.
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

### KeyFactory treats raw McEliece bytes as PKCS#8/X.509 without parsing
`src/main/java/org/openhitls/crypto/jce/key/factory/McElieceKeyFactory.java:22-31`
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
**Issue**: The McEliece key factory has the same problem as the FrodoKEM one: `PKCS8EncodedKeySpec` and `X509EncodedKeySpec` are accepted and returned without parsing any standard wrapper. The provider is therefore advertising standard encodings that it does not actually implement, and malformed encoded input is turned into a key object without validation.
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


## Medium

### Missing key parameters cause a NullPointerException during init
`src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java:52-55`
```
} else if (frodoKemPrivateKey != null) {
    parameterSet = frodoKemPrivateKey.getParams().getName();
} else if (frodoKemPublicKey != null) {
    parameterSet = frodoKemPublicKey.getParams().getName();
}
```
**Issue**: `engineInit` assumes every FrodoKEM key carries a non-null `FrodoKEMParameterSpec`. That is false for keys created from the new `PKCS8EncodedKeySpec`/`X509EncodedKeySpec` paths, because those constructors leave `params` null. Initializing `KeyAgreement` with such a key will crash with `NullPointerException` instead of failing deterministically with `InvalidKeyException` or deriving the parameter set from the encoding.
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

### Missing key parameters cause a NullPointerException during init
`src/main/java/org/openhitls/crypto/jce/keyagreement/McElieceKeyAgreement.java:55-58`
```
} else if (mcEliecePrivateKey != null) {
    parameterSet = mcEliecePrivateKey.getParams().getName();
} else if (mcEliecePublicKey != null) {
    parameterSet = mcEliecePublicKey.getParams().getName();
}
```
**Issue**: `engineInit` dereferences `getParams()` without checking for null. Keys constructed from the new encoded-key paths have `params == null`, so initializing `KeyAgreement` with a deserialized McEliece key throws `NullPointerException` instead of a checked key error.
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

### Test suite uses a provider name that does not exist
`src/test/java/org/openhitls/crypto/jce/pqc/FrodoKEMTest.java:44-45`
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", "HiTls4j");
...
KeyAgreement senderAgreement = KeyAgreement.getInstance("FrodoKEM", "HiTls4j");
...
KeyAgreement receiverAgreement = KeyAgreement.getInstance("FrodoKEM", "HiTls4j");
```
**Issue**: These calls request provider `"HiTls4j"`, but the provider is registered as `"HITLS4J"`. Java provider lookup is case-sensitive, so every `getInstance(..., "HiTls4j")` call throws `NoSuchProviderException` and the new FrodoKEM tests fail before exercising the feature.
**Fix**:
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
...
KeyAgreement senderAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
...
KeyAgreement receiverAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
```

---

### Test suite uses a provider name that does not exist
`src/test/java/org/openhitls/crypto/jce/pqc/McElieceTest.java:40-41`
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Classic-McEliece", "HiTls4j");
...
KeyAgreement senderAgreement = KeyAgreement.getInstance("Classic-McEliece", "HiTls4j");
...
KeyAgreement receiverAgreement = KeyAgreement.getInstance("Classic-McEliece", "HiTls4j");
```
**Issue**: The new McEliece tests also request provider `"HiTls4j"` instead of the registered `"HITLS4J"`. Because provider lookup is case-sensitive, the test class fails with `NoSuchProviderException` instead of validating the implementation.
**Fix**:
```
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
...
KeyAgreement senderAgreement = KeyAgreement.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
...
KeyAgreement receiverAgreement = KeyAgreement.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
```

---
