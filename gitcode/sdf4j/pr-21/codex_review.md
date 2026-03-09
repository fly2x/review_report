# Code Review: openHiTLS/sdf4j#21
**Reviewer**: CODEX


## Critical

### HybridCipher conversion can read past fixed `ct_m` buffer
`sdf4j/src/main/native/src/type_conversion.c:754-760`
```
jsize ctm_len = (jsize)native_cipher->L1;
jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
if (ctm_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ctM array");
    return NULL;
}
(*env)->SetByteArrayRegion(env, ctm_array, 0, ctm_len, (jbyte*)native_cipher->ct_m);
```
**Issue**: `native_cipher->L1` is used directly as copy length, but `HybridCipher.ct_m` is fixed-size (`HYBRIDENCref_MAX_LEN` = 1576). If a device/library returns `L1 > 1576`, `SetByteArrayRegion` reads out of bounds.
**Fix**:
```
if (native_cipher->L1 > HYBRIDENCref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridCipher L1 exceeds buffer");
    return NULL;
}
jsize ctm_len = (jsize)native_cipher->L1;
jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
if (ctm_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ctM array");
    return NULL;
}
if (ctm_len > 0) {
    (*env)->SetByteArrayRegion(env, ctm_array, 0, ctm_len, (jbyte*)native_cipher->ct_m);
}
```

---

### HybridSignature conversion uses unchecked length for fixed `sig_m` buffer
`sdf4j/src/main/native/src/type_conversion.c:840-848`
```
jbyteArray sig_m_array = NULL;
if (sig_m_len > 0) {
    sig_m_array = (*env)->NewByteArray(env, sig_m_len);
    if (sig_m_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to new byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
}
```
**Issue**: `sig_m_len` is copied directly from `native_sig->sig_m` without validating against `HYBRIDSIGref_MAX_LEN` (4636). A malformed `L` can trigger out-of-bounds reads.
**Fix**:
```
if (sig_m_len > HYBRIDSIGref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridSignature L exceeds buffer");
    return NULL;
}

jbyteArray sig_m_array = (*env)->NewByteArray(env, (jsize)sig_m_len);
if (sig_m_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create sigM array");
    return NULL;
}
if (sig_m_len > 0) {
    (*env)->SetByteArrayRegion(env, sig_m_array, 0, (jsize)sig_m_len, (jbyte*)native_sig->sig_m);
}
```

---


## High

### RSAPrivateKey constructor now accepts null key components
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:101-113`
```
public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                     byte[][] prime, byte[][] pexp, byte[] coef) {
    if (bits <= 0 || bits > RSA_MAX_BITS) {
        throw new IllegalArgumentException("Invalid bits: " + bits);
    }
    this.bits = bits;
    this.m = m;
    this.e = e;
    this.d = d;
    this.prime = prime;
    this.pexp = pexp;
    this.coef = coef;
}
```
**Issue**: The constructor assigns key arrays directly with no null/shape validation. Invalid keys can be created and passed to JNI, where missing fields are silently treated as zeroed buffers.
**Fix**:
```
public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                     byte[][] prime, byte[][] pexp, byte[] coef) {
    if (bits <= 0 || bits > RSA_MAX_BITS) {
        throw new IllegalArgumentException("Invalid bits: " + bits);
    }
    if (m == null || e == null || d == null || coef == null ||
        prime == null || pexp == null ||
        prime.length != 2 || pexp.length != 2 ||
        prime[0] == null || prime[1] == null ||
        pexp[0] == null || pexp[1] == null) {
        throw new IllegalArgumentException("RSA private key components cannot be null");
    }

    this.bits = bits;
    this.m = Arrays.copyOf(m, RSA_MAX_LEN);
    this.e = Arrays.copyOf(e, RSA_MAX_LEN);
    this.d = Arrays.copyOf(d, RSA_MAX_LEN);
    this.prime = new byte[][] {
        Arrays.copyOf(prime[0], RSA_MAX_PLEN),
        Arrays.copyOf(prime[1], RSA_MAX_PLEN)
    };
    this.pexp = new byte[][] {
        Arrays.copyOf(pexp[0], RSA_MAX_PLEN),
        Arrays.copyOf(pexp[1], RSA_MAX_PLEN)
    };
    this.coef = Arrays.copyOf(coef, RSA_MAX_PLEN);
}
```

---


## Medium

### `setC` no longer keeps `l` in sync with ciphertext bytes
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java:135-140`
```
public void setC(byte[] c) {
    if (c == null || this.l > c.length) {
        throw new IllegalArgumentException("cipher value is invalid");
    }
    this.c = c;
}
```
**Issue**: `setC` now updates only `c`, leaving `l` unchanged. Existing call patterns that set ciphertext via `setC` can now send `L=0` with non-empty `C` to JNI/native code, breaking decrypt/import behavior.
**Fix**:
```
public void setC(byte[] c) {
    if (c == null) {
        throw new IllegalArgumentException("cipher value is invalid");
    }
    this.c = c;
    this.l = c.length; // keep C/L consistent for native conversion
}
```

---

### Public constructor signature change breaks backward compatibility
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java:68`
```
public ECCCipher(byte[] x, byte[] y, byte[] m, long l, byte[] c) {
```
**Issue**: The previous public constructor `(byte[] x, byte[] y, byte[] m, byte[] c)` was removed and replaced with `(byte[] x, byte[] y, byte[] m, long l, byte[] c)`. Existing client code using the old API will fail to compile.
**Fix**:
```
public ECCCipher(byte[] x, byte[] y, byte[] m, long l, byte[] c) {
    if (x == null || y == null || m == null || c == null) {
        throw new IllegalArgumentException("x, y, m, c cannot be null");
    }
    if (l < 0 || l > c.length) {
        throw new IllegalArgumentException("l is invalid");
    }
    this.x = x;
    this.y = y;
    this.m = m;
    this.l = l;
    this.c = c;
}

// Backward-compatible overload
public ECCCipher(byte[] x, byte[] y, byte[] m, byte[] c) {
    this(x, y, m, c == null ? 0 : c.length, c == null ? new byte[0] : c);
}
```

---
