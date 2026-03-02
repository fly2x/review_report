# Code Review: openHiTLS/sdf4j#21
**Reviewer**: CODEX


## Critical

### Removed ECC coordinate length enforcement enables native buffer overflow
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPublicKey.java:56-65`
```
public ECCPublicKey(int bits, byte[] x, byte[] y) {
    if (bits <= 0) {
        throw new IllegalArgumentException("Invalid bits: " + bits);
    }
    if (x == null || y == null) {
        throw new IllegalArgumentException("X and Y coordinates cannot be null");
    }
    this.bits = bits;
    this.x = x;
    this.y = y;
}
```
**Issue**: The constructor now stores caller-provided `x`/`y` arrays without max-length checks or fixed-size copy. JNI conversion (`java_to_native_ECCPublicKey`) copies Java array length directly into fixed 64-byte native fields, so oversized arrays can overflow native memory.
**Fix**:
```
public static final int ECC_MAX_BITS = 512;
public static final int ECC_MAX_LEN = (ECC_MAX_BITS + 7) / 8;

public ECCPublicKey(int bits, byte[] x, byte[] y) {
    if (bits <= 0 || bits > ECC_MAX_BITS) {
        throw new IllegalArgumentException("Invalid bits: " + bits);
    }
    if (x == null || y == null) {
        throw new IllegalArgumentException("X and Y coordinates cannot be null");
    }
    if (x.length > ECC_MAX_LEN || y.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("ECC coordinate length exceeds " + ECC_MAX_LEN);
    }
    this.bits = bits;
    this.x = Arrays.copyOf(x, ECC_MAX_LEN);
    this.y = Arrays.copyOf(y, ECC_MAX_LEN);
}
```

---

### Removed ECC private key size checks allows overflow in JNI conversion
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPrivateKey.java:50-59`
```
public ECCPrivateKey(int bits, byte[] k) {
    if (bits <= 0) {
        throw new IllegalArgumentException("Invalid bits: " + bits);
    }
    if (k == null) {
        throw new IllegalArgumentException("Private key value cannot be null");
    }
    this.bits = bits;
    this.k = k;
}
```
**Issue**: `k` is assigned directly without enforcing max length. JNI conversion (`java_to_native_ECCPrivateKey`) copies full Java array length into fixed 64-byte native `K`, so oversized keys can corrupt memory.
**Fix**:
```
public static final int ECC_MAX_BITS = 512;
public static final int ECC_MAX_LEN = (ECC_MAX_BITS + 7) / 8;

public ECCPrivateKey(int bits, byte[] k) {
    if (bits <= 0 || bits > ECC_MAX_BITS) {
        throw new IllegalArgumentException("Invalid bits: " + bits);
    }
    if (k == null) {
        throw new IllegalArgumentException("Private key value cannot be null");
    }
    if (k.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("Private key length exceeds " + ECC_MAX_LEN);
    }
    this.bits = bits;
    this.k = Arrays.copyOf(k, ECC_MAX_LEN);
}
```

---

### Signature component length validation removed, exposing native overflow path
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCSignature.java:50-56`
```
public ECCSignature(byte[] r, byte[] s) {
    if (r == null || s == null) {
        throw new IllegalArgumentException("Signature r and s cannot be null");
    }
    this.r = r;
    this.s = s;
}
```
**Issue**: `r`/`s` are now accepted at arbitrary length and stored directly. JNI conversion (`java_to_native_ECCSignature`) copies raw array length into fixed-size native `ECCSignature` buffers, enabling memory corruption with oversized inputs.
**Fix**:
```
public static final int ECC_MAX_LEN = 64;

public ECCSignature(byte[] r, byte[] s) {
    if (r == null || s == null) {
        throw new IllegalArgumentException("Signature r and s cannot be null");
    }
    if (r.length > ECC_MAX_LEN || s.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("ECC signature component exceeds " + ECC_MAX_LEN);
    }
    this.r = Arrays.copyOf(r, ECC_MAX_LEN);
    this.s = Arrays.copyOf(s, ECC_MAX_LEN);
}
```

---

### ECCCipher constructor no longer bounds-checks fixed-size fields
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java:68-79`
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
```
**Issue**: `x` and `y` are stored directly with no max-length checks. JNI conversion (`java_to_native_ECCCipher_alloc`) copies Java lengths directly into fixed-size native buffers (`x[64]`, `y[64]`), causing overflow when caller passes oversized arrays.
**Fix**:
```
public static final int ECC_MAX_LEN = 64;
public static final int HASH_LEN = 32;

public ECCCipher(byte[] x, byte[] y, byte[] m, long l, byte[] c) {
    if (x == null || y == null || m == null || c == null) {
        throw new IllegalArgumentException("x, y, m, c cannot be null");
    }
    if (x.length > ECC_MAX_LEN || y.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("ECC coordinate length exceeds " + ECC_MAX_LEN);
    }
    if (m.length > HASH_LEN) {
        throw new IllegalArgumentException("Hash value M exceeds " + HASH_LEN);
    }
    if (l < 0 || l > c.length) {
        throw new IllegalArgumentException("l is invalid");
    }
    this.x = Arrays.copyOf(x, ECC_MAX_LEN);
    this.y = Arrays.copyOf(y, ECC_MAX_LEN);
    this.m = Arrays.copyOf(m, HASH_LEN);
    this.l = l;
    this.c = Arrays.copyOf(c, c.length);
}
```

---

### HybridCipher conversion trusts device length and can read past fixed buffer
`sdf4j/src/main/native/src/type_conversion.c:727-733`
```
jsize ctm_len = (jsize)native_cipher->L1;
jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
if (ctm_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ctM array");
    return NULL;
}
(*env)->SetByteArrayRegion(env, ctm_array, 0, ctm_len, (jbyte*)native_cipher->ct_m);
```
**Issue**: `ctm_len` is taken directly from `native_cipher->L1` and used for `SetByteArrayRegion` without capping to `HYBRIDENCref_MAX_LEN` (1576). If a provider returns oversized `L1`, this reads beyond `ct_m` and can leak memory or crash.
**Fix**:
```
jsize ctm_len = (jsize)native_cipher->L1;
if (ctm_len < 0 || ctm_len > HYBRIDENCref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridCipher L1 exceeds max length");
    return NULL;
}
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

### HybridSignature conversion removed max-length guard and can over-read sig_m
`sdf4j/src/main/native/src/type_conversion.c:814-826`
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

jobject obj = (*env)->NewObject(env, g_jni_cache.hybridSignature.cls,
                                g_jni_cache.hybridSignature.ctor,
                                ecc_sig_obj, (jint)native_sig->L, sig_m_array);
```
**Issue**: `sig_m_len` is no longer clamped/validated against `HYBRIDSIGref_MAX_LEN` before copying from fixed-size `sig_m[4636]`. Oversized lengths can read out-of-bounds. Also, when `sig_m_len == 0`, `sig_m_array` remains `NULL` and is passed to a constructor that rejects null.
**Fix**:
```
if (sig_m_len > HYBRIDSIGref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "HybridSignature length exceeds max");
    return NULL;
}

jbyteArray sig_m_array = (*env)->NewByteArray(env, sig_m_len);
if (sig_m_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to new byte array");
    return NULL;
}
if (sig_m_len > 0) {
    (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
}

jobject obj = (*env)->NewObject(env, g_jni_cache.hybridSignature.cls,
                                g_jni_cache.hybridSignature.ctor,
                                ecc_sig_obj, (jint)native_sig->L, sig_m_array);
```

---


## Medium

### Zero-length ECCCipher output now fails due null `c` passed to strict constructor
`sdf4j/src/main/native/src/type_conversion.c:243-256`
```
jbyteArray c_array = NULL;
if (cipher_len > 0) {
    c_array = (*env)->NewByteArray(env, cipher_len);
    if (c_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, c_array, 0, cipher_len, (jbyte*)&native_cipher->C);
}

jobject obj = (*env)->NewObject(env, g_jni_cache.eccCipher.cls,
                        g_jni_cache.eccCipher.ctor,
                        x_array, y_array, m_array,
                        (jlong)native_cipher->L, c_array);
```
**Issue**: `c_array` is left `NULL` when `cipher_len == 0`, but `ECCCipher(byte[] x, byte[] y, byte[] m, long l, byte[] c)` now throws if `c == null`. This creates a new failure path for valid zero-length cipher payloads.
**Fix**:
```
jbyteArray c_array = (*env)->NewByteArray(env, cipher_len);
if (c_array == NULL) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
    return NULL;
}
if (cipher_len > 0) {
    (*env)->SetByteArrayRegion(env, c_array, 0, cipher_len, (jbyte*)&native_cipher->C);
}

jobject obj = (*env)->NewObject(env, g_jni_cache.eccCipher.cls,
                                g_jni_cache.eccCipher.ctor,
                                x_array, y_array, m_array,
                                (jlong)native_cipher->L, c_array);
```

---
