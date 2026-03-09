# Code Review: openHiTLS/sdf4j#21
**Reviewer**: CLAUDE


## High

### Default constructor doesn't initialize asymAlgAbility array
`sdf4j/src/main/java/org/openhitls/sdf4j/types/DeviceInfo.java:38-40`
```
public DeviceInfo() {
    // asymAlgAbility not initialized - will be null
}
```
**Issue**: The default constructor no longer initializes the asymAlgAbility array to a 2-element array. This will cause NullPointerException when getAsymAlgAbility() is called on a default-constructed object, or when setAsymAlgAbility() checks for null but other code expects a non-null array.
**Fix**:
```
public DeviceInfo() {
    this.asymAlgAbility = new long[2];
}
```

---

### setC() validation depends on call order of setL()
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java:104-108`
```
public void setC(byte[] c) {
    if (c == null || this.l > c.length) {
        throw new IllegalArgumentException("cipher value is invalid");
    }
    this.c = c;
}
```
**Issue**: The validation `this.l > c.length` in setC() depends on l being set BEFORE c. If a caller calls setC() first, then setL() with a larger value, the object will be in an invalid state. The validation is ineffective.
**Fix**:
```
public void setC(byte[] c) {
    if (c == null) {
        throw new IllegalArgumentException("cipher value cannot be null");
    }
    this.c = c;
    // Validate l matches c.length
    if (this.l > c.length) {
        throw new IllegalArgumentException("l cannot exceed c.length");
    }
}

// Also update setL() to validate against existing c
public void setL(long l) {
    if (l < 0) {
        throw new IllegalArgumentException("Ciphertext length cannot be negative");
    }
    if (this.c != null && l > this.c.length) {
        throw new IllegalArgumentException("Ciphertext length cannot exceed c.length");
    }
    this.l = l;
}
```

---

### setCtM() validation has call order dependency
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java:72-76`
```
public void setCtM(byte[] ctM) {
    if (ctM == null || this.l1 > ctM.length) {
        throw new IllegalArgumentException("cipher value is invalid");
    }
    this.ctM = ctM;
}
```
**Issue**: Similar to ECCCipher issue - validation `this.l1 > ctM.length` depends on l1 being set before ctM. Default l1 is 0, so validation passes even for invalid arrays.
**Fix**:
```
public void setCtM(byte[] ctM) {
    if (ctM == null) {
        throw new IllegalArgumentException("cipher value cannot be null");
    }
    this.ctM = ctM;
}

public void setL1(long l1) {
    if (l1 < 0) {
        throw new IllegalArgumentException("Ciphertext length cannot be negative");
    }
    if (this.ctM != null && l1 > this.ctM.length) {
        throw new IllegalArgumentException("l1 cannot exceed ctM.length");
    }
    this.l1 = l1;
}
```

---

### setSigM() validation has call order dependency
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridSignature.java:61-65`
```
public void setSigM(byte[] sigM) {
    if (sigM == null || this.l > sigM.length) {
        throw new IllegalArgumentException("signature value is invalid");
    }
    this.sigM = sigM;
}
```
**Issue**: Same validation order issue - depends on l being set before sigM.
**Fix**:
```
public void setSigM(byte[] sigM) {
    if (sigM == null) {
        throw new IllegalArgumentException("signature value cannot be null");
    }
    this.sigM = sigM;
}

public void setL(int l) {
    if (l < 0) {
        throw new IllegalArgumentException("Signature length cannot be negative");
    }
    if (this.sigM != null && l > this.sigM.length) {
        throw new IllegalArgumentException("l cannot exceed sigM.length");
    }
    this.l = l;
}
```

---


## Medium

### Constructor doesn't validate asymAlgAbility length
`sdf4j/src/main/java/org/openhitls/sdf4j/types/DeviceInfo.java:49-59`
```
public DeviceInfo(String issuerName, String deviceName, String deviceSerial,
                  long deviceVersion, long standardVersion, long[] asymAlgAbility,
                  long symAlgAbility, long hashAlgAbility, long bufferSize) {
    if (issuerName == null || deviceName == null || deviceSerial == null || asymAlgAbility == null) {
        throw new IllegalArgumentException("null input");
    }
    this.asymAlgAbility = asymAlgAbility;  // No length validation
```
**Issue**: The constructor checks for null but doesn't validate that asymAlgAbility has exactly 2 elements as documented. This can cause ArrayIndexOutOfBoundsException or incorrect behavior when the array is used.
**Fix**:
```
public DeviceInfo(String issuerName, String deviceName, String deviceSerial,
                  long deviceVersion, long standardVersion, long[] asymAlgAbility,
                  long symAlgAbility, long hashAlgAbility, long bufferSize) {
    if (issuerName == null || deviceName == null || deviceSerial == null || asymAlgAbility == null) {
        throw new IllegalArgumentException("null input");
    }
    if (asymAlgAbility.length != 2) {
        throw new IllegalArgumentException("asymAlgAbility must have exactly 2 elements");
    }
    this.asymAlgAbility = asymAlgAbility;
```

---

### Constructor accepts null for prime and pexp arrays
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:62-72`
```
public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                     byte[][] prime, byte[][] pexp, byte[] coef) {
    // ...
    this.prime = prime;  // No null or length check
    this.pexp = pexp;    // No null or length check
    this.coef = coef;
}
```
**Issue**: The constructor no longer validates that prime and pexp arrays are non-null or have exactly 2 elements. This can cause NullPointerException when these fields are accessed.
**Fix**:
```
public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                     byte[][] prime, byte[][] pexp, byte[] coef) {
    if (bits <= 0) {
        throw new IllegalArgumentException("Invalid bits: " + bits);
    }
    if (m == null || e == null || d == null || coef == null) {
        throw new IllegalArgumentException("Key components cannot be null");
    }
    if (prime == null || prime.length < 2) {
        throw new IllegalArgumentException("prime must have at least 2 elements");
    }
    if (pexp == null || pexp.length < 2) {
        throw new IllegalArgumentException("pexp must have at least 2 elements");
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

---

### setPrime() and setPexp() accept null or invalid arrays
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:157-167`
```
public void setPrime(byte[][] prime) {
    this.prime = prime;
}

public void setPexp(byte[][] pexp) {
    this.pexp = pexp;
}
```
**Issue**: The setters no longer validate null or array dimensions, allowing invalid state.
**Fix**:
```
public void setPrime(byte[][] prime) {
    if (prime == null || prime.length < 2) {
        throw new IllegalArgumentException("prime must have at least 2 elements");
    }
    this.prime = prime;
}

public void setPexp(byte[][] pexp) {
    if (pexp == null || pexp.length < 2) {
        throw new IllegalArgumentException("pexp must have at least 2 elements");
    }
    this.pexp = pexp;
}
```

---

### setX() and setY() don't validate array bounds
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPublicKey.java:89-93`
```
public void setX(byte[] x) {
    if (x == null) {
        throw new IllegalArgumentException("X coordinate cannot be null");
    }
    this.x = x;
}

public void setY(byte[] y) {
    if (y == null) {
        throw new IllegalArgumentException("Y coordinate cannot be null");
    }
    this.y = y;
}
```
**Issue**: Setters don't validate that coordinate arrays don't exceed ECC_MAX_LEN (64 bytes for 512-bit keys), allowing invalid state.
**Fix**:
```
private static final int ECC_MAX_BITS = 512;
private static final int ECC_MAX_LEN = (ECC_MAX_BITS + 7) / 8;

public void setX(byte[] x) {
    if (x == null) {
        throw new IllegalArgumentException("X coordinate cannot be null");
    }
    if (x.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("X coordinate exceeds maximum length of " + ECC_MAX_LEN + " bytes");
    }
    this.x = x;
}

public void setY(byte[] y) {
    if (y == null) {
        throw new IllegalArgumentException("Y coordinate cannot be null");
    }
    if (y.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("Y coordinate exceeds maximum length of " + ECC_MAX_LEN + " bytes");
    }
    this.y = y;
}
```

---

### setK() doesn't validate array bounds
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPrivateKey.java:75-80`
```
public void setK(byte[] k) {
    if (k == null) {
        throw new IllegalArgumentException("Private key value cannot be null");
    }
    this.k = k;
}
```
**Issue**: Setter doesn't validate that K array doesn't exceed ECC_MAX_LEN (64 bytes).
**Fix**:
```
private static final int ECC_MAX_BITS = 512;
private static final int ECC_MAX_LEN = (ECC_MAX_BITS + 7) / 8;

public void setK(byte[] k) {
    if (k == null) {
        throw new IllegalArgumentException("Private key value cannot be null");
    }
    if (k.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("Private key K exceeds maximum length of " + ECC_MAX_LEN + " bytes");
    }
    this.k = k;
}
```

---

### setR() and setS() don't validate array bounds
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCSignature.java:50-58`
```
public void setR(byte[] r) {
    if (r == null) {
        throw new IllegalArgumentException("Signature r cannot be null");
    }
    this.r = r;
}

public void setS(byte[] s) {
    if (s == null) {
        throw new IllegalArgumentException("Signature s cannot be null");
    }
    this.s = s;
}
```
**Issue**: Setters don't validate that signature value arrays don't exceed ECC_MAX_LEN (64 bytes).
**Fix**:
```
private static final int ECC_MAX_BITS = 512;
private static final int ECC_MAX_LEN = (ECC_MAX_BITS + 7) / 8;

public void setR(byte[] r) {
    if (r == null) {
        throw new IllegalArgumentException("Signature r cannot be null");
    }
    if (r.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("Signature r exceeds maximum length of " + ECC_MAX_LEN + " bytes");
    }
    this.r = r;
}

public void setS(byte[] s) {
    if (s == null) {
        throw new IllegalArgumentException("Signature s cannot be null");
    }
    if (s.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("Signature s exceeds maximum length of " + ECC_MAX_LEN + " bytes");
    }
    this.s = s;
}
```

---

### setX(), setY(), setM() don't validate array bounds
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java:54-60`
```
public void setX(byte[] x) {
    if (x == null) {
        throw new IllegalArgumentException("X coordinate cannot be null");
    }
    this.x = x;
}
```
**Issue**: Setters don't validate that coordinate/hash arrays don't exceed expected lengths.
**Fix**:
```
private static final int ECC_MAX_BITS = 512;
private static final int ECC_MAX_LEN = (ECC_MAX_BITS + 7) / 8;
private static final int HASH_LEN = 32;

public void setX(byte[] x) {
    if (x == null) {
        throw new IllegalArgumentException("X coordinate cannot be null");
    }
    if (x.length > ECC_MAX_LEN) {
        throw new IllegalArgumentException("X coordinate exceeds maximum length");
    }
    this.x = x;
}
```

---

### setM() and setE() don't validate array bounds
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPublicKey.java:89-97`
```
public void setM(byte[] m) {
    if (m == null) {
        throw new IllegalArgumentException("Modulus cannot be null");
    }
    this.m = m;
}

public void setE(byte[] e) {
    if (e == null) {
        throw new IllegalArgumentException("Exponent cannot be null");
    }
    this.e = e;
}
```
**Issue**: Setters don't validate that modulus/exponent arrays don't exceed RSA_MAX_LEN (512 bytes).
**Fix**:
```
private static final int RSA_MAX_BITS = 4096;
private static final int RSA_MAX_LEN = (RSA_MAX_BITS + 7) / 8;

public void setM(byte[] m) {
    if (m == null) {
        throw new IllegalArgumentException("Modulus cannot be null");
    }
    if (m.length > RSA_MAX_LEN) {
        throw new IllegalArgumentException("Modulus exceeds maximum length of " + RSA_MAX_LEN + " bytes");
    }
    this.m = m;
}

public void setE(byte[] e) {
    if (e == null) {
        throw new IllegalArgumentException("Exponent cannot be null");
    }
    if (e.length > RSA_MAX_LEN) {
        throw new IllegalArgumentException("Exponent exceeds maximum length of " + RSA_MAX_LEN + " bytes");
    }
    this.e = e;
}
```

---


## Low

### bytesToHex() outputs entire array without truncation
`sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPublicKey.java:148-156`
```
private static String bytesToHex(byte[] bytes) {
    if (bytes == null) {
        return "";
    }
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < bytes.length; i++) {
        sb.append(String.format("%02X", bytes[i]));
    }
    return sb.toString();
}
```
**Issue**: For large arrays (e.g., RSA 512-byte keys), the toString() method will generate very long hex strings (1024+ hex characters). This was previously truncated for readability.
**Fix**:
```
private static String bytesToHex(byte[] bytes) {
    if (bytes == null) {
        return "";
    }
    int limit = Math.min(bytes.length, 32);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < limit; i++) {
        sb.append(String.format("%02X", bytes[i]));
    }
    if (bytes.length > limit) {
        sb.append("...(").append(bytes.length).append(" bytes)");
    }
    return sb.toString();
}
```

---

### RSA array length check throws exception but documentation unclear
`sdf4j/src/main/native/src/type_conversion.c:141-147`
```
if (len > RSAref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA modulus array exceeds 512");
    return false;
}
```
**Issue**: The code throws an exception if array exceeds RSAref_MAX_LEN (512), but the Java layer constructors no longer enforce this limit. Users may create valid Java objects that fail at JNI boundary with unclear error message.
**Fix**:
```
if (len > RSAref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA modulus array exceeds maximum length of 512 bytes");
    return false;
}
```

---

### setM(), setE(), setD() don't validate array bounds
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:44-48`
```
public void setM(byte[] m) {
    this.m = m;
}

public void setE(byte[] e) {
    this.e = e;
}

public void setD(byte[] d) {
    this.d = d;
}
```
**Issue**: Setters don't validate that byte arrays don't exceed RSA_MAX_LEN (512 bytes), allowing invalid state that will fail at JNI boundary.
**Fix**:
```
public void setM(byte[] m) {
    if (m == null) {
        throw new IllegalArgumentException("Modulus cannot be null");
    }
    if (m.length > RSA_MAX_LEN) {
        throw new IllegalArgumentException("Modulus exceeds maximum length of " + RSA_MAX_LEN + " bytes");
    }
    this.m = m;
}

public void setE(byte[] e) {
    if (e == null) {
        throw new IllegalArgumentException("Exponent cannot be null");
    }
    if (e.length > RSA_MAX_LEN) {
        throw new IllegalArgumentException("Exponent exceeds maximum length of " + RSA_MAX_LEN + " bytes");
    }
    this.e = e;
}

public void setD(byte[] d) {
    if (d == null) {
        throw new IllegalArgumentException("Private exponent cannot be null");
    }
    if (d.length > RSA_MAX_LEN) {
        throw new IllegalArgumentException("Private exponent exceeds maximum length of " + RSA_MAX_LEN + " bytes");
    }
    this.d = d;
}
```

---

### setCoef() doesn't validate array bounds
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:172-176`
```
public void setCoef(byte[] coef) {
    this.coef = coef;
}
```
**Issue**: Setter doesn't validate that coef array doesn't exceed RSA_MAX_PLEN (256 bytes).
**Fix**:
```
public void setCoef(byte[] coef) {
    if (coef == null) {
        throw new IllegalArgumentException("CRT coefficient cannot be null");
    }
    if (coef.length > RSA_MAX_PLEN) {
        throw new IllegalArgumentException("CRT coefficient exceeds maximum length of " + RSA_MAX_PLEN + " bytes");
    }
    this.coef = coef;
}
```

---
