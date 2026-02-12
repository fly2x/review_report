# Code Review: openHiTLS/sdf4j#15
**Reviewer**: CODEX


## High

### RSA max size increased to 4096 without matching native struct update
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPublicKey.java:23-33`
```
/**
 * 最大位数
 */
public static final int RSA_MAX_BITS = 4096;
```
**Issue**: Java now accepts 4096-bit RSA keys, but JNI native structs are still compiled with 2048-bit buffers (`RSAref_MAX_BITS=2048`). This creates a capability mismatch (truncation/incorrect behavior) and can lead to ABI misuse when interacting with 4096-capable vendor libraries.
**Fix**:
```
/**
 * 最大位数（must stay aligned with native RSAref_MAX_BITS）
 */
public static final int RSA_MAX_BITS = 2048;
```

---


## Medium

### Output buffer size uses unvalidated RSA bit length
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:379-381`
```
ULONG output_len = (native_key.bits + 7) / 8;
BYTE *output_buf = (BYTE*)malloc(output_len);
```
**Issue**: `output_len` is derived directly from `native_key.bits` with no range check. A malformed/default key (`bits == 0`) can produce `malloc(0)` and pass an invalid output buffer contract into `SDF_ExchangeDigitEnvelopeBaseOnRSA`.
**Fix**:
```
if (native_key.bits == 0 || native_key.bits > RSAref_MAX_BITS) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Invalid RSA key bits");
    return NULL;
}

ULONG output_len = (native_key.bits + 7) / 8;
BYTE *output_buf = (BYTE*)malloc(output_len);
```

---

### RSA private operation buffer sizing trusts mutable key metadata
`sdf4j/src/main/native/src/sdf_jni_util.c:135-137`
```
/* Allocate output buffer based on key size */
ULONG output_len = (priv_key.bits + 7) / 8;  /* Calculate from private key bits */
BYTE *output_buf = (BYTE*)malloc(output_len);
```
**Issue**: Buffer length now depends on `priv_key.bits` from Java object state. If `bits` is inconsistent or zero, output buffer can be under-sized/invalid before calling `SDF_ExternalPrivateKeyOperation_RSA`.
**Fix**:
```
if (priv_key.bits == 0 || priv_key.bits > RSAref_MAX_BITS) {
    free(input_buf);
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Invalid RSA key bits");
    return NULL;
}

ULONG output_len = (priv_key.bits + 7) / 8;
BYTE *output_buf = (BYTE*)malloc(output_len);
```

---

### New RSA envelope test uses synthetic invalid input and is flaky
`examples/src/test/java/org/openhitls/sdf4j/examples/AsymmetricOperationTest.java:965-974`
```
Object[] keyPair = sdf.SDF_GenerateKeyPair_RSA(sessionHandle, 2048);
assertNotNull(keyPair);
RSAPublicKey publicKey = (RSAPublicKey) keyPair[0];
byte[] deInput = new byte[256];
byte[] deOutput = sdf.SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, keyIndex, publicKey, deInput);
```
**Issue**: The test feeds an all-zero envelope (`new byte[256]`) into `SDF_ExchangeDigitEnvelopeBaseOnRSA`. That is not a real digital envelope and can fail on compliant devices with argument/key errors, causing false negatives.
**Fix**:
```
Object[] keyPair = sdf.SDF_GenerateKeyPair_RSA(sessionHandle, 2048);
assertNotNull(keyPair);
RSAPublicKey publicKey = (RSAPublicKey) keyPair[0];

KeyEncryptionResult wrapped = sdf.SDF_GenerateKeyWithIPK_RSA(sessionHandle, keyIndex, 128);
try {
    byte[] deOutput = sdf.SDF_ExchangeDigitEnvelopeBaseOnRSA(
            sessionHandle, keyIndex, publicKey, wrapped.getEncryptedKey());
    assertNotNull(deOutput);
    assertTrue("输出长度应大于0", deOutput.length > 0);
} finally {
    sdf.SDF_DestroyKey(sessionHandle, wrapped.getKeyHandle());
}
```

---

### Documentation overstates RSA capability as 4096-bit
`docs/API_GUIDE.md:1095-1101`
```
| `SDF_ExportSignPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA签名公钥  (最大规格4096 bits) |
| `SDF_ExportEncPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA加密公钥  (最大规格4096 bits) |
| `SDF_GenerateKeyWithIPK_RSA(sessionHandle, keyIndex, keyBits)` | 用内部RSA公钥生成会话密钥  (最大规格4096 bits) |
| `SDF_GenerateKeyWithEPK_RSA(sessionHandle, keyBits, publicKey)` | 用外部RSA公钥生成会话密钥  (最大规格4096 bits) |
| `SDF_ImportKeyWithISK_RSA(sessionHandle, keyIndex, encryptedKey)` | 用内部RSA私钥导入会话密钥  (最大规格4096 bits) |
```
**Issue**: Multiple table entries now state 4096-bit RSA support, but current JNI native RSA structs remain 2048-bit. This creates incorrect operational expectations for users.
**Fix**:
```
| `SDF_ExportSignPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA签名公钥 (当前实现最大规格2048 bits) |
| `SDF_ExportEncPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA加密公钥 (当前实现最大规格2048 bits) |
| `SDF_GenerateKeyWithIPK_RSA(sessionHandle, keyIndex, keyBits)` | 用内部RSA公钥生成会话密钥 (当前实现最大规格2048 bits) |
| `SDF_GenerateKeyWithEPK_RSA(sessionHandle, keyBits, publicKey)` | 用外部RSA公钥生成会话密钥 (当前实现最大规格2048 bits) |
| `SDF_ImportKeyWithISK_RSA(sessionHandle, keyIndex, encryptedKey)` | 用内部RSA私钥导入会话密钥 (当前实现最大规格2048 bits) |
```

---


## Low

### Newly added algorithm IDs are not handled by getAlgorithmName
`sdf4j/src/main/java/org/openhitls/sdf4j/constants/AlgorithmID.java:167-271`
```
public static final int SGD_SM2 = 0x00020100;
...
public static final int SGD_SM2_DECRYPT = 0x00020801;
...
public static final int SGD_SM3_HMAC = 0x00100001;
```
**Issue**: `SGD_SM2`, `SGD_SM2_DECRYPT`, and `SGD_SM3_HMAC` were added, but `getAlgorithmName()` has no matching cases, so these constants resolve to `Unknown(...)`.
**Fix**:
```
// SM2
case SGD_SM2:
    return "SM2";
case SGD_SM2_1:
    return "SM2-Sign";
case SGD_SM2_2:
    return "SM2-KeyExchange";
case SGD_SM2_3:
    return "SM2-Encrypt";
case SGD_SM2_DECRYPT:
    return "SM2-Decrypt";

// Hash / HMAC
case SGD_SM3:
    return "SM3";
case SGD_SM3_HMAC:
    return "SM3-HMAC";
```

---

### API signature typo in RSA digital envelope entry
`docs/API_GUIDE.md:1126`
```
| `SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, uiKeyIndex, pucPublicKey, pucDEInput))` | RSA 数字信封转换 (最大规格4096 bits) |
```
**Issue**: The documented method has an extra closing parenthesis, which makes the signature incorrect for copy/paste usage.
**Fix**:
```
| `SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, uiKeyIndex, pucPublicKey, pucDEInput)` | RSA 数字信封转换 (最大规格4096 bits) |
```

---
