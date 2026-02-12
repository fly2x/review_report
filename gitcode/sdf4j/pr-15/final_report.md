# Final Code Review Report
## openHiTLS/sdf4j - PR #15

### Summary
- **Total Issues**: 9
- **Critical**: 1
- **High**: 3
- **Medium**: 3
- **Low**: 2
- **Reviewers**: claude, gemini, codex

---


## Critical

### RSA 4096-bit support incomplete - native struct size mismatch
`sdf4j/src/main/native/include/sdf_types.h:89-92`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
```
#define RSAref_MAX_BITS     2048
#define RSAref_MAX_LEN      ((RSAref_MAX_BITS + 7) / 8)
```
**Issue**: The Java classes RSAPublicKey and RSAPrivateKey were updated to support 4096-bit RSA keys (changing RSA_MAX_BITS from 2048 to 4096), but the native C structures RSArefPublicKey and RSArefPrivateKey still define RSAref_MAX_BITS as 2048. This causes silent data truncation when using 4096-bit keys and ABI incompatibility between Java and native layers.
**Fix**:
```
#define RSAref_MAX_BITS     4096
#define RSAref_MAX_LEN      ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS    ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN     ((RSAref_MAX_PBITS + 7) / 8)
```

---


## High

### RSA envelope output buffer overflow potential
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:379`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
ULONG output_len = (native_key.bits + 7) / 8;
BYTE *output_buf = (BYTE*)malloc(output_len);
```
**Issue**: The output buffer is allocated based on native_key.bits, which is user-controlled. If a malicious RSAPublicKey object has bits set to a large value while the actual m/e arrays are smaller, this could cause buffer overflow or excessive memory allocation.
**Fix**:
```
ULONG output_len = (native_key.bits + 7) / 8;
/* Cap output buffer size to RSAref_MAX_LEN (256 bytes) */
if (output_len > RSAref_MAX_LEN) {
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Key bits too large");
    return NULL;
}
BYTE *output_buf = (BYTE*)malloc(output_len);
```

---

### Documentation claims 4096-bit RSA support not implemented in native code
`docs/API_GUIDE.md:1095-1101`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
| `SDF_ExportSignPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA签名公钥  (最大规格4096 bits) |
| `SDF_ExportEncPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA加密公钥  (最大规格4096 bits) |
```
**Issue**: The API documentation claims RSA functions support 4096-bit keys, but the native C code still limits RSA keys to 2048 bits (RSAref_MAX_BITS = 2048 in sdf_types.h). This is misleading and could lead to silent data truncation.
**Fix**:
```
| `SDF_ExportSignPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA签名公钥 (当前实现最大规格2048 bits) |
| `SDF_ExportEncPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA加密公钥 (当前实现最大规格2048 bits) |
| `SDF_GenerateKeyWithIPK_RSA(sessionHandle, keyIndex, keyBits)` | 用内部RSA公钥生成会话密钥 (当前实现最大规格2048 bits) |
| `SDF_GenerateKeyWithEPK_RSA(sessionHandle, keyBits, publicKey)` | 用外部RSA公钥生成会话密钥 (当前实现最大规格2048 bits) |
| `SDF_ImportKeyWithISK_RSA(sessionHandle, keyIndex, encryptedKey)` | 用内部RSA私钥导入会话密钥 (当前实现最大规格2048 bits) |
| `SDF_ExternalPublicKeyOperation_RSA(sessionHandle, publicKey, data)` | 外部公钥RSA运算 (当前实现最大规格2048 bits) |
| `SDF_InternalPublicKeyOperation_RSA(sessionHandle, keyIndex, data)` | 内部公钥RSA运算 (当前实现最大规格2048 bits) |
| `SDF_InternalPrivateKeyOperation_RSA(sessionHandle, keyIndex, data)` | 内部私钥RSA运算 (当前实现最大规格2048 bits) |
| `SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, uiKeyIndex, pucPublicKey, pucDEInput)` | RSA 数字信封转换 (当前实现最大规格2048 bits) |
```

---

### AuthDecFinal buffer size reduced to unsafe value
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1274-1276`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 较可信
```
/* max len is the last block size */
ULONG output_len = 16;
BYTE output_buf[16];
```
**Issue**: The output buffer for SDF_AuthDecFinal was reduced from 4096 bytes to just 16 bytes. For authenticated decryption (GCM mode), the final block may need more than 16 bytes, especially considering the last plaintext block. This could cause buffer overflow or truncated output.
**Fix**:
```
ULONG output_len = 256;
BYTE output_buf[256];
```

---


## Medium

### Test uses uninitialized input array
`examples/src/test/java/org/openhitls/sdf4j/examples/AsymmetricOperationTest.java:968`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
byte[] deInput = new byte[256];
byte[] deOutput = sdf.SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, keyIndex, publicKey, deInput);
```
**Issue**: The test creates a 256-byte input array filled with zeros but doesn't verify this is valid input for the RSA envelope operation. The test may pass due to SDR_NOTSUPPORT exception rather than actually testing the function.
**Fix**:
```
// First create a valid digital envelope, then test exchanging it
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

### Zero-length buffer allocation for ECC decrypt
`sdf4j/src/main/native/src/sdf_jni_util.c:250-251`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
ULONG plaintext_len = ecc_cipher->L;
BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
```
**Issue**: If ecc_cipher->L is 0, malloc(0) behavior is implementation-defined and may return NULL or a non-dereferenceable pointer.
**Fix**:
```
ULONG plaintext_len = ecc_cipher->L;
if (plaintext_len == 0) {
    free(ecc_cipher);
    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Invalid cipher length");
    return NULL;
}
BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
```

---

### RSA private operation buffer sizing trusts mutable key metadata
`sdf4j/src/main/native/src/sdf_jni_util.c:135-137`
**Reviewers**: CODEX | **置信度**: 较可信
```
ULONG output_len = (priv_key.bits + 7) / 8;
BYTE *output_buf = (BYTE*)malloc(output_len);
```
**Issue**: Buffer length depends on priv_key.bits from Java object state. If bits is inconsistent or zero, output buffer can be under-sized/invalid before calling SDF_ExternalPrivateKeyOperation_RSA.
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


## Low

### Newly added algorithm IDs are not handled by getAlgorithmName
`sdf4j/src/main/java/org/openhitls/sdf4j/constants/AlgorithmID.java:167-271`
**Reviewers**: CODEX | **置信度**: 可信
```
public static final int SGD_SM2 = 0x00020100;
public static final int SGD_SM2_DECRYPT = 0x00020801;
public static final int SGD_SM3_HMAC = 0x00100001;
```
**Issue**: SGD_SM2, SGD_SM2_DECRYPT, and SGD_SM3_HMAC were added, but getAlgorithmName() has no matching cases, so these constants resolve to "Unknown(...)".
**Fix**:
```
// Add to getAlgorithmName():
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
case SGD_SM3:
    return "SM3";
case SGD_SM3_HMAC:
    return "SM3-HMAC";
```

---

### API signature typo in RSA digital envelope entry
`docs/API_GUIDE.md:1126`
**Reviewers**: CODEX | **置信度**: 可信
```
| `SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, uiKeyIndex, pucPublicKey, pucDEInput))` | RSA 数字信封转换 (最大规格4096 bits) |
```
**Issue**: The documented method has an extra closing parenthesis, which makes the signature incorrect for copy/paste usage.
**Fix**:
```
| `SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, uiKeyIndex, pucPublicKey, pucDEInput)` | RSA 数字信封转换 (最大规格4096 bits) |
```

---
