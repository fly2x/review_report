# Code Review: openHiTLS/sdf4j#15
**Reviewer**: CLAUDE


## Critical

### RSA 4096-bit support incomplete - native struct size mismatch
`sdf4j/src/main/native/include/sdf_types.h:89`
```
#define RSAref_MAX_BITS     2048  // Still 2048, should be 4096
#define RSAref_MAX_LEN      ((RSAref_MAX_BITS + 7) / 8)  // 256 bytes, should be 512
```
**Issue**: The Java classes RSAPublicKey and RSAPrivateKey were updated to support 4096-bit RSA keys (changing RSA_MAX_BITS from 2048 to 4096), but the native C structures RSArefPublicKey and RSArefPrivateKey still define RSAref_MAX_BITS as 2048. This causes silent data truncation when using 4096-bit keys.
**Fix**:
```
#define RSAref_MAX_BITS     4096
#define RSAref_MAX_LEN      ((RSAref_MAX_BITS + 7) / 8)  // 512 bytes
#define RSAref_MAX_PBITS    ((RSAref_MAX_BITS + 1) / 2)  // 2048 bits
#define RSAref_MAX_PLEN     ((RSAref_MAX_PBITS + 7) / 8)  // 256 bytes
```

---


## High

### AuthDecFinal buffer size reduced to unsafe value
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1274-1276`
```
/* max len is the last block size */
ULONG output_len = 16;
BYTE output_buf[16];
```
**Issue**: The output buffer for SDF_AuthDecFinal was reduced from 4096 bytes to just 16 bytes. For authenticated decryption (GCM mode), the final block may need more than 16 bytes, especially considering the last plaintext block. This could cause buffer overflow or truncated output.
**Fix**:
```
ULONG output_len = 4096;  /* Allocate sufficient buffer size for final output */
BYTE *output_buf = (BYTE*)malloc(output_len);
if (output_buf == NULL) {
    THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
    return NULL;
}
/* ... use output_buf ... */
if (ret != SDR_OK) {
    free(output_buf);
    THROW_SDF_EXCEPTION(env, ret, "Failed to perform auth dec final operation");
    return NULL;
}
jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
free(output_buf);
return result;
```

---

### RSA envelope output buffer overflow potential
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:379`
```
ULONG output_len = (native_key.bits + 7) / 8;  // User-controlled value
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
`docs/API_GUIDE.md:1095-1126`
```
| `SDF_ExportSignPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA签名公钥  (最大规格4096 bits) |
| `SDF_ExportEncPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA加密公钥  (最大规格4096 bits) |
```
**Issue**: The API documentation claims RSA functions support 4096-bit keys, but the native C code still limits RSA keys to 2048 bits (RSAref_MAX_BITS = 2048 in sdf_types.h). This is misleading and could lead to silent data truncation.
**Fix**:
```
Update documentation to reflect actual 2048-bit limit, or update native code to support 4096-bit keys first.
| `SDF_ExportSignPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA签名公钥  (最大规格2048 bits) |
| `SDF_ExportEncPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA加密公钥  (最大规格2048 bits) |
```

---


## Medium

### Test uses uninitialized input array
`examples/src/test/java/org/openhitls/sdf4j/examples/AsymmetricOperationTest.java:968`
```
byte[] deInput = new byte[256];  // All zeros - is this valid input?
byte[] deOutput = sdf.SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, keyIndex, publicKey, deInput);
```
**Issue**: The test creates a 256-byte input array filled with zeros but doesn't verify this is valid input for the RSA envelope operation. The test may pass due to SDR_NOTSUPPORT exception rather than actually testing the function.
**Fix**:
```
// First create a valid digital envelope, then test exchanging it
// Or document that this test is for API verification only
```

---

### Zero-length buffer allocation for ECC decrypt
`sdf4j/src/main/native/src/sdf_jni_util.c:250-251`
```
ULONG plaintext_len = ecc_cipher->L;
BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
```
**Issue**: If ecc_cipher->L is 0, malloc(0) behavior is implementation-defined and may return NULL or a non-dereferenceable pointer. This could cause issues.
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
