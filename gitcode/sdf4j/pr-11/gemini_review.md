# Code Review: openHiTLS/sdf4j#11
**Reviewer**: GEMINI


## Critical

### Plaintext Password Logging
`sdf4j/src/main/native/src/sdf_jni_device.c:220`
```
SDF_JNI_LOG("SDF_GetPrivateKeyAccessRight: pwd='%s', pwd_len=%lu",
                pwd ? pwd : "(null)", (unsigned long)pwd_len);
```
**Issue**: The function `JNI_SDF_GetPrivateKeyAccessRight` logs the user's password in plaintext. This is a severe security vulnerability that leaks sensitive credentials to the application logs.
**Fix**:
```
SDF_JNI_LOG("SDF_GetPrivateKeyAccessRight: pwd='***', pwd_len=%lu",
                (unsigned long)pwd_len);
```

---

### Plaintext Password Logging
`sdf4j/src/main/native/src/sdf_jni_device.c:282`
```
SDF_JNI_LOG("SDF_GetKEKAccessRight: pwd='%s', pwd_len=%lu",
                pwd ? pwd : "(null)", (unsigned long)pwd_len);
```
**Issue**: The function `JNI_SDF_GetKEKAccessRight` logs the user's password in plaintext.
**Fix**:
```
SDF_JNI_LOG("SDF_GetKEKAccessRight: pwd='***', pwd_len=%lu",
                (unsigned long)pwd_len);
```

---

### Heap Buffer Overflow in JNI_SDF_AuthEncFinal
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:531-558`
```
/* Convert pucEncData to native buffer */
    BYTE *output_buf = NULL;
    ULONG output_len = 0;
    if (pucEncData != NULL) {
        output_len = (*env)->GetArrayLength(env, pucEncData);
        output_buf = (BYTE*)malloc(output_len);
        if (output_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, pucEncData, 0, output_len, (jbyte*)output_buf);
    }
```
**Issue**: The function allocates `output_buf` based on the size of the input Java array `pucEncData`. The `SDF_AuthEncFinal` C function writes final ciphertext (padding) and authentication tag. If the user passes a small or empty array (e.g., `new byte[0]`), `malloc` allocates a small buffer, but `SDF_AuthEncFinal` writes padding bytes, causing a heap buffer overflow. Additionally, copying data from `pucEncData` (`GetByteArrayRegion`) is unnecessary as `SDF_AuthEncFinal` is an output-only function for the ciphertext buffer.
**Fix**:
```
/* Allocate output buffer with sufficient size for padding (e.g. 256 bytes) */
    /* pucEncData input is ignored as this is a finalization step producing new data */
    ULONG output_len = 256; 
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    /* Do not copy from pucEncData */
```

---


## High

### Heap Buffer Over-read in java_to_native_ECCCipher_alloc
`sdf4j/src/main/native/src/type_conversion.c:350-353`
```
/* L - cipher data length */
    native_cipher->L = (ULONG)l_value;
    if (native_cipher->L == 0 && c_len > 0) {
        native_cipher->L = c_len;
    }
```
**Issue**: The function allows the `L` field of `ECCCipher` to be set to a value larger than the actual allocated size of the `C` array. `native_cipher->L` is set to `l_value` (from Java object), while the memory allocated depends on the Java byte array length. If a malicious user sets a large `L` and a small `C` array, subsequent native calls (like `SDF_ExternalDecrypt_ECC`) will read past the allocated buffer boundary.
**Fix**:
```
/* L - cipher data length */
    /* Ensure L does not exceed actual buffer size to prevent over-read */
    if (l_value > c_len) {
        SDF_LOG_ERROR("java_to_native_ECCCipher_alloc", "Invalid L value: exceeds array length");
        free(native_cipher);
        return NULL;
    }
    native_cipher->L = (ULONG)l_value;
    if (native_cipher->L == 0 && c_len > 0) {
        native_cipher->L = c_len;
    }
```

---


## Medium

### Potential Pointer Corruption in JNI_SDF_AuthDec
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:433`
```
LONG ret = g_sdf_functions.SDF_AuthDec(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len,
        (BYTE*)aad_buf,
        (ULONG)aad_len,
        (BYTE*)tag_buf,
        (ULONG *)&tag_len,
        (BYTE*)enc_buf,
```
**Issue**: The function casts `jsize*` (int*) to `ULONG*` (unsigned int*). While `ULONG` is typedef'd to `unsigned int` in this project (making it 32-bit and likely safe), this cast is dangerous. If `ULONG` were ever changed to `unsigned long` (64-bit on Linux), `SDF_AuthDec` would overwrite stack memory adjacent to `tag_len`.
**Fix**:
```
ULONG ul_tag_len = (ULONG)tag_len;
    LONG ret = g_sdf_functions.SDF_AuthDec(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len,
        (BYTE*)aad_buf,
        (ULONG)aad_len,
        (BYTE*)tag_buf,
        &ul_tag_len,
        (BYTE*)enc_buf,
```

---
