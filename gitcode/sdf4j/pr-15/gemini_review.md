# Code Review: openHiTLS/sdf4j#15
**Reviewer**: GEMINI


## Critical

### Native header mismatch for RSA key size
`sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java:32`
```
/**
     * 最大位数
     */
    public static final int RSA_MAX_BITS = 4096;
```
**Issue**: The Java constant `RSA_MAX_BITS` was updated to 4096, but the corresponding C definition `RSAref_MAX_BITS` in `sdf4j/src/main/native/include/sdf_types.h` (not included in this PR) remains 2048. This causes `java_to_native_RSAPrivateKey` in `type_conversion.c` to truncate 4096-bit keys to 2048 bits (256 bytes) when copying to the fixed-size native struct. Furthermore, when these native structs (with `bits=4096` but only 256 bytes of space for `m`) are passed to SDF functions, it leads to buffer over-reads or stack corruption as the SDF implementation expects 512 bytes based on the bit length.
**Fix**:
```
// You must update sdf4j/src/main/native/include/sdf_types.h to match:
// #define RSAref_MAX_BITS     4096
// And recompile the native library.
public static final int RSA_MAX_BITS = 4096;
```

---


## High

### Potential stack buffer overflow in AuthDecFinal
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1275`
```
/* max len is the last block size */
    ULONG output_len = 16;
    BYTE output_buf[16];
    LONG ret = g_sdf_functions.SDF_AuthDecFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len
    );
```
**Issue**: The output buffer `output_buf` was reduced from a heap-allocated 4096 bytes to a stack-allocated 16 bytes. While GCM/CCM `Final` typically outputs only the final partial block (<= 16 bytes), relying on this exact size is dangerous. If the underlying SDF implementation buffers more data (e.g., a full block + partial) or behaves differently, writing more than 16 bytes to `output_buf` will cause a stack buffer overflow.
**Fix**:
```
/* Allocate sufficient buffer size for final block(s) */
    ULONG output_len = 256; 
    BYTE output_buf[256];
    LONG ret = g_sdf_functions.SDF_AuthDecFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len
    );
```

---
