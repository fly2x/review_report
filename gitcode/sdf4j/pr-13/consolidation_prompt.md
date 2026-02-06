# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdf4j
- PR: #13
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/sdf4j#13
**Reviewer**: CLAUDE


## High

### THROW_SDF_EXCEPTION macro missing string.h include for strrchr
`sdf4j/src/main/native/include/type_conversion.h:37-41`
```
#define THROW_SDF_EXCEPTION(env, error_code, ...) \
    throw_sdf_exception_with_format(env, error_code, \
        "Function: %s, File: %s, Line: %d, ErrorNum: 0x%08X, Message: " __VA_ARGS__, \
        __func__, strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__, __LINE__, \
        (unsigned int)(error_code))
```
**Issue**: The THROW_SDF_EXCEPTION macro uses strrchr() function on line 40, but type_conversion.h does not include <string.h>. This will cause a compilation error or undefined behavior when using the macro in files that don't include <string.h> before this header.
**Fix**:
```
#include <string.h>

#define THROW_SDF_EXCEPTION(env, error_code, ...) \
    throw_sdf_exception_with_format(env, error_code, \
        "Function: %s, File: %s, Line: %d, ErrorNum: 0x%08X, Message: " __VA_ARGS__, \
        __func__, strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__, __LINE__, \
        (unsigned int)(error_code))
```

---

### THROW_SDF_EXCEPTION macro requires at least one vararg but comment suggests it's optional
`sdf4j/src/main/native/include/type_conversion.h:37-41`
```
/**
 * 抛出SDF异常的便利宏（自动传递函数名、文件名、行号）
 * 用法:
 *   THROW_SDF_EXCEPTION(env, error_code, "message: %s", str)
 *   THROW_SDF_EXCEPTION(env, error_code)  // 使用默认消息
 *
 * 异常消息格式: Function: xxx, File: xxx, Line: xxx, ErrorNum: 0xXXXXXXXX, Message: xxx
 */
#define THROW_SDF_EXCEPTION(env, error_code, ...) \
    throw_sdf_exception_with_format(env, error_code, \
        "Function: %s, File: %s, Line: %d, ErrorNum: 0x%08X, Message: " __VA_ARGS__, \
```
**Issue**: The macro comment states "THROW_SDF_EXCEPTION(env, error_code) // 使用默认消息" suggesting it can be called with only 2 arguments, but the macro uses `__VA_ARGS__` in a way that requires at least one additional argument (the message format string). Calling THROW_SDF_EXCEPTION(env, error_code) without any message would result in malformed string concatenation and compilation error.
**Fix**:
```
/**
 * 抛出SDF异常的便利宏（自动传递函数名、文件名、行号）
 * 用法:
 *   THROW_SDF_EXCEPTION(env, error_code, "message: %s", str)
 *   THROW_SDF_EXCEPTION(env, error_code, "message")
 *
 * 异常消息格式: Function: xxx, File: xxx, Line: xxx, ErrorNum: 0xXXXXXXXX, Message: xxx
 * 注意: 必须提供消息字符串参数
 */
#define THROW_SDF_EXCEPTION(env, error_code, ...) \
    throw_sdf_exception_with_format(env, error_code, \
        "Function: %s, File: %s, Line: %d, ErrorNum: 0x%08X, Message: " __VA_ARGS__, \
```

---


## Medium

### Misleading error message for RSA key pair generation
`sdf4j/src/main/native/src/sdf_jni_util.c:43`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_GenerateKeyPair_RSA which generates RSA key pairs, not hash computation.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate RSA key pair");
        return NULL;
    }
```

---

### Misleading error message for ECC key pair generation
`sdf4j/src/main/native/src/sdf_jni_util.c:94`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_GenerateKeyPair_ECC which generates ECC key pairs.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate ECC key pair");
        return NULL;
    }
```

---

### Misleading error message for RSA private key operation
`sdf4j/src/main/native/src/sdf_jni_util.c:167`
```
if (ret != SDR_OK) {
        free(output_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalPrivateKeyOperation_RSA which performs RSA private key operations.
**Fix**:
```
if (ret != SDR_OK) {
        free(output_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform RSA private key operation");
        return NULL;
    }
```

---

### Misleading error message for ECC external sign
`sdf4j/src/main/native/src/sdf_jni_util.c:222`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalSign_ECC which performs ECC signing operations.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ECC signing");
        return NULL;
    }
```

---

### Misleading error message for ECC external decrypt
`sdf4j/src/main/native/src/sdf_jni_util.c:281`
```
if (ret != SDR_OK) {
        free(ecc_cipher);
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalDecrypt_ECC which performs ECC decryption operations.
**Fix**:
```
if (ret != SDR_OK) {
        free(ecc_cipher);
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ECC decryption");
        return NULL;
    }
```

---

### Misleading error message for symmetric encryption
`sdf4j/src/main/native/src/sdf_jni_util.c:372`
```
if (ret != SDR_OK) {
        free(enc_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalKeyEncrypt which performs symmetric encryption operations.
**Fix**:
```
if (ret != SDR_OK) {
        free(enc_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform encryption");
        return NULL;
    }
```

---

### Misleading error message for symmetric decryption
`sdf4j/src/main/native/src/sdf_jni_util.c:462`
```
if (ret != SDR_OK) {
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalKeyDecrypt which performs symmetric decryption operations.
**Fix**:
```
if (ret != SDR_OK) {
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform decryption");
        return NULL;
    }
```

---

### Misleading error message for encryption init
`sdf4j/src/main/native/src/sdf_jni_util.c:521`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalKeyEncryptInit which initializes symmetric encryption.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize encryption");
    }
```

---

### Misleading error message for decryption init
`sdf4j/src/main/native/src/sdf_jni_util.c:574`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalKeyDecryptInit which initializes symmetric decryption.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize decryption");
    }
```

---

### Misleading error message for HMAC init
`sdf4j/src/main/native/src/sdf_jni_util.c:609`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message says "Failed to compute hash" but the function is JNI_SDF_ExternalKeyHMACInit which initializes HMAC operation.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize HMAC");
    }
```

---

### Misleading error message for HashInit
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1395`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform symmetric operation");
    }
```
**Issue**: The error message says "Failed to perform symmetric operation" but the function is JNI_SDF_HashInit which performs hash initialization, not symmetric encryption.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize hash");
    }
```

---

### Misleading error message for HashUpdate
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1424`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform symmetric operation");
    }
```
**Issue**: The error message says "Failed to perform symmetric operation" but the function is JNI_SDF_HashUpdate which performs hash update, not symmetric encryption.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to update hash");
    }
```

---

### Misleading error message for HashFinal
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1442`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform symmetric operation");
        return NULL;
    }
```
**Issue**: The error message says "Failed to perform symmetric operation" but the function is JNI_SDF_HashFinal which performs hash finalization, not symmetric encryption.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to finalize hash");
        return NULL;
    }
```

---


## Low

### Duplicate comment in error message
`sdf4j/src/main/native/src/sdf_jni_keygen.c:289`
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */  /* SDR_INARGERR */
```
**Issue**: The error message has a duplicate "/* SDR_INARGERR */" comment.
**Fix**:
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
```

---

### Duplicate comment in error message
`sdf4j/src/main/native/src/sdf_jni_keygen.c:295`
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */  /* SDR_INARGERR */
```
**Issue**: The error message has a duplicate "/* SDR_INARGERR */" comment.
**Fix**:
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
```

---

### Duplicate comment in error message
`sdf4j/src/main/native/src/sdf_jni_keygen.c:333`
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */  /* SDR_INARGERR */
```
**Issue**: The error message has a duplicate "/* SDR_INARGERR */" comment.
**Fix**:
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
```

---

### Duplicate comment in error message
`sdf4j/src/main/native/src/sdf_jni_keygen.c:394`
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */  /* SDR_INARGERR */
```
**Issue**: The error message has a duplicate "/* SDR_INARGERR */" comment.
**Fix**:
```
THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
```

---


---

## GEMINI Review

# Code Review: openHiTLS/sdf4j#13
**Reviewer**: GEMINI


## Medium

### Code Duplication in RSA Public Key Conversion
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:366`
```
/* 转换公钥 */
    RSArefPublicKey native_key;
    memset(&native_key, 0, sizeof(RSArefPublicKey));

    jclass key_class = (*env)->GetObjectClass(env, publicKey);
    
    /* 获取bits字段 */
    jfieldID bits_fid = (*env)->GetFieldID(env, key_class, "bits", "I");
    if (bits_fid == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000001, "Cannot get bits field");
        return NULL;
    }
    native_key.bits = (*env)->GetIntField(env, publicKey, bits_fid);

    /* 获取m字段 */
    jfieldID m_fid = (*env)->GetFieldID(env, key_class, "m", "[B");
    if (m_fid != NULL) {
        jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, m_fid);
        if (m_array != NULL) {
            jsize m_len = (*env)->GetArrayLength(env, m_array);
            if (m_len > RSAref_MAX_LEN) m_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, m_array, 0, m_len, (jbyte*)native_key.m);
        }
    }

    /* 获取e字段 */
    jfieldID e_fid = (*env)->GetFieldID(env, key_class, "e", "[B");
    if (e_fid != NULL) {
        jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, e_fid);
        if (e_array != NULL) {
            jsize e_len = (*env)->GetArrayLength(env, e_array);
            if (e_len > RSAref_MAX_LEN) e_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, e_array, 0, e_len, (jbyte*)native_key.e);
        }
    }
```
**Issue**: The function `JNI_SDF_ExternalPublicKeyOperation_RSA` manually converts the Java RSA public key to the native `RSArefPublicKey` structure. This duplicates the logic already implemented in `java_to_native_RSAPublicKey` (declared in `type_conversion.h`), increasing maintenance burden and the risk of inconsistencies (e.g., if the helper function is updated to handle edge cases).
**Fix**:
```
/* 转换公钥 */
    RSArefPublicKey native_key;
    if (!java_to_native_RSAPublicKey(env, publicKey, &native_key)) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Failed to convert public key");
        return NULL;
    }
```

---


## Low

### Incorrect Error Message in JNI_SDF_GenerateKeyPair_RSA
`sdf4j/src/main/native/src/sdf_jni_util.c:46`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_GenerateKeyPair_RSA` fails. This is misleading as the operation is key generation, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate RSA key pair");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_GenerateKeyPair_ECC
`sdf4j/src/main/native/src/sdf_jni_util.c:97`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_GenerateKeyPair_ECC` fails. This is misleading as the operation is key generation, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate ECC key pair");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalPrivateKeyOperation_RSA
`sdf4j/src/main/native/src/sdf_jni_util.c:170`
```
if (ret != SDR_OK) {
        free(output_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalPrivateKeyOperation_RSA` fails. This is misleading as the operation is RSA private key operation, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(output_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform RSA private key operation");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalSign_ECC
`sdf4j/src/main/native/src/sdf_jni_util.c:225`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalSign_ECC` fails. This is misleading as the operation is ECC signing, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to sign with external private key");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalDecrypt_ECC
`sdf4j/src/main/native/src/sdf_jni_util.c:284`
```
if (ret != SDR_OK) {
        free(ecc_cipher);
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalDecrypt_ECC` fails. This is misleading as the operation is ECC decryption, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(ecc_cipher);
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to decrypt with external private key");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyEncrypt
`sdf4j/src/main/native/src/sdf_jni_util.c:375`
```
if (ret != SDR_OK) {
        free(enc_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyEncrypt` fails. This is misleading as the operation is symmetric encryption, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(enc_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform symmetric encryption");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyDecrypt
`sdf4j/src/main/native/src/sdf_jni_util.c:465`
```
if (ret != SDR_OK) {
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
        return NULL;
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyDecrypt` fails. This is misleading as the operation is symmetric decryption, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        free(plaintext_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform symmetric decryption");
        return NULL;
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyEncryptInit
`sdf4j/src/main/native/src/sdf_jni_util.c:524`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyEncryptInit` fails. This is misleading as the operation is symmetric encryption initialization, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize symmetric encryption");
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyDecryptInit
`sdf4j/src/main/native/src/sdf_jni_util.c:577`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyDecryptInit` fails. This is misleading as the operation is symmetric decryption initialization, not hashing.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize symmetric decryption");
    }
```

---

### Incorrect Error Message in JNI_SDF_ExternalKeyHMACInit
`sdf4j/src/main/native/src/sdf_jni_util.c:612`
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to compute hash");
    }
```
**Issue**: The error message "Failed to compute hash" is used when `SDF_ExternalKeyHMACInit` fails. While HMAC is related to hash, the message should be more specific to the initialization failure.
**Fix**:
```
if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to initialize HMAC operation");
    }
```

---


---

## CODEX Review

# Code Review: openHiTLS/sdf4j#13
**Reviewer**: CODEX


## Critical

### Variadic exception macro corrupts vararg ordering
`sdf4j/src/main/native/include/type_conversion.h:37-41`
```
#define THROW_SDF_EXCEPTION(env, error_code, ...) \
    throw_sdf_exception_with_format(env, error_code, \
        "Function: %s, File: %s, Line: %d, ErrorNum: 0x%08X, Message: " __VA_ARGS__, \
        __func__, strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__, __LINE__, \
        (unsigned int)(error_code))
```
**Issue**: `THROW_SDF_EXCEPTION` concatenates `__VA_ARGS__` into the format string but always appends fixed metadata arguments after it. Calls with formatted message args (for example `THROW_SDF_EXCEPTION(..., "%s", error)` in `sdf_jni_loader.c:46`) shift argument positions and produce undefined behavior in `vsnprintf`, which can crash the JVM on library-load failure paths.
**Fix**:
```
#define THROW_SDF_EXCEPTION(env, error_code, msg_fmt, ...) \
    throw_sdf_exception_with_format(env, error_code, \
        "Function: %s, File: %s, Line: %d, ErrorNum: 0x%08X, Message: " msg_fmt, \
        __func__, strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__, __LINE__, \
        (unsigned int)(error_code), ##__VA_ARGS__)
```

---


## High

### Public logging API removed without compatibility shim
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:1321-1404`
```
public static void setLogger(SDFLogger logger) { ... }
public static SDFLogger getLogger() { ... }
public static native void setFileLoggingEnabled(boolean enable);
public static native void setJavaLoggingEnabled(boolean enable);
```
**Issue**: The PR removes `SDF.setLogger`, `SDF.getLogger`, `SDF.setFileLoggingEnabled`, and `SDF.setJavaLoggingEnabled` (and also deletes `SDFLogger` / `DefaultSDFLogger`). This is a source/binary breaking change for existing consumers and will fail upgrades without migration support.
**Fix**:
```
@Deprecated
public static void setLogger(SDFLogger logger) {
    // Compatibility no-op: native logger callback removed.
}

@Deprecated
public static SDFLogger getLogger() {
    return message -> { };
}

@Deprecated
public static void setFileLoggingEnabled(boolean enable) {
    // Compatibility no-op.
}

@Deprecated
public static void setJavaLoggingEnabled(boolean enable) {
    // Compatibility no-op.
}
```

---


## Low

### Error field name does not match documented exception format
`docs/API_GUIDE.md:841`
```
| Error | 十六进制错误码 |
```
**Issue**: The field table says `Error`, but the documented/actual message key is `ErrorNum`. This inconsistency is misleading for users parsing exception text.
**Fix**:
```
| ErrorNum | 十六进制错误码 |
```

---

### Negative-path test does not assert expected exception
`examples/src/test/java/org/openhitls/sdf4j/examples/DeviceManagementTest.java:190-195`
```
try {
    sdf.SDF_CloseSession(99999);
} catch (SDFException e) {
    System.err.println("[通过]关闭会话失败: " + e.getErrorCodeHex());
    System.err.println("[通过]关闭会话失败: " + e.getMessage());
}
```
**Issue**: The test calls `SDF_CloseSession(99999)` but never fails if no exception is thrown, so regressions in invalid-handle validation can pass silently.
**Fix**:
```
try {
    sdf.SDF_CloseSession(99999);
    fail("Expected SDFException for invalid session handle");
} catch (SDFException e) {
    System.err.println("[通过]关闭会话失败: " + e.getErrorCodeHex());
    System.err.println("[通过]关闭会话失败: " + e.getMessage());
}
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
