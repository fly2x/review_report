# Code Review Consolidation Task

You are consolidating code review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdf4j
- PR: #11
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/sdf4j#11
**Reviewer**: CLAUDE


## High

### Duplicate typedef for SDF_ImportKey_FN
`sdf4j/src/main/native/include/dynamic_loader.h:93-97`
```
typedef LONG (*SDF_ImportKey_FN)(HANDLE hSessionHandle, BYTE *pucKey,
                                 ULONG uiKeyLength, HANDLE *phKeyHandle);
typedef LONG (*SDF_DestroyKey_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle);

typedef LONG (*SDF_ImportKey_FN)(HANDLE hSessionHandle, BYTE *pucKey,
                                 ULONG uiKeyLength, HANDLE *phKeyHandle);
```
**Issue**: The typedef for SDF_ImportKey_FN is defined twice on lines 93-94 and 97-98. The second definition on lines 97-98 is redundant and will cause a compilation warning or error.
**Fix**:
```
typedef LONG (*SDF_ImportKey_FN)(HANDLE hSessionHandle, BYTE *pucKey,
                                 ULONG uiKeyLength, HANDLE *phKeyHandle);
typedef LONG (*SDF_DestroyKey_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle);

typedef LONG (*SDF_ExchangeDigitEnvelopeBaseOnECC_FN)(HANDLE hSessionHandle, ULONG uiKEKIndex,
                                        ULONG uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
                                        ECCCipher *pucEncDataOut);
```

---

### SDF_ImportKey loaded twice from library
`sdf4j/src/main/native/src/dynamic_loader.c:135-139`
```
load_function(handle, (void**)&g_sdf_functions.SDF_ImportKey,
                 "SDF_ImportKey", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_DestroyKey,
                 "SDF_DestroyKey", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ImportKey,
                 "SDF_ImportKey", false);
```
**Issue**: The code calls load_function twice for SDF_ImportKey (lines 135-136 and 137-138). The second call is redundant and may cause confusion or unexpected behavior if the function pointers were different.
**Fix**:
```
load_function(handle, (void**)&g_sdf_functions.SDF_DestroyKey,
                 "SDF_DestroyKey", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ImportKey,
                 "SDF_ImportKey", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExchangeDigitEnvelopeBaseOnECC,
                 "SDF_ExchangeDigitEnvelopeBaseOnECC", false);
```

---

### Key handles not registered with SessionResource for tracking
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:443-444`
```
public native long SDF_ImportKeyWithISK_RSA(
            long sessionHandle, int keyIndex, byte[] encryptedKey) throws SDFException;

    public native long SDF_ImportKeyWithISK_ECC(
            long sessionHandle, int keyIndex, ECCCipher cipher) throws SDFException;

    public native long SDF_GenerateAgreementDataWithECC(
            long sessionHandle, int keyIndex, int keyBits,
            byte[] sponsorID, ECCPublicKey sponsorPublicKey,
            ECCPublicKey sponsorTmpPublicKey) throws SDFException;
```
**Issue**: Key generation functions that return long handles (SDF_ImportKeyWithISK_RSA, SDF_ImportKeyWithISK_ECC, SDF_GenerateAgreementDataWithECC, SDF_GenerateKeyWithECC, SDF_GenerateAgreementDataAndKeyWithECC, SDF_ImportKeyWithKEK, SDF_ImportKey) do not register their returned handles with SessionResource. This means these keys will not be automatically cleaned up when the session is closed, causing resource leaks. Only SDF_GenerateKeyWithIPK_RSA, SDF_GenerateKeyWithEPK_RSA, SDF_GenerateKeyWithIPK_ECC, SDF_GenerateKeyWithEPK_ECC, and SDF_GenerateKeyWithKEK properly register keys.
**Fix**:
```
public long SDF_ImportKeyWithISK_RSA(
            long sessionHandle, int keyIndex, byte[] encryptedKey) throws SDFException {
        long keyHandle = SDF_ImportKeyWithISK_RSA_Native(sessionHandle, keyIndex, encryptedKey);
        if (keyHandle != 0) {
            SessionResource sessionResource = gSessResource.get(sessionHandle);
            if (sessionResource != null) {
                sessionResource.addKey(keyHandle);
            }
        }
        return keyHandle;
    }

    private native long SDF_ImportKeyWithISK_RSA_Native(
            long sessionHandle, int keyIndex, byte[] encryptedKey) throws SDFException;

    // Apply similar wrapper pattern to SDF_ImportKeyWithISK_ECC,
    // SDF_GenerateAgreementDataWithECC, SDF_GenerateKeyWithECC,
    // SDF_GenerateAgreementDataAndKeyWithECC, SDF_ImportKeyWithKEK, and SDF_ImportKey
```

---


## Medium

### Potential JNI exception pending after native call
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:47-57`
```
LONG ret = g_sdf_functions.SDF_InternalSign_ECC((HANDLE)sessionHandle, keyIndex,
                                                     (BYTE*)data_buf, data_len, &signature);
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        SDF_LOG_HEX("SDF_InternalSign_ECC signature.r", signature.r, ECCref_MAX_LEN);
        SDF_LOG_HEX("SDF_InternalSign_ECC signature.s", signature.s, ECCref_MAX_LEN);
        throw_sdf_exception(env, ret);
        return NULL;
    }
```
**Issue**: After calling g_sdf_functions.SDF_InternalSign_ECC on line 48-49, the code releases the primitive array critical on line 50 BEFORE checking the return value and throwing an exception on lines 51-55. If ret != SDR_OK, a Java exception is thrown, but the array is already released. While JNI_ABORT is correct, the error logging on lines 52-53 happens after release which could lose context. More critically, if native_to_java_ECCSignature fails on line 57, the exception is thrown without proper context.
**Fix**:
```
LONG ret = g_sdf_functions.SDF_InternalSign_ECC((HANDLE)sessionHandle, keyIndex,
                                                     (BYTE*)data_buf, data_len, &signature);
    
    if (ret != SDR_OK) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        SDF_LOG_HEX("SDF_InternalSign_ECC signature.r", signature.r, ECCref_MAX_LEN);
        SDF_LOG_HEX("SDF_InternalSign_ECC signature.s", signature.s, ECCref_MAX_LEN);
        throw_sdf_exception(env, ret);
        return NULL;
    }
    
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
```

---

### DeviceResource finalize uses obsolete gDevHandle after close
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:57-85`
```
private class DeviceResource {
        private java.util.Set<Long> sessions = new java.util.HashSet<>();

        @Override
        protected void finalize() throws Throwable {
            try {
                SDF_CloseDevice(gDevHandle);
            } catch (Exception e) {
                // 忽略异常
            } finally {
                super.finalize();
            }
        }
```
**Issue**: In DeviceResource.finalize(), if SDF_CloseDevice(gDevHandle) is called on line 70 but gDevHandle has already been set to null by another thread, a NullPointerException could occur. Also, the finalize method doesn't check if gDevHandle is null before calling SDF_CloseDevice.
**Fix**:
```
private class DeviceResource {
        private java.util.Set<Long> sessions = new java.util.HashSet<>();

        @Override
        protected void finalize() throws Throwable {
            try {
                if (gDevHandle != null) {
                    SDF_CloseDevice(gDevHandle);
                }
            } catch (Exception e) {
                // 忽略异常
            } finally {
                super.finalize();
            }
        }
```

---


## Low

### SDF_OpenDevice returns cached handle without thread-safety
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:144-153`
```
public long SDF_OpenDevice() throws SDFException {
        // 如果已初始化，直接返回
        if (gDevHandle != null) {
            return gDevHandle;
        }
        
        // 初始化 device
        gDevHandle = SDF_OpenDeviceNative();
        gDevResource = new DeviceResource();
        return gDevHandle;
    }
```
**Issue**: The SDF_OpenDevice method checks if gDevHandle != null on line 146 and returns the cached handle. This has two issues: 1) If gDevHandle is non-null but the device was actually closed externally, it returns an invalid handle. 2) The check and assignment is not thread-safe - multiple threads could race and create multiple DeviceResource instances.
**Fix**:
```
public long SDF_OpenDevice() throws SDFException {
        // 如果已初始化，直接返回
        Long cachedHandle;
        synchronized (this) {
            cachedHandle = gDevHandle;
            if (cachedHandle != null) {
                return cachedHandle;
            }
            // 初始化 device
            gDevHandle = SDF_OpenDeviceNative();
            gDevResource = new DeviceResource();
            return gDevHandle;
        }
    }
```

---

### Test comment says "自动清理" but manually closes session
`examples/src/test/java/org/openhitls/sdf4j/examples/ResourceManagementTest.java:64-70`
```
/**
     * 自动清理
     */
    @Test
    public void testAutoCleanup() throws SDFException {
        SDF sdf2 = new SDF();
        System.out.println("--- 自动清理 ---");
        long deviceHandle = sdf2.SDF_OpenDevice();
        assertNotEquals("设备句柄有效", 0, deviceHandle);
        System.out.println("打开设备成功: handle=0x" + Long.toHexString(deviceHandle));

        long sessionHandle = sdf2.SDF_OpenSession(deviceHandle);
        assertNotEquals("会话句柄有效", 0, sessionHandle);
        System.out.println("打开会话成功: handle=0x" + Long.toHexString(sessionHandle));

        // 获取设备信息
        DeviceInfo info = sdf2.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息应该不为空", info);
        System.out.println("获取设备信息: " + info.getIssuerName());
        // 直接关闭设备，保证session也能被关闭
        sdf2.SDF_CloseDevice(deviceHandle);
```
**Issue**: The testAutoCleanup method's comment says it tests automatic cleanup, but the code manually closes the device on line 70 without closing the session first. The comment and implementation are misleading.
**Fix**:
```
/**
     * 自动清理 - 依赖 finalize() 方法自动清理资源
     */
    @Test
    public void testAutoCleanup() throws SDFException {
        SDF sdf2 = new SDF();
        System.out.println("--- 自动清理 ---");
        long deviceHandle = sdf2.SDF_OpenDevice();
        assertNotEquals("设备句柄有效", 0, deviceHandle);
        System.out.println("打开设备成功: handle=0x" + Long.toHexString(deviceHandle));

        long sessionHandle = sdf2.SDF_OpenSession(deviceHandle);
        assertNotEquals("会话句柄有效", 0, sessionHandle);
        System.out.println("打开会话成功: handle=0x" + Long.toHexString(sessionHandle));

        // 获取设备信息
        DeviceInfo info = sdf2.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息应该不为空", info);
        System.out.println("获取设备信息: " + info.getIssuerName());
        
        // 不手动关闭，依赖 finalize() 自动清理 (实际使用不建议)
        System.out.println("测试完成，资源将由 finalize() 自动清理\n");
```

---


---

## GEMINI Review

# Code Review: openHiTLS/sdf4j#11
**Reviewer**: GEMINI


## Critical

### Invalid free of JNI primitive array
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1296`
```
if (ret != SDR_OK) {
        if (output_buf != NULL) free(output_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }
```
**Issue**: In `JNI_SDF_AuthEncFinal`, if the native `SDF_AuthEncFinal` fails (returns non-SDR_OK), the code attempts to `free(output_buf)`. However, `output_buf` was obtained using `GetPrimitiveArrayCritical`, which may point to a pinned Java object or a copy managed by the JVM. Calling `free()` on it will corrupt the heap allocator and crash the JVM.
**Fix**:
```
if (ret != SDR_OK) {
        if (output_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, pucEncData, output_buf, JNI_ABORT);
        }
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }
```

---

### Double release of JNI primitive array
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1045`
```
if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
    if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
```
**Issue**: In `JNI_SDF_AuthDec`, the `aad_buf` (Additional Authenticated Data) is released twice using `ReleasePrimitiveArrayCritical` in the success cleanup path. This leads to undefined behavior, potentially corrupting JVM memory or crashing.
**Fix**:
```
if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
```

---


## High

### Thread-unsafe resource management
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:57`
```
private Long gDevHandle = null;
    private DeviceResource gDevResource = null;
    private java.util.Map<Long, SessionResource> gSessResource = new java.util.HashMap<>();
```
**Issue**: The `SDF` class introduces instance-level state (`gSessResource` HashMap, `gDevResource` object) to track sessions and keys. These collections are accessed and modified by multiple methods (`SDF_OpenSession`, `SDF_CloseSession`, `SDF_GenerateKey...`) without any synchronization. If a single `SDF` instance is shared across threads (common for hardware device wrappers), this will lead to `ConcurrentModificationException` or state corruption (e.g., tracking leaks, double-frees).
**Fix**:
```
private Long gDevHandle = null;
    private DeviceResource gDevResource = null;
    private java.util.Map<Long, SessionResource> gSessResource = new java.util.concurrent.ConcurrentHashMap<>();
    
    // Also ensure DeviceResource.sessions access is thread-safe, e.g., use Collections.synchronizedSet or ConcurrentHashMap.newKeySet()
```

---

### JVM Garbage Collector blocking
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:94`
```
jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    // ...
    LONG ret = g_sdf_functions.SDF_EncryptUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)data_buf,
        // ...
    );
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
```
**Issue**: The code uses `GetPrimitiveArrayCritical` to access byte arrays. This function temporarily disables the JVM Garbage Collector. Inside the critical region, the code calls `malloc` (which can lock) and, more importantly, calls the underlying SDF hardware library functions (`g_sdf_functions.SDF_EncryptUpdate`, etc.). If the hardware device or driver blocks or takes a significant amount of time (e.g., high load, hardware fault), the entire JVM GC will be paused, potentially causing the whole Java application to stall or become unresponsive.
**Fix**:
```
/* Prefer GetByteArrayRegion / SetByteArrayRegion for potentially blocking operations */
    jbyte *data_buf = (jbyte*)malloc(data_len);
    if (data_buf == NULL) { ... }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, data_buf);
    
    LONG ret = g_sdf_functions.SDF_EncryptUpdate(..., (BYTE*)data_buf, ...);
    
    free(data_buf);
```

---


## Medium

### Potential buffer overflow in Envelope Exchange
`sdf4j/src/main/native/src/sdf_jni_asymmetric.c:345`
```
ULONG out_len = in_cipher->L;
    ECCCipher *out_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + out_len);
```
**Issue**: `JNI_SDF_ExchangeDigitEnvelopeBaseOnECC` allocates the output buffer based solely on the input cipher length (`in_cipher->L`). If the operation results in a larger ciphertext (e.g., due to key wrapping overhead, padding, or format differences), `SDF_ExchangeDigitEnvelopeBaseOnECC` will write past the allocated buffer.
**Fix**:
```
/* Ensure buffer is large enough for potential expansion. 
       Consult SDF spec for maximum expansion. typically ECCref_MAX_CIPHER_LEN or similar constant */
    ULONG out_len = in_cipher->L + 128; // Add safety margin
    ECCCipher *out_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + out_len);
    out_cipher->L = out_len; // Tell native lib the max buffer size if possible, otherwise rely on sufficient alloc
```

---


---

## CODEX Review

# Code Review: openHiTLS/sdf4j#11
**Reviewer**: CODEX


## Critical

### Buffer overflow in ECC conversions (missing length clamps)
`sdf4j/src/main/native/src/type_conversion.c:300-449`
```
jsize len = (*env)->GetArrayLength(env, x_array);
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
...
jsize len = (*env)->GetArrayLength(env, y_array);
(*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_key->y);
```
**Issue**: The new code copies Java byte arrays directly into fixed-size ECC buffers without clamping to `ECCref_MAX_LEN`. If Java supplies longer arrays, this writes past the end of `ECCrefPublicKey`, `ECCSignature`, and `ECCCipher` fields, causing memory corruption.
**Fix**:
```
jsize len = (*env)->GetArrayLength(env, x_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);

len = (*env)->GetArrayLength(env, y_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_key->y);
```

---

### Buffer overflow in ECC private key conversion
`sdf4j/src/main/native/src/type_conversion.c:667-678`
```
jsize len = (*env)->GetArrayLength(env, k_array);
(*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
```
**Issue**: `java_to_native_ECCPrivateKey` copies the Java `k` array into a fixed-size `ECCrefPrivateKey.K` buffer without clamping. Oversized input overflows the native struct.
**Fix**:
```
memset(native_key, 0, sizeof(ECCrefPrivateKey));
jsize len = (*env)->GetArrayLength(env, k_array);
if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
(*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
```

---


## High

### Build break: undefined variable keyHandle
`sdf4j/src/main/native/src/sdf_jni_keygen.c:662-668`
```
SDF_LOG_EXIT("SDF_ImportKey", ret);
SDF_JNI_LOG("SDF_ImportKey: keyHandle=0x%lX", (unsigned long)keyHandle);
return (jlong)key_handle;
```
**Issue**: The new `SDF_ImportKey` JNI method logs `keyHandle`, but the variable is named `key_handle`. This is a compile error.
**Fix**:
```
SDF_LOG_EXIT("SDF_ImportKey", ret);
SDF_JNI_LOG("SDF_ImportKey: keyHandle=0x%lX", (unsigned long)key_handle);
return (jlong)key_handle;
```

---

### Double ReleasePrimitiveArrayCritical on aad_buf
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:960-967`
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
```
**Issue**: `aad_buf` is released twice in `JNI_SDF_AuthDec`, which can corrupt JNI state or crash the JVM.
**Fix**:
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
```

---

### Invalid free() of pinned JNI array
`sdf4j/src/main/native/src/sdf_jni_symmetric.c:1229-1236`
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
if (aad_buf != NULL) free(aad_buf);
```
**Issue**: `aad_buf` is obtained via `GetPrimitiveArrayCritical` and must be released via `ReleasePrimitiveArrayCritical`. Calling `free(aad_buf)` is undefined behavior and can crash.
**Fix**:
```
if (aad_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
}
```

---

### Invalid free() on GetPrimitiveArrayCritical buffers
`sdf4j/src/main/native/src/sdf_jni_util.c:405-448`
```
if (iv_buf == NULL) {
    free(key_buf);
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
if (enc_buf == NULL) {
    free(key_buf);
    if (iv_buf) free(iv_buf);
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
free(key_buf);
if (iv_buf) free(iv_buf);
free(enc_buf);
```
**Issue**: `key_buf`, `iv_buf`, and `enc_buf` are obtained via `GetPrimitiveArrayCritical` but are freed with `free(...)`. This is invalid and can cause memory corruption or JVM crashes, including in error paths.
**Fix**:
```
if (iv_buf == NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
if (enc_buf == NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
    throw_sdf_exception(env, 0x0100001C);
    return NULL;
}
...
(*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
if (iv_buf != NULL) {
    (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
}
(*env)->ReleasePrimitiveArrayCritical(env, encData, enc_buf, JNI_ABORT);
```

---


## Medium

### NullPointerException on CloseDevice when gDevHandle is null
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:181-184`
```
if (deviceHandle != gDevHandle) {
    return;
}
```
**Issue**: `deviceHandle != gDevHandle` auto-unboxes `gDevHandle`. If `SDF_CloseDevice` is called before `SDF_OpenDevice` or after a close, `gDevHandle` is null and this throws a NullPointerException instead of behaving as a no-op or clean error.
**Fix**:
```
if (gDevHandle == null || deviceHandle != gDevHandle.longValue()) {
    return;
}
```

---

### OpenSession can throw NPE when device resource is missing
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:216-221`
```
long handle = SDF_OpenSessionNative(deviceHandle);
// 创建 SessionResource 并注册到 gDevResource 和 gSessResource
SessionResource sessionResource = new SessionResource(handle);
gSessResource.put(handle, sessionResource);
```
**Issue**: `SessionResource` uses `gDevResource.addSession(...)` but `gDevResource` is only set in `SDF_OpenDevice`. Calling `SDF_OpenSession` without an open device (or after closing) now throws a NullPointerException instead of a controlled `SDFException`.
**Fix**:
```
if (gDevResource == null) {
    throw new SDFException(SDR_INARGERR);
}
long handle = SDF_OpenSessionNative(deviceHandle);
SessionResource sessionResource = new SessionResource(handle);
gSessResource.put(handle, sessionResource);
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the code
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
- Only include issues you've verified in the code
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
