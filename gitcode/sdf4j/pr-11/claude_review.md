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
