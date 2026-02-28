# Code Review: openHiTLS/sdf4j#19
**Reviewer**: GEMINI


## High

### HSM Resource Leak on KeyAgreementResult object creation failure
`sdf4j/src/main/native/src/sdf_jni_keygen.c:360-365`
```
/* 创建 KeyAgreementResult 对象 */
    jobject result = native_to_java_KeyAgreementResult (env, agreement_handle,
                                                 &sponsor_pub_key, &sponsor_tmp_pub_key);
    if (result == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Failed to create KeyAgreementResult");
        return NULL;
    }
```
**Issue**: In `JNI_SDF_GenerateAgreementDataWithECC`, if the `native_to_java_KeyAgreementResult` function fails (returns NULL due to memory/JNI errors), the `agreement_handle` created in the HSM via `SDF_GenerateAgreementDataWithECC` is never destroyed. This leaks handles directly on the hardware device. It must be explicitly destroyed before throwing the exception, similar to how `key_handle` is cleaned up in `JNI_SDF_GenerateAgreementDataAndKeyWithECC`.
**Fix**:
```
/* 创建 KeyAgreementResult 对象 */
    jobject result = native_to_java_KeyAgreementResult (env, agreement_handle,
                                                 &sponsor_pub_key, &sponsor_tmp_pub_key);
    if (result == NULL) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)agreement_handle);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Failed to create KeyAgreementResult");
        return NULL;
    }
```

---


## Medium

### Missing Java wrapper for SDF_GenerateAgreementDataWithECC leads to untracked agreement handle
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:504-508`
```
public native KeyAgreementResult SDF_GenerateAgreementDataWithECC(long sessionHandle, int keyIndex, int keyBits,
            byte[] sponsorID) throws SDFException;
```
**Issue**: Unlike `SDF_GenerateKeyWithECC` and `SDF_GenerateAgreementDataAndKeyWithECC`, which were correctly wrapped in this PR to register their resulting keys with `SessionResource`, `SDF_GenerateAgreementDataWithECC` was left as a `native` method. As a result, its returned `agreementHandle` is not tracked and will not be automatically destroyed when the session is closed, potentially leading to a resource leak on the HSM.
**Fix**:
```
public KeyAgreementResult SDF_GenerateAgreementDataWithECC(long sessionHandle, int keyIndex, int keyBits,
            byte[] sponsorID) throws SDFException {
        KeyAgreementResult result = SDF_GenerateAgreementDataWithECC_Native(sessionHandle, keyIndex, keyBits, sponsorID);
        SessionResource sessionResource = gSessResource.get(sessionHandle);
        if (sessionResource != null) {
            sessionResource.addKey(result.getAgreementHandle());
        }
        return result;
    }

    private native KeyAgreementResult SDF_GenerateAgreementDataWithECC_Native(long sessionHandle, int keyIndex, int keyBits,
            byte[] sponsorID) throws SDFException;
```

---

### Incorrect native method name registration for SDF_GenerateAgreementDataWithECC
`sdf4j/src/main/native/src/sdf_jni_register.c:45`
```
{"SDF_GenerateAgreementDataWithECC", "(JII[B)Lorg/openhitls/sdf4j/types/KeyAgreementResult;", (void*)JNI_SDF_GenerateAgreementDataWithECC},
```
**Issue**: Due to the missing Java wrapper in `SDF.java` (described in the previous issue), the JNI method registration for `SDF_GenerateAgreementDataWithECC` was not updated to `_Native`. It must be updated to match the required `_Native` suffix to enable the correct wrapping and tracking of the agreement handle.
**Fix**:
```
{"SDF_GenerateAgreementDataWithECC_Native", "(JII[B)Lorg/openhitls/sdf4j/types/KeyAgreementResult;", (void*)JNI_SDF_GenerateAgreementDataWithECC},
```

---
