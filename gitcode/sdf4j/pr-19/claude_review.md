# Code Review: openHiTLS/sdf4j#19
**Reviewer**: CLAUDE


## Medium

### JNI local reference leak in native_to_java_KeyAgreementResult
`sdf4j/src/main/native/src/type_conversion.c:633-653`
```
jobject native_to_java_KeyAgreementResult (JNIEnv *env, HANDLE agreement_handle,
                                    const ECCrefPublicKey *pub_key,
                                    const ECCrefPublicKey *tmp_pub_key)
{
    /* Convert ECCrefPublicKey to Java ECCPublicKey objects */
    jobject java_pub_key = native_to_java_ECCPublicKey(env, pub_key);
    if (java_pub_key == NULL) {
        return NULL;
    }

    jobject java_tmp_pub_key = native_to_java_ECCPublicKey(env, tmp_pub_key);
    if (java_tmp_pub_key == NULL) {
        return NULL;  // LEAK: java_pub_key not deleted
    }
```
**Issue**: When java_tmp_pub_key conversion fails (returns NULL), the function returns NULL without deleting the local reference to java_pub_key. While local references are automatically freed when the native method returns, this is bad practice and could cause issues in long-running native methods with many conversions.
**Fix**:
```
jobject native_to_java_KeyAgreementResult (JNIEnv *env, HANDLE agreement_handle,
                                    const ECCrefPublicKey *pub_key,
                                    const ECCrefPublicKey *tmp_pub_key)
{
    /* Convert ECCrefPublicKey to Java ECCPublicKey objects */
    jobject java_pub_key = native_to_java_ECCPublicKey(env, pub_key);
    if (java_pub_key == NULL) {
        return NULL;
    }

    jobject java_tmp_pub_key = native_to_java_ECCPublicKey(env, tmp_pub_key);
    if (java_tmp_pub_key == NULL) {
        (*env)->DeleteLocalRef(env, java_pub_key);
        return NULL;
    }
```

---


## Low

### Misleading use of Assume.assumeTrue with false condition
`sdf4j/src/test/java/org/openhitls/sdf4j/KeyManagementTest.java:719-723`
```
try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取私钥权限不支持");
                    Assume.assumeTrue("获取私钥权限不需要或不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }
```
**Issue**: The code uses `Assume.assumeTrue("获取私钥权限不需要或不支持，继续测试...", false)` which always causes the test to be skipped. The message says "continue testing" but passing false means "don't continue - skip the test". This is confusing and should use the actual condition.
**Fix**:
```
try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取私钥权限不支持");
                    Assume.assumeTrue("获取私钥权限不支持，跳过测试", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }
```

---

### Inconsistent struct initialization style
`sdf4j/src/main/native/src/sdf_jni_keygen.c:355-357`
```
/* 公钥和临时公钥由设备生成 */
    ECCrefPublicKey sponsor_pub_key = {0};
    ECCrefPublicKey sponsor_tmp_pub_key = {0};
```
**Issue**: The code uses `= {0}` for initializing ECCrefPublicKey structures, which is correct but inconsistent with the earlier pattern using `memset(&sponsor_tmp_pub_key, 0, sizeof(ECCrefPublicKey))`. While both work, consistency is preferred for maintainability.
**Fix**:
```
/* 公钥和临时公钥由设备生成 */
    ECCrefPublicKey sponsor_pub_key;
    ECCrefPublicKey sponsor_tmp_pub_key;
    memset(&sponsor_pub_key, 0, sizeof(ECCrefPublicKey));
    memset(&sponsor_tmp_pub_key, 0, sizeof(ECCrefPublicKey));
```

---
