# Code Review: openHiTLS/sdf4j#16
**Reviewer**: CODEX


## High

### Optional KEK failures now skip the entire test class in `@Before`
`examples/src/test/java/org/openhitls/sdf4j/examples/SymmetricOperationTest.java:94-97`
```
if (e.getErrorCode() == org.openhitls.sdf4j.constants.ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] KEK 权限获取功能不支持");
    Assume.assumeTrue("[跳过] KEK 权限获取功能不支持", false);
}
...
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] SDF_GenerateKeyWithKEK 功能不支持，跳过需要密钥的测试");
    Assume.assumeTrue("SDF_GenerateKeyWithKEK 功能不支持，跳过需要密钥的测试", false);
    keyAvailable = false;
    return;
}
```
**Issue**: `Assume.assumeTrue(false)` is called inside `setUp()`. In JUnit 4 this aborts each test before execution, including tests that do not depend on KEK/session-key setup (for example external-key API tests). This regresses coverage and can hide real failures.
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    // KEK access control is optional on some devices; continue.
    kekAccessRightObtained = false;
} else {
    throw e;
}
...
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT || e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
    // Only key-dependent tests should skip via assumeKeyAvailable().
    keyAvailable = false;
    return;
}
throw new SDFException(e.getErrorCode(), "setUp: 密钥生成失败 - " + e.getMessage());
```

---


## Medium

### Treating unsupported access-right API as full test skip drops valid internal-sign coverage
`examples/src/test/java/org/openhitls/sdf4j/examples/AsymmetricOperationTest.java:349-352`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥使用权限功能未实现");
    Assume.assumeTrue("获取私钥使用权限功能未实现", false);
}
```
**Issue**: `SDF_GetPrivateKeyAccessRight` can be unsupported on some devices while internal signing/verifying still works. The new logic now skips the whole test immediately, so a working `SDF_InternalSign_ECC/SDF_InternalVerify_ECC` path is never exercised.
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    // Some devices do not require/implement explicit access-right calls.
    // Continue test; release is still guarded by accessRightObtained.
} else {
    System.out.println(e.getMessage());
    throw e;
}
```

---

### Optional validation step now converts a successful key-generation test into “skipped”
`examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java:247-250`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
}
```
**Issue**: This catch block is inside `testGenerateKeyWithIPK_ECC` after key generation assertions already passed. If symmetric encrypt/decrypt is unsupported, the test is marked skipped, which hides successful verification of `SDF_GenerateKeyWithIPK_ECC` and weakens regression detection.
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    // Keep test result based on key-generation assertions; skip only this sub-check.
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
} else {
    System.out.println(e.getMessage());
    throw e;
}
```

---


## Low

### `assertNotNull` used on primitive-returning getters creates no-op assertions
`sdf4j/src/test/java/org/openhitls/sdf4j/DeviceManagementTest.java:46-48`
```
assertNotNull("设备版本不应为null", info.getDeviceVersion());
assertNotNull("标准版本不应为null", info.getStandardVersion());
assertNotNull("缓冲区大小不应为null", info.getBufferSize());
```
**Issue**: `getDeviceVersion()`, `getStandardVersion()`, and `getBufferSize()` return primitives (`long`). `assertNotNull` on primitives always passes due autoboxing, so these checks do not validate anything.
**Fix**:
```
assertTrue("设备版本应为非负值", info.getDeviceVersion() >= 0);
assertTrue("标准版本应为非负值", info.getStandardVersion() >= 0);
assertTrue("缓冲区大小应大于0", info.getBufferSize() > 0);
```

---
