# Code Review: openHiTLS/sdf4j#16
**Reviewer**: CLAUDE


## Low

### Inconsistent exception handling pattern
`examples/src/test/java/org/openhitls/sdf4j/examples/HashOperationTest.java:169-171`
```
} catch (SDFException e) {
    if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
        System.out.println("[跳过] 无法导出 SM2 公钥: " + e.getMessage() + "\n");
        return;
    }
```
**Issue**: In testSM3WithUserIDAndPublicKey(), when SDF_ExportSignPublicKey_ECC throws SDR_NOTSUPPORT, the method returns without using Assume.assumeTrue(). This is inconsistent with the pattern used in other test methods where Assume.assumeTrue() is called for SDR_NOTSUPPORT. This means the test will pass instead of being skipped.
**Fix**:
```
} catch (SDFException e) {
    if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
        System.out.println("[跳过] 无法导出 SM2 公钥: " + e.getMessage());
        Assume.assumeTrue("无法导出 SM2 公钥", false);
    }
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/HashOperationTest.java:463-465`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不支持，继续测试...", false);
```
**Issue**: In testInternalKeyHMAC(), the Assume.assumeTrue() message doesn't match the pattern. The message "获取私钥权限不支持，继续测试..." is not a proper condition description for Assume.assumeTrue().
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不支持", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java:157-158`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不支持，继续测试...", false);
```
**Issue**: In testGenerateKeyWithIPK_ECC(), the Assume.assumeTrue() message is inconsistent - it has Chinese text mixed with "..." and doesn't follow the pattern of other similar calls.
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不支持", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java:207-208`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
```
**Issue**: In testGenerateKeyWithIPK_ECC(), the Assume.assumeTrue() message has leading spaces which is inconsistent with other calls.
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
    Assume.assumeTrue("加密功能未实现，跳过可用性验证", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java:308-309`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
```
**Issue**: In testGenerateKeyWithEPK_ECC(), the Assume.assumeTrue() message has leading spaces.
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
    Assume.assumeTrue("加密功能未实现，跳过可用性验证", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java:359-360`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不需要或不支持，继续测试...", false);
```
**Issue**: In testImportKeyWithISK_ECC(), the Assume.assumeTrue() message is inconsistent with Chinese text mixed with "..."
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不支持", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java:403-404`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
```
**Issue**: In testImportKeyWithISK_ECC(), the Assume.assumeTrue() message has leading spaces.
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
    Assume.assumeTrue("加密功能未实现，跳过可用性验证", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java:464-465`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不需要或不支持，继续测试...", false);
```
**Issue**: In testGenerateAgreementDataWithECC(), the Assume.assumeTrue() message has Chinese text mixed with "..."
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] 获取私钥权限不支持");
    Assume.assumeTrue("获取私钥权限不支持", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/SymmetricOperationTest.java:31-32`
```
if (e.getErrorCode() == org.openhitls.sdf4j.constants.ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] KEK 权限获取功能不支持");
    Assume.assumeTrue("[跳过] KEK 权限获取功能不支持", false);
```
**Issue**: In setUp(), the Assume.assumeTrue() message has Chinese text mixed with "..." which doesn't follow the pattern.
**Fix**:
```
if (e.getErrorCode() == org.openhitls.sdf4j.constants.ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] KEK 权限获取功能不支持");
    Assume.assumeTrue("KEK 权限获取功能不支持", false);
```

---

### Inconsistent exception handling with malformed message
`examples/src/test/java/org/openhitls/sdf4j/examples/SymmetricOperationTest.java:49-50`
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] SDF_GenerateKeyWithKEK 功能不支持，跳过需要密钥的测试");
    Assume.assumeTrue("SDF_GenerateKeyWithKEK 功能不支持，跳过需要密钥的测试", false);
```
**Issue**: In setUp(), the Assume.assumeTrue() message has Chinese text mixed with "..."
**Fix**:
```
if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
    System.out.println("[跳过] SDF_GenerateKeyWithKEK 功能不支持，跳过需要密钥的测试");
    Assume.assumeTrue("SDF_GenerateKeyWithKEK 功能不支持", false);
```

---
