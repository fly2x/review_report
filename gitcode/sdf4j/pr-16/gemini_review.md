# Code Review: openHiTLS/sdf4j#16
**Reviewer**: GEMINI


## Medium

### Resource leak in exception handling test
`sdf4j/src/test/java/org/openhitls/sdf4j/ResourceManagementTest.java:102-118`
```
long deviceHandle = sdf3.SDF_OpenDevice();
        try {
            // 打开设备
            assertNotEquals("设备句柄有效", 0, deviceHandle);

            long sessionHandle = sdf3.SDF_OpenSession(deviceHandle);
            assertNotEquals("会话句柄有效", 0, sessionHandle);

            // 获取设备信息
            DeviceInfo info = sdf3.SDF_GetDeviceInfo(sessionHandle);
            assertNotNull("设备信息应该不为空", info);

            // 模拟异常情况
            throw new RuntimeException("模拟异常");
        } catch (RuntimeException e) {
            // 直接关闭设备，保证session也能被关闭
            sdf3.SDF_CloseDevice(deviceHandle);
        }
```
**Issue**: In `testExceptionHandling`, if `sdf3.SDF_OpenSession(deviceHandle)` throws an `SDFException`, the execution flow exits the method immediately because `SDFException` is not caught by `catch (RuntimeException e)`. Consequently, `sdf3.SDF_CloseDevice(deviceHandle)` in the catch block is never executed, causing a resource leak of `deviceHandle`.
**Fix**:
```
long deviceHandle = sdf3.SDF_OpenDevice();
        try {
            // 打开设备
            assertNotEquals("设备句柄有效", 0, deviceHandle);

            long sessionHandle = sdf3.SDF_OpenSession(deviceHandle);
            assertNotEquals("会话句柄有效", 0, sessionHandle);

            // 获取设备信息
            DeviceInfo info = sdf3.SDF_GetDeviceInfo(sessionHandle);
            assertNotNull("设备信息应该不为空", info);

            // 模拟异常情况
            throw new RuntimeException("模拟异常");
        } catch (RuntimeException e) {
            // 捕获运行时异常
        } finally {
            // 确保设备总是被关闭
            try {
                sdf3.SDF_CloseDevice(deviceHandle);
            } catch (SDFException e) {
                // 忽略关闭时的错误
            }
        }
```

---


## Low

### Redundant null checks on primitive types
`sdf4j/src/test/java/org/openhitls/sdf4j/DeviceManagementTest.java:45-48`
```
assertNotNull("设备序列号不应为null", info.getDeviceSerial());
        assertNotNull("设备版本不应为null", info.getDeviceVersion());
        assertNotNull("标准版本不应为null", info.getStandardVersion());
        assertNotNull("缓冲区大小不应为null", info.getBufferSize());
```
**Issue**: The test asserts `assertNotNull` on `getDeviceVersion()`, `getStandardVersion()`, and `getBufferSize()`. These methods return `long` (primitive), which is auto-boxed to `Long`. Since a primitive `long` can never be null, the boxed `Long` object is never null, making these assertions redundant and ineffective.
**Fix**:
```
assertNotNull("设备序列号不应为null", info.getDeviceSerial());
        assertTrue("设备版本应大于0", info.getDeviceVersion() > 0);
        assertTrue("标准版本应大于0", info.getStandardVersion() > 0);
        assertTrue("缓冲区大小应大于0", info.getBufferSize() > 0);
```

---
