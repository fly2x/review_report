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
