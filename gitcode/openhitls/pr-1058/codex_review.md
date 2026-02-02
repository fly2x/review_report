# Code Review: openhitls/openhitls#1058
**Reviewer**: CODEX


## High

### Unverified ISO19790 certification claim
`README.md:8`
```
The architecture of openHiTLS is highly modular, and openHiTLS can be configured in modules and features. The RAM/ROM footprint depends on the features selected. It provides the optimal performance optimization for cryptographic algorithms. Currently, 5 components and cryptographic algorithms are configured, ISO19790 certified, and the performance optimization of ShangMi cryptographic algorithms on ARM, x86 is ready. More architectures and features are to be planned.
```
**Issue**: The new text asserts “ISO19790 certified,” which is a compliance/legal claim not supported by any certification artifacts in this repo (only an ISO19790 provider implementation exists). This can mislead users and conflicts with the release notes wording.
**Fix**:
```
The architecture of openHiTLS is highly modular, and openHiTLS can be configured in modules and features. The RAM/ROM footprint depends on the features selected. It provides the optimal performance optimization for cryptographic algorithms. Currently, 5 components and cryptographic algorithms are configured, with ISO19790 provider support, and the performance optimization of ShangMi cryptographic algorithms on ARM, x86 is ready. More architectures and features are to be planned.
```

---

### ISO19790认证表述缺乏依据
`README-zh.md:8`
```
openHiTLS架构高度模块化，可通过模块和特性配置。RAM/ROM尺寸取决于所选的特性。openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```
**Issue**: 新增“已经通过ISO19790认证”属于合规/认证声明，但仓库中未提供任何认证材料，仅有ISO19790 Provider实现，容易误导用户且与发行声明中的表述不一致。
**Fix**:
```
openHiTLS架构高度模块化，可通过模块和特性配置。RAM/ROM尺寸取决于所选的特性。openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，支持ISO19790 Provider，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```

---


## Medium

### STM32F407 build configuration claim not backed by repo
`docs/en/1_Release Notes.md:63`
```
* STM32F407 build configuration
```
**Issue**: The release notes claim “STM32F407 build configuration,” but there is no STM32F407-specific toolchain/config in `config/toolchain` (only generic `arm-none-eabi` exists). This misleads users looking for a concrete STM32F407 config.
**Fix**:
```
### Performance and Platform
* SM2/SM3 ARMv7 assembly optimization
* Darwin/macOS cross-platform support
```

---

### STM32F407编译配置表述与仓库不符
`docs/zh/1_发行声明.md:63`
```
* 新增STM32F407编译配置
```
**Issue**: 发行声明新增“STM32F407编译配置”，但仓库内无STM32F407专用toolchain/config（仅有通用arm-none-eabi），会误导用户。
**Fix**:
```
### 性能与平台
* SM2/SM3 ARMv7汇编优化
* 新增Darwin/macOS跨平台支持
```

---


## Low

### Deleting Change History breaks docs index link
`docs/en/6_Appendix/2_Change History.md:1-5`
```
# Change History

| Date      | Issue             | Change Description                        |
| ---------- | ----------------- | -------------------------------- |
| 2024-01-25| The first release of openHiTLS.| First release of version alpha.|
```
**Issue**: This file was removed, but `docs/index/index.md` still links to it, resulting in a broken “Change History” link.
**Fix**:
```
# Change History

This page has moved to [Release Notes](../1_Release%20Notes.md).
```

---

### 删除修订记录导致目录索引链接失效
`docs/zh/6_附录/2_修订记录.md:1-7`
```
# 修订记录

| 日期       | 版本              | 变更说明                         |
| ---------- | ----------------- | -------------------------------- |
| 2024/5/15 | openHiTLS首个版本 | 首次发布alpha版本 |
```
**Issue**: 删除该文件后，`docs/index/index.md`中的“修订记录”链接失效，需要保留占位或同步更新索引。
**Fix**:
```
# 修订记录

该页面已移至 [发行声明](../1_发行声明.md)。
```

---
