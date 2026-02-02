# Code Review: openhitls/openhitls#1058
**Reviewer**: GEMINI


## Low

### Typo in Chinese text (extra space)
`README-zh.md:5`
```
欢迎访问openHiTLS代码仓，该代码仓的项目官网是openHiTLS社区<https://openhitls.net>，openHiTLS的目标是提供高效、敏捷的全场景开源密码学开发套件。openHiTLS已支持通 用的标准密码算法、(D)TLS、(D)TLCP等安全通信协议，更多特性待规划。
```
**Issue**: There is an unnecessary space in the word "通用" (universal/general).
**Fix**:
```
欢迎访问openHiTLS代码仓，该代码仓的项目官网是openHiTLS社区<https://openhitls.net>，openHiTLS的目标是提供高效、敏捷的全场景开源密码学开发套件。openHiTLS已支持通用的标准密码算法、(D)TLS、(D)TLCP等安全通信协议，更多特性待规划。
```

---

### Punctuation spacing issue
`README-zh.md:103`
```
openHiTLS依赖于Secure C（libboundscheck），**现已由 configure.py 脚本自动管理** 。
```
**Issue**: There is an unnecessary space before the period at the end of the sentence.
**Fix**:
```
openHiTLS依赖于Secure C（libboundscheck），**现已由 configure.py 脚本自动管理**。
```

---

### Typo in link text (extra space)
`README-zh.md:132`
```
在Linux系统中进行构建与安装时，可参考[构建安装指导](docs/zh/4_使用指南/1_构建及 安装指导.md)
```
**Issue**: There is an unnecessary space in the link text "构建及安装指导".
**Fix**:
```
在Linux系统中进行构建与安装时，可参考[构建安装指导](docs/zh/4_使用指南/1_构建及安装指导.md)
```

---

### Typo in text (extra space)
`README-zh.md:160`
```
如果您有意为openHiTLS社区做贡献，请先在[CLA签署](https://cla.openhitls.net)平台 上完成CLA签署。
```
**Issue**: There is an unnecessary space in the phrase "平台上".
**Fix**:
```
如果您有意为openHiTLS社区做贡献，请先在[CLA签署](https://cla.openhitls.net)平台上完成CLA签署。
```

---

### Multiple typos in overview text (extra spaces)
`docs/zh/2_关键特性.md:3`
```
openHiTLS的目标是提供高效敏捷的全场景密码学套件，通过模块分层特性分级的弹性架构 ，实现特性按需选择和扩展，支撑全场景应用满足RAM/ROM内存、计算性能、特性满足度等 不同需求；当前已支持密码算法功能以及TLS、DTLS、TLCP安全通信协议功能，商密算法支 持基于ARM、x86指令的性能优化，**并支持混合密钥交换（Hybrid Key Exchange）和后量 子密码算法**，更多特性待规划、欢迎参与共建。
```
**Issue**: There are unnecessary spaces in "等不同", "支持", and "后量子".
**Fix**:
```
openHiTLS的目标是提供高效敏捷的全场景密码学套件，通过模块分层特性分级的弹性架构，实现特性按需选择和扩展，支撑全场景应用满足RAM/ROM内存、计算性能、特性满足度等不同需求；当前已支持密码算法功能以及TLS、DTLS、TLCP安全通信协议功能，商密算法支持基于ARM、x86指令的性能优化，**并支持混合密钥交换（Hybrid Key Exchange）和后量子密码算法**，更多特性待规划、欢迎参与共建。
```

---
