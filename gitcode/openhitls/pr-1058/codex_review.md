# Code Review: openhitls/openhitls#1058
**Reviewer**: CODEX


## Medium

### Unsubstantiated ISO19790 certification claim
`README.md:8`
```
The architecture of openHiTLS is highly modular, and openHiTLS can be configured in modules and features. The RAM/ROM footprint depends on the features selected. It provides the optimal performance optimization for cryptographic algorithms. Currently, 5 components and cryptographic algorithms are configured, ISO19790 certified, and the performance optimization of ShangMi cryptographic algorithms on ARM, x86 is ready. More architectures and features are to be planned.
```
**Issue**: The README states "ISO19790 certified" but the repository only documents an ISO19790 provider feature; this reads like a formal certification claim and is misleading without evidence.
**Fix**:
```
The architecture of openHiTLS is highly modular, and openHiTLS can be configured in modules and features. The RAM/ROM footprint depends on the features selected. It provides the optimal performance optimization for cryptographic algorithms. Currently, 5 components and cryptographic algorithms are configured, ISO19790 provider support is available, and the performance optimization of ShangMi cryptographic algorithms on ARM, x86 is ready. More architectures and features are to be planned.
```

---

### ISO19790认证表述不准确
`README-zh.md:8`
```
openHiTLS架构高度模块化，可通过模块和特性配置。RAM/ROM尺寸取决于所选的特性。openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```
**Issue**: “已经通过ISO19790认证”属于正式认证声明，但文档仅提到ISO19790 Provider特性，缺少认证依据，容易误导。
**Fix**:
```
openHiTLS架构高度模块化，可通过模块和特性配置。RAM/ROM尺寸取决于所选的特性。openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已提供ISO19790 Provider支持，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```

---


## Low

### Incorrect terminology for Privacy Pass
`README.md:45`
```
- Auth authentication component provides authentication functions. Currently, it provides publicly token authentication, TOTP/HOTP, SPAKE2+.
```
**Issue**: "publicly token authentication" is a malformed term and conflicts with the "Privacy Pass" naming used elsewhere, which can confuse readers.
**Fix**:
```
- Auth authentication component provides authentication functions. Currently, it provides Privacy Pass token authentication, TOTP/HOTP, SPAKE2+.
```

---

### Paillier算法拼写错误
`README-zh.md:20`
```
- 传统非对称算法：RSA，RSA-Bind，DSA，ECDSA，ECDH，DH，SM2，SM9，Pailler，ElGamal；
```
**Issue**: “Pailler”拼写错误，应为“Paillier”，否则影响读者检索和理解算法名称。
**Fix**:
```
- 传统非对称算法：RSA，RSA-Bind，DSA，ECDSA，ECDH，DH，SM2，SM9，Paillier，ElGamal；
```

---

### Privacy Pass术语不一致
`README-zh.md:45`
```
- Auth认证组件提供了认证功能，当前提供publicly token认证功能，TOTP/HOTP，SPAKE2+等协议；
```
**Issue**: “publicly token认证功能”表述不正确且与上文“Privacy Pass”不一致，容易引起误解。
**Fix**:
```
- Auth认证组件提供了认证功能，当前提供Privacy Pass 令牌认证功能，TOTP/HOTP，SPAKE2+等协议；
```

---

### Paillier算法拼写错误
`docs/zh/1_发行声明.md:35`
```
* Pailler算法支持同态运算
```
**Issue**: “Pailler”拼写错误，应为“Paillier”，否则算法名称不准确。
**Fix**:
```
* Paillier算法支持同态运算
```

---

### Buffer拼写不一致
`docs/zh/1_发行声明.md:40`
```
* 支持从Buff加载证书
```
**Issue**: “Buff”是拼写错误/缩写不规范，与后文“Buffer”不一致，影响文档专业性。
**Fix**:
```
* 支持从Buffer加载证书
```

---

### PKI拼写错误
`docs/zh/1_发行声明.md:56`
```
* 证书和PKIL: req，x509，pkcs7，pkcs12，crl ...
```
**Issue**: “PKIL”拼写错误，应为“PKI”，否则会误导读者。
**Fix**:
```
* 证书和PKI: req，x509，pkcs7，pkcs12，crl ...
```

---
