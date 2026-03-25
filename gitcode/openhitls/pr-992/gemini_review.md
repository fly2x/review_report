# Code Review: openHiTLS/openhitls#992
**Reviewer**: GEMINI


## Critical

### Buffer overflow due to integer underflow in destination size calculation for memcpy_s
`crypto/hbs/hss/src/hss_core.c:237-239`
```
(void)memcpy_s(output->data, *output->len, parentSig, parentSigLen);
    (void)memcpy_s(output->data + parentSigLen, *output->len - parentSigLen, childPubKey, LMS_PUBKEY_LEN);
    *output->len = parentSigLen + LMS_PUBKEY_LEN;
```
**Issue**: In `HssGenerateSignedPubKey`, `memcpy_s` is used to copy `parentSig` and `childPubKey` into `output->data` without verifying that `*output->len` is sufficiently large. If `*output->len < parentSigLen`, the expression `*output->len - parentSigLen` will result in an integer underflow, yielding a massive `destMax` value for the second `memcpy_s`. Furthermore, `output->data + parentSigLen` will point to out-of-bounds memory where 56 bytes (`LMS_PUBKEY_LEN`) will be written, leading to a severe buffer overflow. The return values of `memcpy_s` are also unsafely ignored.
**Fix**:
```
if (*output->len < parentSigLen + LMS_PUBKEY_LEN) {
        BSL_SAL_Free(parentSig);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(output->data, *output->len, parentSig, parentSigLen) != 0) {
        BSL_SAL_Free(parentSig);
        return CRYPT_HSS_SIGN_FAIL;
    }
    if (memcpy_s(output->data + parentSigLen, *output->len - parentSigLen, childPubKey, LMS_PUBKEY_LEN) != 0) {
        BSL_SAL_Free(parentSig);
        return CRYPT_HSS_SIGN_FAIL;
    }
    *output->len = parentSigLen + LMS_PUBKEY_LEN;
```

---


## High

### Unsafe memory function memset used instead of memset_s
`crypto/hbs/hss/src/hss_tree.c:268`
```
memset(&parsed, 0, sizeof(parsed));
```
**Issue**: The code uses the unsafe `memset` function instead of the required `memset_s` from `libboundscheck` as per project coding conventions.
**Fix**:
```
(void)memset_s(&parsed, sizeof(parsed), 0, sizeof(parsed));
```

---

### Unsafe memory function memset used instead of memset_s
`crypto/hbs/hss/src/hss_utils.c:47`
```
memset(para, 0, sizeof(HSS_Para));
```
**Issue**: The code uses the unsafe `memset` function instead of the required `memset_s` from `libboundscheck` as per project coding conventions.
**Fix**:
```
(void)memset_s(para, sizeof(HSS_Para), 0, sizeof(HSS_Para));
```

---

### Unsafe memory function memset used instead of memset_s
`crypto/hbs/hss/src/hss_utils.c:141`
```
memset(compressed, 0, HSS_COMPRESSED_PARAMS_LEN);
```
**Issue**: The code uses the unsafe `memset` function instead of the required `memset_s` from `libboundscheck` as per project coding conventions.
**Fix**:
```
(void)memset_s(compressed, HSS_COMPRESSED_PARAMS_LEN, 0, HSS_COMPRESSED_PARAMS_LEN);
```

---

### Unsafe memory function memset used instead of memset_s
`crypto/hbs/lms/src/lms_hash.c:444`
```
memset(para, 0, sizeof(LMS_Para));
```
**Issue**: The code uses the unsafe `memset` function instead of the required `memset_s` from `libboundscheck` as per project coding conventions.
**Fix**:
```
(void)memset_s(para, sizeof(LMS_Para), 0, sizeof(LMS_Para));
```

---
