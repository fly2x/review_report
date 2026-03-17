# Code Review: openHiTLS/openhitls-rs#2
**Reviewer**: GEMINI


## Critical

### AEAD MAC leaked in error message and timing attack vulnerability
`openhitls/src/aes.rs:204-206`
```
if calculated_tag != tag {
                return Err(format!("AEAD Tag mismatch! Expected {:?}, Got {:?}", tag, calculated_tag));
            }
```
**Issue**: In `aes_decrypt`, the calculated AEAD tag is compared using the non-constant time `!=` operator, enabling timing attacks (CWE-208). Furthermore, if the tags do not match, the application leaks the valid `calculated_tag` in the error message string, allowing an attacker to trivially forge the MAC for any modified ciphertext by simply reading the error message (CWE-209).
**Fix**:
```
if calculated_tag.len() != tag.len() {
                return Err("AEAD Tag mismatch!".to_string());
            }
            let mut diff = 0u8;
            for (a, b) in calculated_tag.iter().zip(tag.iter()) {
                diff |= a ^ b;
            }
            if diff != 0 {
                return Err("AEAD Tag mismatch!".to_string());
            }
```

---


## High

### Memory leak of ECC context on sign failure
`openhitls/src/ecdsa.rs:26-28`
```
if ret != 0 {
        return Err(format!("Sign failed: 0x{:x}", ret));
    }
```
**Issue**: In `ecdsa_sign`, if `pkey_sign` fails (`ret != 0`), the function immediately returns an error without freeing the allocated `key_ctx`. This causes a memory leak of the unmanaged C ECC context.
**Fix**:
```
if ret != 0 {
        free_ecc_pkey(key_ctx);
        return Err(format!("Sign failed: 0x{:x}", ret));
    }
```

---

### Potential Use-After-Free due to dropped local vectors
`openhitls/src/ecc_pkey_gen.rs:111-135`
```
if !pub_key.is_empty() {
        let mut pub_buf = pub_key.to_vec();
        let mut pub_key_wrapper = CRYPT_EAL_PkeyPub::new(ctx_id);
        pub_key_wrapper.setter(pub_buf.as_mut_ptr(), pub_buf.len() as u32);

        let ret = ecc_set_pub(ctx, &mut pub_key_wrapper);
        if ret != 0 {
            println!("Failed to set ECC public key: {}", ret);
            ecc_free_ctx(ctx);
            return std::ptr::null_mut();
        }
    }

    if !prv_key.is_empty() {
        let mut prv_buf = prv_key.to_vec();
        let mut prv_key_wrapper = CRYPT_EAL_PkeyPrv::new(ctx_id);
        prv_key_wrapper.setter(prv_buf.as_mut_ptr(), prv_buf.len() as u32);

        let ret = ecc_set_prv(ctx, &mut prv_key_wrapper);
        if ret != 0 {
            println!("Failed to set ECC private key: {}", ret);
            ecc_free_ctx(ctx);
            return std::ptr::null_mut();
        }
    }
```
**Issue**: In `key_to_ctx`, `pub_key` and `prv_key` are copied into local vectors (`pub_buf` and `prv_buf`), and their data pointers are set into the ECC context via `ecc_set_pub`/`ecc_set_prv`. However, these vectors are dropped at the end of their respective `if` scopes. If the C library retains these pointers, the returned `ctx` will contain dangling pointers, causing a Use-After-Free. Bypassing `.to_vec()` and directly using the caller's slice pointers is both safer (since the caller's slices live longer) and more efficient.
**Fix**:
```
if !pub_key.is_empty() {
        let mut pub_key_wrapper = CRYPT_EAL_PkeyPub::new(ctx_id);
        pub_key_wrapper.setter(pub_key.as_ptr() as *mut u8, pub_key.len() as u32);

        let ret = ecc_set_pub(ctx, &mut pub_key_wrapper);
        if ret != 0 {
            println!("Failed to set ECC public key: {}", ret);
            ecc_free_ctx(ctx);
            return std::ptr::null_mut();
        }
    }

    if !prv_key.is_empty() {
        let mut prv_key_wrapper = CRYPT_EAL_PkeyPrv::new(ctx_id);
        prv_key_wrapper.setter(prv_key.as_ptr() as *mut u8, prv_key.len() as u32);

        let ret = ecc_set_prv(ctx, &mut prv_key_wrapper);
        if ret != 0 {
            println!("Failed to set ECC private key: {}", ret);
            ecc_free_ctx(ctx);
            return std::ptr::null_mut();
        }
    }
```

---


## Medium

### Compilation error due to missing unsafe block for union field access
`crypto/src/ecc_pkey_gen.rs:58-61`
```
pub fn setter(&mut self, data_ptr: *mut u8, data_len: u32) {
        self.key.ecc_pub.data = data_ptr;
        self.key.ecc_pub.len = data_len;
    }
```
**Issue**: In Rust, reading or modifying sub-fields of a union field directly (e.g., `self.key.ecc_pub.data = ...`) is considered an unsafe operation and requires an `unsafe` block. Without it, this code will fail to compile. Assigning the entire variant struct at once avoids the need for `unsafe`.
**Fix**:
```
pub fn setter(&mut self, data_ptr: *mut u8, data_len: u32) {
        self.key = CRYPT_EAL_PkeyPubUnion {
            ecc_pub: CRYPT_Data {
                data: data_ptr,
                len: data_len,
            },
        };
    }
```

---

### Compilation error due to missing unsafe block for union field access
`crypto/src/ecc_pkey_gen.rs:76-79`
```
pub fn setter(&mut self, data_ptr: *mut u8, data_len: u32) {
        self.key.ecc_prv.data = data_ptr;
        self.key.ecc_prv.len = data_len;
    }
```
**Issue**: Modifying sub-fields of a union field directly requires an `unsafe` block in Rust. Assigning the entire variant struct at once resolves the compilation error securely.
**Fix**:
```
pub fn setter(&mut self, data_ptr: *mut u8, data_len: u32) {
        self.key = CRYPT_EAL_PkeyPrvUnion {
            ecc_prv: CRYPT_Data {
                data: data_ptr,
                len: data_len,
            },
        };
    }
```

---

### Missing null pointer check for context allocation
`openhitls/src/sha2_256.rs:10-14`
```
pub fn new() -> Self {
        let ctx = sha2_256_newctx();
        sha2_256_init(ctx);
        Self { ctx }
    }
```
**Issue**: `sha2_256_newctx()` can return a null pointer if the internal allocation fails. Passing a null pointer directly to `sha2_256_init()` and storing it in the `Sha256` struct without checking will lead to undefined behavior or segmentation faults in C.
**Fix**:
```
pub fn new() -> Self {
        let ctx = sha2_256_newctx();
        if ctx.is_null() {
            panic!("Failed to allocate SHA256 context");
        }
        sha2_256_init(ctx);
        Self { ctx }
    }
```

---


## Low

### Unnecessary consumption of private key
`openhitls/src/ecdsa.rs:4-13`
```
pub fn ecdsa_sign(
    prv_key: Vec<u8>,
    curve_id: u32,
    digest: i32,
    data: &[u8]
) -> Result<Vec<u8>, String> {
    if prv_key.is_empty() {
        return Err("Invalid private key".to_string());
    }
    let key_ctx = key_to_ctx(curve_id, &Vec::<u8>::new(), &prv_key);
```
**Issue**: `ecdsa_sign` takes `prv_key` as `Vec<u8>` instead of `&[u8]`. This unnecessarily consumes the private key, forcing the caller to clone it if they want to reuse the key for multiple signatures.
**Fix**:
```
pub fn ecdsa_sign(
    prv_key: &[u8],
    curve_id: u32,
    digest: i32,
    data: &[u8]
) -> Result<Vec<u8>, String> {
    if prv_key.is_empty() {
        return Err("Invalid private key".to_string());
    }
    let key_ctx = key_to_ctx(curve_id, &[], prv_key);
```

---

### Unnecessary consumption of public key
`openhitls/src/ecdsa.rs:33-43`
```
pub fn ecdsa_verify(
    pub_key: Vec<u8>,
    curve_id: u32,
    digest: i32,
    data: &[u8],
    signature: &[u8]
) -> Result<bool, String> {
    if pub_key.is_empty() {
        return Err("Invalid public key".to_string());
    }
    let key_ctx = key_to_ctx(curve_id, &pub_key, &Vec::<u8>::new());
```
**Issue**: `ecdsa_verify` takes `pub_key` as `Vec<u8>` instead of `&[u8]`. This forces the caller to transfer ownership or clone the public key, resulting in suboptimal performance and ergonomics.
**Fix**:
```
pub fn ecdsa_verify(
    pub_key: &[u8],
    curve_id: u32,
    digest: i32,
    data: &[u8],
    signature: &[u8]
) -> Result<bool, String> {
    if pub_key.is_empty() {
        return Err("Invalid public key".to_string());
    }
    let key_ctx = key_to_ctx(curve_id, pub_key, &[]);
```

---
