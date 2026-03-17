# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls-rs
- PR: #2
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/openhitls-rs#2
**Reviewer**: CLAUDE


## Critical

### AEAD tag comparison vulnerable to timing attacks
`openhitls/src/aes.rs:202`
```
if calculated_tag != tag {
    return Err(format!("AEAD Tag mismatch! Expected {:?}, Got {:?}", tag, calculated_tag));
}
```
**Issue**: The tag comparison uses `!=` operator which is not constant-time. This allows an attacker to potentially forge valid tags through timing side-channel attacks.
**Fix**:
```
use subtle::ConstantTimeEq;

if calculated_tag.ct_eq(&tag).into() == false {
    return Err("AEAD Tag mismatch".to_string());
}
```

---

### Indistinguishable error return from successful empty key generation
`openhitls/src/ecc_pkey_gen.rs:19`
```
if ctx.is_null() {
    println!("Failed to create ECC context");
    return (Vec::new(), Vec::new());
}
```
**Issue**: The function returns (Vec::new(), Vec::new()) on error, which is indistinguishable from a successful (but impossible) generation of empty keys. Callers cannot detect failures and may use uninitialized/invalid cryptographic keys.
**Fix**:
```
pub fn ecc_genpkey(curve_id: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
    // ...
    if ctx.is_null() {
        return Err("Failed to create ECC context".to_string());
    }
    // ...
    Ok((actual_pub, actual_prv))
}
```

---


## High

### Ignored return value from sha2_256_init
`openhitls/src/sha2_256.rs:12`
```
pub fn new() -> Self {
    let ctx = sha2_256_newctx();
    sha2_256_init(ctx);
    Self { ctx }
}
```
**Issue**: The sha2_256_init function returns an i32 status code (0 = success), but the return value is ignored. If initialization fails, the context will be in an invalid state but the new() function still succeeds, leading to undefined behavior when the context is used.
**Fix**:
```
pub fn new() -> Result<Self, String> {
    let ctx = sha2_256_newctx();
    if ctx.is_null() {
        return Err("Failed to allocate SHA256 context".to_string());
    }
    let ret = sha2_256_init(ctx);
    if ret != 0 {
        sha2_256_freectx(ctx);
        return Err(format!("Failed to initialize SHA256 context: {}", ret));
    }
    Ok(Self { ctx })
}
```

---

### Ignored return value from sha2_256_update
`openhitls/src/sha2_256.rs:16-18`
```
pub fn update(&mut self, data: &[u8]) {
    sha2_256_update(self.ctx, data);
}
```
**Issue**: The sha2_256_update function returns an i32 status code, but the return value is ignored. If update fails, the hash state is corrupted and the final result will be invalid.
**Fix**:
```
pub fn update(&mut self, data: &[u8]) -> Result<(), String> {
    let ret = sha2_256_update(self.ctx, data);
    if ret != 0 {
        Err(format!("Failed to update SHA256: {}", ret))
    } else {
        Ok(())
    }
}
```

---

### Silent IV truncation for CCM mode without length validation
`openhitls/src/aes.rs:33-37`
```
let actual_iv = if is_ccm(algid) && iv.len() > 12 {
    &iv[..12]
} else {
    iv
};
```
**Issue**: For CCM mode, the IV is truncated to 12 bytes if longer, but no error is raised if the IV is shorter than 12 bytes. CCM requires a 12-byte nonce (7-13 bytes allowed by spec, but 12 is standard). Using a shorter IV may lead to weak cryptography.
**Fix**:
```
let actual_iv = if is_ccm(algid) {
    if iv.len() < 12 {
        return Err("CCM mode requires IV of at least 12 bytes".to_string());
    }
    &iv[..12]
} else {
    iv
};
```

---

### Silent IV truncation for CCM mode in decrypt without length validation
`openhitls/src/aes.rs:127-131`
```
let actual_iv = if is_ccm(algid) && iv.len() > 12 {
    &iv[..12]
} else {
    iv
};
```
**Issue**: Same issue as in encrypt - CCM IV is truncated to 12 bytes if longer, but no error if shorter than 12 bytes.
**Fix**:
```
let actual_iv = if is_ccm(algid) {
    if iv.len() < 12 {
        return Err("CCM mode requires IV of at least 12 bytes".to_string());
    }
    &iv[..12]
} else {
    iv
};
```

---

### ctx_to_key returns empty vectors on error without indication
`openhitls/src/ecc_pkey_gen.rs:49-84`
```
let ret_pub = ecc_get_pub(ctx, &mut pub_key_wrapper);
if ret_pub == 0 {
    let len = pub_key_wrapper.get_pub_len() as usize;
    actual_pub = pub_buf[..len].to_vec();
} else {
    println!("Failed to get ECC public key: {}", ret_pub);
}
```
**Issue**: When ecc_get_pub or ecc_get_prv fails, the function returns partially filled or empty vectors without any error indication. The caller cannot detect that key extraction failed.
**Fix**:
```
pub fn ctx_to_key(ctx: *mut std::ffi::c_void, curve_id: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
    // ...
    let ret_pub = ecc_get_pub(ctx, &mut pub_key_wrapper);
    if ret_pub != 0 {
        return Err(format!("Failed to get ECC public key: {}", ret_pub));
    }
    let ret_prv = ecc_get_prv(ctx, &mut prv_key_wrapper);
    if ret_prv != 0 {
        return Err(format!("Failed to get ECC private key: {}", ret_prv));
    }
    // ...
    Ok((actual_pub, actual_prv))
}
```

---

### pub_buf dropped before use in key_to_ctx
`openhitls/src/ecc_pkey_gen.rs:110-121`
```
if !pub_key.is_empty() {
    let mut pub_buf = pub_key.to_vec();
    let mut pub_key_wrapper = CRYPT_EAL_PkeyPub::new(ctx_id);
    pub_key_wrapper.setter(pub_buf.as_mut_ptr(), pub_buf.len() as u32);

    let ret = ecc_set_pub(ctx, &mut pub_key_wrapper);
    // pub_buf is dropped here!
}
```
**Issue**: The `pub_buf` vector is allocated and its pointer is passed to `ecc_set_pub`, but the vector goes out of scope immediately after. If the C library stores the pointer and uses it later, this will cause use-after-free. The vector needs to live as long as the context.

---


## Medium

### Output buffer size based on encrypted data length may be insufficient
`openhitls/src/ecc_pkey_crypt.rs:37`
```
let mut out_len: u32 = enc_data.len() as u32;
let mut out_buf = vec![0u8; out_len as usize];
```
**Issue**: The output buffer is sized to `enc_data.len()`, but decrypted data can be larger than encrypted data for some encryption schemes (though SM2 typically produces ciphertext larger than plaintext). This could cause a buffer overflow or truncation.
**Fix**:
```
let mut out_len: u32 = (enc_data.len() + 256) as u32;
let mut out_buf = vec![0u8; out_len as usize];
```

---

### Working directory not restored on subprocess failure
`configure.py:9-15`
```
os.chdir(deps_dir)
subprocess.run(['python3', 'configure.py'], check=True)
build_dir = os.path.join(deps_dir, 'build')
os.makedirs(build_dir, exist_ok=True)
os.chdir(build_dir)
```
**Issue**: If subprocess.run() with check=True fails, an exception is raised but the working directory has already been changed. This leaves the process in an inconsistent state and makes debugging harder.
**Fix**:
```
original_dir = os.getcwd()
try:
    os.chdir(deps_dir)
    subprocess.run(['python3', 'configure.py'], check=True)
    build_dir = os.path.join(deps_dir, 'build')
    os.makedirs(build_dir, exist_ok=True)
    os.chdir(build_dir)
    subprocess.run(['cmake', '..'], check=True)
    subprocess.run(['make', '-j'], check=True)
    os.chdir(script_dir)
except Exception:
    os.chdir(original_dir)
    raise
```

---

### sha2_256_init wrapper discards return value
`crypto/src/sha2_256.rs:18-20`
```
pub fn sha2_256_init(ctx: *mut c_void) -> i32 {
    unsafe { CRYPT_SHA2_256_Init(ctx, std::ptr::null_mut()) }
}
```
**Issue**: The safe wrapper function sha2_256_init does not return the status code from the underlying C function, making it impossible for callers to detect initialization failures.

---


---

## GEMINI Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls-rs#2
**Reviewer**: CODEX


## High

### Generated build script uses `rustc-link-arg` instead of Cargo link directives
`configure.py:44-48`
```
println!("cargo:rustc-link-search=native={{}}", lib_dir);
    println!("cargo:rustc-link-arg=-Wl,-rpath,{{}}", lib_dir);
    println!("cargo:rustc-link-arg=-L{{}}", lib_dir);
    println!("cargo:rustc-link-arg=-lhitls_bsl");
    println!("cargo:rustc-link-arg=-lhitls_crypto");
```
**Issue**: The generated `crypto/build.rs` passes `-L` and `-l` through `cargo:rustc-link-arg`. Cargo only applies `rustc-link-arg` to final binaries/examples/tests, not to normal library compilation, so downstream crates depending on `openhitls` can still fail to link `hitls_bsl` and `hitls_crypto`. This makes the documented consumption path unreliable.
**Fix**:
```
content = f"""fn main() {{
    let lib_dir = "{abs_location}";
    println!("cargo:rustc-link-search=native={{}}", lib_dir);
    println!("cargo:rustc-link-lib=dylib=hitls_bsl");
    println!("cargo:rustc-link-lib=dylib=hitls_crypto");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{{}}", lib_dir);
    println!("cargo:rerun-if-changed=build.rs");
}}
"""
```

---

### CCM mode silently truncates caller-supplied IVs
`openhitls/src/aes.rs:33-37`
```
let actual_iv = if is_ccm(algid) && iv.len() > 12 {
            &iv[..12]
        } else {
            iv
        };
```
**Issue**: For CCM, any IV longer than 12 bytes is silently shortened to its first 12 bytes before encryption and decryption. That collapses distinct nonces onto the same effective IV, which is a cryptographic misuse and can cause nonce reuse under the same key. If longer IVs are unsupported, the wrapper must reject them instead of mutating them.
**Fix**:
```
let actual_iv = if is_ccm(algid) {
            if iv.len() > 12 {
                return Err("CCM IVs longer than 12 bytes are not supported".to_string());
            }
            iv
        } else {
            iv
        };
```

---


## Medium

### Signing error path leaks the allocated key context
`openhitls/src/ecdsa.rs:22-29`
```
let ret = pkey_sign(key_ctx, digest, data, &mut sig_buf, &mut sig_len);

    if ret != 0 {
        return Err(format!("Sign failed: 0x{:x}", ret));
    }

    sig_buf.truncate(sig_len as usize);
    free_ecc_pkey(key_ctx);
    Ok(sig_buf)
```
**Issue**: When `pkey_sign` fails, the function returns immediately without freeing `key_ctx`. Repeated signing failures will leak native contexts in a public API that is otherwise expected to manage resources safely.
**Fix**:
```
let ret = pkey_sign(key_ctx, digest, data, &mut sig_buf, &mut sig_len);
    if ret != 0 {
        free_ecc_pkey(key_ctx);
        return Err(format!("Sign failed: 0x{:x}", ret));
    }

    sig_buf.truncate(sig_len as usize);
    free_ecc_pkey(key_ctx);
    Ok(sig_buf)
```

---

### Verification API turns operational failures into `Ok(false)`
`openhitls/src/ecdsa.rs:48-53`
```
let ret = pkey_verify(key_ctx, digest, data, signature);
    free_ecc_pkey(key_ctx);
    if ret == 0 {
        Ok(true)
    } else {
        Ok(false)
    }
```
**Issue**: Every nonzero return code from `pkey_verify` is reported as `Ok(false)`. That hides real library failures such as bad parameters, unsupported digests, or internal verification errors, and makes callers treat infrastructure errors as ordinary signature mismatches.
**Fix**:
```
let ret = pkey_verify(key_ctx, digest, data, signature);
    free_ecc_pkey(key_ctx);

    if ret == 0 {
        Ok(true)
    } else {
        Err(format!("Verify failed: 0x{:x}", ret))
    }
```

---

### Safe SHA-256 wrapper ignores allocation and FFI error returns
`openhitls/src/sha2_256.rs:10-25`
```
pub fn new() -> Self {
        let ctx = sha2_256_newctx();
        sha2_256_init(ctx);
        Self { ctx }
    }

    pub fn update(&mut self, data: &[u8]) {
        sha2_256_update(self.ctx, data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let this = ManuallyDrop::new(self);
        let mut out = [0u8; 32];
        let mut out_len = 32u32;
        sha2_256_final(this.ctx, &mut out, &mut out_len);
        sha2_256_freectx(this.ctx);
        out
    }
```
**Issue**: `Sha256::new`, `update`, and `finalize` discard the native return codes and never check whether `sha2_256_newctx()` returned null. That means allocation/init failures can turn into null-pointer calls or silently produce an all-zero/partial digest while still presenting a safe Rust API.
**Fix**:
```
pub fn new() -> Result<Self, String> {
        let ctx = sha2_256_newctx();
        if ctx.is_null() {
            return Err("CRYPT_SHA2_256_NewCtx failed".to_string());
        }

        let ret = sha2_256_init(ctx);
        if ret != 0 {
            sha2_256_freectx(ctx);
            return Err(format!("CRYPT_SHA2_256_Init failed: 0x{:x}", ret));
        }

        Ok(Self { ctx })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), String> {
        let ret = sha2_256_update(self.ctx, data);
        if ret != 0 {
            return Err(format!("CRYPT_SHA2_256_Update failed: 0x{:x}", ret));
        }
        Ok(())
    }

    pub fn finalize(self) -> Result<[u8; 32], String> {
        let this = ManuallyDrop::new(self);
        let mut out = [0u8; 32];
        let mut out_len = 32u32;
        let ret = sha2_256_final(this.ctx, &mut out, &mut out_len);
        sha2_256_freectx(this.ctx);

        if ret != 0 || out_len != 32 {
            return Err(format!("CRYPT_SHA2_256_Final failed: 0x{:x}", ret));
        }

        Ok(out)
    }
```

---

### AES example documents a fixed IV
`README.md:192-197`
```
let plaintext = "Hello OpenHiTLS!";
let key = b"0123456789abcdef";
let iv = b"0123456789abcdef";

let encrypted = aes_encrypt(AES128_CBC, plaintext.as_bytes(), key, iv).unwrap();
let decrypted = aes_decrypt(AES128_CBC, &encrypted, key, iv).unwrap();
```
**Issue**: The README shows AES encryption with a hard-coded IV. Reusing a fixed IV is unsafe for CBC and catastrophic for GCM/CCM under the same key, so this example teaches an insecure pattern in the main user-facing documentation.
**Fix**:
```
let plaintext = "Hello OpenHiTLS!";
let key = b"0123456789abcdef";
let mut iv = [0u8; 16];
getrandom::fill(&mut iv).unwrap(); // 每次加密都要生成新的 IV

let encrypted = aes_encrypt(AES128_CBC, plaintext.as_bytes(), key, &iv).unwrap();
let decrypted = aes_decrypt(AES128_CBC, &encrypted, key, &iv).unwrap();
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
