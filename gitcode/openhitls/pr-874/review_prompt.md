# Code Review Task

You are reviewing PR #874 for openHiTLS/openhitls.


## Changed Files (161 files)

**Source** (76 files):
  - bsl/obj/src/bsl_cid_op.c
  - bsl/obj/src/bsl_obj.c
  - config/macro_config/hitls_config_check.h
  - config/macro_config/hitls_config_layer_crypto.h
  - crypto/cmac/include/crypt_cbc_mac.h
  - crypto/cmac/include/crypt_cmac.h
  - crypto/cmac/src/cbc_mac.c
  - crypto/cmac/src/cmac.c
  - crypto/codecskey/include/crypt_decoder.h
  - crypto/codecskey/src/crypt_codecskey_local.c
  - crypto/codecskey/src/crypt_codecskey_local.h
  - crypto/codecskey/src/crypt_decoder_composite.c
  - crypto/codecskey/src/crypt_decoder_der2key.c
  - crypto/composite/include/crypt_composite.h
  - crypto/composite/src/composite.c
  - crypto/composite/src/composite_encdec.c
  - crypto/composite/src/composite_local.h
  - crypto/eal/src/eal_cipher.c
  - crypto/eal/src/eal_cipher_method.c
  - crypto/eal/src/eal_kdf.c
  - ... and 56 more

**Test** (84 files):
  - testcode/sdv/CMakeLists.txt
  - testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_cipher.c
  - testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_cipher.data
  - testcode/sdv/testcase/crypto/cbc_mac/test_suite_sdv_eal_mac_cbc_mac.c
  - testcode/sdv/testcase/crypto/cbc_mac/test_suite_sdv_eal_mac_cbc_mac.data
  - testcode/sdv/testcase/crypto/cmac/test_suite_sdv_eal_mac_cmac.c
  - testcode/sdv/testcase/crypto/cmac/test_suite_sdv_eal_mac_cmac.data
  - testcode/sdv/testcase/crypto/composite/test_suite_sdv_composite.c
  - testcode/sdv/testcase/crypto/composite/test_suite_sdv_composite.data
  - testcode/sdv/testcase/crypto/gmac/test_suite_sdv_eal_gmac.c
  - testcode/sdv/testcase/crypto/gmac/test_suite_sdv_eal_gmac.data
  - testcode/sdv/testcase/crypto/hkdf/test_suite_sdv_eal_kdf_hkdf.c
  - testcode/sdv/testcase/crypto/hkdf/test_suite_sdv_eal_kdf_hkdf.data
  - testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.base.c
  - testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c
  - testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.data
  - testcode/sdv/testcase/crypto/kdf_tls12/test_suite_sdv_eal_kdf_tls12.c
  - testcode/sdv/testcase/crypto/kdf_tls12/test_suite_sdv_eal_kdf_tls12.data
  - testcode/sdv/testcase/crypto/pbkdf2/test_suite_sdv_eal_kdf_pbkdf2.c
  - testcode/sdv/testcase/crypto/pbkdf2/test_suite_sdv_eal_kdf_pbkdf2.data
  - ... and 64 more

**Config** (1 files):
  - config/json/feature.json


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 57954183ced230f447c23a5f2c968c53915b2353 mr-874`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 57954183ced230f447c23a5f2c968c53915b2353 mr-874 -- <file>`
   - If you need more context, read the full file or search for related code
   - Look for: security issues, logic errors, edge cases, error handling

3. **Track Dependencies**
   - When you find a changed function, check its callers
   - When you see a new API, verify it's used correctly
   - Use grep/search to find related code

4. **Focus Areas**
   - Security: injection, auth bypass, data exposure, buffer overflow
   - Logic: null/nil checks, boundary conditions, error paths
   - API: breaking changes, compatibility, proper error returns
   - Resources: leaks, proper cleanup, race conditions

## Output Format - CRITICAL

You MUST output each issue in the EXACT format below. Do NOT output summaries, tables, or prose.
Your ONLY output should be ===ISSUE=== blocks. No introduction, no conclusion.

For each issue found, output EXACTLY:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
PROBLEM: <what's wrong>
CODE:
```
<problematic code>
```
FIX:
```
<suggested fix>
```
===END===

## Rules

- ONLY output ===ISSUE=== blocks, nothing else
- Do NOT write summaries or conclusions
- Do NOT use markdown headers or bullet points outside of issue blocks
- Only flag issues in CHANGED code (not pre-existing issues)
- Be specific with line numbers
- Provide working fixes, not just descriptions

Start the review now. Output each issue as you find it.
