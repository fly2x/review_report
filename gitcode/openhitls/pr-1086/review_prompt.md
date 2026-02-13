# Change Review Task

You are reviewing PR #1086 for openHiTLS/openhitls.


## Changed Files (592 files)

**Source** (344 files):
  - apps/src/app_client.c
  - apps/src/app_conf.c
  - apps/src/app_crl.c
  - apps/src/app_dgst.c
  - apps/src/app_enc.c
  - apps/src/app_genpkey.c
  - apps/src/app_genrsa.c
  - apps/src/app_kdf.c
  - apps/src/app_keymgmt.c
  - apps/src/app_list.c
  - apps/src/app_mac.c
  - apps/src/app_opt.c
  - apps/src/app_pkcs12.c
  - apps/src/app_pkey.c
  - apps/src/app_pkeyutl.c
  - apps/src/app_prime.c
  - apps/src/app_print.c
  - apps/src/app_provider.c
  - apps/src/app_rand.c
  - apps/src/app_req.c
  - ... and 324 more

**Test** (237 files):
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_cipher.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_ecdh.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_ecdsa.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_mldsa.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_mlkem.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_rsa.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_slhdsa.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_sm2.c
  - crypto/provider/src/cmvp/iso_prov/crypt_iso_selftest.c
  - crypto/provider/src/cmvp/sm_prov/crypt_sm_selftest.c
  - testcode/benchmark/CMakeLists.txt
  - testcode/common/execute_base.c
  - testcode/common/execute_test.c
  - testcode/demo/CMakeLists.txt
  - testcode/demo/client.c
  - testcode/demo/otp.c
  - testcode/demo/server.c
  - testcode/demo/tlcp_client.c
  - testcode/demo/tlcp_server.c
  - testcode/framework/crypto/crypto_test_util.c
  - ... and 217 more

**Config** (1 files):
  - config/json/feature.json

**Docs** (5 files):
  - CMakeLists.txt
  - README-zh.md
  - README.md
  - docs/en/3_Quick Start.md
  - docs/en/4_User Guide/1_Build and Installation Guide.md

**Other** (5 files):
  - .gitmodules
  - "docs/zh/3_\345\277\253\351\200\237\345\205\245\351\227\250.md"
  - "docs/zh/4_\344\275\277\347\224\250\346\214\207\345\215\227/1_\346\236\204\345\273\272\345\217\212\345\256\211\350\243\205\346\214\207\345\257\274.md"
  - platform/SecureC.cmake
  - platform/Secure_C


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat b58d6d510d06b882bdf5c33b0e1b2be39279e508 mr-1086`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff b58d6d510d06b882bdf5c33b0e1b2be39279e508 mr-1086 -- <file>`
   - If you need more context, read the full file or search for related code
   - Look for: security issues, logic errors, edge cases, error handling
   - For non-code files (docs/config), focus on correctness and safety of the content

3. **Track Dependencies**
   - When you find a changed function, check its callers
   - When you see a new API, verify it's used correctly
   - Use grep/search to find related code

4. **Focus Areas**
   - Security: injection, auth bypass, data exposure, buffer overflow
   - Logic: null/nil checks, boundary conditions, error paths
   - API: breaking changes, compatibility, proper error returns
   - Resources: leaks, proper cleanup, race conditions
   - Documentation (Markdown/docs): incorrect or outdated instructions, wrong flags/paths,
     broken references, misleading examples, missing steps, or unsafe guidance
   - Config/build/CI: insecure defaults, mismatched versions, missing required keys

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
- Only flag issues in CHANGED lines (code or docs, not pre-existing issues)
- Be specific with line numbers
- Provide working fixes, not just descriptions
  - For docs, FIX should be the corrected text/snippet

Start the review now. Output each issue as you find it.
