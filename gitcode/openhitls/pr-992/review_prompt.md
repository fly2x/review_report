# Code Review Task

You are reviewing PR #992 for openHiTLS/openhitls.


## Changed Files (37 files)

**Source** (24 files):
  - config/macro_config/hitls_config_layer_crypto.h
  - crypto/eal/src/eal_pkey_method.c
  - crypto/lms/include/crypt_hss.h
  - crypto/lms/include/crypt_lms.h
  - crypto/lms/src/hss_api.c
  - crypto/lms/src/hss_core.c
  - crypto/lms/src/hss_local.h
  - crypto/lms/src/hss_params.h
  - crypto/lms/src/hss_utils.c
  - crypto/lms/src/lms_api.c
  - crypto/lms/src/lms_core.c
  - crypto/lms/src/lms_hash.c
  - crypto/lms/src/lms_hash.h
  - crypto/lms/src/lms_local.h
  - crypto/lms/src/lms_ots.c
  - crypto/lms/src/lms_params.h
  - crypto/provider/include/crypt_default_provderimpl.h
  - crypto/provider/src/default/crypt_default_keymgmt.c
  - crypto/provider/src/default/crypt_default_provider.c
  - crypto/provider/src/default/crypt_default_sign.c
  - ... and 4 more

**Test** (12 files):
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_hss.c
  - crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_lms.c
  - testcode/script/build_hitls.sh
  - testcode/sdv/CMakeLists.txt
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_eal_hss.c
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_eal_hss.data
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_eal_lms.c
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_eal_lms.data
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_hss.c
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_hss.data
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_lms.c
  - testcode/sdv/testcase/crypto/lms/test_suite_sdv_lms.data

**Config** (1 files):
  - config/json/feature.json


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 05342ecfae9070fa5ea390a0d4ef8e4e054fae6c mr-992`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 05342ecfae9070fa5ea390a0d4ef8e4e054fae6c mr-992 -- <file>`
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
