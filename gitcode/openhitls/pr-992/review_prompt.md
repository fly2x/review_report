# Change Review Task

You are reviewing PR #992 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-992/openhitls`
- Base ref: `58ecc387ad39b4a31db0ab9f6e2b271ef45bce92`
- Head ref: `mr-992`
- The change under review is already checked out locally in this repository.

## Changed Files (89 files)

**Source** (64 files):
  - crypto/eal/src/eal_pkey_method.c
  - crypto/hbs/common/hbs_address.h
  - crypto/hbs/common/hbs_common.h
  - crypto/hbs/common/hbs_tree.c
  - crypto/hbs/common/hbs_tree.h
  - crypto/hbs/common/hbs_wots.c
  - crypto/hbs/common/hbs_wots.h
  - crypto/hbs/hss/src/hss_api.c
  - crypto/hbs/hss/src/hss_core.c
  - crypto/hbs/hss/src/hss_local.h
  - crypto/hbs/hss/src/hss_params.h
  - crypto/hbs/hss/src/hss_tree.c
  - crypto/hbs/hss/src/hss_tree.h
  - crypto/hbs/hss/src/hss_utils.c
  - crypto/hbs/include/crypt_hss.h
  - crypto/hbs/include/crypt_lms.h
  - crypto/hbs/include/crypt_slh_dsa.h
  - crypto/hbs/include/crypt_xmss.h
  - crypto/hbs/lms/src/lms_address.c
  - crypto/hbs/lms/src/lms_address.h
  - ... and 44 more

**Test** (13 files):
  - crypto/include/crypt_cmvp_selftest.h
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

**Docs** (9 files):
  - crypto/CMakeLists.txt
  - crypto/codecskey/CMakeLists.txt
  - crypto/eal/CMakeLists.txt
  - crypto/hbs/common/CMakeLists.txt
  - crypto/hbs/hss/CMakeLists.txt
  - crypto/hbs/lms/CMakeLists.txt
  - crypto/hbs/slh_dsa/CMakeLists.txt
  - crypto/hbs/xmss/CMakeLists.txt
  - crypto/provider/CMakeLists.txt

**Other** (3 files):
  - cmake/config.h.in
  - cmake/hitls_define_dependencies.cmake
  - cmake/hitls_options.cmake


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 58ecc387ad39b4a31db0ab9f6e2b271ef45bce92 mr-992`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 58ecc387ad39b4a31db0ab9f6e2b271ef45bce92 mr-992 -- <file>`
   - If you need more context, read the full file or search for related code
   - Look for: security issues, logic errors, edge cases, error handling
   - Treat assembly files (`.S`, `.s`, `.asm`) as source code and review ABI/calling convention,
     register and stack preservation, memory addressing, bounds, and architecture guards
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
   - Assembly: calling convention mismatches, save/restore bugs, bad clobbers,
     stack alignment, incorrect addressing, missing feature/architecture guards
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
