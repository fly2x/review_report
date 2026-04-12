# Change Review Task

You are reviewing PR #1233 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1233/openhitls`
- Base ref: `918632a998ef01254d20c3a5c1a4a8d065da33d5`
- Head ref: `mr-1233`
- The change under review is already checked out locally in this repository.

## Changed Files (67 files)

**Source** (47 files):
  - apps/src/app_conf.c
  - apps/src/app_keymgmt.c
  - apps/src/app_pkcs12.c
  - apps/src/app_pkeyutl.c
  - apps/src/app_tls_common.c
  - apps/src/app_utils.c
  - apps/src/app_verify.c
  - bsl/conf/src/bsl_conf_def.c
  - bsl/list/include/bsl_list_internal.h
  - bsl/list/src/bsl_list.c
  - bsl/list/src/bsl_list_ex.c
  - bsl/list/src/bsl_list_internal.c
  - bsl/params/src/bsl_param_maker.c
  - bsl/uio/src/uio_file.c
  - bsl/uio/src/uio_mem.c
  - codecs/src/decode_chain.c
  - crypto/entropy/src/entropy_seed_pool.c
  - crypto/entropy/src/es_entropy.c
  - crypto/entropy/src/es_noise_source.c
  - crypto/provider/src/mgr/crypt_provider.c
  - ... and 27 more

**Test** (19 files):
  - testcode/demo/chacha20.c
  - testcode/sdv/testcase/apps/test_suite_ut_app_genpkey.c
  - testcode/sdv/testcase/bsl/list/test_suite_sdv_list.c
  - testcode/sdv/testcase/bsl/list/test_suite_sdv_list.data
  - testcode/sdv/testcase/codecs/decode/test_suite_sdv_decode.c
  - testcode/sdv/testcase/crypto/entropy/test_suite_sdv_entropy.c
  - testcode/sdv/testcase/crypto/provider/test_suite_sdv_eal_provider_load.c
  - testcode/sdv/testcase/crypto/provider/test_suite_sdv_eal_provider_load.data
  - testcode/sdv/testcase/pki/common/test_suite_sdv_common.c
  - testcode/sdv/testcase/pki/common/test_suite_sdv_common.data
  - testcode/sdv/testcase/pki/csr/test_suite_sdv_x509_csr.c
  - testcode/sdv/testcase/pki/verify/test_suite_sdv_x509_vfy.c
  - testcode/sdv/testcase/pki/verify/test_suite_sdv_x509_vfy.data
  - testcode/sdv/testcase/tls/consistency/dtlcp/test_suite_sdv_hlt_dtlcp_consistency.c
  - testcode/sdv/testcase/tls/consistency/dtls12/test_suite_sdv_hlt_dtls12_consistency.c
  - testcode/sdv/testcase/tls/interface/test_suite_sdv_frame_tls_config_1.c
  - testcode/sdv/testcase/tls/interface/test_suite_sdv_frame_tls_config_1.data
  - testcode/sdv/testcase/tls/interface_tlcp/test_suite_sdv_frame_cert_interface.c
  - testcode/sdv/testcase/tls/interface_tlcp/test_suite_sdv_frame_cert_interface_2.c

**Docs** (1 files):
  - bsl/CMakeLists.txt


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 918632a998ef01254d20c3a5c1a4a8d065da33d5 mr-1233`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 918632a998ef01254d20c3a5c1a4a8d065da33d5 mr-1233 -- <file>`
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
