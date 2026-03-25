# Change Review Task

You are reviewing PR #1138 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1138/openhitls`
- Base ref: `d9c4a7848c563c4519b981a4ddb9521950fa778d`
- Head ref: `mr-1138`
- The change under review is already checked out locally in this repository.

## Changed Files (132 files)

**Source** (124 files):
  - bsl/asn1/src/bsl_asn1.c
  - bsl/base64/src/bsl_base64.c
  - bsl/buffer/src/bsl_buffer.c
  - bsl/conf/src/bsl_conf_def.c
  - bsl/err/src/avl.c
  - bsl/err/src/err.c
  - bsl/list/src/bsl_list.c
  - bsl/sal/include/sal_time.h
  - bsl/sal/src/sal_net.c
  - bsl/sal/src/sal_time.c
  - bsl/uio/src/uio_buffer.c
  - bsl/uio/src/uio_file.c
  - bsl/uio/src/uio_mem.c
  - bsl/uio/src/uio_sctp.c
  - bsl/uio/src/uio_tcp.c
  - bsl/uio/src/uio_udp.c
  - codecs/src/decode_chain.c
  - config/macro_config/hitls_config_layer_bsl.h
  - config/macro_config/hitls_config_layer_crypto.h
  - crypto/aes/src/asm/crypt_aes_ctr_armv8.S
  - ... and 104 more

**Test** (6 files):
  - testcode/framework/tls/msg/src/pack_frame_msg.c
  - testcode/sdv/testcase/crypto/hpke/test_suite_sdv_eal_hpke.c
  - testcode/sdv/testcase/crypto/rsa/test_suite_sdv_eal_rsa_encrypt_decrypt.data
  - testcode/sdv/testcase/pki/common/test_suite_sdv_common.c
  - testcode/sdv/testcase/pki/common/test_suite_sdv_x509.c
  - testcode/sdv/testcase/pki/verify/test_suite_sdv_x509_vfy.c

**Config** (2 files):
  - config/json/complete_options.json
  - config/json/feature.json


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- Do NOT search the web.
- Do NOT open GitHub, GitLab, Gitee, or GitCode pages for this review.
- Do NOT rely on remote PR pages or web search results for code analysis.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat d9c4a7848c563c4519b981a4ddb9521950fa778d mr-1138`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff d9c4a7848c563c4519b981a4ddb9521950fa778d mr-1138 -- <file>`
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
