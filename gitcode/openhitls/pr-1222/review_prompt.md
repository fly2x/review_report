# Change Review Task

You are reviewing PR #1222 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1222/openhitls`
- Base ref: `7b10de2c71b079d381bb9745a5a7f170d8bb7fb2`
- Head ref: `mr-1222`
- The change under review is already checked out locally in this repository.

## Changed Files (16 files)

**Source** (12 files):
  - apps/src/app_list.c
  - crypto/eal/src/eal_cipher.c
  - crypto/eal/src/eal_cipher_method.c
  - crypto/ealinit/src/crypt_asmcap.c
  - crypto/include/crypt_local_types.h
  - crypto/modes/include/crypt_modes_gcm_siv.h
  - crypto/modes/src/modes_gcm_siv.c
  - crypto/provider/include/crypt_default_provderimpl.h
  - crypto/provider/src/default/crypt_default_cipher.c
  - crypto/provider/src/default/crypt_default_provider.c
  - include/bsl/bsl_obj.h
  - include/crypto/crypt_algid.h

**Test** (4 files):
  - testcode/framework/crypto/alg_check.c
  - testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes_gcm_siv.c
  - testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes_gcm_siv.data
  - testcode/test_config/crypto_test_config.json


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 7b10de2c71b079d381bb9745a5a7f170d8bb7fb2 mr-1222`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 7b10de2c71b079d381bb9745a5a7f170d8bb7fb2 mr-1222 -- <file>`
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
