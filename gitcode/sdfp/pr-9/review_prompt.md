# Change Review Task

You are reviewing PR #9 for openHiTLS/sdfp.


## Local Repository Context

- Repository root: `sdfp-9/sdfp`
- Base ref: `515a00cb9fa010d47470fa93cc03890305249347`
- Head ref: `mr-9`
- The change under review is already checked out locally in this repository.

## Changed Files (45 files)

**Source** (40 files):
  - demo/provider_init.c
  - demo/rsa_encrypt.c
  - demo/rsa_sign.c
  - demo/sdfp_demo.c
  - demo/sm2_encrypt.c
  - demo/sm2_sign.c
  - demo/sm3_hash.c
  - demo/sm4_cbc.c
  - demo/sm4_ecb.c
  - demo/sm4_gcm.c
  - include/sdfp.h
  - include/sdfp_errno.h
  - src/bsl_asn1_internal.h
  - src/common/bsl_asn1.c
  - src/common/crypt_encode.c
  - src/common/crypt_util_mgf.c
  - src/common/crypt_util_pkey.c
  - src/common/crypt_utils.h
  - src/common/provider.c
  - src/common/provider.h
  - ... and 20 more

**Test** (2 files):
  - demo/demo_tests.h
  - demo/sm4_test.c

**Docs** (2 files):
  - CMakeLists.txt
  - README.md

**Other** (1 files):
  - src/common/version.lds


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 515a00cb9fa010d47470fa93cc03890305249347 mr-9`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 515a00cb9fa010d47470fa93cc03890305249347 mr-9 -- <file>`
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
