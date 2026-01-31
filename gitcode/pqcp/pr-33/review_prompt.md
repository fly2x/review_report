# Code Review Task

You are reviewing PR #33 for openhitls/pqcp.


## Changed Files (21 files)

**Source** (11 files):
  - include/pqcp_err.h
  - include/pqcp_provider.h
  - include/pqcp_types.h
  - src/composite_sign/include/crypt_composite_sign.h
  - src/composite_sign/src/crypt_composite_sign.c
  - src/composite_sign/src/crypt_composite_sign_encdec.c
  - src/composite_sign/src/crypt_composite_sign_local.h
  - src/polarlac/src/polarlac.c
  - src/provider/pqcp_pkey.c
  - src/provider/pqcp_provider.c
  - src/provider/pqcp_provider_impl.h

**Test** (9 files):
  - test/CMakeLists.txt
  - test/demo/composite_sign_demo.c
  - test/demo/hybrid_env_demo.c
  - test/sdv/kem/kem_test.c
  - test/sdv/kem/kem_test.h
  - test/sdv/main.c
  - test/sdv/sign/composite_sign_test.c
  - test/sdv/sign/sign_test.c
  - test/sdv/sign/sign_test.h

**Docs** (1 files):
  - CMakeLists.txt


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat ab276dc393ecc69acd10fcf5d959d6177ba5c1a0 mr-33`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff ab276dc393ecc69acd10fcf5d959d6177ba5c1a0 mr-33 -- <file>`
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
