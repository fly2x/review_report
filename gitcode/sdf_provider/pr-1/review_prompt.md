# Change Review Task

You are reviewing PR #1 for openHiTLS/sdf_provider.


## Changed Files (30 files)

**Source** (28 files):
  - demo/rsa_encrypt.c
  - demo/rsa_sign.c
  - demo/sm2_encrypt.c
  - demo/sm2_sign.c
  - src/bsl_asn1.c
  - src/bsl_asn1_internal.h
  - src/bsl_bytes.h
  - src/crypt_encode.c
  - src/crypt_encode_internal.h
  - src/crypt_local_types.h
  - src/crypt_util_mgf.c
  - src/crypt_util_pkey.c
  - src/crypt_utils.h
  - src/log.c
  - src/log.h
  - src/provider.c
  - src/provider.h
  - src/providerimpl.h
  - src/rsa_keymgmt.c
  - src/rsa_local.h
  - ... and 8 more

**Docs** (2 files):
  - CMakeLists.txt
  - README.md


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 53fa9012f46bd3ff6fe31befab6f6a6b1f017150 mr-1`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 53fa9012f46bd3ff6fe31befab6f6a6b1f017150 mr-1 -- <file>`
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
