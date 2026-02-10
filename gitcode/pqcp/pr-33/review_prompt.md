# Change Review Task

You are reviewing PR #33 for openHiTLS/pqcp.


## Changed Files (34 files)

**Source** (18 files):
  - include/pqcp_err.h
  - include/pqcp_provider.h
  - include/pqcp_types.h
  - src/classic_mceliece/include/internal/mceliece_params.h
  - src/classic_mceliece/src/mceliece_api.c
  - src/classic_mceliece/src/mceliece_params.c
  - src/composite_sign/include/crypt_composite_sign.h
  - src/composite_sign/src/crypt_composite_sign.c
  - src/composite_sign/src/crypt_composite_sign_encdec.c
  - src/composite_sign/src/crypt_composite_sign_local.h
  - src/frodokem/src/frodokem.c
  - src/frodokem/src/frodokem_api.c
  - src/polarlac/src/polarlac.c
  - src/polarlac/src/polarlac_pke.c
  - src/provider/pqcp_pkey.c
  - src/provider/pqcp_provider.c
  - src/provider/pqcp_provider_impl.h
  - src/scloudplus/src/scloudplus.c

**Test** (15 files):
  - test/CMakeLists.txt
  - test/demo/composite_sign_demo.c
  - test/demo/frodokem_demo.c
  - test/demo/mceliece_demo.c
  - test/demo/polarlac_demo.c
  - test/demo/scloudplus_demo.c
  - test/sdv/kem/frodokem_test.c
  - test/sdv/kem/kem_test.c
  - test/sdv/kem/kem_test.h
  - test/sdv/kem/mceliece_test.c
  - test/sdv/kem/scloudplus_test.c
  - test/sdv/main.c
  - test/sdv/sign/composite_sign_test.c
  - test/sdv/sign/sign_test.c
  - test/sdv/sign/sign_test.h

**Docs** (1 files):
  - CMakeLists.txt


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat ab276dc393ecc69acd10fcf5d959d6177ba5c1a0 mr-33`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff ab276dc393ecc69acd10fcf5d959d6177ba5c1a0 mr-33 -- <file>`
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
