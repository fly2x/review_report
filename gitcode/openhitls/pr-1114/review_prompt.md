# Change Review Task

You are reviewing PR #1114 for openHiTLS/openhitls.


## Changed Files (16 files)

**Source** (11 files):
  - crypto/mlkem/src/asm_ml_kem_ntt.c
  - crypto/mlkem/src/asm_ml_kem_poly.c
  - crypto/mlkem/src/ml_kem_local.h
  - crypto/mlkem/src/ml_kem_pke.c
  - crypto/mlkem/src/ml_kem_poly.c
  - crypto/sha3/include/crypt_sha3.h
  - crypto/sha3/src/aarch64_sha3.c
  - crypto/sha3/src/aarch64_sha3.h
  - crypto/sha3/src/noasm_sha3.c
  - crypto/sha3/src/sha3.c
  - crypto/sha3/src/sha3_core.h

**Config** (2 files):
  - config/json/compile.json
  - config/json/feature.json

**Other** (3 files):
  - crypto/mlkem/src/asm/ml_kem_basemul_armv8.S
  - crypto/mlkem/src/asm/ml_kem_ntt_armv8.S
  - crypto/mlkem/src/asm/ml_kem_poly_armv8.S


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0 mr-1114`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0 mr-1114 -- <file>`
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
