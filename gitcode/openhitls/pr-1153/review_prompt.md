# Change Review Task

You are reviewing PR #1153 for openHiTLS/openhitls.


## Changed Files (23 files)

**Source** (9 files):
  - crypto/mldsa/src/asm/aarch64_zeta_table.c
  - crypto/mldsa/src/asm/export_ml_dsa_armv8.c
  - crypto/mldsa/src/asm/export_ml_dsa_armv8.h
  - crypto/mldsa/src/asm/polyz_unpack_table.c
  - crypto/mldsa/src/asm/rej_uniform_table.c
  - crypto/mldsa/src/ml_dsa_core.c
  - crypto/mldsa/src/ml_dsa_local.h
  - crypto/mldsa/src/noasm/export_mldsa_c.c
  - crypto/mldsa/src/noasm/ml_dsa_ntt.c

**Config** (1 files):
  - config/json/feature.json

**Other** (13 files):
  - crypto/mldsa/src/asm/decompose_armv8.S
  - crypto/mldsa/src/asm/intt_armv8.S
  - crypto/mldsa/src/asm/ntt_armv8.S
  - crypto/mldsa/src/asm/pointwise_acc_montgomery_armv8.S
  - crypto/mldsa/src/asm/pointwise_montgomery_armv8.S
  - crypto/mldsa/src/asm/polyz_unpack_armv8.S
  - crypto/mldsa/src/asm/power2round_armv8.S
  - crypto/mldsa/src/asm/rej_uniform_armv8.S
  - crypto/mldsa/src/asm/rej_uniform_eta2_armv8.S
  - crypto/mldsa/src/asm/rej_uniform_eta4_armv8.S
  - crypto/mldsa/src/asm/usehint_armv8.S
  - crypto/mldsa/src/asm/validity_check_armv8.S
  - crypto/mldsa/src/asm/vec_opts_x8_armv8.S


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat e6f9560091967dbcdddde9c74ce5a8aa771cba08 mr-1153`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff e6f9560091967dbcdddde9c74ce5a8aa771cba08 mr-1153 -- <file>`
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
