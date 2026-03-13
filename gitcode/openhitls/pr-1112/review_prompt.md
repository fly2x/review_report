# Change Review Task

You are reviewing PR #1112 for openHiTLS/openhitls.


## Changed Files (12 files)

**Source** (10 files):
  - crypto/sha3/src/noasm_sha3.c
  - crypto/sha3/src/sha3_core.h
  - crypto/slh_dsa/src/slh_dsa.c
  - crypto/slh_dsa/src/slh_dsa_hash.c
  - crypto/slh_dsa/src/slh_dsa_hash.h
  - crypto/slh_dsa/src/slh_dsa_local.h
  - crypto/xmss/src/xmss_common.h
  - crypto/xmss/src/xmss_hash.c
  - crypto/xmss/src/xmss_wots.c
  - crypto/xmss/src/xmss_wots.h

**Config** (1 files):
  - config/json/feature.json

**Other** (1 files):
  - crypto/sha3/src/asm/sha3_armv8.S


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 97f213948e96c50051f9b01e5cac3705a3aee77c mr-1112`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 97f213948e96c50051f9b01e5cac3705a3aee77c mr-1112 -- <file>`
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
