# Code Review Task

You are reviewing PR #993 for openHiTLS/openhitls.


## Changed Files (25 files)

**Source** (23 files):
  - crypto/slh_dsa/src/slh_dsa.c
  - crypto/slh_dsa/src/slh_dsa_hash.c
  - crypto/slh_dsa/src/slh_dsa_hypertree.c
  - crypto/slh_dsa/src/slh_dsa_local.h
  - crypto/slh_dsa/src/slh_dsa_wots.c
  - crypto/slh_dsa/src/slh_dsa_wots.h
  - crypto/slh_dsa/src/slh_dsa_xmss.c
  - crypto/slh_dsa/src/slh_dsa_xmss.h
  - crypto/xmss/include/crypt_xmss.h
  - crypto/xmss/src/xmss.c
  - crypto/xmss/src/xmss_address.c
  - crypto/xmss/src/xmss_address.h
  - crypto/xmss/src/xmss_core.c
  - crypto/xmss/src/xmss_hash.c
  - crypto/xmss/src/xmss_hash.h
  - crypto/xmss/src/xmss_local.h
  - crypto/xmss/src/xmss_params.c
  - crypto/xmss/src/xmss_params.h
  - crypto/xmss/src/xmss_tree.c
  - crypto/xmss/src/xmss_tree.h
  - ... and 3 more

**Test** (1 files):
  - testcode/sdv/testcase/crypto/xmss/test_suite_sdv_eal_xmss.data

**Config** (1 files):
  - config/json/feature.json


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 63f700386a2f9fbe1695ca0cbc3759c4a6671fd2 mr-993`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 63f700386a2f9fbe1695ca0cbc3759c4a6671fd2 mr-993 -- <file>`
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
