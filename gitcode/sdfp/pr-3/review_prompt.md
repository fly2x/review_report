# Change Review Task

You are reviewing PR #3 for openHiTLS/sdfp.


## Changed Files (19 files)

**Source** (17 files):
  - src/bsl_bytes.h
  - src/log.c
  - src/log.h
  - src/provider.c
  - src/provider.h
  - src/rsa_keymgmt.c
  - src/rsa_local.h
  - src/rsa_padding.c
  - src/rsa_pkeycipher.c
  - src/rsa_sign.c
  - src/sdf_dl.c
  - src/sdf_dl.h
  - src/sm2_keyexch.c
  - src/sm2_keymgmt.c
  - src/sm2_local.h
  - src/sm2_pkeycipher.c
  - src/sm2_sign.c

**Docs** (1 files):
  - CMakeLists.txt

**Other** (1 files):
  - src/version.lds


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 875ed94bc80654f9627e133c31a1c3e1bdb06204 mr-3`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 875ed94bc80654f9627e133c31a1c3e1bdb06204 mr-3 -- <file>`
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
