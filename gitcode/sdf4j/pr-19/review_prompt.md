# Change Review Task

You are reviewing PR #19 for openHiTLS/sdf4j.


## Changed Files (12 files)

**Source** (10 files):
  - sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/KeyAgreementResult.java
  - sdf4j/src/main/native/include/jni_cache.h
  - sdf4j/src/main/native/include/sdf_jni_functions.h
  - sdf4j/src/main/native/include/type_conversion.h
  - sdf4j/src/main/native/src/jni_cache.c
  - sdf4j/src/main/native/src/sdf_jni_key.c
  - sdf4j/src/main/native/src/sdf_jni_keygen.c
  - sdf4j/src/main/native/src/sdf_jni_register.c
  - sdf4j/src/main/native/src/type_conversion.c

**Test** (1 files):
  - sdf4j/src/test/java/org/openhitls/sdf4j/KeyManagementTest.java

**Other** (1 files):
  - examples/pom.xml


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat ade8ea47b54ee8c063adc9f95e4b5aa484c24303 mr-19`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff ade8ea47b54ee8c063adc9f95e4b5aa484c24303 mr-19 -- <file>`
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
