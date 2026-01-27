# Code Review Task

You are reviewing PR #11 for openHiTLS/sdf4j.


## Changed Files (24 files)

**Source** (21 files):
  - sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java
  - sdf4j/src/main/native/include/dynamic_loader.h
  - sdf4j/src/main/native/include/org_openhitls_sdf4j_SDF.h
  - sdf4j/src/main/native/include/org_openhitls_sdf4j_internal_NativeLibraryLoader.h
  - sdf4j/src/main/native/include/sdf.h
  - sdf4j/src/main/native/include/sdf_jni_common.h
  - sdf4j/src/main/native/include/sdf_jni_functions.h
  - sdf4j/src/main/native/include/sdf_log.h
  - sdf4j/src/main/native/include/type_conversion.h
  - sdf4j/src/main/native/src/dynamic_loader.c
  - sdf4j/src/main/native/src/jni_cache.c
  - sdf4j/src/main/native/src/sdf_jni_asymmetric.c
  - sdf4j/src/main/native/src/sdf_jni_device.c
  - sdf4j/src/main/native/src/sdf_jni_file.c
  - sdf4j/src/main/native/src/sdf_jni_key.c
  - sdf4j/src/main/native/src/sdf_jni_keygen.c
  - sdf4j/src/main/native/src/sdf_jni_log.c
  - sdf4j/src/main/native/src/sdf_jni_register.c
  - sdf4j/src/main/native/src/sdf_jni_symmetric.c
  - sdf4j/src/main/native/src/sdf_jni_util.c
  - ... and 1 more

**Test** (2 files):
  - examples/src/test/java/org/openhitls/sdf4j/examples/KeyManagementTest.java
  - examples/src/test/java/org/openhitls/sdf4j/examples/ResourceManagementTest.java

**Docs** (1 files):
  - sdf4j/src/main/native/CMakeLists.txt


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 7c7da1f2971c47890409448e6234878439d89744 mr-11`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 7c7da1f2971c47890409448e6234878439d89744 mr-11 -- <file>`
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
