# Change Review Task

You are reviewing PR #21 for openHiTLS/sdf4j.


## Changed Files (28 files)

**Source** (24 files):
  - sdf4j/src/main/java/org/openhitls/sdf4j/SDFException.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/DeviceInfo.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCKeyEncryptionResult.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPrivateKey.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPublicKey.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCSignature.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridSignature.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/KeyEncryptionResult.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPublicKey.java
  - sdf4j/src/main/native/include/jni_cache.h
  - sdf4j/src/main/native/include/type_conversion.h
  - sdf4j/src/main/native/src/jni_cache.c
  - sdf4j/src/main/native/src/sdf_jni_asymmetric.c
  - sdf4j/src/main/native/src/sdf_jni_file.c
  - sdf4j/src/main/native/src/sdf_jni_hybrid.c
  - sdf4j/src/main/native/src/sdf_jni_key.c
  - sdf4j/src/main/native/src/sdf_jni_keygen.c
  - ... and 4 more

**Test** (4 files):
  - sdf4j/src/test/java/org/openhitls/sdf4j/DeviceAndSessionManageTest.java
  - sdf4j/src/test/java/org/openhitls/sdf4j/JniValidationTest.java
  - sdf4j/src/test/java/org/openhitls/sdf4j/types/ECCSignatureTest.java
  - sdf4j/src/test/java/org/openhitls/sdf4j/types/TypeValidationTest.java


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 9867718249fcded3611be9a9b74f99ca45ea2ed7 mr-21`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 9867718249fcded3611be9a9b74f99ca45ea2ed7 mr-21 -- <file>`
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
