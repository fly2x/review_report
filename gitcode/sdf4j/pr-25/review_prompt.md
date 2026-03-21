# Change Review Task

You are reviewing PR #25 for openHiTLS/sdf4j.


## Local Repository Context

- Repository root: `sdf4j-25/sdf4j`
- Base ref: `3aa8a144ae67756bbc401d11e6a4ae8213804778`
- Head ref: `mr-25`
- The change under review is already checked out locally in this repository.

## Changed Files (22 files)

**Source** (17 files):
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM2KeyPairGenerator.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM4KeyGenerator.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/random/SDFSecureRandom.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java
  - sdf4j/src/main/native/src/sdf_jni_asymmetric.c
  - sdf4j/src/main/native/src/sdf_jni_device.c
  - sdf4j/src/main/native/src/sdf_jni_file.c
  - sdf4j/src/main/native/src/sdf_jni_hybrid.c
  - sdf4j/src/main/native/src/sdf_jni_key.c
  - sdf4j/src/main/native/src/sdf_jni_keygen.c
  - sdf4j/src/main/native/src/sdf_jni_symmetric.c
  - sdf4j/src/main/native/src/sdf_jni_util.c

**Test** (4 files):
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceAlgorithmTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceExamplesTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SM2InnerTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SM4InnerTest.java

**Other** (1 files):
  - script/build_with_simulator.sh


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- Do NOT search the web.
- Do NOT open GitHub, GitLab, Gitee, or GitCode pages for this review.
- Do NOT rely on remote PR pages or web search results for code analysis.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 3aa8a144ae67756bbc401d11e6a4ae8213804778 mr-25`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 3aa8a144ae67756bbc401d11e6a4ae8213804778 mr-25 -- <file>`
   - If you need more context, read the full file or search for related code
   - Look for: security issues, logic errors, edge cases, error handling
   - Treat assembly files (`.S`, `.s`, `.asm`) as source code and review ABI/calling convention,
     register and stack preservation, memory addressing, bounds, and architecture guards
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
   - Assembly: calling convention mismatches, save/restore bugs, bad clobbers,
     stack alignment, incorrect addressing, missing feature/architecture guards
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
