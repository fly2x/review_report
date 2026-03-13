# Change Review Task

You are reviewing PR #22 for openHiTLS/sdf4j.


## Changed Files (45 files)

**Source** (31 files):
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/NativeLoader.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFJceErrorCode.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFJceException.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFJceNative.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/SDFProvider.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM2Cipher.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/cipher/SM4Cipher.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/digest/SM3MessageDigest.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PrivateKey.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/key/SM2PublicKey.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM2KeyPairGenerator.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/keygen/SM4KeyGenerator.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/HmacSM3.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/mac/SM4Mac.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/random/SDFSecureRandom.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/signature/SM2Signature.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/spec/SM2ParameterSpec.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/DERCodec.java
  - sdf4j-jce/src/main/java/org/openhitls/sdf4j/jce/util/SM2Util.java
  - sdf4j-jce/src/main/native/include/jce_common.h
  - ... and 11 more

**Test** (9 files):
  - examples/src/test/java/org/openhitls/SM2ExampleTest.java
  - examples/src/test/java/org/openhitls/SM3ExampleTest.java
  - examples/src/test/java/org/openhitls/SM4ExampleTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceAlgorithmTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFJceExamplesTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SDFProviderTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SM2InnerTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/SM4VectorTest.java
  - sdf4j-jce/src/test/java/org/openhitls/sdf4j/jce/key/SM2KeyTest.java

**Docs** (2 files):
  - sdf4j-jce/README.md
  - sdf4j-jce/src/main/native/CMakeLists.txt

**Other** (3 files):
  - pom.xml
  - sdf4j-jce/pom.xml
  - sdf4j-jce/src/main/resources/sdf4j-jce.properties


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 73f492f08081f9fa7d08c7c03869459a6e629426 mr-22`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 73f492f08081f9fa7d08c7c03869459a6e629426 mr-22 -- <file>`
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
