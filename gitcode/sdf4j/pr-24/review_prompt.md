# Change Review Task

You are reviewing PR #24 for openHiTLS/sdf4j.


## Changed Files (21 files)

**Source** (15 files):
  - sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/constants/AlgorithmID.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/internal/NativeLibraryLoader.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/DeviceInfo.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCCipher.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCKeyEncryptionResult.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPrivateKey.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCPublicKey.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/ECCSignature.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridSignature.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/KeyAgreementResult.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPrivateKey.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/RSAPublicKey.java
  - sdf4j/src/main/java/org/openhitls/sdf4j/types/package-info.java

**Test** (3 files):
  - examples/src/test/java/org/openhitls/SM2ExampleTest.java
  - examples/src/test/java/org/openhitls/SM3ExampleTest.java
  - examples/src/test/java/org/openhitls/SM4ExampleTest.java

**Other** (3 files):
  - "docs/\345\274\200\345\217\221\346\214\207\345\215\227.md"
  - "docs/\346\265\213\350\257\225\346\214\207\345\215\227.md"
  - script/build_with_simulator.sh


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 73f492f08081f9fa7d08c7c03869459a6e629426 mr-24`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 73f492f08081f9fa7d08c7c03869459a6e629426 mr-24 -- <file>`
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
