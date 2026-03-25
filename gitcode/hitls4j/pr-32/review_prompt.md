# Change Review Task

You are reviewing PR #32 for openHiTLS/hitls4j.


## Changed Files (36 files)

**Source** (33 files):
  - src/main/java/org/openhitls/crypto/core/CryptoNative.java
  - src/main/java/org/openhitls/crypto/core/pqc/FrodoKEMImpl.java
  - src/main/java/org/openhitls/crypto/core/pqc/McElieceImpl.java
  - src/main/java/org/openhitls/crypto/jce/interfaces/FrodoKEMKey.java
  - src/main/java/org/openhitls/crypto/jce/interfaces/FrodoKEMPrivateKey.java
  - src/main/java/org/openhitls/crypto/jce/interfaces/FrodoKEMPublicKey.java
  - src/main/java/org/openhitls/crypto/jce/interfaces/McElieceKey.java
  - src/main/java/org/openhitls/crypto/jce/interfaces/McEliecePrivateKey.java
  - src/main/java/org/openhitls/crypto/jce/interfaces/McEliecePublicKey.java
  - src/main/java/org/openhitls/crypto/jce/key/FrodoKEMCiphertextKey.java
  - src/main/java/org/openhitls/crypto/jce/key/FrodoKEMPrivateKeyImpl.java
  - src/main/java/org/openhitls/crypto/jce/key/FrodoKEMPublicKeyImpl.java
  - src/main/java/org/openhitls/crypto/jce/key/McElieceCiphertextKey.java
  - src/main/java/org/openhitls/crypto/jce/key/McEliecePrivateKeyImpl.java
  - src/main/java/org/openhitls/crypto/jce/key/McEliecePublicKeyImpl.java
  - src/main/java/org/openhitls/crypto/jce/key/factory/FrodoKEMKeyFactory.java
  - src/main/java/org/openhitls/crypto/jce/key/factory/McElieceKeyFactory.java
  - src/main/java/org/openhitls/crypto/jce/key/generator/FrodoKEMKeyPairGenerator.java
  - src/main/java/org/openhitls/crypto/jce/key/generator/McElieceKeyPairGenerator.java
  - src/main/java/org/openhitls/crypto/jce/keyagreement/FrodoKEMKeyAgreement.java
  - ... and 13 more

**Test** (2 files):
  - src/test/java/org/openhitls/crypto/jce/pqc/FrodoKEMTest.java
  - src/test/java/org/openhitls/crypto/jce/pqc/McElieceTest.java

**Docs** (1 files):
  - README.md


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 90464bee7d7aee4b59f8e79d4cfe7aa1c64d2e61 mr-32`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 90464bee7d7aee4b59f8e79d4cfe7aa1c64d2e61 mr-32 -- <file>`
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
