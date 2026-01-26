# Code Review Task

You are reviewing PR #1004 for openHiTLS/openhitls.


## Changed Files (30 files)

**Source** (19 files):
  - bsl/async/include/async_local.h
  - bsl/async/src/async.c
  - bsl/async/src/async_context_local.h
  - bsl/async/src/async_local.h
  - bsl/async/src/async_notify.c
  - bsl/async/src/noasm/linux_coroutine_context.c
  - bsl/sal/include/sal_async.h
  - bsl/sal/include/sal_mem.h
  - bsl/sal/src/posix/posix_mem.c
  - bsl/sal/src/posix/posix_sal_asyncimpl.c
  - bsl/sal/src/sal_async.c
  - bsl/sal/src/sal_asyncimpl.h
  - bsl/sal/src/sal_ctrl.c
  - bsl/sal/src/sal_mem.c
  - bsl/sal/src/sal_memimpl.h
  - config/macro_config/hitls_config_layer_bsl.h
  - include/bsl/bsl_async.h
  - include/bsl/bsl_errno.h
  - include/bsl/bsl_sal.h

**Test** (8 files):
  - testcode/script/execute_sdv.sh
  - testcode/sdv/CMakeLists.txt
  - testcode/sdv/testcase/bsl/async/test_suite_sdv_async.c
  - testcode/sdv/testcase/bsl/async/test_suite_sdv_async.data
  - testcode/sdv/testcase/bsl/async/test_suite_sdv_async_notify_ctx.c
  - testcode/sdv/testcase/bsl/async/test_suite_sdv_async_notify_ctx.data
  - testcode/sdv/testcase/bsl/async/test_suite_sdv_async_pool.c
  - testcode/sdv/testcase/bsl/async/test_suite_sdv_async_pool.data

**Config** (3 files):
  - config/json/compile.json
  - config/json/complete_options.json
  - config/json/feature.json


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 1ce55ba421cb1c0c15358d683163bd67146969c6 mr-1004`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 1ce55ba421cb1c0c15358d683163bd67146969c6 mr-1004 -- <file>`
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
