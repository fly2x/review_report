# Code Review: openHiTLS/openhitls#1004
**Reviewer**: GEMINI


## Critical

### Use-after-free / Dangling pointer in RegisterFd
`bsl/async/src/async_notify.c:159-163`
```
newFd->next = ctx->fds;
    ctx->fds = newFd;

    if (ctx->fdChangeList != NULL) {
        struct AsyncFdEvent *event = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
        if (event == NULL) {
            BSL_SAL_FREE(newFd);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        event->fd = fd;
        event->type = ASYNC_EVENT_ADD;
        if (BSL_LIST_AddElement(ctx->fdChangeList, event, BSL_LIST_POS_END) != BSL_SUCCESS) {
            BSL_SAL_FREE(event);
            BSL_SAL_FREE(newFd);
            return BSL_ASYNC_ERR;
        }
    }
```
**Issue**: `newFd` is linked to `ctx->fds` before the `BSL_LIST_AddElement` call. If `BSL_LIST_AddElement` fails, `newFd` is freed, but `ctx->fds` still points to it. This leaves a dangling pointer in the linked list, leading to use-after-free or double-free later.
**Fix**:
```
if (ctx->fdChangeList != NULL) {
        struct AsyncFdEvent *event = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
        if (event == NULL) {
            BSL_SAL_FREE(newFd);
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        event->fd = fd;
        event->type = ASYNC_EVENT_ADD;
        if (BSL_LIST_AddElement(ctx->fdChangeList, event, BSL_LIST_POS_END) != BSL_SUCCESS) {
            BSL_SAL_FREE(event);
            BSL_SAL_FREE(newFd);
            return BSL_ASYNC_ERR;
        }
    }

    newFd->next = ctx->fds;
    ctx->fds = newFd;
```

---

### Race condition in BSL_ASYNC_ScheduleNew due to local lock
`bsl/async/src/async.c:491-496`
```
BSL_SAL_ThreadLockHandle scheduleNewLock = NULL;
    int32_t ret = BSL_SAL_ThreadLockNew(&scheduleNewLock);
    if (ret != BSL_SUCCESS) {
        UnlockAndFree(scheduleNewLock);
        scheduleNewLock = NULL;
        return ret;
    }

    int32_t err = BSL_SUCCESS;
    struct AsyncSchedule *schedule = NULL;
    do {
        BSL_SAL_ThreadWriteLock(scheduleNewLock);
        schedule = ScheduleAlloc();
```
**Issue**: `BSL_ASYNC_ScheduleNew` creates a new lock (`scheduleNewLock`) on every call using `BSL_SAL_ThreadLockNew`. This local lock fails to synchronize multiple threads attempting to initialize the global `g_schedule`, leading to race conditions, memory leaks (multiple allocations of `schedule`), and undefined behavior.
**Fix**:
```
/* Use a static/global lock or atomic compare-and-swap to protect initialization */
    static BSL_SAL_ThreadLockHandle g_initLock = NULL;
    /* (Initialization of g_initLock logic needed, e.g., via pthread_once or atomic) */
    
    /* Alternatively, assume single-threaded initialization or use atomic check first */
    if (ScheduleGet() != NULL) {
         return BSL_SUCCESS;
    }
    
    /* Proper fix requires a persistent lock, not a local one. 
       If BSL_SAL provides a global lock mechanism, use it. 
       Otherwise: */
    // ... Implementation depends on BSL_SAL capabilities for global locks ...
```

---


## High

### Buffer overflow in BSL_NOTIFY_CTX_PollFdChanges
`bsl/async/src/async_notify.c:218-220`
```
int32_t BSL_NOTIFY_CTX_PollFdChanges(HITLS_NOTIFY_Ctx *ctx, int *addedFds, uint32_t *addedCount,
    int *removedFds, uint32_t *removedCount)
```
**Issue**: The function accepts pointers `addedFds` and `removedFds` but no arguments specifying their buffer sizes. It writes to these arrays based on the number of events in the list (`addTotal`, `delTotal`). If the caller provides a buffer smaller than the number of events, a heap/stack overflow will occur.
**Fix**:
```
int32_t BSL_NOTIFY_CTX_PollFdChanges(HITLS_NOTIFY_Ctx *ctx, int *addedFds, uint32_t *addedCount,
    int *removedFds, uint32_t *removedCount)
{
    // ...
    // Treat addedCount and removedCount as IN/OUT or add new size parameters
    uint32_t maxAdd = (addedCount != NULL) ? *addedCount : 0;
    uint32_t maxDel = (removedCount != NULL) ? *removedCount : 0;
    // ...
    if (addedFds != NULL && addWriteIdx < maxAdd) {
        addedFds[addWriteIdx++] = event->fd;
    }
    // ...
}
```

---

### BSL_ASYNC_Free destroys thread-local context breaking other coroutines
`bsl/async/src/async.c:704`
```
void BSL_ASYNC_Free(HITLS_Coroutine *job)
{
    AsyncCtxFree();
    if (job == NULL) {
        return;
    }
    AsyncReleaseJob(job);
}
```
**Issue**: `BSL_ASYNC_Free` calls `AsyncCtxFree()`, which frees the thread-local `AsyncCtx` (`g_coroutineCtxKey`). If this is called while other coroutines are active on the same thread (e.g., from within another coroutine), it destroys the shared execution environment/dispatcher, causing subsequent crashes or inability to yield/schedule.
**Fix**:
```
void BSL_ASYNC_Free(HITLS_Coroutine *job)
{
    /* Do not free the thread-local context here. 
       It should be freed only when the thread exits or via a specific cleanup API. */
    // AsyncCtxFree(); 
    if (job == NULL) {
        return;
    }
    AsyncReleaseJob(job);
}
```

---


## Medium

### Invalid assertion in test UT_BSL_NOTIFY_CTX_POLL_REMOVED_FD_TC001
`testcode/sdv/testcase/bsl/async/test_suite_sdv_async_notify_ctx.c:531`
```
ASSERT_EQ(addedCount, 0);
    ASSERT_EQ(removedCount, 0);
    ASSERT_EQ(removedFds[0], fd);
```
**Issue**: The test expects `removedCount` to be 0, but then checks `removedFds[0] == fd`. If `removedCount` is 0, `removedFds` contains initialized zeros (from line 523), so `removedFds[0]` is 0, which does not equal `fd` (10). This test is logically inconsistent.
**Fix**:
```
ASSERT_EQ(addedCount, 0);
    ASSERT_EQ(removedCount, 0);
    /* Since removedCount is 0, checking removedFds[0] is invalid/meaningless unless we expect it to be 0 */
    // ASSERT_EQ(removedFds[0], fd);
```

---
