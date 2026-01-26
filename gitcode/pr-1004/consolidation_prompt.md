# Code Review Consolidation Task

You are consolidating code review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1004
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/openhitls#1004
**Reviewer**: CLAUDE


## High

### Struct copy overwrites caller's job pointer contents
`bsl/async/src/async.c:658`
```
if (status == ASYNC_JOB_PAUSING) {
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05093, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
                          "async start job enter the [pausing] branch.", 0, 0, 0, 0);
    *job = *ctx->currjob;
    ctx->currjob->status = ASYNC_JOB_PAUSED;
    ctx->currjob = NULL;
    return BSL_ASYNC_PAUSE;
}
```
**Issue**: In BSL_ASYNC_Start, when status is ASYNC_JOB_PAUSING, the code performs `*job = *ctx->currjob` which copies the entire Coroutine struct by value to the caller's pointer location. This is problematic because: 1) The caller passes a pointer to their job struct, and this overwrites their entire struct with a copy; 2) If the caller later calls BSL_ASYNC_Free on the job, it may double-free resources or corrupt memory since both the original and the copy may have pointers to the same resources (stack, args, notifyctx).
**Fix**:
```
if (status == ASYNC_JOB_PAUSING) {
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05093, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
                          "async start job enter the [pausing] branch.", 0, 0, 0, 0);
    ctx->currjob->status = ASYNC_JOB_PAUSED;
    ctx->currjob = NULL;
    return BSL_ASYNC_PAUSE;
}
```

---

### Null pointer dereference in AsyncStartRunFunc
`bsl/async/src/async.c:550-553`
```
void AsyncStartRunFunc(void)
{
    HITLS_Coroutine *job = NULL;
    AsyncCtx *ctx = AsyncGetCtx();
    while (true) {
        job = ctx->currjob;
        job->coError = job->func(job->args);
```
**Issue**: In AsyncStartRunFunc, ctx is retrieved from AsyncGetCtx() without a null check. Then ctx->currjob is accessed without validation. If ctx is NULL or ctx->currjob is NULL, this will cause a crash. This function is called as the entry point for coroutines, so if the context is not properly set up, it will dereference null pointers.
**Fix**:
```
void AsyncStartRunFunc(void)
{
    HITLS_Coroutine *job = NULL;
    AsyncCtx *ctx = AsyncGetCtx();
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_ASYNC_JOB_NOT_EXIST);
        return;
    }
    while (true) {
        job = ctx->currjob;
        if (job == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_ASYNC_JOB_NOT_EXIST);
            return;
        }
        job->coError = job->func(job->args);
```

---


## Medium

### Unreachable code after infinite while loop
`bsl/async/src/async.c:672-674`
```
while (true) {
    int status = ctx->currjob->status;
    if (status == ASYNC_JOB_STOPPING) {
        // ... returns
    }
    if (status == ASYNC_JOB_READY) {
        // ... continues
    }
    if (status == ASYNC_JOB_PAUSING) {
        // ... returns
    }
    if (status == ASYNC_JOB_PAUSED) {
        // ... continues
    }
}

AsyncReleaseJob(ctx->currjob);  // Unreachable
ctx->currjob = NULL;
return BSL_ASYNC_ERR;
```
**Issue**: The code after the `while (true)` loop (lines 672-674) is unreachable. The loop only exits via return statements in the status checks. This dead code could indicate a logic error where certain status values are not handled, leading to an infinite loop instead of proper cleanup and return.
**Fix**:
```
while (true) {
    int status = ctx->currjob->status;
    if (status == ASYNC_JOB_STOPPING) {
        *ret = ctx->currjob->coError;
        ctx->currjob = NULL;
        return BSL_ASYNC_FINISH;
    }

    if (status == ASYNC_JOB_READY) {
        ctx->currjob->status = ASYNC_JOB_RUNNING;
        AsyncSwapcontext(&ctx->dispatcher, &ctx->currjob->ctx);
        continue;
    }

    if (status == ASYNC_JOB_PAUSING) {
        ctx->currjob->status = ASYNC_JOB_PAUSED;
        ctx->currjob = NULL;
        return BSL_ASYNC_PAUSE;
    }

    if (status == ASYNC_JOB_PAUSED) {
        ctx->currjob = job;
        AsyncSwapcontext(&ctx->dispatcher, &ctx->currjob->ctx);
        continue;
    }

    // Handle unexpected status - prevents infinite loop
    BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR);
    AsyncReleaseJob(ctx->currjob);
    ctx->currjob = NULL;
    return BSL_ASYNC_ERR;
}
```

---

### FD list corrupted when event allocation fails after node insertion
`bsl/async/src/async_notify.c:146-161`
```
newFd->next = ctx->fds;
ctx->fds = newFd;

if (ctx->fdChangeList != NULL) {
    struct AsyncFdEvent *event = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
    if (event == NULL) {
        BSL_SAL_FREE(newFd);  // ctx->fds still points to freed newFd
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    event->fd = fd;
    event->type = ASYNC_EVENT_ADD;
    if (BSL_LIST_AddElement(ctx->fdChangeList, event, BSL_LIST_POS_END) != BSL_SUCCESS) {
        BSL_SAL_FREE(event);
        BSL_SAL_FREE(newFd);  // ctx->fds still points to freed newFd
        return BSL_ASYNC_ERR;
    }
}
```
**Issue**: In BSL_NOTIFY_CTX_RegisterFd, the newFd node is inserted into the ctx->fds linked list before attempting to allocate and add the event to fdChangeList. If the event allocation or list add fails, the newFd is freed but it has already been inserted into ctx->fds. This leaves ctx->fds pointing to freed memory, causing use-after-free on subsequent list traversals.
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

// Only insert into list after all allocations succeed
newFd->next = ctx->fds;
ctx->fds = newFd;
```

---

### Static variable g_pageSize may have inconsistent values in multi-threaded context
`bsl/async/include/async_local.h:107-113`
```
static size_t g_pageSize;

static inline size_t GetPageSize(void)
{
    if (g_pageSize == 0) {
        g_pageSize = (size_t)SAL_GetPageSize();
    }
    return g_pageSize;
}
```
**Issue**: The g_pageSize static variable is declared with file-scope static storage in a header file. When this header is included in multiple translation units, each unit gets its own separate copy of g_pageSize. Additionally, the GetPageSize() function has a race condition: multiple threads could simultaneously read g_pageSize as 0 and call SAL_GetPageSize(), leading to redundant calls. While not a correctness bug, declaring static variables in headers is poor practice.
**Fix**:
```
// In async_local.h - declare extern
extern size_t g_pageSize;

static inline size_t GetPageSize(void)
{
    if (g_pageSize == 0) {
        g_pageSize = (size_t)SAL_GetPageSize();
    }
    return g_pageSize;
}

// In async.c - define the variable
size_t g_pageSize = 0;
```

---

### Race condition in BSL_ASYNC_ScheduleNew with double-check pattern
`bsl/async/src/async.c:475-490`
```
int32_t BSL_ASYNC_ScheduleNew(const struct ScheduleAttr *scheAttr)
{
    if (ScheduleGet() != NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05099, BSL_LOG_LEVEL_DEBUG, BSL_LOG_BINLOG_TYPE_RUN,
                              "schedule new previously.", 0, 0, 0, 0);
        return BSL_SUCCESS;
    }

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
```
**Issue**: BSL_ASYNC_ScheduleNew checks if ScheduleGet() != NULL at line 475 without holding a lock. Then it creates a new lock at line 480 and acquires it at line 491. However, another thread could have completed the same function between the initial check and the lock acquisition, resulting in double initialization. The lock created on each call doesn't protect against concurrent calls from different threads.
**Fix**:
```
static BSL_SAL_ThreadLockHandle g_scheduleInitLock = NULL;

int32_t BSL_ASYNC_ScheduleNew(const struct ScheduleAttr *scheAttr)
{
    // Double-checked locking with a global lock
    if (ScheduleGet() != NULL) {
        return BSL_SUCCESS;
    }

    // Use a static/global lock for thread-safe initialization
    if (g_scheduleInitLock == NULL) {
        int32_t ret = BSL_SAL_ThreadLockNew(&g_scheduleInitLock);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }

    BSL_SAL_ThreadWriteLock(g_scheduleInitLock);
    
    // Re-check after acquiring lock
    if (ScheduleGet() != NULL) {
        BSL_SAL_ThreadUnlock(g_scheduleInitLock);
        return BSL_SUCCESS;
    }
    
    // ... rest of initialization
```

---

### Key update in BSL_NOTIFY_CTX_RegisterFd skips event tracking
`bsl/async/src/async_notify.c:118-133`
```
HITLS_ASYNC_NotifyFd *curr = ctx->fds;
while (curr != NULL) {
    if (curr->key == key) {
        if (curr->cleanup != NULL) {
            curr->cleanup(ctx, curr->fd);
        }
        curr->fd = fd;
        curr->customData = customData;
        curr->cleanup = cleanup;
        return BSL_SUCCESS;  // No event added for the change
    }
    curr = curr->next;
}
```
**Issue**: When updating an existing FD entry by key, the function updates the fd value but does not add an event to fdChangeList. This means callers using BSL_NOTIFY_CTX_PollFdChanges won't be notified that the FD was changed, potentially causing them to poll on an old file descriptor.
**Fix**:
```
HITLS_ASYNC_NotifyFd *curr = ctx->fds;
while (curr != NULL) {
    if (curr->key == key) {
        int oldFd = curr->fd;
        if (curr->cleanup != NULL) {
            curr->cleanup(ctx, curr->fd);
        }
        curr->fd = fd;
        curr->customData = customData;
        curr->cleanup = cleanup;
        
        // Track the FD change if FD value changed
        if (ctx->fdChangeList != NULL && oldFd != fd) {
            // Add DEL event for old FD
            struct AsyncFdEvent *delEvent = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
            if (delEvent != NULL) {
                delEvent->fd = oldFd;
                delEvent->type = ASYNC_EVENT_DEL;
                (void)BSL_LIST_AddElement(ctx->fdChangeList, delEvent, BSL_LIST_POS_END);
            }
            // Add ADD event for new FD
            struct AsyncFdEvent *addEvent = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
            if (addEvent != NULL) {
                addEvent->fd = fd;
                addEvent->type = ASYNC_EVENT_ADD;
                (void)BSL_LIST_AddElement(ctx->fdChangeList, addEvent, BSL_LIST_POS_END);
            }
        }
        return BSL_SUCCESS;
    }
    curr = curr->next;
}
```

---


## Low

### BSL_NOTIFY_CTX_LookupFd returns marked-for-deletion entries
`bsl/async/src/async_notify.c:174-183`
```
HITLS_ASYNC_NotifyFd *curr = ctx->fds;
while (curr != NULL) {
    if (curr->key == key) {
        *fd = curr->fd;
        if (customData != NULL) {
            *customData = curr->customData;
        }
        return BSL_SUCCESS;
    }
    curr = curr->next;
}
```
**Issue**: The BSL_NOTIFY_CTX_LookupFd function searches for an FD by key but does not check the `del` flag. It may return an FD that has been marked for deletion (curr->del == true), which could lead to the caller using a stale/invalid file descriptor.
**Fix**:
```
HITLS_ASYNC_NotifyFd *curr = ctx->fds;
while (curr != NULL) {
    if (curr->key == key && !curr->del) {
        *fd = curr->fd;
        if (customData != NULL) {
            *customData = curr->customData;
        }
        return BSL_SUCCESS;
    }
    curr = curr->next;
}
```

---

### UnlockAndFree called on potentially uninitialized lock on failure
`bsl/async/src/async.c:487-489`
```
int32_t ret = BSL_SAL_ThreadLockNew(&scheduleNewLock);
if (ret != BSL_SUCCESS) {
    UnlockAndFree(scheduleNewLock);
    scheduleNewLock = NULL;
    return ret;
}
```
**Issue**: If BSL_SAL_ThreadLockNew fails, it may leave scheduleNewLock in an undefined state (not necessarily NULL). The code then calls UnlockAndFree on it, which calls BSL_SAL_ThreadUnlock on a potentially invalid handle. This could cause undefined behavior.
**Fix**:
```
int32_t ret = BSL_SAL_ThreadLockNew(&scheduleNewLock);
if (ret != BSL_SUCCESS) {
    // On failure, scheduleNewLock is undefined - don't try to unlock/free
    return ret;
}
```

---

### CheckProt does not allow PROT_READ | PROT_EXEC or other valid combinations
`bsl/sal/src/posix/posix_mem.c:79-83`
```
static bool CheckProt(int val)
{
    if (val == PROT_READ || val == PROT_WRITE || val == PROT_NONE) {
        return true;
    }
    
    if (val == (PROT_READ | PROT_WRITE)) {
        return true;
    }
    return false;
}
```
**Issue**: The CheckProt function only allows specific combinations: PROT_READ, PROT_WRITE, PROT_NONE, and PROT_READ|PROT_WRITE. However, PROT_READ|PROT_EXEC is a valid and commonly used combination for executable memory. The current implementation would reject valid protection flags.
**Fix**:
```
static bool CheckProt(int val)
{
    // Allow combinations of PROT_READ, PROT_WRITE, and PROT_EXEC, or PROT_NONE
    if (val == PROT_NONE) {
        return true;
    }
    
    // Check that only valid protection bits are set
    int validBits = PROT_READ | PROT_WRITE | PROT_EXEC;
    if ((val & ~validBits) != 0) {
        return false;
    }
    
    // At least one protection bit should be set
    return (val & validBits) != 0;
}
```

---

### BSL_NOTIFY_CTX_CollectAllFds counts deleted FDs
`bsl/async/src/async_notify.c:196-200`
```
uint32_t fdCount = 0;
HITLS_ASYNC_NotifyFd *curr = ctx->fds;
while (curr != NULL) {
    fdCount++;
    curr = curr->next;
}
```
**Issue**: The BSL_NOTIFY_CTX_CollectAllFds function counts all FD nodes including those marked for deletion (del == true). This could return an incorrect count to the caller, who may allocate insufficient buffer space if they expect only active FDs.
**Fix**:
```
uint32_t fdCount = 0;
HITLS_ASYNC_NotifyFd *curr = ctx->fds;
while (curr != NULL) {
    if (!curr->del) {
        fdCount++;
    }
    curr = curr->next;
}
```

---

### BSL_NOTIFY_CTX_CollectAllFds copies deleted FDs
`bsl/async/src/async_notify.c:207-212`
```
uint32_t idx = 0;
curr = ctx->fds;
while (curr != NULL && idx < *count) {
    fds[idx++] = curr->fd;
    curr = curr->next;
}
```
**Issue**: When copying FDs to the output array, the function copies all FDs including those marked for deletion. This could expose stale/invalid file descriptors to callers.
**Fix**:
```
uint32_t idx = 0;
curr = ctx->fds;
while (curr != NULL && idx < *count) {
    if (!curr->del) {
        fds[idx++] = curr->fd;
    }
    curr = curr->next;
}
```

---


---

## GEMINI Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1004
**Reviewer**: CODEX


## High

### RegisterFd can leave a freed node in the list
`bsl/async/src/async_notify.c:142-161`
```
newFd->next = ctx->fds;
ctx->fds = newFd;

if (ctx->fdChangeList != NULL) {
    struct AsyncFdEvent *event = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
    if (event == NULL) {
        BSL_SAL_FREE(newFd);
        ...
    }
    ...
    if (BSL_LIST_AddElement(ctx->fdChangeList, event, BSL_LIST_POS_END) != BSL_SUCCESS) {
        BSL_SAL_FREE(event);
        BSL_SAL_FREE(newFd);
        return BSL_ASYNC_ERR;
    }
}
```
**Issue**: The new FD node is linked into `ctx->fds` before the change event is created. If event allocation or list insertion fails, the node is freed but `ctx->fds` still points to it, causing list corruption and use-after-free.
**Fix**:
```
struct AsyncFdEvent *event = NULL;
if (ctx->fdChangeList != NULL) {
    event = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
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


## Medium

### Coroutine ID generation never updates the shared counter
`bsl/async/src/async.c:108-116`
```
BSL_SAL_RefCount threadStartNum = {
    .count = ScheduleGet()->idGen
};
ret = BSL_SAL_AtomicUpReferences(&threadStartNum, &ref);
```
**Issue**: The atomic increment is applied to a local copy of `idGen`, so the shared counter in the scheduler is never updated. This returns duplicate IDs and is not thread-safe.
**Fix**:
```
/* async_local.h */
struct AsyncSchedule {
    int32_t state;
    BSL_SAL_RefCount idGen;
    size_t stackSize;
    unsigned int corpoolCoroutineNum;
    bool stackProtect;
    struct CoroutinePool pool;
    BSL_SAL_ThreadLockHandle poolLock;
};

/* async.c */
static struct AsyncSchedule *ScheduleAlloc(void)
{
    struct AsyncSchedule *schedule = (struct AsyncSchedule *)BSL_SAL_Calloc(1, sizeof(struct AsyncSchedule));
    if (schedule == NULL) {
        ...
    }
    (void)BSL_SAL_ReferencesInit(&schedule->idGen);
    schedule->state = SCHEDULE_INIT;
    return schedule;
}

static int32_t CoroutineNewid(void)
{
    int32_t ref = 0;
    struct AsyncSchedule *schedule = ScheduleGet();
    if (schedule == NULL) {
        return 0;
    }
    (void)BSL_SAL_AtomicUpReferences(&schedule->idGen, &ref);
    return ref;
}

void BSL_ASYNC_ScheduleFree(void)
{
    struct AsyncSchedule *schedule = ScheduleGet();
    if (schedule == NULL) {
        return;
    }
    schedule->state = SCHEDULE_EXITING;
    CoroutinePoolDestroy(schedule);
    BSL_SAL_ReferencesFree(&schedule->idGen);
    BSL_SAL_FREE(schedule);
    ScheduleSet(NULL);
}
```

---

### Swapcontext failure check is inverted
`bsl/async/src/async.c:553-560`
```
job->status = ASYNC_JOB_STOPPING;
if (AsyncSwapcontext(&job->ctx, &ctx->dispatcher) == 0) {
    BSL_ERR_PUSH_ERROR(BSL_ASYNC_UCONTEXT_SWAP_FAIL);
    BSL_LOG_BINLOG_FIXLEN(...);
}
```
**Issue**: `AsyncSwapcontext` returns `BSL_SUCCESS` (0) on success, but the code logs an error when it succeeds and ignores real failures. On failure, the coroutine continues looping and re-executes the job.
**Fix**:
```
job->status = ASYNC_JOB_STOPPING;
int32_t swapRet = AsyncSwapcontext(&job->ctx, &ctx->dispatcher);
if (swapRet != BSL_SUCCESS) {
    BSL_ERR_PUSH_ERROR(BSL_ASYNC_UCONTEXT_SWAP_FAIL);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05103, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                          "async start run func swap context fail.", 0, 0, 0, 0);
}
```

---

### Missing status handling causes infinite loop
`bsl/async/src/async.c:636-669`
```
while (true) {
    int status = ctx->currjob->status;
    if (status == ASYNC_JOB_STOPPING) { ... }
    if (status == ASYNC_JOB_READY) { ... }
    if (status == ASYNC_JOB_PAUSING) { ... }
    if (status == ASYNC_JOB_PAUSED) { ... }
}
```
**Issue**: If `status` is `ASYNC_JOB_RUNNING` or any unexpected value, the loop never changes state and spins forever. This can deadlock a caller that accidentally re-enters `BSL_ASYNC_Start`.
**Fix**:
```
while (true) {
    int status = ctx->currjob->status;
    switch (status) {
        case ASYNC_JOB_STOPPING:
            ...
            return BSL_ASYNC_FINISH;
        case ASYNC_JOB_READY:
            ...
            continue;
        case ASYNC_JOB_PAUSING:
            ...
            return BSL_ASYNC_PAUSE;
        case ASYNC_JOB_PAUSED:
            ...
            continue;
        default:
            BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR);
            ctx->currjob = NULL;
            return BSL_ASYNC_ERR;
    }
}
```

---

### Removed FDs are still visible to Lookup and Collect
`bsl/async/src/async_notify.c:168-214`
```
while (curr != NULL) {
    if (curr->key == key) {
        *fd = curr->fd;
        ...
        return BSL_SUCCESS;
    }
    curr = curr->next;
}
```
**Issue**: `RemoveFd` only marks entries as deleted, but `BSL_NOTIFY_CTX_LookupFd` and `BSL_NOTIFY_CTX_CollectAllFds` ignore `del`, so removed FDs remain visible and contradict the expected behavior (tests expect NOT_FOUND after removal).
**Fix**:
```
while (curr != NULL) {
    if (curr->del) {
        curr = curr->next;
        continue;
    }
    if (curr->key == key) {
        *fd = curr->fd;
        if (customData != NULL) {
            *customData = curr->customData;
        }
        return BSL_SUCCESS;
    }
    curr = curr->next;
}
```

---

### PollFdChanges never consumes the change list
`bsl/async/src/async_notify.c:218-259`
```
*addedCount = addTotal;
*removedCount = delTotal;

return BSL_SUCCESS;
```
**Issue**: The function returns the same events on every call and the list grows unbounded. This contradicts the API comment (consume when arrays are provided) and keeps deleted entries from being finalized unless a coroutine yield occurs.
**Fix**:
```
*addedCount = addTotal;
*removedCount = delTotal;

if (addedFds != NULL || removedFds != NULL) {
    AsyncCleanupFdChanges(ctx);
}

return BSL_SUCCESS;
```

---


## Low

### RemoveFd path skips cleanup callback
`bsl/async/src/async_notify.c:314-319`
```
if (*pp == target) {
    *pp = target->next;
    BSL_SAL_FREE(target);
    return true;
}
```
**Issue**: When a newly-added FD is removed before being polled, `NotifyCtxDetachFdNode` frees the node without calling the cleanup callback, leaking resources such as the FD or associated data.
**Fix**:
```
if (*pp == target) {
    if (target->cleanup != NULL) {
        target->cleanup(ctx, target->fd);
    }
    *pp = target->next;
    BSL_SAL_FREE(target);
    return true;
}
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the code
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the code
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
