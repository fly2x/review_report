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
