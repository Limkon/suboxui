/* src/proxy.c */
#include "proxy.h"
#include "proxy_internal.h"
#include "utils.h"
#include "config.h" 
#include "common.h"
#include <openssl/rand.h>
#include <process.h> // for _beginthreadex
#include <errno.h>

// =========================================================================================
// [Architecture Fix] 线程池与并发控制子系统
// 目的: 解决高并发下的"线程爆炸"和 OOM 问题，通过复用线程和限制栈大小提升稳定性。
// =========================================================================================

// [Config] 优化栈大小至 128KB，OpenSSL 调用链通常不需要 512KB，降低内存占用防止 OOM
// 原值: 512 * 1024 -> 新值: 128 * 1024
#define THREAD_POOL_STACK_SIZE (128 * 1024) 

// [Config] 线程池最大容量跟随最大连接数
#define POOL_MAX_WORKERS MAX_CONNECTIONS   
// [Safety Fix] 任务队列最大深度，防止 OOM (例如最大连接数的 2 倍)
#define MAX_PENDING_TASKS (MAX_CONNECTIONS * 2)

// --- 活跃 Socket 追踪器 (用于强制中断) ---
static SOCKET g_active_sockets[MAX_CONNECTIONS];
static CRITICAL_SECTION g_socket_lock;
static volatile BOOL g_sockets_inited = FALSE;

// [Optimization] 使用轮询索引，避免每次从头遍历数组，减少锁持有时间
static int g_socket_search_idx = 0;

void InitSocketTracker() {
    if (!g_sockets_inited) {
        // [Optimization] 使用自旋锁优化临界区性能 (4000 cycles)
        InitializeCriticalSectionAndSpinCount(&g_socket_lock, 4000);
        
        for (int i = 0; i < MAX_CONNECTIONS; i++) g_active_sockets[i] = INVALID_SOCKET;
        g_sockets_inited = TRUE;
        g_socket_search_idx = 0;
    }
}

// [Optimization] O(1) 追踪：返回索引供快速移除
int TrackSocket(SOCKET s) {
    if (s == INVALID_SOCKET) return -1;
    if (!g_sockets_inited) return -1;
    
    int assigned_idx = -1;
    EnterCriticalSection(&g_socket_lock);
    
    // Round-Robin 查找空闲槽位
    int start_idx = g_socket_search_idx;
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        int curr = (start_idx + i) % MAX_CONNECTIONS;
        if (g_active_sockets[curr] == INVALID_SOCKET) {
            g_active_sockets[curr] = s;
            assigned_idx = curr;
            g_socket_search_idx = (curr + 1) % MAX_CONNECTIONS;
            break;
        }
    }
    
    LeaveCriticalSection(&g_socket_lock);
    return assigned_idx;
}

// [Optimization] O(1) 移除：直接通过索引移除
void UntrackSocketByIndex(int idx) {
    if (idx < 0 || idx >= MAX_CONNECTIONS) return;
    if (!g_sockets_inited) return;

    EnterCriticalSection(&g_socket_lock);
    if (g_active_sockets[idx] != INVALID_SOCKET) {
        g_active_sockets[idx] = INVALID_SOCKET;
    }
    LeaveCriticalSection(&g_socket_lock);
}

// 为了兼容性保留旧接口
void UntrackSocket(SOCKET s) {
    if (s == INVALID_SOCKET) return;
    if (!g_sockets_inited) return;

    EnterCriticalSection(&g_socket_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_active_sockets[i] == s) {
            g_active_sockets[i] = INVALID_SOCKET;
            break;
        }
    }
    LeaveCriticalSection(&g_socket_lock);
}

// [Fix] 仅中断 IO，不关闭句柄，防止 Race Condition
void CloseAllActiveSockets() {
    if (!g_sockets_inited) return;

    EnterCriticalSection(&g_socket_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        SOCKET s = g_active_sockets[i];
        if (s != INVALID_SOCKET) {
            // [Critical] 仅 shutdown 唤醒阻塞线程，绝不 closesocket
            shutdown(s, SD_BOTH);
        }
    }
    LeaveCriticalSection(&g_socket_lock);
}

void CleanupSocketTracker() {
    if (g_sockets_inited) {
        DeleteCriticalSection(&g_socket_lock);
        g_sockets_inited = FALSE;
    }
}

// --- 线程池定义 ---

typedef struct TaskNode {
    void (*function)(void*);
    void* argument;
    void (*cleanup)(void*); // 清理回调
    struct TaskNode* next;
} TaskNode;

// 线程池控制结构
typedef struct {
    TaskNode* head;
    TaskNode* tail;
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE cond;
    HANDLE* threads;        
    int thread_count;       
    int busy_count;         
    int pending_count;      // [Safety Fix] 当前排队任务数
    volatile BOOL running;  
    int max_workers;        
} ThreadPool;

static ThreadPool g_pool;
volatile LONG g_active_connections = 0; // 全局活跃连接计数器

// --- 线程池内部函数 ---

unsigned __stdcall WorkerThreadProc(void* arg) {
    ThreadPool* pool = (ThreadPool*)arg;
    
    while (TRUE) {
        TaskNode* task = NULL;

        EnterCriticalSection(&pool->lock);
        // 等待任务或停止信号
        while (pool->head == NULL && pool->running) {
            SleepConditionVariableCS(&pool->cond, &pool->lock, INFINITE);
        }

        if (!pool->running && pool->head == NULL) {
            LeaveCriticalSection(&pool->lock);
            break;
        }

        // 取出任务
        task = pool->head;
        if (task) {
            pool->head = task->next;
            if (pool->head == NULL) pool->tail = NULL;
            pool->busy_count++;
            pool->pending_count--; // [Safety Fix] 减少排队计数
        }
        LeaveCriticalSection(&pool->lock);

        if (task) {
            // 执行任务
            if (task->function && task->argument) {
                task->function(task->argument);
            }
            
            free(task);
            
            EnterCriticalSection(&pool->lock);
            pool->busy_count--;
            LeaveCriticalSection(&pool->lock);
        }
    }
    return 0;
}

void ThreadPool_Init(int max_workers) {
    g_pool.head = NULL;
    g_pool.tail = NULL;
    g_pool.thread_count = 0;
    g_pool.busy_count = 0;
    g_pool.pending_count = 0; // [Safety Fix]
    g_pool.running = TRUE;
    g_pool.max_workers = max_workers;
    
    g_pool.threads = (HANDLE*)malloc(sizeof(HANDLE) * max_workers);
    if (g_pool.threads) {
        memset(g_pool.threads, 0, sizeof(HANDLE) * max_workers);
    }
    
    InitializeCriticalSectionAndSpinCount(&g_pool.lock, 4000);
    InitializeConditionVariable(&g_pool.cond);
    InitSocketTracker(); 
}

// 提交任务 (带队列深度限制)
BOOL ThreadPool_Submit(void (*func)(void*), void* arg, void (*cleanup)(void*)) {
    if (!g_pool.running) return FALSE;

    // 1. [Pre-check] 如果队列已满，直接拒绝，避免 malloc 消耗
    // 这里读 pending_count 是非加锁的近似值，为了性能可接受
    if (g_pool.pending_count >= MAX_PENDING_TASKS) {
        LOG_WARN("[ThreadPool] Rejected: Queue full (%d)", g_pool.pending_count);
        return FALSE;
    }

    TaskNode* newTask = (TaskNode*)malloc(sizeof(TaskNode));
    if (!newTask) return FALSE;
    
    newTask->function = func;
    newTask->argument = arg;
    newTask->cleanup = cleanup;
    newTask->next = NULL;

    EnterCriticalSection(&g_pool.lock);

    // 2. [Double-check] 加锁后再次检查队列限制
    if (g_pool.pending_count >= MAX_PENDING_TASKS) {
        LeaveCriticalSection(&g_pool.lock);
        free(newTask);
        LOG_WARN("[ThreadPool] Rejected: Queue limit hit (%d)", MAX_PENDING_TASKS);
        return FALSE;
    }
    
    TaskNode* oldTail = g_pool.tail;

    if (g_pool.tail) {
        g_pool.tail->next = newTask;
        g_pool.tail = newTask;
    } else {
        g_pool.head = newTask;
        g_pool.tail = newTask;
    }
    g_pool.pending_count++; // [Safety Fix]
    
    // 扩容策略
    BOOL spawn_needed = (g_pool.busy_count >= g_pool.thread_count && g_pool.thread_count < g_pool.max_workers);
    if (g_pool.thread_count == 0) spawn_needed = TRUE;

    BOOL submission_success = TRUE;

    if (spawn_needed) {
        HANDLE hThread = (HANDLE)_beginthreadex(NULL, THREAD_POOL_STACK_SIZE, WorkerThreadProc, &g_pool, 0, NULL);
        if (hThread) {
            g_pool.threads[g_pool.thread_count++] = hThread;
        } else {
            if (g_pool.thread_count > 0) {
                 LOG_WARN("[ThreadPool] Failed to expand pool. Task queued.");
            } else {
                LOG_ERROR("[ThreadPool] Failed to spawn initial worker.");
                // 回滚队列
                if (oldTail) {
                    oldTail->next = NULL;
                    g_pool.tail = oldTail;
                } else {
                    g_pool.head = NULL;
                    g_pool.tail = NULL;
                }
                g_pool.pending_count--; // 回滚计数
                submission_success = FALSE;
            }
        }
    }
    
    if (submission_success) {
        WakeConditionVariable(&g_pool.cond);
    }
    
    LeaveCriticalSection(&g_pool.lock);
    
    if (!submission_success) {
        free(newTask);
    }
    
    return submission_success;
}

void ThreadPool_Shutdown() {
    EnterCriticalSection(&g_pool.lock);
    g_pool.running = FALSE;
    WakeAllConditionVariable(&g_pool.cond);
    LeaveCriticalSection(&g_pool.lock);

    if (g_pool.thread_count > 0 && g_pool.threads) {
        HANDLE wait_buffer[MAXIMUM_WAIT_OBJECTS];
        int buffer_count = 0;
        int processed_threads = 0;

        while (processed_threads < g_pool.thread_count) {
            buffer_count = 0;
            int start_index = processed_threads;
            
            for (int i = 0; i < MAXIMUM_WAIT_OBJECTS && (start_index + i) < g_pool.thread_count; i++) {
                HANDLE t = g_pool.threads[start_index + i];
                if (t) wait_buffer[buffer_count++] = t;
            }

            if (buffer_count > 0) {
                WaitForMultipleObjects(buffer_count, wait_buffer, TRUE, 5000);
                for (int k = 0; k < buffer_count; k++) CloseHandle(wait_buffer[k]);
            }
            processed_threads += buffer_count;
        }
        memset(g_pool.threads, 0, sizeof(HANDLE) * g_pool.max_workers);
    }

    if (g_pool.threads) {
        free(g_pool.threads);
        g_pool.threads = NULL;
    }
    DeleteCriticalSection(&g_pool.lock);
    
    // 清理未执行的任务
    TaskNode* cur = g_pool.head;
    int dropped_tasks = 0;
    while (cur) {
        TaskNode* next = cur->next;
        if (cur->argument && cur->cleanup) {
            cur->cleanup(cur->argument);
            dropped_tasks++;
        }
        free(cur);
        cur = next;
    }
    
    if (dropped_tasks > 0) {
        LOG_WARN("[ThreadPool] Dropped %d pending tasks.", dropped_tasks);
    }
    
    g_pool.head = NULL;
    g_pool.tail = NULL;
    g_pool.pending_count = 0;
    
    CleanupSocketTracker();
}

// =========================================================================================
// [Core Logic] 客户端处理逻辑
// =========================================================================================

static void CleanupClientContext(void* arg) {
    ClientContext* ctx = (ClientContext*)arg;
    if (ctx) {
        if (ctx->clientSock != INVALID_SOCKET) {
            closesocket(ctx->clientSock);
            ctx->clientSock = INVALID_SOCKET;
        }
        free(ctx);
        InterlockedDecrement(&g_active_connections);
    }
}

void client_task_wrapper(void* p) {
    ClientContext* ctx = (ClientContext*)p;
    if (!ctx) return;
    
    SOCKET cid = ctx->clientSock;
    int track_idx = TrackSocket(cid);
    
    if (track_idx < 0) {
        LOG_ERROR("[Conn-%d] Socket Tracker Full. Rejecting.", cid);
        CleanupClientContext(ctx);
        return;
    }
    
    ProxySession session;
    if (session_init(&session, ctx) != 0) {
        LOG_ERROR("[Conn-%d] Session Init Failed", cid);
        UntrackSocketByIndex(track_idx);
        CleanupClientContext(ctx); // Use helper for consistency
        return;
    }
    
    // 执行代理步骤
    if (step_handshake_browser(&session) == 0) {
        // [New] 分流 UDP Associate
        if (session.is_udp_associate) {
            step_transfer_loop_udp_direct(&session);
        } 
        else {
            // 原有的 TCP/Tunnel 流程
            if (step_connect_upstream(&session) == 0) {
                if (step_handshake_ws(&session) == 0) {
                    if (step_send_proxy_request(&session) == 0) {
                        if (step_respond_to_browser(&session) == 0) {
                            if (session.alpn_is_h2) {
                                step_transfer_loop_h2(&session);
                            } else {
                                step_transfer_loop_h1(&session);
                            }
                        }
                    }
                }
            }
        }
    }

    session_free(&session);
    UntrackSocketByIndex(track_idx); 
    
    if (ctx) free(ctx);
    InterlockedDecrement(&g_active_connections);
}

// =========================================================================================
// [Main Server] 监听线程与管理函数
// =========================================================================================

DWORD WINAPI server_thread(LPVOID p) {
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock == INVALID_SOCKET) {
        LOG_ERROR("Socket create fail: %d", WSAGetLastError());
        g_proxyRunning = FALSE;
        return 0;
    }

    struct sockaddr_in addr; 
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(g_localPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    int opt = 1; 
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERROR("Port %d bind fail: %d", g_localPort, WSAGetLastError()); 
        closesocket(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        g_proxyRunning = FALSE; 
        return 0;
    }
    
    if (listen(g_listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        LOG_ERROR("Listen fail: %d", WSAGetLastError());
        closesocket(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        g_proxyRunning = FALSE;
        return 0;
    }

    LOG_INFO("Server listening on 127.0.0.1:%d", g_localPort);
    
    // 初始化线程池
    ThreadPool_Init(MAX_CONNECTIONS);
    
    int accept_fail_count = 0;

    while(g_proxyRunning) {
        // [Refactor] 路由热重载逻辑
        // 使用 select 超时机制，确保即使没有新连接也能响应重载信号
        if (g_needReloadRoutes) {
            ReloadRoutingRules();
            g_needReloadRoutes = FALSE;
            LOG_INFO("Routing rules hot-reloaded.");
        }

        // 1. 设置 select 监听
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(g_listen_sock, &readfds);

        // 2. 设置超时时间 (200ms)
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;

        // 3. 等待事件
        int ret = select(0, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            LOG_ERROR("Select failed: %d", WSAGetLastError());
            break; 
        }

        if (ret == 0) {
            // 超时，无新连接，继续循环检查 g_proxyRunning 和 g_needReloadRoutes
            continue;
        }

        // 4. 有可读事件，执行 Accept
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c == INVALID_SOCKET) {
            if (!g_proxyRunning) break;
            
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                accept_fail_count++;
                if (accept_fail_count > 100) Sleep(100); 
                else if (accept_fail_count > 10) Sleep(10);
            }
            continue; 
        }
        accept_fail_count = 0;

        long current_conns = InterlockedIncrement(&g_active_connections);
        if (current_conns > MAX_CONNECTIONS) {
            LOG_WARN("Max connections limit (%d) exceeded", MAX_CONNECTIONS);
            InterlockedDecrement(&g_active_connections); 
            closesocket(c);
            Sleep(50); 
            continue;
        }

        ClientContext* ctx = (ClientContext*)malloc(sizeof(ClientContext));
        if (ctx) {
            ctx->clientSock = c;
            
            EnterCriticalSection(&g_configLock);
            ctx->config = g_proxyConfig; 
            strncpy(ctx->userAgent, g_userAgentStr, sizeof(ctx->userAgent)-1);
            ctx->userAgent[sizeof(ctx->userAgent)-1] = 0;
            
            // 复制加密配置...
            ctx->cryptoSettings.enableFragment = g_enableFragment;
            ctx->cryptoSettings.fragMin = g_fragSizeMin;
            ctx->cryptoSettings.fragMax = g_fragSizeMax;
            ctx->cryptoSettings.fragDelay = g_fragDelayMs;
            ctx->cryptoSettings.enablePadding = g_enablePadding;
            ctx->cryptoSettings.padMin = g_padSizeMin;
            ctx->cryptoSettings.padMax = g_padSizeMax;
            ctx->cryptoSettings.browserType = g_browserType;
            strncpy(ctx->cryptoSettings.customCiphers, g_customCiphers, sizeof(ctx->cryptoSettings.customCiphers));
            ctx->cryptoSettings.alpnOverride = 0;
            LeaveCriticalSection(&g_configLock);

            // [Safety Fix] 如果提交失败（队列满），调用 CleanupClientContext 进行清理
            if (!ThreadPool_Submit(client_task_wrapper, ctx, CleanupClientContext)) {
                // 手动调用清理函数，因为 ThreadPool_Submit 在失败时不会自动调用 arg 的清理函数
                CleanupClientContext(ctx);
            }
        } else {
            LOG_ERROR("OOM: Failed to allocate ClientContext");
            InterlockedDecrement(&g_active_connections);
            closesocket(c);
        }
    }
    
    ThreadPool_Shutdown();
    return 0;
}

void StartProxyCore() {
    if (g_proxyRunning) return;
    g_proxyRunning = TRUE;
    hProxyThread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    if (!hProxyThread) {
        g_proxyRunning = FALSE;
        LOG_ERROR("Failed to start server thread");
    }
}

void StopProxyCore() {
    g_proxyRunning = FALSE;
    
    if (g_listen_sock != INVALID_SOCKET) { 
        closesocket(g_listen_sock); 
        g_listen_sock = INVALID_SOCKET; 
        LOG_INFO("Listen socket closed.");
    }

    LOG_INFO("Interrupting active connections...");
    CloseAllActiveSockets();
    
    if (hProxyThread) { 
        WaitForSingleObject(hProxyThread, 8000); 
        CloseHandle(hProxyThread); 
        hProxyThread = NULL; 
    }
    
    if (g_active_connections > 0) {
        LOG_WARN("Core stopped but %ld connections count remains.", g_active_connections);
        g_active_connections = 0;
    }
    
    LOG_INFO("Proxy Stopped");
}
