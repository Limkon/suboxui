/* src/utils_sys.c */
// [Refactor] 2026-01-11: 实现 TLS (Thread-Local Storage) 高性能内存池
// [Fix] 2026-01-18: 修复 MinGW 下 __declspec(thread) 警告，增加 GCC/Clang 兼容性
// [Fix] 2026-01-29: 增加 g_total_allocated_mem 定义，解决链接错误

#include "utils.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>

// [Fix] 定义全局内存统计变量 (解决 undefined reference 错误)
// 由于 globals.c 和 proxy_utils.c 均未提供有效定义，且此文件管理内存池，故在此定义
volatile LONG64 g_total_allocated_mem = 0;

// [Fix] 辅助宏：安全关闭句柄
#define SAFE_CLOSE_HANDLE(h) do { if((h) && (h)!=INVALID_HANDLE_VALUE) { CloseHandle(h); (h) = NULL; } } while(0)
#define SAFE_CLOSE_REG(h) do { if((h)) { RegCloseKey(h); (h) = NULL; } } while(0)

// --------------------------------------------------------------------------
// 注册表与系统操作 (保持不变)
// --------------------------------------------------------------------------

BOOL SetAutoStartup(BOOL enable) {
    HKEY hKey = NULL;
    const wchar_t* runPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* appName = L"MandalaClient";
    BOOL result = FALSE;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, runPath, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
        log_msg("[Sys] Failed to open startup registry key");
        return FALSE;
    }

    if (enable) {
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) > 0) {
            wchar_t cmdPath[MAX_PATH + 4];
            _snwprintf(cmdPath, MAX_PATH + 4, L"\"%s\"", exePath);
            if (RegSetValueExW(hKey, appName, 0, REG_SZ, (const BYTE*)cmdPath, (DWORD)(wcslen(cmdPath) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                result = TRUE;
                log_msg("[Sys] Auto-startup enabled");
            }
        }
    } else {
        if (RegDeleteValueW(hKey, appName) == ERROR_SUCCESS) {
            result = TRUE;
            log_msg("[Sys] Auto-startup disabled");
        } else {
            result = TRUE; 
        }
    }
    SAFE_CLOSE_REG(hKey);
    return result;
}

BOOL CheckAutoStartup() {
    HKEY hKey = NULL;
    const wchar_t* runPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* appName = L"MandalaClient";
    BOOL exists = FALSE;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, runPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, appName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) exists = TRUE;
        SAFE_CLOSE_REG(hKey);
    }
    return exists;
}

BOOL SetSystemProxy(BOOL enable) {
    HKEY hKey = NULL;
    const wchar_t* proxyPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    BOOL success = FALSE;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, proxyPath, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        log_msg("[Sys] Failed to open proxy registry settings");
        return FALSE;
    }

    if (enable) {
        DWORD enableVal = 1;
        wchar_t proxyServer[64];
        extern int g_localPort;
        _snwprintf(proxyServer, 64, L"127.0.0.1:%d", g_localPort);
        
        if (RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&enableVal, sizeof(DWORD)) != ERROR_SUCCESS) goto cleanup;
        if (RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, (const BYTE*)proxyServer, (DWORD)(wcslen(proxyServer) + 1) * sizeof(wchar_t)) != ERROR_SUCCESS) goto cleanup;
        const wchar_t* override = L"<local>";
        RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, (const BYTE*)override, (DWORD)(wcslen(override) + 1) * sizeof(wchar_t));
        log_msg("[Sys] System Proxy SET to %ls", proxyServer);
        success = TRUE;
    } else {
        DWORD enableVal = 0;
        if (RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&enableVal, sizeof(DWORD)) == ERROR_SUCCESS) {
            log_msg("[Sys] System Proxy CLEARED");
            success = TRUE;
        }
    }

    typedef BOOL (WINAPI *pInternetSetOptionW)(void*, DWORD, void*, DWORD);
    HMODULE hWinInet = LoadLibraryW(L"wininet.dll");
    if (hWinInet) {
        pInternetSetOptionW InternetSetOptionW = (pInternetSetOptionW)GetProcAddress(hWinInet, "InternetSetOptionW");
        if (InternetSetOptionW) {
            InternetSetOptionW(NULL, 39, NULL, 0); 
            InternetSetOptionW(NULL, 37, NULL, 0); 
        }
        FreeLibrary(hWinInet);
    }
cleanup:
    SAFE_CLOSE_REG(hKey);
    return success;
}

BOOL IsSystemProxyEnabled() {
    HKEY hKey = NULL;
    DWORD val = 0; DWORD len = sizeof(DWORD); BOOL enabled = FALSE;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"ProxyEnable", NULL, NULL, (BYTE*)&val, &len) == ERROR_SUCCESS) enabled = (val == 1);
        SAFE_CLOSE_REG(hKey);
    }
    return enabled;
}

BOOL IsProcessRunning(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe32; pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                SAFE_CLOSE_HANDLE(hSnapshot);
                return TRUE;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    SAFE_CLOSE_HANDLE(hSnapshot);
    return FALSE;
}

void OpenURL(const char* url) {
    if (!url) return;
    int len = MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
    if (len > 0) {
        wchar_t* wUrl = (wchar_t*)malloc(len * sizeof(wchar_t));
        if (wUrl) {
            MultiByteToWideChar(CP_UTF8, 0, url, -1, wUrl, len);
            ShellExecuteW(NULL, L"open", wUrl, NULL, NULL, SW_SHOWNORMAL);
            free(wUrl);
        }
    }
}

// --------------------------------------------------------------------------
// [Core] 手动实现的高性能 TLS 内存池 (批量优化版)
// --------------------------------------------------------------------------

#define POOL_BLOCK_SIZE (16 * 1024)

// L2 全局池参数
#define GLOBAL_POOL_MAX 512
static void* g_global_stack[GLOBAL_POOL_MAX];
static int g_global_top = 0;
static CRITICAL_SECTION g_global_lock;
static volatile BOOL g_pool_inited = FALSE;

// L1 线程池参数
#define TLS_CACHE_SIZE 8
// 批量搬运的数量 (L1 <-> L2)，通常设为容量的一半
#define BATCH_SIZE 4 

// [Fix] 核心修复：根据编译器选择正确的线程局部存储语法
// GCC/MinGW 使用 __thread
// MSVC 使用 __declspec(thread)
#ifdef _MSC_VER
  #define THREAD_LOCAL __declspec(thread)
#else
  #define THREAD_LOCAL __thread
#endif

// 使用宏定义的 THREAD_LOCAL 替代直接的 __declspec(thread)
static THREAD_LOCAL void* t_local_cache[TLS_CACHE_SIZE];
static THREAD_LOCAL int t_local_count = 0;
static THREAD_LOCAL BOOL t_inited = FALSE;

void InitMemoryPool() {
    if (!g_pool_inited) {
        InitializeCriticalSection(&g_global_lock);
        g_global_top = 0;
        g_pool_inited = TRUE;
        log_msg("[System] Memory Pool: Initialized (TLS Batch Mode)");
    }
}

void CleanupMemoryPool() {
    if (g_pool_inited) {
        EnterCriticalSection(&g_global_lock);
        while (g_global_top > 0) {
            void* ptr = g_global_stack[--g_global_top];
            free(ptr); 
        }
        LeaveCriticalSection(&g_global_lock);
        DeleteCriticalSection(&g_global_lock);
        g_pool_inited = FALSE;
    }
}

// [New] 线程退出时清理 TLS 缓存
void Pool_Thread_Cleanup() {
    if (!t_inited) return;

    if (t_local_count > 0) {
        // 尝试归还给全局池
        if (g_pool_inited) {
            EnterCriticalSection(&g_global_lock);
            while (t_local_count > 0 && g_global_top < GLOBAL_POOL_MAX) {
                g_global_stack[g_global_top++] = t_local_cache[--t_local_count];
            }
            LeaveCriticalSection(&g_global_lock);
        }
        
        // 如果全局池也满了，或者未初始化，直接释放剩余的
        while (t_local_count > 0) {
            free(t_local_cache[--t_local_count]);
        }
    }
    t_inited = FALSE; // 防止重复清理
}

// 核心分配函数 (批量进货优化)
void* Pool_Alloc_16K() {
    void* ptr = NULL;

    if (!t_inited) {
        memset(t_local_cache, 0, sizeof(t_local_cache));
        t_local_count = 0;
        t_inited = TRUE;
    }

    // 1. L1 Hit
    if (t_local_count > 0) {
        return t_local_cache[--t_local_count];
    }

    // 2. L1 Miss -> 从全局批量进货
    if (g_pool_inited) {
        EnterCriticalSection(&g_global_lock);
        // 如果全局池有货，尝试拿 BATCH_SIZE 个
        int move_count = 0;
        while (move_count < BATCH_SIZE && g_global_top > 0) {
            t_local_cache[t_local_count++] = g_global_stack[--g_global_top];
            move_count++;
        }
        LeaveCriticalSection(&g_global_lock);
    }

    // 3. 进货后再次尝试从 L1 拿
    if (t_local_count > 0) {
        return t_local_cache[--t_local_count];
    }

    // 4. 全局也没货，向 OS 申请
    return malloc(POOL_BLOCK_SIZE);
}

// 核心释放函数 (批量退货优化)
void Pool_Free_16K(void* ptr) {
    if (!ptr) return;

    if (!t_inited) {
        memset(t_local_cache, 0, sizeof(t_local_cache));
        t_local_count = 0;
        t_inited = TRUE;
    }

    // 1. L1 有空位
    if (t_local_count < TLS_CACHE_SIZE) {
        t_local_cache[t_local_count++] = ptr;
        return; 
    }

    // 2. L1 满了 -> 批量退货到全局池
    // 策略：把本地缓存的一半 (BATCH_SIZE) 搬到全局，腾出空间
    if (g_pool_inited) {
        EnterCriticalSection(&g_global_lock);
        int move_count = 0;
        // 只要全局池没满，就搬
        while (move_count < BATCH_SIZE && g_global_top < GLOBAL_POOL_MAX && t_local_count > 0) {
            // 从 L1 尾部拿一个，放到全局
            // 注意：t_local_cache 是栈结构，拿出最新的效率最高
            g_global_stack[g_global_top++] = t_local_cache[--t_local_count];
            move_count++;
        }
        LeaveCriticalSection(&g_global_lock);
    }

    // 3. 退货后检查 L1 空间
    if (t_local_count < TLS_CACHE_SIZE) {
        t_local_cache[t_local_count++] = ptr;
    } else {
        // 极罕见情况：L1 满了，且全局 L2 也满了，只能直接 free
        free(ptr);
    }
}
