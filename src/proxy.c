/* src/proxy.c */
#include <winsock2.h> // [Fix] Must include before windows.h
#include <windows.h>
#include <process.h>
#include "proxy.h"
#include "driver_singbox.h" // 引入驱动层接口
#include "config.h"         // 引入全局配置与节点定义
#include "utils.h"
#include "common.h"

// =========================================================================================
// [Refactor] Sing-box 外壳驱动逻辑
// 原有的 TCP/TLS/WS 转发逻辑已被移除，转而由独立的 Sing-box 进程处理流量。
// 本文件现在负责监控核心进程状态，并在节点切换时重载配置。
// =========================================================================================

// 状态记录
static int g_last_node_id = -1;

// [Compatibility] 保留此全局变量以维持 GUI 显示 (0=停止, >0=运行中)
volatile LONG g_active_connections = 0; 

// -----------------------------------------------------------------------------------------
// 核心监控线程
// -----------------------------------------------------------------------------------------
unsigned __stdcall ProxyMonitorThread(void* arg) {
    LOG_INFO("[Proxy] Shell mode started. Monitoring Sing-box core...");
    
    // 初始化驱动内部状态
    singbox_init();
    
    // 重置状态记录，确保首次循环能触发启动
    g_last_node_id = -1;

    while (g_proxyRunning) {
        // 1. 获取当前节点 ID
        // 注意：g_currentNode 在 globals.c 中定义，在 config.h 中声明
        int current_id = g_currentNode.id;
        
        // 2. 检查节点是否变更
        if (current_id != g_last_node_id) {
            // 只有当 ID 有效（非 0）时才启动
            if (current_id != 0) {
                LOG_INFO("[Proxy] Node switch detected (ID: %d -> %d). Reloading core...", g_last_node_id, current_id);
                
                // 调用驱动启动/重启 Sing-box
                // 这会自动生成 config.json 并重启子进程
                int ret = singbox_start(&g_currentNode, &global_settings);
                
                if (ret == 0) {
                    LOG_INFO("[Proxy] Core reloaded successfully.");
                } else {
                    LOG_ERROR("[Proxy] Failed to reload core. Error code: %d", ret);
                }
            } else {
                // 如果切换到了无效节点（例如未选择），则停止核心
                if (singbox_is_running()) {
                    LOG_INFO("[Proxy] No node selected. Stopping core.");
                    singbox_stop();
                }
            }
            g_last_node_id = current_id;
        }
        
        // 3. 守护进程逻辑：如果应该运行但未运行，则尝试重启
        if (g_last_node_id != 0 && !singbox_is_running()) {
            LOG_WARN("[Proxy] Sing-box core process exited unexpectedly. Restarting...");
            
            int ret = singbox_start(&g_currentNode, &global_settings);
            if (ret != 0) {
                LOG_ERROR("[Proxy] Daemon restart failed: %d", ret);
            }
            
            // 避免在持续崩溃时占满 CPU
            Sleep(2000);
        }

        // 4. 维持心跳，响应 g_proxyRunning 变化
        Sleep(1000);
    }

    // 退出循环时，确保停止核心进程
    singbox_stop();
    LOG_INFO("[Proxy] Monitor thread exited.");
    return 0;
}

// -----------------------------------------------------------------------------------------
// 对外接口
// -----------------------------------------------------------------------------------------

void StartProxyCore() {
    if (g_proxyRunning) return;
    
    LOG_INFO("[Proxy] Starting proxy service (Driver Mode)...");
    g_proxyRunning = TRUE;
    
    // 设置虚拟连接数，让 GUI 显示“运行中”状态
    // 在 Sing-box 模式下无法获取实时连接数，固定为 1 表示服务正常
    InterlockedExchange(&g_active_connections, 1);
    
    // 启动监控线程
    hProxyThread = (HANDLE)_beginthreadex(NULL, 0, ProxyMonitorThread, NULL, 0, NULL);
    
    if (!hProxyThread) {
        LOG_ERROR("[Proxy] Failed to create monitor thread!");
        g_proxyRunning = FALSE;
        InterlockedExchange(&g_active_connections, 0);
    }
}

void StopProxyCore() {
    if (!g_proxyRunning) return;

    LOG_INFO("[Proxy] Stopping proxy service...");
    g_proxyRunning = FALSE; // 通知线程退出
    
    // 等待监控线程结束
    if (hProxyThread) {
        WaitForSingleObject(hProxyThread, 5000); // 最多等待 5 秒
        CloseHandle(hProxyThread);
        hProxyThread = NULL;
    }
    
    // 再次确保核心被终止 (双重保险)
    singbox_stop();
    
    InterlockedExchange(&g_active_connections, 0);
    LOG_INFO("[Proxy] Service stopped.");
}

// -----------------------------------------------------------------------------------------
// 僵尸代码桩 (Zombie Stubs)
// 保留这些空函数以防止链接错误，因为 main.c 或其他模块可能引用了它们。
// -----------------------------------------------------------------------------------------

void InitSocketTracker() { /* No-op */ }
void CleanupSocketTracker() { /* No-op */ }
int TrackSocket(SOCKET s) { return -1; }
void UntrackSocket(SOCKET s) { /* No-op */ }
void UntrackSocketByIndex(int idx) { /* No-op */ }
void CloseAllActiveSockets() { /* No-op */ }

// [Fix] ReloadRoutingRules 已在 config_nodes.c 中定义，此处移除
// void ReloadRoutingRules(void) { } 

// ThreadPool Stub
void ThreadPool_Init(int max_workers) { /* No-op */ }
BOOL ThreadPool_Submit(void (*func)(void*), void* arg, void (*cleanup)(void*)) { 
    // 直接执行清理，避免内存泄漏
    if (cleanup && arg) cleanup(arg);
    return FALSE; 
}
void ThreadPool_Shutdown() { /* No-op */ }
