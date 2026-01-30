/* include/proxy.h */
#ifndef PROXY_H
#define PROXY_H

#include "common.h"

// [New] 路由热重载标志 (由 UI 设置，代理核心读取)
extern volatile BOOL g_needReloadRoutes;

// [New] 重载路由规则 (从 config.json 读取并更新 g_routingRules)
void ReloadRoutingRules();

// 启动/停止代理核心
void StartProxyCore();
void StopProxyCore();

// [Fix] 公开强制断开连接函数，用于路由规则变更后清除 Keep-Alive 连接
void CloseAllActiveSockets();

// 通用网络工具函数 (main.c 可能用到)
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec);
int send_all(SOCKET s, const char *buf, int len);

// 主服务监听线程入口 (由 StartProxyCore 启动)
DWORD WINAPI server_thread(LPVOID p);

#endif // PROXY_H
