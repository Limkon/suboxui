/* src/config_nodes.c */
// [Fix] 恢复核心节点解析函数 ParseTags 和 ParseNodeConfigToGlobal
// [Fix] 添加 ReloadRoutingRules 桩代码以解决链接错误

#include "config.h"
#include "common.h"
#include "utils.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// 引用全局变量 (定义在 globals.c)
extern wchar_t** nodeTags;
extern int nodeCount;
extern CRITICAL_SECTION g_configLock;
extern node_t g_currentNode;

// 假设 config.h 中定义了 CONFIG_FILE，如果未定义则使用默认值
#ifndef CONFIG_FILE
#define CONFIG_FILE L"config.json"
#endif

// -----------------------------------------------------------------------------
// 内部辅助：解析 JSON 到 node_t
// -----------------------------------------------------------------------------
static void _InternalParseToNode(cJSON *item, node_t *node) {
    if (!item || !node) return;
    memset(node, 0, sizeof(node_t));
    node->id = (int)GetTickCount();
    if (node->id == 0) node->id = 1;

    cJSON *addr = cJSON_GetObjectItem(item, "add");
    if (addr && addr->valuestring) strncpy(node->address, addr->valuestring, sizeof(node->address)-1);
    
    cJSON *port = cJSON_GetObjectItem(item, "port");
    if (port) {
        if (cJSON_IsNumber(port)) node->port = port->valueint;
        else if (cJSON_IsString(port)) node->port = atoi(port->valuestring);
    }
    
    // 协议类型
    cJSON *protocol = cJSON_GetObjectItem(item, "protocol");
    char protoStr[32] = {0};
    if (protocol && protocol->valuestring) strncpy(protoStr, protocol->valuestring, 31);
    
    if (strlen(protoStr) == 0) {
        if (cJSON_GetObjectItem(item, "id")) strcpy(protoStr, "vmess");
        else if (cJSON_GetObjectItem(item, "password")) strcpy(protoStr, "shadowsocks");
    }

    if (strcasecmp(protoStr, "vmess") == 0) node->type = 1;
    else if (strcasecmp(protoStr, "vless") == 0) node->type = 2;
    else if (strcasecmp(protoStr, "shadowsocks") == 0) node->type = 3;
    else if (strcasecmp(protoStr, "trojan") == 0) node->type = 4;
    else node->type = 1; 

    // UUID
    cJSON *id = cJSON_GetObjectItem(item, "id");
    if (id && id->valuestring) strncpy(node->uuid, id->valuestring, sizeof(node->uuid)-1);
    else {
        cJSON *pwd = cJSON_GetObjectItem(item, "password");
        if (pwd && pwd->valuestring) strncpy(node->uuid, pwd->valuestring, sizeof(node->uuid)-1);
    }

    // Network & TLS
    cJSON *net = cJSON_GetObjectItem(item, "net");
    if (net && net->valuestring && strcasecmp(net->valuestring, "ws") == 0) node->net_type = 1;
    else node->net_type = 0;
    
    cJSON *path = cJSON_GetObjectItem(item, "path");
    if (path && path->valuestring) strncpy(node->path, path->valuestring, sizeof(node->path)-1);
    
    cJSON *host = cJSON_GetObjectItem(item, "host");
    if (host && host->valuestring) strncpy(node->host, host->valuestring, sizeof(node->host)-1);
    else {
        cJSON *sni = cJSON_GetObjectItem(item, "sni");
        if (sni && sni->valuestring) strncpy(node->host, sni->valuestring, sizeof(node->host)-1);
    }

    cJSON *tls = cJSON_GetObjectItem(item, "tls");
    if (tls && tls->valuestring && strcasecmp(tls->valuestring, "none") != 0 && strlen(tls->valuestring) > 0) node->tls = 1;
    else node->tls = 0;

    cJSON *scy = cJSON_GetObjectItem(item, "scy");
    if (!scy) scy = cJSON_GetObjectItem(item, "security");
    if (!scy) scy = cJSON_GetObjectItem(item, "method");
    if (scy && scy->valuestring) strncpy(node->security, scy->valuestring, sizeof(node->security)-1);
    else strcpy(node->security, "auto");
    
    cJSON *flow = cJSON_GetObjectItem(item, "flow");
    if (flow && flow->valuestring) strncpy(node->flow, flow->valuestring, sizeof(node->flow)-1);
}

// -----------------------------------------------------------------------------
// 对外接口实现
// -----------------------------------------------------------------------------

// 解析 JSON 节点配置到全局变量 (供 crud 调用)
void ParseNodeConfigToGlobal(cJSON *node) {
    if (!node) return;
    // 更新 g_currentNode 供 Sing-box 驱动使用
    _InternalParseToNode(node, &g_currentNode);
}

// 读取配置文件并刷新全局标签列表 (供 GUI 使用)
void ParseTags() {
    EnterCriticalSection(&g_configLock);

    // 1. 释放旧数据
    if (nodeTags) {
        for (int i = 0; i < nodeCount; i++) {
            if (nodeTags[i]) free(nodeTags[i]);
        }
        free(nodeTags);
        nodeTags = NULL;
    }
    nodeCount = 0;

    // 2. 读取新数据
    char* buffer = NULL; long size = 0;
    wchar_t path[MAX_PATH];
    if (wcslen(g_iniFilePath) > 0) {
        wcscpy_s(path, MAX_PATH, g_iniFilePath);
        wchar_t *slash = wcsrchr(path, L'\\');
        if (slash) *(slash + 1) = L'\0';
        wcscat_s(path, MAX_PATH, L"config.json");
    } else {
        wcscpy_s(path, MAX_PATH, L"config.json");
    }

    if (ReadFileToBuffer(path, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer);
        free(buffer);
        
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            if (outbounds && cJSON_IsArray(outbounds)) {
                int count = cJSON_GetArraySize(outbounds);
                nodeTags = (wchar_t**)malloc(sizeof(wchar_t*) * (count + 1));
                if (nodeTags) {
                    cJSON* node = NULL;
                    cJSON_ArrayForEach(node, outbounds) {
                        cJSON* t = cJSON_GetObjectItem(node, "tag");
                        if (t && t->valuestring) {
                            int len = MultiByteToWideChar(CP_UTF8, 0, t->valuestring, -1, NULL, 0);
                            if (len > 0) {
                                nodeTags[nodeCount] = (wchar_t*)malloc(len * sizeof(wchar_t));
                                if (nodeTags[nodeCount]) {
                                    MultiByteToWideChar(CP_UTF8, 0, t->valuestring, -1, nodeTags[nodeCount], len);
                                    nodeCount++;
                                }
                            }
                        }
                    }
                }
            }
            cJSON_Delete(root);
        }
    }

    LeaveCriticalSection(&g_configLock);
}

// 路由规则重载桩 (解决链接错误)
void ReloadRoutingRules(void) {
    // 外壳模式下无需重载内存中的路由表，配置完全由 Sing-box 接管
}
