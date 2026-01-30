/* src/config_nodes.c */
// 文件名: src/config_nodes.c
// 包含: 核心节点管理 (解析Tags, 解析配置到Global)
// 该文件保留了核心的状态同步功能，其他功能已拆分至 config_nodes_crud.c 和 config_nodes_manage.c
// [Mod] 2026: 增加 ReloadRoutingRules 实现路由热重载 (修正结构体成员引用)
// [Fix] 2026: 增加对 xhttp/grpc mode 参数的加载支持

#include "config.h"
#include "utils.h"
#include "proxy.h" 
#include "common.h"
#include "config_nodes_internal.h" // 引入内部头文件
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h> 

// 定义规则内容的限制，与 common.h 保持一致
#define MAX_CONTENTS_PER_RULE 16 

// --- 核心节点状态管理 ---

// [Refactor] 优化并发安全性：先解析到临时数组，再加锁替换
// [Fix] 修复 realloc 失败可能导致的内存泄漏
void ParseTags() {
    char* buffer = NULL; 
    long size = 0;
    
    // 1. 在锁外进行 IO 操作读取配置
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { 
        return; 
    }

    cJSON* root = cJSON_Parse(buffer); 
    free(buffer);
    
    if (!root) return;

    // 2. 解析到临时列表 (Local Scope)
    wchar_t** newTags = NULL;
    int newCount = 0;

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* node = NULL;
    
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* tag = cJSON_GetObjectItem(node, "tag");
        if (tag && tag->valuestring) {
            // [Fix] 使用临时指针防止 realloc 失败导致内存泄漏
            wchar_t** tempTags = (wchar_t**)realloc(newTags, (newCount + 1) * sizeof(wchar_t*));
            if (!tempTags) {
                // realloc 失败，必须清理已分配的所有内存并退出
                for(int i = 0; i < newCount; i++) free(newTags[i]);
                free(newTags);
                cJSON_Delete(root);
                return;
            }
            newTags = tempTags;
            newCount++;
            
            char displayTag[512];
            snprintf(displayTag, 512, "%s", tag->valuestring);

            int wlen = MultiByteToWideChar(CP_UTF8, 0, displayTag, -1, NULL, 0);
            if (wlen > 0) {
                newTags[newCount-1] = (wchar_t*)malloc((wlen + 1) * sizeof(wchar_t));
                if (newTags[newCount-1]) {
                    MultiByteToWideChar(CP_UTF8, 0, displayTag, -1, newTags[newCount-1], wlen + 1);
                } else {
                    // Malloc failed for single tag
                    newTags[newCount-1] = NULL; 
                }
            } else {
                 newTags[newCount-1] = NULL;
            }
        }
    }
    cJSON_Delete(root);

    // 3. 加锁并快速交换全局状态 (Critical Section)
    EnterCriticalSection(&g_configLock);
    
    // 释放旧列表
    if (nodeTags) { 
        for(int i = 0; i < nodeCount; i++) {
            if (nodeTags[i]) free(nodeTags[i]); 
        }
        free(nodeTags); 
    }
    
    // 应用新列表
    nodeCount = newCount;
    nodeTags = newTags;
    
    LeaveCriticalSection(&g_configLock);
}

void ParseNodeConfigToGlobal(cJSON *node) {
    if (!node) return;
    EnterCriticalSection(&g_configLock);

    memset(&g_proxyConfig, 0, sizeof(ProxyConfig));
    // 默认开启证书验证 (Secure by default)
    g_proxyConfig.allowInsecure = FALSE;
    ConfigSafeStrCpy(g_proxyConfig.path, sizeof(g_proxyConfig.path), "/"); 

    cJSON *server = cJSON_GetObjectItem(node, "server");
    cJSON *port = cJSON_GetObjectItem(node, "server_port");
    cJSON *uuid = cJSON_GetObjectItem(node, "uuid");
    if (!uuid) uuid = cJSON_GetObjectItem(node, "password"); 
    
    if (server && server->valuestring) ConfigSafeStrCpy(g_proxyConfig.host, sizeof(g_proxyConfig.host), server->valuestring);
    
    // 兼容数字或字符串类型的端口配置
    if (port) {
        if (cJSON_IsNumber(port)) g_proxyConfig.port = port->valueint;
        else if (cJSON_IsString(port)) g_proxyConfig.port = atoi(port->valuestring);
    }
    
    if (uuid && uuid->valuestring) { 
        ConfigSafeStrCpy(g_proxyConfig.user, sizeof(g_proxyConfig.user), uuid->valuestring); 
        ConfigSafeStrCpy(g_proxyConfig.pass, sizeof(g_proxyConfig.pass), uuid->valuestring); 
    }
    
    cJSON *user = cJSON_GetObjectItem(node, "username"); 
    cJSON *pass = cJSON_GetObjectItem(node, "password");
    if(user && user->valuestring) ConfigSafeStrCpy(g_proxyConfig.user, sizeof(g_proxyConfig.user), user->valuestring);
    if(pass && pass->valuestring) ConfigSafeStrCpy(g_proxyConfig.pass, sizeof(g_proxyConfig.pass), pass->valuestring);
    
    cJSON *tls = cJSON_GetObjectItem(node, "tls");
    if (tls) {
        cJSON *sni = cJSON_GetObjectItem(tls, "server_name");
        if (sni && sni->valuestring) ConfigSafeStrCpy(g_proxyConfig.sni, sizeof(g_proxyConfig.sni), sni->valuestring);
        
        cJSON *insec = cJSON_GetObjectItem(tls, "allowInsecure");
        if (insec && cJSON_IsTrue(insec)) {
            g_proxyConfig.allowInsecure = TRUE;
        }
    }
    
    cJSON *trans = cJSON_GetObjectItem(node, "transport");
    if(trans) {
        cJSON *path = cJSON_GetObjectItem(trans, "path");
        if(path && path->valuestring) ConfigSafeStrCpy(g_proxyConfig.path, sizeof(g_proxyConfig.path), path->valuestring);

        // [Fix] 读取 mode 参数 (用于 xhttp, grpc 等协议)
        // 需确保 ProxyConfig 结构体 (include/config.h) 中包含 char mode[64];
        cJSON *mode = cJSON_GetObjectItem(trans, "mode");
        if(mode && mode->valuestring) {
            ConfigSafeStrCpy(g_proxyConfig.mode, sizeof(g_proxyConfig.mode), mode->valuestring);
        }
    }
    
    if (strlen(g_proxyConfig.sni) == 0) ConfigSafeStrCpy(g_proxyConfig.sni, sizeof(g_proxyConfig.sni), g_proxyConfig.host);

    cJSON *type = cJSON_GetObjectItem(node, "type");
    if (type && type->valuestring) ConfigSafeStrCpy(g_proxyConfig.type, sizeof(g_proxyConfig.type), type->valuestring);
    else ConfigSafeStrCpy(g_proxyConfig.type, sizeof(g_proxyConfig.type), "socks");

    LeaveCriticalSection(&g_configLock);
}

// [New] 热重载路由规则 implementation
void ReloadRoutingRules() {
    char* buffer = NULL;
    long size = 0;
    
    // IO 读取
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;
    
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) return;

    // 使用堆分配临时数组防止栈溢出 (MAX_RULES 可能较大)
    RoutingRule* tempRules = (RoutingRule*)calloc(MAX_RULES, sizeof(RoutingRule));
    if (!tempRules) {
        cJSON_Delete(root);
        return;
    }
    
    int tempCount = 0;
    cJSON* routing = cJSON_GetObjectItem(root, "routing");
    cJSON* rules = cJSON_GetObjectItem(routing, "rules");
    
    if (cJSON_IsArray(rules)) {
        int count = cJSON_GetArraySize(rules);
        // 遍历所有规则，但不超过系统上限
        for (int i = 0; i < count && tempCount < MAX_RULES; i++) {
            cJSON* item = cJSON_GetArrayItem(rules, i);
            if (!item) continue;
            
            RoutingRule* r = &tempRules[tempCount];
            
            // [Fix] 使用 outboundTag
            cJSON* tag = cJSON_GetObjectItem(item, "outboundTag");
            if (tag && tag->valuestring) {
                strncpy(r->outboundTag, tag->valuestring, 31);
                r->outboundTag[31] = '\0';
            } else {
                strcpy(r->outboundTag, "proxy");
            }

            // [Fix] 设置 type 默认为 "field"
            strcpy(r->type, "field");

            // [Fix] 使用 contentCount 和 contents
            r->contentCount = 0;

            // 解析域名
            cJSON* domains = cJSON_GetObjectItem(item, "domain");
            if (cJSON_IsArray(domains)) {
                int dCount = cJSON_GetArraySize(domains);
                for (int j = 0; j < dCount && r->contentCount < MAX_CONTENTS_PER_RULE; j++) {
                    cJSON* d = cJSON_GetArrayItem(domains, j);
                    if (d && d->valuestring) {
                        // 确保字符串不溢出
                        strncpy(r->contents[r->contentCount], d->valuestring, MAX_RULE_CONTENT_LEN - 1);
                        r->contents[r->contentCount][MAX_RULE_CONTENT_LEN - 1] = '\0';
                        r->contentCount++;
                    }
                }
            } 
            
            // 解析 IP
            cJSON* ips = cJSON_GetObjectItem(item, "ip");
            if (cJSON_IsArray(ips)) {
                int iCount = cJSON_GetArraySize(ips);
                for (int j = 0; j < iCount && r->contentCount < MAX_CONTENTS_PER_RULE; j++) {
                    cJSON* ip = cJSON_GetArrayItem(ips, j);
                    if (ip && ip->valuestring) {
                        strncpy(r->contents[r->contentCount], ip->valuestring, MAX_RULE_CONTENT_LEN - 1);
                        r->contents[r->contentCount][MAX_RULE_CONTENT_LEN - 1] = '\0';
                        r->contentCount++;
                    }
                }
            }

            if (r->contentCount > 0) {
                tempCount++;
            }
        }
    }
    
    cJSON_Delete(root);

    // 加锁并更新全局配置
    EnterCriticalSection(&g_configLock);
    memcpy(g_routingRules, tempRules, sizeof(RoutingRule) * MAX_RULES);
    g_routingRuleCount = tempCount;
    LeaveCriticalSection(&g_configLock);
    
    free(tempRules);
}
