// 文件名: src/config_nodes_crud.c
// 包含: Node CRUD (Add, Delete, Switch, Update, Pin, Top)
// 此文件依赖 config_nodes.c 中的 ParseTags() 来刷新状态

#include "config.h"
#include "utils.h"
#include "proxy.h" 
#include "common.h"
#include "crypto.h" 
#include "config_nodes_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h> 

// [New] 引入 Sing-box 驱动需要的节点结构体转换逻辑
static void _ParseJsonToNodeStruct(cJSON *item, node_t *node) {
    if (!item || !node) return;
    memset(node, 0, sizeof(node_t));
    node->id = (int)GetTickCount(); // 使用时间戳作为 ID 触发更新
    if (node->id == 0) node->id = 1;

    cJSON *addr = cJSON_GetObjectItem(item, "add");
    if (addr && addr->valuestring) strncpy(node->address, addr->valuestring, sizeof(node->address)-1);
    
    cJSON *port = cJSON_GetObjectItem(item, "port");
    if (port) {
        if (cJSON_IsNumber(port)) node->port = port->valueint;
        else if (cJSON_IsString(port)) node->port = atoi(port->valuestring);
    }
    
    // 协议类型推断
    cJSON *protocol = cJSON_GetObjectItem(item, "protocol");
    char protoStr[32] = {0};
    if (protocol && protocol->valuestring) strncpy(protoStr, protocol->valuestring, 31);
    
    // 兼容 V2RayN 格式
    if (strlen(protoStr) == 0) {
        if (cJSON_GetObjectItem(item, "id")) strcpy(protoStr, "vmess");
        else if (cJSON_GetObjectItem(item, "password")) strcpy(protoStr, "shadowsocks");
    }

    if (strcasecmp(protoStr, "vmess") == 0) node->type = 1;
    else if (strcasecmp(protoStr, "vless") == 0) node->type = 2;
    else if (strcasecmp(protoStr, "shadowsocks") == 0) node->type = 3;
    else if (strcasecmp(protoStr, "trojan") == 0) node->type = 4;
    else node->type = 1; // Default

    // UUID / Password
    cJSON *id = cJSON_GetObjectItem(item, "id");
    if (id && id->valuestring) strncpy(node->uuid, id->valuestring, sizeof(node->uuid)-1);
    else {
        cJSON *pwd = cJSON_GetObjectItem(item, "password");
        if (pwd && pwd->valuestring) strncpy(node->uuid, pwd->valuestring, sizeof(node->uuid)-1);
    }

    // Network
    cJSON *net = cJSON_GetObjectItem(item, "net");
    char netStr[32] = {0};
    if (net && net->valuestring) strncpy(netStr, net->valuestring, 31);
    if (strcasecmp(netStr, "ws") == 0) node->net_type = 1;
    else node->net_type = 0; // TCP
    
    // Path & Host
    cJSON *path = cJSON_GetObjectItem(item, "path");
    if (path && path->valuestring) strncpy(node->path, path->valuestring, sizeof(node->path)-1);
    
    cJSON *host = cJSON_GetObjectItem(item, "host");
    if (host && host->valuestring) strncpy(node->host, host->valuestring, sizeof(node->host)-1);
    else {
        cJSON *sni = cJSON_GetObjectItem(item, "sni");
        if (sni && sni->valuestring) strncpy(node->host, sni->valuestring, sizeof(node->host)-1);
    }

    // TLS
    cJSON *tls = cJSON_GetObjectItem(item, "tls");
    if (tls && tls->valuestring && strlen(tls->valuestring) > 0 && strcasecmp(tls->valuestring, "none") != 0) {
        node->tls = 1;
    } else {
        node->tls = 0;
    }

    // Security & Flow
    cJSON *scy = cJSON_GetObjectItem(item, "scy");
    if (!scy) scy = cJSON_GetObjectItem(item, "security");
    if (!scy) scy = cJSON_GetObjectItem(item, "method");
    if (scy && scy->valuestring) strncpy(node->security, scy->valuestring, sizeof(node->security)-1);
    else strcpy(node->security, "auto");
    
    cJSON *flow = cJSON_GetObjectItem(item, "flow");
    if (flow && flow->valuestring) strncpy(node->flow, flow->valuestring, sizeof(node->flow)-1);
}

// [Helper] 获取唯一标签名 (去掉 static 以便在 Manage 模块中使用)
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name) {
    static char final_tag[512]; 
    char candidate[450];
    const char* safe_name = (base_name && strlen(base_name) > 0) ? base_name : "Unnamed";
    
    char prefix[64]; 
    snprintf(prefix, sizeof(prefix), "%s-", type);
    
    if (_strnicmp(safe_name, prefix, strlen(prefix)) == 0) {
        snprintf(candidate, sizeof(candidate), "%s", safe_name);
    } else {
        snprintf(candidate, sizeof(candidate), "%s-%s", type, safe_name);
    }
    
    int index = 0;
    while (1) {
        if (index == 0) snprintf(final_tag, sizeof(final_tag), "%s", candidate);
        else snprintf(final_tag, sizeof(final_tag), "%s (%d)", candidate, index);
        
        BOOL exists = FALSE; 
        cJSON* item = NULL;
        cJSON_ArrayForEach(item, outbounds) {
            cJSON* t = cJSON_GetObjectItem(item, "tag");
            if (t && t->valuestring && strcmp(t->valuestring, final_tag) == 0) { 
                exists = TRUE; 
                break; 
            }
        }
        
        if (!exists) break;
        if (index > 10000) break;
        index++;
    }
    return final_tag;
}

// [Mod] 切换节点逻辑更新：保存配置到 JSON 并填充 g_currentNode
void SwitchNode(const wchar_t* tag) {
    if (!tag) return;
    
    char tagUtf8[512]; 
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 512, NULL, NULL);

    EnterCriticalSection(&g_configLock);
    
    // 1. 更新内存状态 (GUI用)
    wcsncpy(currentNode, tag, 255);
    currentNode[255] = L'\0';

    // 2. 查找并加载节点配置
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        log_msg("[Err] 读取 config.json 失败");
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    
    if (!root) {
        log_msg("[Err] JSON 解析失败");
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* targetNode = NULL;
    cJSON* node;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) {
            targetNode = node;
            break;
        }
    }
    
    if (targetNode) {
        // [New] 填充全局节点结构体，供 Sing-box 驱动使用
        _ParseJsonToNodeStruct(targetNode, &g_currentNode);
        log_msg("[System] 节点配置已更新: %s", tagUtf8);

        // 3. 必须先释放锁，因为 SaveSettings 内部也会获取该锁
        LeaveCriticalSection(&g_configLock); 
        
        // 注意：原有的 StopProxyCore/StartProxyCore 调用可能不再适用，
        // 因为现在 proxy.c 中的 ProxyMonitorThread 会自动检测 ID 变更并重启。
        // 但为了兼容性，我们保留它们，因为 StartProxyCore 现在只是启动监控线程。
        
        // SaveSettings 会保存 selected_node 到 json
        SaveSettings();   
        
    } else {
        log_msg("[Err] 未在配置中找到节点: %s", tagUtf8);
        LeaveCriticalSection(&g_configLock);
    }

    cJSON_Delete(root);
}

void DeleteNode(const wchar_t* tag) {
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    cJSON* root = cJSON_Parse(buffer); 
    free(buffer);
    
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    char tagUtf8[256]; 
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);
    
    int idx = 0; 
    cJSON* node = NULL;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && strcmp(t->valuestring, tagUtf8) == 0) { 
            cJSON_DeleteItemFromArray(outbounds, idx); 
            break; 
        }
        idx++;
    }
    
    char* out = cJSON_Print(root); 
    WriteBufferToFile(CONFIG_FILE, out); 
    free(out); 
    cJSON_Delete(root);
    
    LeaveCriticalSection(&g_configLock);
    ParseTags(); 
}

void ToggleNodePin(const wchar_t* tag) {
    if (!tag) return;
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);

    EnterCriticalSection(&g_configLock);
    char* buffer = NULL; long size = 0;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer); 
        free(buffer);
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            cJSON* node = NULL;
            cJSON_ArrayForEach(node, outbounds) {
                cJSON* t = cJSON_GetObjectItem(node, "tag");
                if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) {
                    cJSON* pin = cJSON_GetObjectItem(node, "is_pinned");
                    if (pin && cJSON_IsTrue(pin)) {
                        cJSON_DeleteItemFromObject(node, "is_pinned"); 
                    } else {
                        cJSON_AddBoolToObject(node, "is_pinned", cJSON_True); 
                    }
                    break;
                }
            }
            char* out = cJSON_Print(root);
            WriteBufferToFile(CONFIG_FILE, out);
            free(out); 
            cJSON_Delete(root);
        }
    }
    LeaveCriticalSection(&g_configLock);
    ParseTags();
}

void SetNodeToTop(const wchar_t* tag) {
    if (!tag) return;
    char tagUtf8[256];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 256, NULL, NULL);

    EnterCriticalSection(&g_configLock);
    
    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return;
    }

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (outbounds && cJSON_IsArray(outbounds)) {
        int idx = 0;
        int targetIdx = -1;
        cJSON* node = NULL;
        
        cJSON_ArrayForEach(node, outbounds) {
            cJSON* t = cJSON_GetObjectItem(node, "tag");
            if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) {
                targetIdx = idx;
                break;
            }
            idx++;
        }

        if (targetIdx > 0) { 
            cJSON* targetNode = cJSON_DetachItemFromArray(outbounds, targetIdx);
            if (targetNode) {
                cJSON_InsertItemInArray(outbounds, 0, targetNode);
                cJSON* pin = cJSON_GetObjectItem(targetNode, "is_pinned");
                if (!pin) cJSON_AddBoolToObject(targetNode, "is_pinned", cJSON_True);
                char* out = cJSON_Print(root);
                WriteBufferToFile(CONFIG_FILE, out);
                free(out);
            }
        }
    }
    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
    ParseTags();
}

BOOL AddNodeToConfig(cJSON* newNode) {
    if (!newNode) return FALSE;
    BOOL ret = FALSE;
    
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0; cJSON* root = NULL;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) { 
        root = cJSON_Parse(buffer); 
        free(buffer); 
    }
    if (!root) { 
        root = cJSON_CreateObject(); 
        cJSON_AddItemToObject(root, "outbounds", cJSON_CreateArray()); 
    }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds) { 
        outbounds = cJSON_CreateArray(); 
        cJSON_AddItemToObject(root, "outbounds", outbounds); 
    }
    
    cJSON* jsonType = cJSON_GetObjectItem(newNode, "type");
    const char* typeStr = (jsonType && jsonType->valuestring) ? jsonType->valuestring : "proxy";
    cJSON* jsonTag = cJSON_GetObjectItem(newNode, "tag");
    const char* originalTag = (jsonTag && jsonTag->valuestring) ? jsonTag->valuestring : "NewNode";
    
    char* uniqueTag = GetUniqueTagName(outbounds, typeStr, originalTag);
    if (cJSON_HasObjectItem(newNode, "tag")) cJSON_ReplaceItemInObject(newNode, "tag", cJSON_CreateString(uniqueTag));
    else cJSON_AddStringToObject(newNode, "tag", uniqueTag);
    
    cJSON_AddItemToArray(outbounds, newNode);
    char* out = cJSON_Print(root); 
    ret = WriteBufferToFile(CONFIG_FILE, out); 
    free(out); cJSON_Delete(root);
    
    LeaveCriticalSection(&g_configLock);
    return ret;
}

void UpdateNodeLatency(const wchar_t* tag, int latency) {
    if (!tag) return;
    char tagUtf8[512];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 512, NULL, NULL);

    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer);
        free(buffer);
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            cJSON* node = NULL;
            cJSON_ArrayForEach(node, outbounds) {
                cJSON* t = cJSON_GetObjectItem(node, "tag");
                if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) {
                    if (cJSON_GetObjectItem(node, "latency")) {
                        cJSON_DeleteItemFromObject(node, "latency");
                    }
                    cJSON_AddNumberToObject(node, "latency", latency);
                    break;
                }
            }
            char* out = cJSON_Print(root);
            WriteBufferToFile(CONFIG_FILE, out);
            free(out);
            cJSON_Delete(root);
        }
    }
    LeaveCriticalSection(&g_configLock);
}
