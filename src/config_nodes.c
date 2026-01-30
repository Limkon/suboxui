/* src/config_nodes.c */
#include "config.h"
#include "common.h"
#include "utils.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// 复用全局锁
extern CRITICAL_SECTION g_configLock; 

// 内部函数：解析 JSON 到结构体
static void _ParseJsonToNodeStruct(cJSON *item, node_t *node) {
    if (!item || !node) return;
    memset(node, 0, sizeof(node_t));
    node->id = 1; // 标记为有效

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
        // 尝试从 net 推断，或者默认 VMess
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
    cJSON *scy = cJSON_GetObjectItem(item, "scy"); // VMess security
    if (!scy) scy = cJSON_GetObjectItem(item, "security");
    if (!scy) scy = cJSON_GetObjectItem(item, "method"); // SS method
    if (scy && scy->valuestring) strncpy(node->security, scy->valuestring, sizeof(node->security)-1);
    else strcpy(node->security, "auto");
    
    cJSON *flow = cJSON_GetObjectItem(item, "flow");
    if (flow && flow->valuestring) strncpy(node->flow, flow->valuestring, sizeof(node->flow)-1);
}

// 辅助：从文件读取 JSON 并查找节点
static int LoadNodeFromFile(const wchar_t* tag) {
    if (!tag) return 0;

    wchar_t path[MAX_PATH];
    if (wcslen(g_iniFilePath) > 0) {
        wcscpy_s(path, MAX_PATH, g_iniFilePath);
        wchar_t *slash = wcsrchr(path, L'\\');
        if (slash) *(slash + 1) = L'\0';
        wcscat_s(path, MAX_PATH, L"gui-config.json"); // 通常节点存储在 gui-config.json
    } else {
        wcscpy_s(path, MAX_PATH, L"gui-config.json");
    }

    // 尝试读取文件
    FILE *f = _wfopen(path, L"rb");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *data = (char*)malloc(len + 1);
    if (!data) { fclose(f); return 0; }
    fread(data, 1, len, f);
    data[len] = 0;
    fclose(f);

    cJSON *root = cJSON_Parse(data);
    free(data);
    
    if (!root) return 0;

    int found = 0;
    cJSON *configs = cJSON_GetObjectItem(root, "configs");
    if (configs && cJSON_IsArray(configs)) {
        int count = cJSON_GetArraySize(configs);
        for (int i = 0; i < count; i++) {
            cJSON *item = cJSON_GetArrayItem(configs, i);
            cJSON *ps = cJSON_GetObjectItem(item, "ps");
            if (ps && ps->valuestring) {
                // 转换 ps 为宽字符进行比较
                wchar_t wPs[256];
                MultiByteToWideChar(CP_UTF8, 0, ps->valuestring, -1, wPs, 256);
                if (wcscmp(wPs, tag) == 0) {
                    _ParseJsonToNodeStruct(item, &g_currentNode);
                    // 更新 ID 为当前时间戳或随机数，以触发 proxy.c 的变更检测
                    g_currentNode.id = (int)GetTickCount(); 
                    if (g_currentNode.id == 0) g_currentNode.id = 1;
                    found = 1;
                    break;
                }
            }
        }
    }
    
    cJSON_Delete(root);
    return found;
}

void SwitchNode(const wchar_t* tag) {
    if (!tag) return;

    EnterCriticalSection(&g_configLock);
    
    // 1. 更新当前节点名称
    wcscpy_s(currentNode, 256, tag);
    
    // 2. 尝试从文件加载节点详情填充到 g_currentNode
    // 这样驱动层就能获取到配置
    if (!LoadNodeFromFile(tag)) {
        // 如果加载失败（例如文件不存在），重置节点
        memset(&g_currentNode, 0, sizeof(node_t));
    }
    
    LeaveCriticalSection(&g_configLock);
    
    SaveSettings(); // 触发保存
}

// 占位函数实现
void ParseTags() {}
void ParseNodeConfigToGlobal(cJSON *node) {}
void DeleteNode(const wchar_t* tag) {}
void ToggleNodePin(const wchar_t* tag) {}
void SortNodes() {}
void SaveNodeOrder(wchar_t** orderedTags, int count) {}
BOOL AddNodeToConfig(cJSON* newNode) { return FALSE; }
int ImportFromClipboard() { return 0; }
void SetNodeToTop(const wchar_t* tag) {}
int DeduplicateNodes() { return 0; }
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds) { return 0; }
