// 文件名: src/config_nodes_crud.c
// 包含: Node CRUD (Add, Delete, Switch, Update, Pin, Top)
// 此文件依赖 config_nodes.c 中的 ParseTags() 来刷新状态

#include "config.h"
#include "utils.h"
#include "proxy.h" 
#include "common.h"
#include "crypto.h"  // [Fix] 添加此行以支持 ReloadSSLContext
#include "config_nodes_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h> 

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
        
        // [Safety] 防止无限循环
        if (index > 10000) break;
        index++;
    }
    return final_tag;
}

// [Mod] 切换节点逻辑更新：保存配置到 JSON 而不是 INI
void SwitchNode(const wchar_t* tag) {
    if (!tag) return;
    
    char tagUtf8[512]; 
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, 512, NULL, NULL);

    EnterCriticalSection(&g_configLock);
    
    // 1. 更新内存状态
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
        ParseNodeConfigToGlobal(targetNode);
        log_msg("[System] 节点配置已更新: %s", tagUtf8);

        // 3. 必须先释放锁，因为 SaveSettings 内部也会获取该锁
        LeaveCriticalSection(&g_configLock); 
        
        if (g_proxyRunning) {
            StopProxyCore();
        }
        
        EnterCriticalSection(&g_configLock);
        ReloadSSLContext();
        LeaveCriticalSection(&g_configLock);
        
        StartProxyCore(); 
        
        // [New] 调用全局保存函数，同步选中节点到 config.json
        SaveSettings();   
        
     // wchar_t tip[128];
     // _snwprintf(tip, 128, L"节点已切换: %.60s", tag);
     // wcsncpy(nid.szInfo, tip, 127);
     // nid.uFlags |= NIF_INFO;
     // Shell_NotifyIconW(NIM_MODIFY, &nid);
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
    
    // 更新内存中的 tag 列表
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

// [Refactor] 将指定节点置顶
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

// 更新节点测速结果到配置文件
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
                    // 如果已存在 latency 字段则删除，重新添加
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
