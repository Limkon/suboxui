// 文件名: src/config_nodes_manage.c
// 包含: Node Management (Batch Delete, Import, Sort, Deduplicate)
// 依赖 config_nodes.c 中的 ParseTags() 刷新状态

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

// 外部解析函数声明 (通常在 config_parsers.c 中实现，通过 config.h 或 common.h 暴露)
// 如果项目中没有统一头文件声明这些，可能需要在此声明或引入对应头文件
// 假设现有环境已通过 config.h 或 common.h 包含

// [New] 批量删除节点 (只读写一次文件)
int BatchDeleteNodes(wchar_t** tagsToDelete, int count) {
    if (!tagsToDelete || count <= 0) return 0;
    
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return 0;
    }
    
    cJSON* root = cJSON_Parse(buffer); 
    free(buffer);
    
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return 0;
    }
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds || !cJSON_IsArray(outbounds)) {
        cJSON_Delete(root);
        LeaveCriticalSection(&g_configLock);
        return 0;
    }

    // 为了提高查找效率，先将 UTF16 tags 转换为 UTF8 字符串数组
    char** utf8Tags = (char**)malloc(count * sizeof(char*));
    for (int i = 0; i < count; i++) {
        char buf[512];
        WideCharToMultiByte(CP_UTF8, 0, tagsToDelete[i], -1, buf, 512, NULL, NULL);
        utf8Tags[i] = _strdup(buf);
    }

    // 构建新的节点数组
    cJSON* newArray = cJSON_CreateArray();
    cJSON* node = NULL;
    int deleted = 0;

    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        BOOL shouldDelete = FALSE;
        
        if (t && t->valuestring) {
            for (int i = 0; i < count; i++) {
                if (utf8Tags[i] && strcmp(t->valuestring, utf8Tags[i]) == 0) {
                    shouldDelete = TRUE;
                    break;
                }
            }
        }
        
        if (shouldDelete) {
            deleted++;
        } else {
            cJSON_AddItemToArray(newArray, cJSON_Duplicate(node, 1));
        }
    }
    
    // 清理临时 UTF8 数组
    for (int i = 0; i < count; i++) free(utf8Tags[i]);
    free(utf8Tags);

    // 只有在确实有删除发生时才写入文件
    if (deleted > 0) {
        cJSON_ReplaceItemInObject(root, "outbounds", newArray);
        char* out = cJSON_Print(root); 
        WriteBufferToFile(CONFIG_FILE, out); 
        free(out); 
    } else {
        cJSON_Delete(newArray); // 没变化，销毁新数组
    }

    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
    
    if (deleted > 0) ParseTags(); // 刷新内存中的 Tag 列表
    return deleted;
}

// [New] 批量清除所有节点的延迟信息 (只读写一次文件)
void ClearAllNodeLatency() {
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    cJSON* root = cJSON_Parse(buffer); 
    free(buffer);
    
    if (root) {
        cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
        cJSON* node = NULL;
        BOOL changed = FALSE;
        
        cJSON_ArrayForEach(node, outbounds) {
            if (cJSON_HasObjectItem(node, "latency")) {
                cJSON_DeleteItemFromObject(node, "latency");
                changed = TRUE;
            }
        }
        
        if (changed) {
            char* out = cJSON_Print(root);
            WriteBufferToFile(CONFIG_FILE, out);
            free(out);
        }
        cJSON_Delete(root);
    }
    
    LeaveCriticalSection(&g_configLock);
}

// [New] 批量移除无效节点 (latency == -1) (只读写一次文件)
int BatchRemoveInvalidNodes() {
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return 0;
    }
    
    cJSON* root = cJSON_Parse(buffer); 
    free(buffer);
    
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return 0;
    }

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (!outbounds || !cJSON_IsArray(outbounds)) {
        cJSON_Delete(root);
        LeaveCriticalSection(&g_configLock);
        return 0;
    }

    cJSON* newArray = cJSON_CreateArray();
    cJSON* node = NULL;
    int deleted = 0;

    cJSON_ArrayForEach(node, outbounds) {
        cJSON* lat = cJSON_GetObjectItem(node, "latency");
        // 如果 latency 存在且为 -1 (超时)，则视为无效
        if (lat && lat->valueint == -1) {
            deleted++;
        } else {
            cJSON_AddItemToArray(newArray, cJSON_Duplicate(node, 1));
        }
    }

    if (deleted > 0) {
        cJSON_ReplaceItemInObject(root, "outbounds", newArray);
        char* out = cJSON_Print(root); 
        WriteBufferToFile(CONFIG_FILE, out); 
        free(out); 
    } else {
        cJSON_Delete(newArray);
    }

    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
    
    if (deleted > 0) ParseTags();
    return deleted;
}

// [已废弃] 自动排序逻辑清空，以支持手动排序持久化
void SortNodes() {
    return;
}

// [Refactor] 保存排序后的节点列表
void SaveNodeOrder(wchar_t** orderedTags, int count) {
    if (!orderedTags || count <= 0) return;

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
        cJSON* finalArray = cJSON_CreateArray();
        cJSON* tempNode = NULL;
        
        // 临时链表结构
        struct NodeEntry {
            cJSON* json;
            char* tag;
            BOOL used;
            struct NodeEntry* next;
        } *head = NULL, *curr = NULL;

        // 提取所有现有节点到链表
        tempNode = outbounds->child;
        while(tempNode) {
            struct NodeEntry* entry = (struct NodeEntry*)malloc(sizeof(struct NodeEntry));
            entry->json = tempNode;
            entry->used = FALSE;
            
            cJSON* t = cJSON_GetObjectItem(tempNode, "tag");
            entry->tag = (t && t->valuestring) ? _strdup(t->valuestring) : _strdup("");
            entry->next = NULL;

            if(!head) head = entry;
            else curr->next = entry;
            curr = entry;

            tempNode = tempNode->next;
        }
        
        // 断开原数组与节点的连接
        outbounds->child = NULL; 

        // 1. 按 orderedTags 的顺序查找并添加到新数组
        for (int i = 0; i < count; i++) {
            char tagUtf8[512];
            WideCharToMultiByte(CP_UTF8, 0, orderedTags[i], -1, tagUtf8, 512, NULL, NULL);

            struct NodeEntry* search = head;
            while (search) {
                if (!search->used && strcmp(search->tag, tagUtf8) == 0) {
                    // 找到匹配，加入新数组
                    search->json->next = NULL; 
                    search->json->prev = NULL;
                    cJSON_AddItemToArray(finalArray, search->json);
                    search->used = TRUE;
                    break;
                }
                search = search->next;
            }
        }

        // 2. 添加剩余未被排序包含的节点 (防止数据丢失)
        struct NodeEntry* search = head;
        while (search) {
            if (!search->used) {
                search->json->next = NULL;
                search->json->prev = NULL;
                cJSON_AddItemToArray(finalArray, search->json);
            }
            free(search->tag);
            struct NodeEntry* toFree = search;
            search = search->next;
            free(toFree);
        }

        // 替换根对象中的数组
        cJSON_ReplaceItemInObject(root, "outbounds", finalArray);
    }

    char* out = cJSON_Print(root);
    WriteBufferToFile(CONFIG_FILE, out);
    free(out);
    cJSON_Delete(root);

    LeaveCriticalSection(&g_configLock);
    
    // 更新内存状态
    ParseTags();
}

// [Helper] 获取节点比较关键信息
static int IsNodeDuplicate(cJSON* nodeA, cJSON* nodeB) {
    if (!nodeA || !nodeB) return 0;

    // 1. 比较类型 (Type)
    cJSON* typeA = cJSON_GetObjectItem(nodeA, "type");
    cJSON* typeB = cJSON_GetObjectItem(nodeB, "type");
    char* sTypeA = (typeA && typeA->valuestring) ? typeA->valuestring : "";
    char* sTypeB = (typeB && typeB->valuestring) ? typeB->valuestring : "";
    if (strcmp(sTypeA, sTypeB) != 0) return 0;

    // 2. 比较地址 (Server/Host)
    cJSON* serverA = cJSON_GetObjectItem(nodeA, "server");
    cJSON* serverB = cJSON_GetObjectItem(nodeB, "server");
    char* sServerA = (serverA && serverA->valuestring) ? serverA->valuestring : "";
    char* sServerB = (serverB && serverB->valuestring) ? serverB->valuestring : "";
    if (strcmp(sServerA, sServerB) != 0) return 0;

    // 3. 比较端口 (Port)
    cJSON* portA = cJSON_GetObjectItem(nodeA, "server_port");
    cJSON* portB = cJSON_GetObjectItem(nodeB, "server_port");
    int iPortA = 0, iPortB = 0;
    
    if (portA) iPortA = cJSON_IsNumber(portA) ? portA->valueint : atoi(portA->valuestring ? portA->valuestring : "0");
    if (portB) iPortB = cJSON_IsNumber(portB) ? portB->valueint : atoi(portB->valuestring ? portB->valuestring : "0");
    if (iPortA != iPortB) return 0;

    // 4. 比较 SNI (TLS Server Name)
    cJSON* tlsA = cJSON_GetObjectItem(nodeA, "tls");
    cJSON* tlsB = cJSON_GetObjectItem(nodeB, "tls");
    char* sniA = ""; char* sniB = "";

    if (tlsA) {
        cJSON* t = cJSON_GetObjectItem(tlsA, "server_name");
        if (t && t->valuestring) sniA = t->valuestring;
    }
    if (tlsB) {
        cJSON* t = cJSON_GetObjectItem(tlsB, "server_name");
        if (t && t->valuestring) sniB = t->valuestring;
    }

    if (strcmp(sniA, sniB) != 0) return 0;

    return 1; // 所有关键字段相同
}

// [Refactor] 节点去重函数
int DeduplicateNodes() {
    int deletedCount = 0;
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return 0;
    }

    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return 0;
    }

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    if (outbounds && cJSON_IsArray(outbounds)) {
        int count = cJSON_GetArraySize(outbounds);
        int* toDelete = (int*)calloc(count, sizeof(int));
        
        if (toDelete) {
            for (int i = 0; i < count; i++) {
                if (toDelete[i]) continue;
                cJSON* nodeA = cJSON_GetArrayItem(outbounds, i);
                
                for (int j = i + 1; j < count; j++) {
                    if (toDelete[j]) continue;
                    cJSON* nodeB = cJSON_GetArrayItem(outbounds, j);
                    
                    if (IsNodeDuplicate(nodeA, nodeB)) {
                        toDelete[j] = 1;
                        deletedCount++;
                    }
                }
            }

            if (deletedCount > 0) {
                // 重建数组
                cJSON* newArray = cJSON_CreateArray();
                for (int i = 0; i < count; i++) {
                     if (!toDelete[i]) {
                         cJSON* item = cJSON_GetArrayItem(outbounds, i);
                         cJSON_AddItemToArray(newArray, cJSON_Duplicate(item, 1));
                     }
                }
                cJSON_ReplaceItemInObject(root, "outbounds", newArray);
                
                char* out = cJSON_Print(root);
                WriteBufferToFile(CONFIG_FILE, out);
                free(out);
            }
            free(toDelete);
        }
    }

    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);

    if (deletedCount > 0) ParseTags();
    return deletedCount;
}

// [Refactor] 批量添加节点，已移除 VMess 解析调用
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds) {
    if (!text || !outbounds) return 0;
    int count = 0; 
    char* sourceText = NULL;
    unsigned char* decoded = NULL;
    size_t decLen = 0;

    if (strstr(text, "://")) {
        sourceText = _strdup(text);
    } else {
        decoded = Base64Decode(text, &decLen);
        if (decoded && decLen > 0) {
             sourceText = (char*)decoded;
        } else {
             if (decoded) free(decoded);
             sourceText = _strdup(text);
        }
    }
    
    if (!sourceText) return 0;
    
    char* p = sourceText;
    while (*p) {
        size_t span = strspn(p, "\r\n ,"); p += span; if (!*p) break;
        size_t len = strcspn(p, "\r\n ,");
        if (len > 0) {
            char* line = (char*)malloc(len + 1);
            if (line) {
                strncpy(line, p, len); 
                line[len] = '\0'; 
                TrimString(line);
                
                if (strlen(line) > 0) {
                    cJSON* node = NULL;
                    
                    // [Modified] 仅解析指定协议 (SS, VLESS, Trojan, Socks, Mandala)
                    if (_strnicmp(line, "ss://", 5) == 0) node = ParseShadowsocks(line);
                    else if (_strnicmp(line, "vless://", 8) == 0) node = ParseVlessOrTrojan(line);
                    else if (_strnicmp(line, "trojan://", 9) == 0) node = ParseVlessOrTrojan(line);
                    else if (_strnicmp(line, "socks://", 8) == 0) node = ParseSocks(line);
                    else if (_strnicmp(line, "mandala://", 10) == 0) node = ParseMandala(line); 
                    
                    if (node) {
                        cJSON* jsonType = cJSON_GetObjectItem(node, "type");
                        const char* typeStr = (jsonType && jsonType->valuestring) ? jsonType->valuestring : "proxy";
                        cJSON* jsonTag = cJSON_GetObjectItem(node, "tag");
                        const char* originalTag = (jsonTag && jsonTag->valuestring) ? jsonTag->valuestring : "Auto";
                        
                        // 调用已在 internal 头文件中声明的函数
                        char* uniqueTag = GetUniqueTagName(outbounds, typeStr, originalTag);
                        
                        if (cJSON_HasObjectItem(node, "tag")) cJSON_ReplaceItemInObject(node, "tag", cJSON_CreateString(uniqueTag));
                        else cJSON_AddStringToObject(node, "tag", uniqueTag);
                        
                        cJSON_AddItemToArray(outbounds, node); 
                        count++;
                    }
                }
                free(line);
            }
            p += len;
        }
    }
    
    free(sourceText); 
    return count;
}

int ImportFromClipboard() {
    char* text = GetClipboardText(); 
    if (!text) return 0;
    
    int successCount = 0;
    
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
    
    successCount = Internal_BatchAddNodesFromText(text, outbounds);
    
    if (successCount > 0) { 
        char* out = cJSON_Print(root); 
        WriteBufferToFile(CONFIG_FILE, out); 
        free(out); 
    }
    cJSON_Delete(root); 
    
    LeaveCriticalSection(&g_configLock);
    
    if (successCount > 0) ParseTags(); 
    free(text); 
    return successCount;
}
