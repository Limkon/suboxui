/* src/config_sub.c */
// 文件名: src/config_sub.c
// 包含: UpdateAllSubscriptions
// [Refactor] 2026-01-29: 增强订阅更新的原子性与内存安全性
// [Fix] 2026-01-29: 实现 config.json 的原子写入 (Write-Replace)，防止更新中断导致配置丢失

#include "config.h"
#include "utils.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <windows.h> // For MoveFileExW

// 内部辅助：读取文件内容 (无锁)
static char* Internal_ReadFile(const wchar_t* path) {
    FILE* f = _wfopen(path, L"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) { fclose(f); return NULL; }
    char* buffer = (char*)malloc(fsize + 1);
    if (!buffer) { fclose(f); return NULL; }
    if (fread(buffer, 1, fsize, f) != (size_t)fsize) { free(buffer); fclose(f); return NULL; }
    buffer[fsize] = 0;
    fclose(f);
    return buffer;
}

// 内部辅助：原子写入文件
static BOOL Internal_AtomicWriteFile(const wchar_t* path, const char* content) {
    if (!path || !content) return FALSE;
    
    wchar_t tempPath[MAX_PATH];
    swprintf_s(tempPath, MAX_PATH, L"%s.sub.tmp", path);
    
    FILE* f = _wfopen(tempPath, L"wb");
    if (!f) return FALSE;
    
    if (fputs(content, f) < 0) {
        fclose(f);
        DeleteFileW(tempPath);
        return FALSE;
    }
    fclose(f);
    
    // 原子替换
    if (!MoveFileExW(tempPath, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tempPath);
        return FALSE;
    }
    return TRUE;
}

// [Mod] UpdateAllSubscriptions: 实现差异化更新，互不影响，且保留手动节点
// forceMsg: 是否显示日志/弹窗 (手动模式=TRUE)
// onlyDue: 是否仅更新到期的订阅 (自动模式=TRUE)
int UpdateAllSubscriptions(BOOL forceMsg, BOOL onlyDue) {
    // 1. 确定需要更新的订阅索引
    int indicesToUpdate[MAX_SUBS];
    int updateCount = 0;
    long long now = (long long)time(NULL);

    EnterCriticalSection(&g_configLock);
    
    for (int i = 0; i < g_subCount; i++) {
        // 边界检查
        if (i >= MAX_SUBS) break;

        if (!g_subs[i].enabled) continue;

        BOOL needUpdate = FALSE;
        if (!onlyDue) {
            // 手动模式或启动显式调用：强制更新所有启用的
            needUpdate = TRUE;
        } else {
            // 自动模式：检查周期
            int cycle = g_subs[i].update_cycle;
            
            // [Mod] 自动定时轮询时跳过“启动时更新”和“手动更新”模式
            // “启动时更新”模式由 main 启动时触发
            // “手动更新”模式仅由用户点击按钮触发
            if (cycle == UPDATE_MODE_ON_START || cycle == UPDATE_MODE_MANUAL) continue;

            long long interval = 24 * 3600; // 默认每天
            if (cycle == UPDATE_MODE_WEEKLY) interval = 7 * 24 * 3600;
            else if (cycle == UPDATE_MODE_CUSTOM) interval = (long long)g_subUpdateInterval * 3600;

            if (g_subs[i].updateTime == 0 || (now - g_subs[i].updateTime) >= interval) {
                needUpdate = TRUE;
            }
        }

        if (needUpdate) {
            indicesToUpdate[updateCount++] = i;
        }
    }
    
    // 复制 URL 以便在锁外下载
    // [Stack Safety] MAX_SUBS=20, 512 bytes each => ~10KB stack, safe.
    char urlsToDownload[MAX_SUBS][512];
    for(int k = 0; k < updateCount; k++) {
        int idx = indicesToUpdate[k];
        ConfigSafeStrCpy(urlsToDownload[k], sizeof(urlsToDownload[k]), g_subs[idx].url);
    }
    
    LeaveCriticalSection(&g_configLock);

    if (updateCount == 0) {
        if (forceMsg) log_msg("[Sub] No subscriptions need update.");
        return 0;
    }

    // 2. 网络下载 (耗时操作，不加锁)
    if (forceMsg) log_msg("[Sub] Updating %d subscriptions...", updateCount);
    
    char* rawData[MAX_SUBS] = {0}; 
    int successCount = 0;

    for (int k = 0; k < updateCount; k++) {
        if (forceMsg) log_msg("[Sub] DL (%d/%d): %s", k+1, updateCount, urlsToDownload[k]);
        char* data = Utils_HttpGet(urlsToDownload[k]);
        if (data) { 
            rawData[k] = data; 
            successCount++;
            if (forceMsg) log_msg("[Sub] Downloaded %d bytes", strlen(data));
        } else {
            if (forceMsg) log_msg("[Sub] Failed to download: %s", urlsToDownload[k]);
        }
    }

    if (successCount == 0) {
        if (forceMsg) log_msg("[Err] All downloads failed. Old nodes retained.");
        return 0;
    }

    // 3. 核心逻辑：合并新旧节点 (加锁，防止与 UI 操作冲突)
    EnterCriticalSection(&g_configLock);

    // [Fix] 使用内部读取函数
    char* buffer = Internal_ReadFile(CONFIG_FILE); 
    cJSON* root = NULL;
    
    if (buffer) { 
        root = cJSON_Parse(buffer); 
        free(buffer); 
    }
    
    // 如果解析失败或文件不存在，创建新对象
    if (!root) { 
        root = cJSON_CreateObject(); 
    }
    
    cJSON* oldOutbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* newOutbounds = cJSON_CreateArray(); // 用于构建新的完整列表
    
    if (!newOutbounds) {
        // OOM Emergency
        cJSON_Delete(root);
        for(int k=0; k<updateCount; k++) if(rawData[k]) free(rawData[k]);
        LeaveCriticalSection(&g_configLock);
        return 0;
    }

    // A. 保留阶段：遍历旧节点，保留“未参与本次成功更新”的节点（包括手动节点）
    if (oldOutbounds && cJSON_IsArray(oldOutbounds)) {
        cJSON* node = oldOutbounds->child;
        cJSON* next = NULL;
        
        while (node) {
            next = node->next; 
            
            BOOL shouldKeep = TRUE;
            
            // 检查该节点是否属于本次“下载成功”的订阅
            cJSON* subUrlTag = cJSON_GetObjectItem(node, "_sub_url");
            if (subUrlTag && subUrlTag->valuestring) {
                for (int k = 0; k < updateCount; k++) {
                    // 如果节点的 _sub_url 匹配某个本次下载成功的 URL，则不保留（准备替换为新的）
                    if (rawData[k] != NULL && strcmp(subUrlTag->valuestring, urlsToDownload[k]) == 0) {
                        shouldKeep = FALSE;
                        break;
                    }
                }
            } else {
                // 没有 _sub_url 标签的通常是手动添加的节点，必须保留
                shouldKeep = TRUE;
            }
            
            if (shouldKeep) {
                cJSON_DetachItemViaPointer(oldOutbounds, node);
                cJSON_AddItemToArray(newOutbounds, node);
            }
            
            node = next;
        }
    }
    
    if (cJSON_HasObjectItem(root, "outbounds")) {
        cJSON_DeleteItemFromObject(root, "outbounds");
    }
    cJSON_AddItemToObject(root, "outbounds", newOutbounds);

    // B. 追加阶段：解析新下载的数据并打标
    int totalNewNodes = 0;
    now = (long long)time(NULL);

    for (int k = 0; k < updateCount; k++) {
        if (rawData[k]) {
            cJSON* tempArray = cJSON_CreateArray();
            if (tempArray) {
                // 调用解析器将文本转换为 JSON 节点数组
                int c = Internal_BatchAddNodesFromText(rawData[k], tempArray);
                
                cJSON* tNode = tempArray->child;
                while (tNode) {
                    cJSON* nextT = tNode->next;
                    cJSON_DetachItemViaPointer(tempArray, tNode);
                    
                    // 打上订阅来源标签
                    if (cJSON_HasObjectItem(tNode, "_sub_url")) cJSON_DeleteItemFromObject(tNode, "_sub_url");
                    cJSON_AddStringToObject(tNode, "_sub_url", urlsToDownload[k]);
                    
                    cJSON_AddItemToArray(newOutbounds, tNode);
                    tNode = nextT;
                }
                cJSON_Delete(tempArray); 

                totalNewNodes += c;
                if (forceMsg) log_msg("[Sub] Parsed %d nodes from sub %d", c, indicesToUpdate[k] + 1);

                int idx = indicesToUpdate[k];
                g_subs[idx].updateTime = now;
            }
            
            free(rawData[k]);
        }
    }

    // 4. 保存文件 (原子写入)
    char* out = cJSON_Print(root); 
    if (out) {
        // [Fix] 使用原子写入替代 WriteBufferToFile
        if (!Internal_AtomicWriteFile(CONFIG_FILE, out)) {
            if (forceMsg) log_msg("[Err] Failed to save config file!");
        }
        free(out); 
    }
    cJSON_Delete(root);
    
    if (successCount > 0) {
        g_lastUpdateTime = now;
        SaveSettings(); // 保存订阅的时间戳更新
    }
    
    LeaveCriticalSection(&g_configLock);
    
    // 重新加载内存中的 Tags 列表以刷新界面
    ParseTags(); 
    
    if (forceMsg) {
        log_msg("[Sub] Update done. Total new added: %d", totalNewNodes);
    }
    
    return totalNewNodes;
}
