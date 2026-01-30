/* src/config_settings.c */
// 文件名: src/config_settings.c
// 包含: LoadSettings, SaveSettings, Globals, Helpers
// [Refactor] 2026-01-29: 实现原子文件写入 (Write-Replace)，防止配置文件损坏
// [Fix] 2026-01-29: 增强 JSON 解析容错与备份机制

#include "config.h"
#include "utils.h"
#include "common.h"
#include "cJSON.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h> 
#include <time.h> 
#include <ctype.h> 
#include <windows.h> // Ensure MoveFileExW is available

// --- 全局变量定义 ---
Subscription g_subs[MAX_SUBS];
int g_subCount = 0;

int g_subUpdateMode = 0;      // 0=每天 (默认)
int g_subUpdateInterval = 24; // 24小时 (默认)
long long g_lastUpdateTime = 0; 

// [Security] 安全字符串复制
void ConfigSafeStrCpy(char* dest, size_t destSize, const char* src) {
    if (!dest || destSize == 0) return;
    if (!src) { dest[0] = '\0'; return; }
    // 使用 snprintf 确保截断安全
    snprintf(dest, destSize, "%s", src);
}

// --- 辅助函数：文件路径与基础 I/O ---

static void GetJsonConfigPath(wchar_t* path, size_t size) {
    if (wcslen(g_iniFilePath) > 0) {
        wcscpy_s(path, size, g_iniFilePath);
        wchar_t *slash = wcsrchr(path, L'\\');
        if (slash) {
            *(slash + 1) = L'\0'; 
            wcscat_s(path, size, L"config.json");
        } else {
            wcscpy_s(path, size, L"config.json");
        }
    } else {
        wcscpy_s(path, size, L"config.json");
    }
}

// [Helper] 读取完整文件内容到内存 (无锁)
// 返回: 动态分配的 buffer，调用者需 free
static char* ReadFileContent(const wchar_t* path) {
    FILE* f = _wfopen(path, L"rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) { fclose(f); return NULL; }

    char* buffer = (char*)malloc(fsize + 1);
    if (!buffer) { fclose(f); return NULL; }

    if (fread(buffer, 1, fsize, f) != (size_t)fsize) {
        free(buffer);
        fclose(f);
        return NULL;
    }
    
    buffer[fsize] = '\0';
    fclose(f);
    return buffer;
}

// --- JSON 配置处理 (纯内存操作) ---

// [Refactor] 仅解析内存中的 JSON，应用到全局变量 (需在锁内调用)
static void ApplyJsonConfig(const char* jsonContent) {
    if (!jsonContent) return;

    cJSON* root = cJSON_Parse(jsonContent);
    if (root) {
        // 读取代理地址
        cJSON* jAddr = cJSON_GetObjectItem(root, "proxy_address");
        if (cJSON_IsString(jAddr) && (jAddr->valuestring != NULL)) {
            ConfigSafeStrCpy(g_localAddr, 64, jAddr->valuestring);
        }

        // 读取代理端口
        cJSON* jPort = cJSON_GetObjectItem(root, "proxy_port");
        if (cJSON_IsNumber(jPort)) {
            g_localPort = jPort->valueint;
        }

        // 读取选中节点
        cJSON* jNode = cJSON_GetObjectItem(root, "selected_node");
        if (cJSON_IsString(jNode) && (jNode->valuestring != NULL)) {
            MultiByteToWideChar(CP_UTF8, 0, jNode->valuestring, -1, currentNode, 256);
        }

        // [New] 解析路由规则 (Routing Rules)
        // 注意：此函数在 LoadSettings 的锁内调用，直接修改全局变量是安全的
        g_routingRuleCount = 0;
        cJSON* routing = cJSON_GetObjectItem(root, "routing");
        cJSON* rules = routing ? cJSON_GetObjectItem(routing, "rules") : NULL;
        
        if (rules && cJSON_IsArray(rules)) {
            int count = cJSON_GetArraySize(rules);
            if (count > MAX_RULES) count = MAX_RULES; // 限制最大规则数防止溢出

            for (int i = 0; i < count; i++) {
                cJSON* item = cJSON_GetArrayItem(rules, i);
                if (!item) continue;

                cJSON* cTag = cJSON_GetObjectItem(item, "outboundTag");
                cJSON* cDomains = cJSON_GetObjectItem(item, "domain");
                cJSON* cIPs = cJSON_GetObjectItem(item, "ip");
                
                // 仅当存在 tag 且有 domain 或 ip 内容时才加载
                if (cTag && cTag->valuestring && ((cDomains && cJSON_IsArray(cDomains)) || (cIPs && cJSON_IsArray(cIPs)))) {
                    RoutingRule* r = &g_routingRules[g_routingRuleCount];
                    memset(r, 0, sizeof(RoutingRule));

                    // 1. 读取策略 (block/direct/proxy)
                    ConfigSafeStrCpy(r->outboundTag, 32, cTag->valuestring);
                    
                    // 2. 读取域名列表
                    if (cDomains) {
                        int dCount = cJSON_GetArraySize(cDomains);
                        for (int j = 0; j < dCount; j++) {
                            if (r->contentCount >= 16) break; // 每个规则最多16个条目
                            cJSON* val = cJSON_GetArrayItem(cDomains, j);
                            if (val && val->valuestring) {
                                ConfigSafeStrCpy(r->contents[r->contentCount], MAX_RULE_CONTENT_LEN, val->valuestring);
                                r->contentCount++;
                            }
                        }
                    }
                    
                    // 3. 读取 IP 列表
                    if (cIPs) {
                         int iCount = cJSON_GetArraySize(cIPs);
                         for (int j = 0; j < iCount; j++) {
                            if (r->contentCount >= 16) break;
                            cJSON* val = cJSON_GetArrayItem(cIPs, j);
                            if (val && val->valuestring) {
                                ConfigSafeStrCpy(r->contents[r->contentCount], MAX_RULE_CONTENT_LEN, val->valuestring);
                                r->contentCount++;
                            }
                         }
                    }

                    if (r->contentCount > 0) {
                        g_routingRuleCount++;
                    }
                }
            }
        }
        
        cJSON_Delete(root);
    }
}

// [Refactor] 原子写入 JSON 配置 (先写临时文件，再 MoveFile)
static void WriteJsonConfig(const char* addr, int port, const wchar_t* wNode) {
    wchar_t jsonPath[MAX_PATH];
    wchar_t tempPath[MAX_PATH];
    GetJsonConfigPath(jsonPath, MAX_PATH);
    
    // 构造临时文件路径
    swprintf_s(tempPath, MAX_PATH, L"%s.tmp", jsonPath);

    cJSON* root = NULL;
    char* buffer = ReadFileContent(jsonPath); // 读取旧内容以保留其他字段

    if (buffer) {
        root = cJSON_Parse(buffer);
        free(buffer);
        
        // [Fix] 如果解析失败 (JSON 损坏)，创建一个新对象，避免 crash
        if (!root) {
            root = cJSON_CreateObject();
        }
    } else {
        root = cJSON_CreateObject();
    }
    
    // 更新字段
    if (cJSON_GetObjectItem(root, "proxy_address")) cJSON_DeleteItemFromObject(root, "proxy_address");
    cJSON_AddStringToObject(root, "proxy_address", addr);
    
    if (cJSON_GetObjectItem(root, "proxy_port")) cJSON_DeleteItemFromObject(root, "proxy_port");
    cJSON_AddNumberToObject(root, "proxy_port", port);

    // 转换节点名为 UTF-8
    char utf8Node[1024] = {0};
    WideCharToMultiByte(CP_UTF8, 0, wNode, -1, utf8Node, sizeof(utf8Node), NULL, NULL);
    
    if (cJSON_GetObjectItem(root, "selected_node")) cJSON_DeleteItemFromObject(root, "selected_node");
    cJSON_AddStringToObject(root, "selected_node", utf8Node);

    // 生成 JSON 字符串
    char* jsonStr = cJSON_Print(root);
    BOOL writeSuccess = FALSE;
    
    if (jsonStr) {
        // 1. 写入临时文件
        FILE* f = _wfopen(tempPath, L"wb");
        if (f) {
            if (fputs(jsonStr, f) >= 0) {
                writeSuccess = TRUE;
            }
            fclose(f);
        }
        free(jsonStr);
    }
    cJSON_Delete(root);

    // 2. 原子替换
    if (writeSuccess) {
        if (!MoveFileExW(tempPath, jsonPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            // 如果替换失败，尝试删除临时文件
            DeleteFileW(tempPath);
        }
    }
}

// --- 主加载与保存函数 ---

void LoadSettings() {
    // 1. [I/O] 预读取所有文件内容 (无锁)
    // 读取 INI (Win32 API 内部会有文件 I/O，但它是读取到栈变量，不占用全局锁)
    UINT modifiers = GetPrivateProfileIntW(L"Settings", L"Modifiers", MOD_CONTROL | MOD_ALT, g_iniFilePath);
    UINT vk = GetPrivateProfileIntW(L"Settings", L"VK", 'H', g_iniFilePath);
    int hideTray = GetPrivateProfileIntW(L"Settings", L"HideTray", 0, g_iniFilePath);
    
    int bType = GetPrivateProfileIntW(L"Settings", L"BrowserType", 0, g_iniFilePath);
    // 兼容旧配置
    if (bType == 0) {
        int oldChrome = GetPrivateProfileIntW(L"Settings", L"ChromeCiphers", -1, g_iniFilePath);
        if (oldChrome == 1) bType = 1; 
    }
    
    wchar_t wCustomCipher[2048] = {0};
    GetPrivateProfileStringW(L"Settings", L"CustomCiphers", L"", wCustomCipher, 2048, g_iniFilePath);
    
    int alpnMode = GetPrivateProfileIntW(L"Settings", L"ALPNMode", 1, g_iniFilePath);
    int oldEnableALPN = GetPrivateProfileIntW(L"Settings", L"EnableALPN", -1, g_iniFilePath);
    if (oldEnableALPN == 0) alpnMode = 0; 

    int enableFrag = GetPrivateProfileIntW(L"Settings", L"EnableFragment", 0, g_iniFilePath);
    int fragMin = GetPrivateProfileIntW(L"Settings", L"FragMin", 5, g_iniFilePath);
    int fragMax = GetPrivateProfileIntW(L"Settings", L"FragMax", 20, g_iniFilePath);
    int fragDly = GetPrivateProfileIntW(L"Settings", L"FragDelay", 2, g_iniFilePath);
    int enablePad = GetPrivateProfileIntW(L"Settings", L"EnablePadding", 0, g_iniFilePath);
    int padMin = GetPrivateProfileIntW(L"Settings", L"PadMin", 100, g_iniFilePath);
    int padMax = GetPrivateProfileIntW(L"Settings", L"PadMax", 500, g_iniFilePath);
    int uaIdx = GetPrivateProfileIntW(L"Settings", L"UAPlatform", 0, g_iniFilePath);

    int enableECH = GetPrivateProfileIntW(L"Settings", L"EnableECH", 0, g_iniFilePath);
    wchar_t wEchServer[256] = {0}, wEchPub[256] = {0};
    GetPrivateProfileStringW(L"Settings", L"ECHServer", L"https://dns.alidns.com/dns-query", wEchServer, 256, g_iniFilePath);
    GetPrivateProfileStringW(L"Settings", L"ECHPublicName", L"cloudflare-ech.com", wEchPub, 256, g_iniFilePath);

    int upMode = GetPrivateProfileIntW(L"Subscriptions", L"UpdateMode", 0, g_iniFilePath);
    int upInterval = GetPrivateProfileIntW(L"Subscriptions", L"UpdateInterval", 24, g_iniFilePath);
    wchar_t wTimeBuf[64] = {0};
    GetPrivateProfileStringW(L"Subscriptions", L"LastUpdateTime", L"0", wTimeBuf, 64, g_iniFilePath);
    long long lastTime = wcstoll(wTimeBuf, NULL, 10);

    wchar_t wUABuf[512] = {0}; 
    GetPrivateProfileStringW(L"Settings", L"UserAgent", L"", wUABuf, 512, g_iniFilePath);

    // 预读 JSON 配置文件
    wchar_t jsonPath[MAX_PATH];
    GetJsonConfigPath(jsonPath, MAX_PATH);
    char* jsonContent = ReadFileContent(jsonPath);
    
    // [Fix] 检查 JSON 完整性，如果损坏则备份
    if (jsonContent) {
        cJSON* test = cJSON_Parse(jsonContent);
        if (!test) {
             // JSON 损坏，备份文件
             wchar_t bakPath[MAX_PATH];
             swprintf_s(bakPath, MAX_PATH, L"%s.bak", jsonPath);
             CopyFileW(jsonPath, bakPath, FALSE);
             // 此时继续执行，ApplyJsonConfig 会忽略内容，但至少程序不崩
        } else {
            cJSON_Delete(test);
        }
    }

    // 读取订阅 (临时存储)
    int subCount = GetPrivateProfileIntW(L"Subscriptions", L"Count", 0, g_iniFilePath);
    if (subCount > MAX_SUBS) subCount = MAX_SUBS;
    
    // 使用栈内存临时存储订阅信息 (避免锁内 I/O)
    // Subscription 结构体约 600字节，20个约 12KB，栈上分配安全
    Subscription tempSubs[MAX_SUBS];
    memset(tempSubs, 0, sizeof(tempSubs));

    for (int i = 0; i < subCount; i++) {
        wchar_t wKeyEn[32], wKeyUrl[32], wKeyTime[32], wKeyCycle[32], wKeyName[32];
        wchar_t wUrl[512], wTime[64], wName[64];
        
        swprintf_s(wKeyEn, 32, L"Sub%d_Enabled", i); 
        swprintf_s(wKeyName, 32, L"Sub%d_Name", i); 
        swprintf_s(wKeyUrl, 32, L"Sub%d_Url", i);
        swprintf_s(wKeyTime, 32, L"Sub%d_UpdateTime", i);
        swprintf_s(wKeyCycle, 32, L"Sub%d_UpdateCycle", i);

        tempSubs[i].enabled = GetPrivateProfileIntW(L"Subscriptions", wKeyEn, 1, g_iniFilePath);
        tempSubs[i].update_cycle = GetPrivateProfileIntW(L"Subscriptions", wKeyCycle, 0, g_iniFilePath);
        
        GetPrivateProfileStringW(L"Subscriptions", wKeyName, L"", wName, 64, g_iniFilePath);
        if (wcslen(wName) > 0) {
            WideCharToMultiByte(CP_UTF8, 0, wName, -1, tempSubs[i].name, 64, NULL, NULL);
        } else {
            snprintf(tempSubs[i].name, 64, "订阅 %d", i + 1);
        }
        
        GetPrivateProfileStringW(L"Subscriptions", wKeyUrl, L"", wUrl, 512, g_iniFilePath);
        WideCharToMultiByte(CP_UTF8, 0, wUrl, -1, tempSubs[i].url, 512, NULL, NULL);
        
        GetPrivateProfileStringW(L"Subscriptions", wKeyTime, L"0", wTime, 64, g_iniFilePath);
        tempSubs[i].updateTime = wcstoll(wTime, NULL, 10);
    }

    // 2. [Lock] 快速应用配置到全局变量
    EnterCriticalSection(&g_configLock);

    g_hotkeyModifiers = modifiers; g_hotkeyVk = vk;
    g_hideTrayStart = hideTray;
    
    g_browserType = bType;
    WideCharToMultiByte(CP_UTF8, 0, wCustomCipher, -1, g_customCiphers, 2048, NULL, NULL);
    
    g_alpnMode = alpnMode;

    g_enableFragment = enableFrag; g_fragSizeMin = fragMin; g_fragSizeMax = fragMax; g_fragDelayMs = fragDly;
    g_enablePadding = enablePad; g_padSizeMin = padMin; g_padSizeMax = padMax;

    if (g_fragSizeMin < 1) g_fragSizeMin = 1; if (g_fragSizeMax < g_fragSizeMin) g_fragSizeMax = g_fragSizeMin;
    if (g_fragDelayMs < 0) g_fragDelayMs = 0; 
    if (g_padSizeMin < 0) g_padSizeMin = 0; if (g_padSizeMax < g_padSizeMin) g_padSizeMax = g_padSizeMin;

    g_enableECH = enableECH;
    WideCharToMultiByte(CP_UTF8, 0, wEchServer, -1, g_echConfigServer, sizeof(g_echConfigServer), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wEchPub, -1, g_echPublicName, sizeof(g_echPublicName), NULL, NULL);

    g_uaPlatformIndex = uaIdx;
    g_subUpdateMode = upMode; g_subUpdateInterval = upInterval; g_lastUpdateTime = lastTime;

    if (wcslen(wUABuf) > 5) WideCharToMultiByte(CP_UTF8, 0, wUABuf, -1, g_userAgentStr, sizeof(g_userAgentStr), NULL, NULL);
    else ConfigSafeStrCpy(g_userAgentStr, sizeof(g_userAgentStr), UA_TEMPLATES[0]);

    // 应用 JSON 配置
    currentNode[0] = L'\0'; // Reset before load
    if (jsonContent) {
        ApplyJsonConfig(jsonContent);
        free(jsonContent); // 释放内存
    }

    // 应用订阅列表
    g_subCount = subCount;
    for(int i=0; i<MAX_SUBS; i++) {
        g_subs[i] = tempSubs[i];
    }

    LeaveCriticalSection(&g_configLock);
}

void SaveSettings() {
    // 1. [Lock] 快照所有全局配置到本地变量 (Snapshot)
    EnterCriticalSection(&g_configLock);

    UINT s_modifiers = g_hotkeyModifiers;
    UINT s_vk = g_hotkeyVk;
    int s_hideTray = g_hideTrayStart;
    
    int s_browserType = g_browserType;
    char s_customCiphers[2048]; memcpy(s_customCiphers, g_customCiphers, sizeof(s_customCiphers));
    
    int s_alpnMode = g_alpnMode;
    int s_enableFrag = g_enableFragment;
    int s_fragMin = g_fragSizeMin; int s_fragMax = g_fragSizeMax; int s_fragDly = g_fragDelayMs;
    int s_enablePad = g_enablePadding;
    int s_padMin = g_padSizeMin; int s_padMax = g_padSizeMax;
    int s_uaIdx = g_uaPlatformIndex;
    
    int s_enableECH = g_enableECH;
    char s_echServer[256]; memcpy(s_echServer, g_echConfigServer, sizeof(s_echServer));
    char s_echPub[256]; memcpy(s_echPub, g_echPublicName, sizeof(s_echPub));
    
    char s_userAgent[512]; memcpy(s_userAgent, g_userAgentStr, sizeof(s_userAgent));
    
    // JSON 相关快照
    char s_localAddr[64]; memcpy(s_localAddr, g_localAddr, sizeof(s_localAddr));
    int s_localPort = g_localPort;
    wchar_t s_currentNode[256]; wcscpy_s(s_currentNode, 256, currentNode);

    // 订阅相关快照
    long long s_lastUpdate = g_lastUpdateTime;
    int s_subMode = g_subUpdateMode;
    int s_subInterval = g_subUpdateInterval;
    int s_subCount = g_subCount;
    
    // 申请堆内存快照订阅列表，防止栈溢出
    size_t subsSize = sizeof(Subscription) * MAX_SUBS;
    Subscription* s_subs = (Subscription*)malloc(subsSize);
    if (s_subs) {
        memcpy(s_subs, g_subs, subsSize);
    }

    LeaveCriticalSection(&g_configLock);

    // 2. [I/O] 执行文件写入 (无锁)
    
    wchar_t buffer[32];
    swprintf_s(buffer, 32, L"%u", s_modifiers); WritePrivateProfileStringW(L"Settings", L"Modifiers", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%u", s_vk); WritePrivateProfileStringW(L"Settings", L"VK", buffer, g_iniFilePath);
    
    // 清除旧 INI 端口配置
    WritePrivateProfileStringW(L"Settings", L"LocalPort", NULL, g_iniFilePath); 

    swprintf_s(buffer, 32, L"%d", s_hideTray); WritePrivateProfileStringW(L"Settings", L"HideTray", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_browserType); WritePrivateProfileStringW(L"Settings", L"BrowserType", buffer, g_iniFilePath);
    
    // 移除旧键
    WritePrivateProfileStringW(L"Settings", L"ChromeCiphers", NULL, g_iniFilePath);
    
    wchar_t wCustom[2048] = {0};
    MultiByteToWideChar(CP_UTF8, 0, s_customCiphers, -1, wCustom, 2048);
    WritePrivateProfileStringW(L"Settings", L"CustomCiphers", wCustom, g_iniFilePath);
    
    swprintf_s(buffer, 32, L"%d", s_alpnMode); WritePrivateProfileStringW(L"Settings", L"ALPNMode", buffer, g_iniFilePath);
    WritePrivateProfileStringW(L"Settings", L"EnableALPN", NULL, g_iniFilePath); 

    swprintf_s(buffer, 32, L"%d", s_enableFrag); WritePrivateProfileStringW(L"Settings", L"EnableFragment", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_fragMin); WritePrivateProfileStringW(L"Settings", L"FragMin", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_fragMax); WritePrivateProfileStringW(L"Settings", L"FragMax", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_fragDly); WritePrivateProfileStringW(L"Settings", L"FragDelay", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_enablePad); WritePrivateProfileStringW(L"Settings", L"EnablePadding", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_padMin); WritePrivateProfileStringW(L"Settings", L"PadMin", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_padMax); WritePrivateProfileStringW(L"Settings", L"PadMax", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_uaIdx); WritePrivateProfileStringW(L"Settings", L"UAPlatform", buffer, g_iniFilePath);
    
    swprintf_s(buffer, 32, L"%d", s_enableECH); WritePrivateProfileStringW(L"Settings", L"EnableECH", buffer, g_iniFilePath);
    
    wchar_t wEchServerOut[256] = {0}, wEchPubOut[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, s_echServer, -1, wEchServerOut, 256);
    WritePrivateProfileStringW(L"Settings", L"ECHServer", wEchServerOut, g_iniFilePath);
    MultiByteToWideChar(CP_UTF8, 0, s_echPub, -1, wEchPubOut, 256);
    WritePrivateProfileStringW(L"Settings", L"ECHPublicName", wEchPubOut, g_iniFilePath);

    wchar_t wUABuf[512] = {0}; 
    MultiByteToWideChar(CP_UTF8, 0, s_userAgent, -1, wUABuf, 512);
    WritePrivateProfileStringW(L"Settings", L"UserAgent", wUABuf, g_iniFilePath);

    WritePrivateProfileStringW(L"Settings", L"LastNode", NULL, g_iniFilePath);
    
    // 写入 config.json
    WriteJsonConfig(s_localAddr, s_localPort, s_currentNode);
    
    // 写入订阅
    WritePrivateProfileStringW(L"Subscriptions", NULL, NULL, g_iniFilePath); 
    
    wchar_t wTimeBuf[64]; swprintf_s(wTimeBuf, 64, L"%lld", s_lastUpdate);
    WritePrivateProfileStringW(L"Subscriptions", L"LastUpdateTime", wTimeBuf, g_iniFilePath);

    swprintf_s(buffer, 32, L"%d", s_subMode); WritePrivateProfileStringW(L"Subscriptions", L"UpdateMode", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_subInterval); WritePrivateProfileStringW(L"Subscriptions", L"UpdateInterval", buffer, g_iniFilePath);
    swprintf_s(buffer, 32, L"%d", s_subCount); WritePrivateProfileStringW(L"Subscriptions", L"Count", buffer, g_iniFilePath);

    if (s_subs) {
        for (int i = 0; i < s_subCount; i++) {
            wchar_t wKeyEn[32], wKeyUrl[32], wKeyTime[32], wKeyCycle[32], wKeyName[32];
            wchar_t wUrl[512], wVal[2], wTimeStr[64], wCycleStr[8], wName[64];

            swprintf_s(wKeyEn, 32, L"Sub%d_Enabled", i); 
            swprintf_s(wKeyName, 32, L"Sub%d_Name", i); 
            swprintf_s(wKeyUrl, 32, L"Sub%d_Url", i);
            swprintf_s(wKeyTime, 32, L"Sub%d_UpdateTime", i);
            swprintf_s(wKeyCycle, 32, L"Sub%d_UpdateCycle", i); 

            swprintf_s(wVal, 2, L"%d", s_subs[i].enabled); 
            WritePrivateProfileStringW(L"Subscriptions", wKeyEn, wVal, g_iniFilePath);
            
            MultiByteToWideChar(CP_UTF8, 0, s_subs[i].name, -1, wName, 64);
            WritePrivateProfileStringW(L"Subscriptions", wKeyName, wName, g_iniFilePath);

            swprintf_s(wCycleStr, 8, L"%d", s_subs[i].update_cycle);
            WritePrivateProfileStringW(L"Subscriptions", wKeyCycle, wCycleStr, g_iniFilePath);
            
            MultiByteToWideChar(CP_UTF8, 0, s_subs[i].url, -1, wUrl, 512); 
            WritePrivateProfileStringW(L"Subscriptions", wKeyUrl, wUrl, g_iniFilePath);

            swprintf_s(wTimeStr, 64, L"%lld", s_subs[i].updateTime);
            WritePrivateProfileStringW(L"Subscriptions", wKeyTime, wTimeStr, g_iniFilePath);
        }
        free(s_subs); // 释放快照内存
    }
}

void SetAutorun(BOOL enable) {
    HKEY hKey; wchar_t path[MAX_PATH]; GetModuleFileNameW(NULL, path, MAX_PATH);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (enable) RegSetValueExW(hKey, L"MyProxyClient", 0, REG_SZ, (BYTE*)path, (DWORD)(wcslen(path)+1)*sizeof(wchar_t));
        else RegDeleteValueW(hKey, L"MyProxyClient");
        RegCloseKey(hKey);
    }
}

BOOL IsAutorun() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"MyProxyClient", NULL, NULL, NULL, NULL) == ERROR_SUCCESS) { RegCloseKey(hKey); return TRUE; }
        RegCloseKey(hKey);
    }
    return FALSE;
}

void ToggleTrayIcon() {
    EnterCriticalSection(&g_configLock);
    if (g_isIconVisible) { Shell_NotifyIconW(NIM_DELETE, &nid); g_isIconVisible = FALSE; g_hideTrayStart = 1; }
    else { nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; Shell_NotifyIconW(NIM_ADD, &nid); g_isIconVisible = TRUE; g_hideTrayStart = 0; }
    LeaveCriticalSection(&g_configLock);
    SaveSettings(); 
}
