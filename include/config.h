// 文件名: include/config.h
// [Refactor] 2024: 彻底移除了废弃的 VMess 声明，并增加了新功能接口
// [Refactor] 2026: 升级浏览器指纹模拟，支持多种浏览器及自定义输入

#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"
#include "cJSON.h"

// 注意：原有的全局变量 (g_localPort, g_proxyConfig 等) 已在 common.h 中声明

// --- [New] 浏览器指纹配置 ---
// 定义浏览器类型枚举
enum BrowserType {
    BROWSER_TYPE_NONE = 0,    // 禁用 (使用 OpenSSL 默认)
    BROWSER_TYPE_CHROME,      // Chrome (PC)
    BROWSER_TYPE_FIREFOX,     // Firefox (PC)
    BROWSER_TYPE_SAFARI,      // Safari (Mac/iOS)
    BROWSER_TYPE_EDGE,        // Edge
    BROWSER_TYPE_CUSTOM       // 自定义 (手动输入)
};

// 全局配置变量
extern int g_browserType;         // 当前选择的浏览器类型
extern char g_customCiphers[2048]; // 自定义加密套件字符串 (OpenSSL 格式)

// [New] 代理地址配置 (移入 config.json)
extern char g_localAddr[64];

// --- 订阅管理系统 ---
#define MAX_SUBS 20

// 定义更新模式枚举
enum UpdateMode {
    UPDATE_MODE_DAILY = 0,
    UPDATE_MODE_WEEKLY,
    UPDATE_MODE_CUSTOM,
    UPDATE_MODE_ON_START, // [Mod] 将 UPDATE_MODE_NEVER 改为 UPDATE_MODE_ON_START
    UPDATE_MODE_MANUAL    // [New] 手动更新模式
};

typedef struct {
    BOOL enabled;         // 是否启用
    char name[64];        // [New] 订阅名称 (可修改)
    char url[512];        // 订阅地址
    long long updateTime; // [New] 上次更新时间 (timestamp)
    int update_cycle;     // [New] 更新周期: 0=每天, 1=每周, 2=自定义, 3=启动时更新, 4=手动
} Subscription;

extern Subscription g_subs[MAX_SUBS];
extern int g_subCount;

// 订阅更新配置全局变量
extern int g_subUpdateMode;      // 更新模式: 0=每天, 1=每周, 2=自定义, 3=启动时更新
extern int g_subUpdateInterval;  // 自定义间隔（单位：小时）
extern long long g_lastUpdateTime; // 上次更新时间戳

// --- 核心设置 (config_settings.c) ---
void LoadSettings();
void SaveSettings();
void SetAutorun(BOOL enable);
BOOL IsAutorun();
void ToggleTrayIcon();

// [New] 跨模块通用的安全字符串复制函数
void ConfigSafeStrCpy(char* dest, size_t destSize, const char* src);

// --- 节点管理 (config_nodes.c) ---
void ParseTags();
void SwitchNode(const wchar_t* tag);
void ParseNodeConfigToGlobal(cJSON *node);
void DeleteNode(const wchar_t* tag);
void ToggleNodePin(const wchar_t* tag);
void SortNodes();
// [New] 保存节点排序
void SaveNodeOrder(wchar_t** orderedTags, int count);
BOOL AddNodeToConfig(cJSON* newNode);
int ImportFromClipboard();

// [New] 新增功能声明：置顶与去重
void SetNodeToTop(const wchar_t* tag); // 将指定节点移动到最顶部
int DeduplicateNodes();                // 节点去重，返回删除的数量

// [New] 内部函数公开，供 Subscription 和 Clipboard 模块调用
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds);

// --- 协议解析 (config_parsers.c) ---
// [Removed] VMess 解析声明已彻底移除
cJSON* ParseShadowsocks(const char* link);
cJSON* ParseVlessOrTrojan(const char* link);
cJSON* ParseSocks(const char* link);
cJSON* ParseMandala(const char* link);

// --- 订阅更新 (config_sub.c) ---
// [Mod] 增加 onlyDue 参数：TRUE=仅更新到期的订阅, FALSE=强制更新所有启用订阅
int UpdateAllSubscriptions(BOOL forceMsg, BOOL onlyDue);

#endif // CONFIG_H
