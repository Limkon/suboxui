/* src/globals.c */
// [Fix] 修复链接错误：
// 1. 移除 g_total_allocated_mem 定义 (已在 proxy_utils.c 中定义)
// 2. 增加 g_localAddr 定义
// [Mod] 2026: 增加 g_needReloadRoutes 全局变量

#include "common.h"
#include "proxy.h"

// --- 全局配置变量 ---
ProxyConfig g_proxyConfig = {0};
volatile BOOL g_proxyRunning = FALSE;

// [Fix] 定义本地监听地址 (之前缺失导致 undefined reference)
char g_localAddr[64] = "127.0.0.1";

// --- 网络资源 ---
SOCKET g_listen_sock = INVALID_SOCKET;
SSL_CTX *g_ssl_ctx = NULL;
HANDLE hProxyThread = NULL;

// --- GUI 资源 ---
NOTIFYICONDATAW nid = {0};
HWND hwnd = NULL;
HMENU hMenu = NULL;
HMENU hNodeSubMenu = NULL;
HWND hLogViewerWnd = NULL;
HFONT hLogFont = NULL;
HFONT hAppFont = NULL;

// --- 节点管理 ---
wchar_t** nodeTags = NULL;
int nodeCount = 0;
wchar_t currentNode[256] = {0};
wchar_t g_editingTag[256] = {0};

// --- 系统与状态 ---
BOOL g_isIconVisible = TRUE;
wchar_t g_iniFilePath[MAX_PATH] = {0};
UINT g_hotkeyModifiers = MOD_CONTROL | MOD_ALT;
UINT g_hotkeyVk = 'H';
int g_localPort = 1080;
int g_hideTrayStart = 0;
WNDPROC g_oldListBoxProc = NULL;
int g_nEditScrollPos = 0;
int g_nEditContentHeight = 0;

// --- 浏览器指纹与伪装 ---
int g_browserType = 0; 
char g_customCiphers[2048] = {0};
int g_alpnMode = 1;
BOOL g_enableFragment = FALSE;
int g_fragSizeMin = 5;
int g_fragSizeMax = 20;
int g_fragDelayMs = 2;
BOOL g_enablePadding = FALSE;
int g_padSizeMin = 100;
int g_padSizeMax = 500;
int g_uaPlatformIndex = 0; 
char g_userAgentStr[512] = {0};

// --- ECH 配置 ---
BOOL g_enableECH = FALSE;
char g_echConfigServer[256] = "https://dns.alidns.com/dns-query"; 
char g_echPublicName[256] = "cloudflare-ech.com";   

// [New] 路由规则全局变量
RoutingRule g_routingRules[MAX_RULES];
int g_routingRuleCount = 0;

// [New] 路由热重载标志
volatile BOOL g_needReloadRoutes = FALSE;

// --- 常量定义 ---
const wchar_t* UA_PLATFORMS[] = {
    L"Windows (Chrome)",
    L"Windows (Edge)",
    L"Windows (Firefox)",
    L"macOS (Safari)",
    L"macOS (Chrome)",
    L"Android (Chrome)",
    L"iOS (Safari)",
    L"自定义 (Custom)"
};

const char* UA_TEMPLATES[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "" 
};

// --- 调试与性能 ---
BOOL g_enableLog = FALSE;

// [Fix] 移除定义，改为仅引用，解决与 proxy_utils.c 的冲突
// volatile LONG64 g_total_allocated_mem = 0; 

CRITICAL_SECTION g_configLock; 

// --- 初始化/销毁锁 ---
void InitGlobalLocks() {
    InitializeCriticalSection(&g_configLock);
}

void DeleteGlobalLocks() {
    DeleteCriticalSection(&g_configLock);
}
