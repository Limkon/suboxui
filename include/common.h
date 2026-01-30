/* include/common.h */
#ifndef COMMON_H
#define COMMON_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

// [Critical Fix] 提升 select 模型支持的最大 Socket 数量
// 必须在包含 winsock2.h 之前定义，否则默认为 64。
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

// 防止旧版 SDK 警告，锁定最低支持 Windows 7 (0x0601)
#ifndef _WIN32_IE
#define _WIN32_IE 0x0601
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define WIN32_LEAN_AND_MEAN

// 尝试阻止 windows.h 包含 wincrypt.h 以避免与 OpenSSL 冲突
#define NOCRYPT 

// --- 生产环境限制参数 ---
// 注意：MAX_CONNECTIONS 必须小于 FD_SETSIZE
#ifndef MAX_CONNECTIONS
#define MAX_CONNECTIONS 512
#endif

#define IO_BUFFER_SIZE 16384 
// 允许的最大单帧大小 (8MB)
#define MAX_WS_FRAME_SIZE 8388608 
// 生产环境建议：单个进程用于网络缓冲的最大内存总量 (如 512MB)
#define MAX_TOTAL_MEMORY_USAGE (512 * 1024 * 1024)

// --- 调试与安全配置 ---
#define LOG_DESENSITIZE TRUE  // 开启日志脱敏

// --- 1. Windows 系统头文件 ---
#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <shlobj.h>
#include <wininet.h>

// --- 2. 引入资源头文件 (ID 定义源) ---
#include "resource.h"

// --- 3. 清理 Windows 宏污染 ---
#ifdef X509_NAME
#undef X509_NAME
#endif
#ifdef X509_EXTENSIONS
#undef X509_EXTENSIONS
#endif
#ifdef X509_CERT_PAIR
#undef X509_CERT_PAIR
#endif
#ifdef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_ISSUER_AND_SERIAL
#endif
#ifdef PKCS7_SIGNER_INFO
#undef PKCS7_SIGNER_INFO
#endif
#ifdef OCSP_REQUEST
#undef OCSP_REQUEST
#endif
#ifdef OCSP_RESPONSE
#undef OCSP_RESPONSE
#endif

// --- 4. 标准 C 头文件 ---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <ctype.h>

// --- 5. OpenSSL/BoringSSL 头文件 ---
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "cJSON.h"

// --- 宏定义 ---
#define REG_PATH_PROXY L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define CONFIG_FILE L"config.json"

// Windows Messages
#define WM_TRAY (WM_USER + 1)
#define WM_LOG_UPDATE (WM_USER + 2)
#define WM_REFRESH_NODELIST (WM_USER + 50)

// Command IDs
#define ID_TRAY_HIDE_ICON 1009
#define ID_GLOBAL_HOTKEY 9001

// ECH 设置控件 ID
#define ID_CHK_ECH         7022
#define ID_EDIT_ECH_SERVER 7023
#define ID_EDIT_ECH_DOMAIN 7024

// [New] 不安全连接复选框 ID
#define ID_CHK_INSECURE    7025

// [New] 定义最大规则数与内容长度
#define MAX_RULES 64
#define MAX_RULE_CONTENT_LEN 256

// --- 结构体定义 ---
typedef struct { 
    SOCKET sock; 
    SSL *ssl; 
} TLSContext;

typedef struct {
    char host[256]; 
    int port; 
    char path[256];
    char sni[256]; 
    char user[128]; 
    char pass[128];
    char type[32]; 
    char mode[64]; 
    BOOL allowInsecure;
} ProxyConfig;

// [New] 路由规则结构体
typedef struct {
    char type[32];          // "field"
    char outboundTag[32];   // "block", "direct", "proxy"
    char contents[16][MAX_RULE_CONTENT_LEN]; 
    int contentCount;
} RoutingRule;

// --- 全局变量声明 ---
extern ProxyConfig g_proxyConfig;
extern volatile BOOL g_proxyRunning;
extern SOCKET g_listen_sock;
extern SSL_CTX *g_ssl_ctx;
extern HANDLE hProxyThread;
extern NOTIFYICONDATAW nid;
extern HWND hwnd;
extern HMENU hMenu, hNodeSubMenu;
extern HWND hLogViewerWnd;
extern HFONT hLogFont;
extern HFONT hAppFont;
extern wchar_t** nodeTags;
extern int nodeCount;
extern wchar_t currentNode[256];
extern wchar_t g_editingTag[256];
extern BOOL g_isIconVisible;
extern wchar_t g_iniFilePath[MAX_PATH];
extern UINT g_hotkeyModifiers; 
extern UINT g_hotkeyVk;                          
extern int g_localPort;
extern int g_hideTrayStart; 
extern WNDPROC g_oldListBoxProc;
extern int g_nEditScrollPos;
extern int g_nEditContentHeight;

extern int g_browserType; 
extern char g_customCiphers[2048];

extern int g_alpnMode;
extern BOOL g_enableFragment;
extern int g_fragSizeMin;
extern int g_fragSizeMax;
extern int g_fragDelayMs;
extern BOOL g_enablePadding;
extern int g_padSizeMin;
extern int g_padSizeMax;
extern int g_uaPlatformIndex; 
extern char g_userAgentStr[512];

extern BOOL g_enableECH;
extern char g_echConfigServer[256]; 
extern char g_echPublicName[256];   

extern RoutingRule g_routingRules[MAX_RULES];
extern int g_routingRuleCount;

extern const wchar_t* UA_PLATFORMS[];
extern const char* UA_TEMPLATES[];

extern BOOL g_enableLog;
extern volatile LONG64 g_total_allocated_mem;
extern CRITICAL_SECTION g_configLock; 

void InitGlobalLocks();
void DeleteGlobalLocks();

// [New] 网络工具全局初始化与清理 (UtilsNet)
void UtilsNet_InitGlobal(void);
void CleanupUtilsNet(void);

// 内存池声明
void InitMemoryPool();
void CleanupMemoryPool();
void* Pool_Alloc_16K();
void Pool_Free_16K(void* ptr);

#endif // COMMON_H
