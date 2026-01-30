/* include/utils.h */
#ifndef UTILS_H
#define UTILS_H

#include "common.h"
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// --------------------------------------------------------------------------
// 基础工具 (utils_base.c)
// --------------------------------------------------------------------------

// 日志记录
void log_msg(const char *format, ...);

// [New] 日志等级宏：自动添加标签以便 gui_log.c 识别过滤
// 使用示例: LOG_INFO("Client %d connected", id);
#define LOG_DEBUG(...) log_msg("[DEBUG] " __VA_ARGS__)
#define LOG_INFO(...)  log_msg("[INFO]  " __VA_ARGS__)
#define LOG_WARN(...)  log_msg("[WARN]  " __VA_ARGS__)
#define LOG_ERROR(...) log_msg("[ERROR] " __VA_ARGS__)

// 字符串与内存
char* SafeStrDup(const char* s, int len);
void TrimString(char* str);
void UrlDecode(char* dst, const char* src);
char* GetQueryParam(const char* query, const char* key);
char* GetClipboardText(); // 从剪贴板获取文本

// Base64 / Hex
unsigned char* Base64Decode(const char* input, size_t* out_len);
int HexToBin(const char* hex, unsigned char* out, int max_len);

// 文件操作
BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size);
BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer);

// --------------------------------------------------------------------------
// 网络工具 (utils_net.c)
// --------------------------------------------------------------------------

// 简单的 HTTPS GET 请求 (用于 ECH 获取等)
char* Utils_HttpGet(const char* url);

// 获取域名的 ECH 配置 (DoH)
unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len);

// [New] IP/CIDR 通用工具
BOOL IsIpStr(const char* s);
BOOL IsValidCidrOrIp(const char* input);
int CidrMatch(const char* target_ip_str, const char* rule_cidr);

// 清理网络工具库使用的全局资源 (如 SSL_CTX)
void CleanupUtilsNet();

// --------------------------------------------------------------------------
// 节点工具 (utils_node.c)
// --------------------------------------------------------------------------

// TCP Ping 测速
int TcpPing(const char* address, int port, int timeout_ms);

// 获取节点详情 (类型、地址等)
void GetNodeDetailInfo(const wchar_t* nodeTag, char* outType, int typeLen, char* outAddr, int addrLen);

// 获取节点纯地址和端口
void GetNodeAddressInfo(const wchar_t* nodeTag, char* outAddr, int addrLen, int* outPort);

// --------------------------------------------------------------------------
// 系统工具 (utils_sys.c)
// --------------------------------------------------------------------------

// [Fix] 返回值修改为 BOOL 以匹配实现
// 设置系统代理 (WinINET / Registry)
BOOL SetSystemProxy(BOOL enable);

// 检查系统代理状态
BOOL IsSystemProxyEnabled();

// [Fix] 返回值修改为 BOOL 以匹配实现
// 开机启动设置
BOOL SetAutoStartup(BOOL enable);
BOOL CheckAutoStartup();

// --------------------------------------------------------------------------
// 内存池 (utils_sys.c)
// --------------------------------------------------------------------------

// 初始化内存池
void InitMemoryPool();

// 清理内存池
void CleanupMemoryPool();

// 申请 16KB 内存块 (线程安全, 高性能)
void* Pool_Alloc_16K();

// 释放 16KB 内存块
void Pool_Free_16K(void* ptr);

#ifdef __cplusplus
}
#endif

#endif // UTILS_H
