/* src/utils_base.c */
// [Refactor] 2026: 修复字符处理的符号扩展问题，增强文件I/O健壮性
// [Fix] 2026-01-08: 修复 GCC/MinGW 下线程局部存储语法不兼容的问题

#include "utils.h"
#include "common.h"
#include "gui.h" // for WM_LOG_UPDATE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

// 最大允许读取的配置文件大小 (10MB)
#define MAX_FILE_READ_SIZE (10 * 1024 * 1024)

// [Fix] 定义跨平台线程局部存储宏
#if defined(_MSC_VER)
    #define THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__MINGW32__)
    #define THREAD_LOCAL __thread
#else
    #define THREAD_LOCAL _Thread_local // C11 standard
#endif

// --------------------------------------------------------------------------
// 字符串与内存辅助
// --------------------------------------------------------------------------

char* SafeStrDup(const char* s, int len) {
    if (!s || len < 0) return NULL;
    // [Safety] 检查整数溢出
    if (len == 2147483647) return NULL; 
    
    char* d = (char*)malloc(len + 1);
    if (d) { memcpy(d, s, len); d[len] = 0; }
    return d;
}

// --------------------------------------------------------------------------
// 日志系统
// --------------------------------------------------------------------------

void log_msg(const char *format, ...) {
    if (!g_enableLog) return;

    // [Refactor] 使用兼容的宏 THREAD_LOCAL
    static THREAD_LOCAL char tls_log_buf[4096];
    static THREAD_LOCAL char tls_combined_buf[4200];
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // 格式化日志内容
    va_list args; 
    va_start(args, format);
    vsnprintf(tls_log_buf, sizeof(tls_log_buf) - 1, format, args);
    va_end(args);
    tls_log_buf[sizeof(tls_log_buf) - 1] = '\0'; 
    
    // 组合时间戳
    // [Fix] 增加缓冲区边界检查，防止截断导致乱码
    int ret = _snprintf(tls_combined_buf, sizeof(tls_combined_buf), "[%02d:%02d:%02d] %s\r\n", 
                        st.wHour, st.wMinute, st.wSecond, tls_log_buf);
                        
    if (ret > 0) {
        // 输出到调试器 (DebugView)
        OutputDebugStringA(tls_combined_buf);
        
        // 发送到 GUI 日志窗口
        extern HWND hLogViewerWnd; 
        if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
            // GUI 接收宽字符，需转换
            int wLen = MultiByteToWideChar(CP_UTF8, 0, tls_combined_buf, -1, NULL, 0);
            if (wLen > 0) {
                // [Safety] 分配内存传递给 UI 线程
                // 注意：接收方 (WndProc) 必须负责 free 此内存，否则泄漏
                wchar_t* wBuf = (wchar_t*)malloc((wLen + 1) * sizeof(wchar_t));
                if (wBuf) {
                    MultiByteToWideChar(CP_UTF8, 0, tls_combined_buf, -1, wBuf, wLen);
                    wBuf[wLen] = 0;
                    
                    // 使用 PostMessage 异步发送
                    // 如果发送失败 (如队列满或窗口无效)，立即释放防止泄漏
                    if (!PostMessageW(hLogViewerWnd, WM_LOG_UPDATE, 0, (LPARAM)wBuf)) {
                        free(wBuf); 
                    }
                }
            }
        }
    }
}

// --------------------------------------------------------------------------
// Base64 / Hex
// --------------------------------------------------------------------------

static const int b64_table[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1 
};

unsigned char* Base64Decode(const char* input, size_t* out_len) {
    if(!input) return NULL;
    size_t len = strlen(input);
    if (len == 0) return NULL;

    // 处理末尾填充
    size_t actual_len = len;
    while (actual_len > 0 && input[actual_len-1] == '=') actual_len--;

    // 计算输出容量
    size_t out_capacity = (actual_len * 3) / 4 + 4;
    unsigned char* out = (unsigned char*)malloc(out_capacity);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    int value_buf = 0, bits_collected = 0;
    const char* p = input;
    
    while (*p) {
        // [Fix] 强制转换为 unsigned char，防止符号扩展导致负数索引越界
        unsigned char c = (unsigned char)*p; 
        p++;
        
        if (c == '=') break; 
        if (c > 127 || b64_table[c] == -1) continue; 
        
        int val = b64_table[c];
        value_buf = (value_buf << 6) | val;
        bits_collected += 6;
        if (bits_collected >= 8) {
            bits_collected -= 8;
            if (j < out_capacity) {
                out[j++] = (unsigned char)((value_buf >> bits_collected) & 0xFF);
            }
        }
    }
    out[j] = 0;
    if (out_len) *out_len = j;
    return out;
}

int HexToBin(const char* hex, unsigned char* out, int max_len) {
    int len = 0;
    while (*hex && len < max_len) {
        // [Fix] 使用 unsigned char 避免 isxdigit 在负值时的未定义行为
        unsigned char h1 = (unsigned char)*hex;
        if (!isxdigit(h1)) { hex++; continue; }
        
        int v1 = isdigit(h1) ? h1 - '0' : tolower(h1) - 'a' + 10;
        
        hex++; if (!*hex) break;
        
        unsigned char h2 = (unsigned char)*hex;
        int v2 = isdigit(h2) ? h2 - '0' : tolower(h2) - 'a' + 10;
        
        out[len++] = (v1 << 4) | v2; 
        hex++;
    }
    return len;
}

// --------------------------------------------------------------------------
// 文件操作
// --------------------------------------------------------------------------

BOOL ReadFileToBuffer(const wchar_t* filename, char** buffer, long* size) {
    if (!filename || !buffer) return FALSE;

    FILE* f = _wfopen(filename, L"rb");
    if (!f) return FALSE;
    
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return FALSE; }
    long fsize = ftell(f);
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return FALSE; }
    
    // [Safety] 增加文件大小上限检查和负值检查
    if (fsize < 0) { fclose(f); return FALSE; }
    if (fsize > MAX_FILE_READ_SIZE) {
        log_msg("[Error] File too large to read: %ls (%ld bytes)", filename, fsize);
        fclose(f);
        return FALSE;
    }

    *buffer = (char*)malloc(fsize + 1);
    if (!*buffer) { fclose(f); return FALSE; }
    
    size_t read_len = fread(*buffer, 1, fsize, f);
    (*buffer)[read_len] = 0;
    
    if (size) *size = (long)read_len;
    fclose(f);
    return TRUE;
}

BOOL WriteBufferToFile(const wchar_t* filename, const char* buffer) {
    wchar_t tempPath[MAX_PATH];
    
    if (!filename || !buffer) return FALSE;

    swprintf(tempPath, MAX_PATH, L"%s.tmp", filename);

    FILE* f = _wfopen(tempPath, L"wb");
    if (!f) {
        log_msg("[Config] Failed to create temp file: %ls", tempPath);
        return FALSE;
    }

    size_t len = strlen(buffer);
    if (fwrite(buffer, 1, len, f) != len) {
        log_msg("[Config] Failed to write temp file");
        fclose(f);
        DeleteFileW(tempPath);
        return FALSE;
    }
    fflush(f); 
    fclose(f);

    if (!MoveFileExW(tempPath, filename, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
         log_msg("[Config] Atomic swap failed, err=%d", GetLastError());
         DeleteFileW(tempPath);
         return FALSE;
    }

    return TRUE;
}

// --------------------------------------------------------------------------
// 字符串与杂项工具
// --------------------------------------------------------------------------

void TrimString(char* str) {
    if (!str) return;
    char* p = str;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p > str) memmove(str, p, strlen(p) + 1);
    char* pEnd = str + strlen(str) - 1;
    while (pEnd >= str && (*pEnd == ' ' || *pEnd == '\t' || *pEnd == '\r' || *pEnd == '\n')) *pEnd-- = 0;
}

// [Safety] UrlDecode 支持原地解码 (dst == src)，但调用者需确保 dst 空间足够
void UrlDecode(char* dst, const char* src) {
    if (!dst || !src) return;
    unsigned char a, b;
    while (*src) {
        // [Safety] 增强边界检查，防止 % 后无足够字符导致的越界读取
        // 且使用 unsigned char 确保 isxdigit 行为正确
        if ((*src == '%') && (src[1] != 0) && (src[2] != 0)) {
            a = (unsigned char)src[1];
            b = (unsigned char)src[2];
            
            if (isxdigit(a) && isxdigit(b)) {
                if (a >= 'a') a -= 'a' - 10; else if (a >= 'A') a -= 'A' - 10; else a -= '0';
                if (b >= 'a') b -= 'a' - 10; else if (b >= 'A') b -= 'A' - 10; else b -= '0';
                *dst++ = 16 * a + b; 
                src += 3;
                continue;
            }
        }
        
        if (*src == '+') { *dst++ = ' '; src++; }
        else { *dst++ = *src++; }
    }
    *dst++ = '\0';
}

char* GetQueryParam(const char* query, const char* key) {
    if (!query || !key) return NULL;
    char search[128]; 
    _snprintf(search, sizeof(search), "%s=", key);
    const char* p = strstr(query, search);
    if (!p) return NULL;
    
    // [Safety] 确保找到的 key 是独立的 (前缀检查)
    if (p != query && *(p-1) != '&' && *(p-1) != '?') return NULL; 
    
    p += strlen(search);
    const char* end_amp = strchr(p, '&');
    const char* end_hash = strchr(p, '#');
    // 找到最近的结束符
    const char* end = (end_amp && end_hash) ? (end_amp < end_hash ? end_amp : end_hash) : (end_amp ? end_amp : end_hash);
    
    int len = end ? (int)(end - p) : (int)strlen(p);
    if (len <= 0) return NULL;
    
    char* val = (char*)malloc(len + 1);
    if (val) { strncpy(val, p, len); val[len] = 0; }
    return val;
}

char* GetClipboardText() {
    if (!OpenClipboard(NULL)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    char* text = pszText ? SafeStrDup(pszText, (int)strlen(pszText)) : NULL;
    GlobalUnlock(hData); CloseClipboard();
    return text;
}
