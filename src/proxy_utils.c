/* src/proxy_utils.c */
// [Refactor] 2026-01-29: 优化 IO 模型，消除退出时的界面卡顿
// [Security] 2026-01-29: 修复 read_header_robust 潜在的 Slowloris DoS 风险
// [Fix] 2026-01-29: 统一使用微秒级轮询检查 g_proxyRunning

#include "proxy_internal.h"
#include "utils.h" 
#include <openssl/sha.h>
#include <stdio.h> 
#include <stdlib.h>

extern volatile BOOL g_proxyRunning;
extern volatile LONG64 g_total_allocated_mem; 

// [Config] 轮询间隔 1ms
#define IO_POLL_INTERVAL_US 1000 

// 1. 动态内存分配与监控包装器
void* proxy_malloc(size_t size) {
    if (size > MAX_TOTAL_MEMORY_USAGE) {
        log_msg("[Warn] Huge allocation request (%zu bytes) denied.", size);
        return NULL;
    }
    if (g_total_allocated_mem + (LONG64)size > MAX_TOTAL_MEMORY_USAGE) {
        log_msg("[Warn] Memory limit reached, allocation denied.");
        return NULL;
    }
    void* p = malloc(size);
    if (p) InterlockedAdd64(&g_total_allocated_mem, (LONG64)size);
    return p;
}

void proxy_free(void* p, size_t size) {
    if (p) {
        free(p);
        InterlockedAdd64(&g_total_allocated_mem, -(LONG64)size);
    }
}

// 2. 解析 UUID
void parse_uuid(const char* uuid_str, unsigned char* out) {
    const char* p = uuid_str;
    int i = 0;
    while (*p && i < 16) {
        if (*p == '-' || *p == ' ' || *p == '{' || *p == '}') { 
            p++; continue; 
        }
        int v;
        if (sscanf(p, "%2x", &v) == 1) {
            out[i++] = (unsigned char)v;
            p += 2;
        } else {
            p++; 
        }
    }
}

// 3. Trojan 密码哈希
void trojan_password_hash(const char* password, char* out_hex) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224((unsigned char*)password, (size_t)strlen(password), digest);
    for(int i = 0; i < SHA224_DIGEST_LENGTH; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]); 
    }
    out_hex[SHA224_DIGEST_LENGTH * 2] = 0;
}

// 4. 接收超时辅助函数 (带全局状态检查)
// 返回: >0 字节数, 0 对方关闭, -1 错误, -2 超时
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec) {
    ULONGLONG start = GetTickCount64();
    ULONGLONG timeout_ms = (ULONGLONG)timeout_sec * 1000;

    while (g_proxyRunning) {
        if (GetTickCount64() - start > timeout_ms) return -2; // Timeout

        fd_set fds; 
        FD_ZERO(&fds); 
        FD_SET(s, &fds);
        
        // 使用短超时轮询，以便及时响应 g_proxyRunning 变化
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = IO_POLL_INTERVAL_US; // 1ms

        int n = select(0, &fds, NULL, NULL, &tv);
        
        if (n > 0) {
            // Data ready
            return recv(s, buf, len, 0);
        }
        else if (n < 0) {
            return -1; // Socket Error
        }
        // n == 0: continue loop
    }
    return -1; // App exit
}

// 5. 健壮的头部读取 (防止 Slowloris 攻击)
int read_header_robust(SOCKET s, char* buf, int max_len, int timeout_sec) {
    int total_read = 0;
    ULONGLONG start_tick = GetTickCount64();
    ULONGLONG max_duration = (ULONGLONG)timeout_sec * 1000;

    while (total_read < max_len - 1 && g_proxyRunning) {
        // [Security] 检查绝对超时，防止慢速攻击 (1 byte/sec)
        if (GetTickCount64() - start_tick > max_duration) return -1;

        // 计算剩余时间，但不超过单次 slice
        int n = recv_timeout(s, buf + total_read, max_len - 1 - total_read, 1); 
        
        if (n == -2) continue; // 小片超时，继续循环检查总超时
        if (n <= 0) return -1; // Error or Closed
        
        total_read += n;
        buf[total_read] = 0; 
        
        // SOCKS5 握手探测 (05 xx xx) - 长度足够即可返回
        if (buf[0] == 0x05) { 
            if (total_read >= 2) return total_read; 
        }
        // HTTP 探测 (\r\n\r\n)
        else { 
            if (strstr(buf, "\r\n\r\n")) return total_read; 
        }
        
        // [Security] 硬限制防止缓冲区溢出
        if (total_read >= max_len - 1) break; 
    }
    return total_read > 0 ? total_read : -1;
}

// 6. 发送全部数据 (非阻塞兼容 + 极速退出)
int send_all(SOCKET s, const char *buf, int len) {
    int total = 0; 
    int bytesleft = len; 
    int n;
    
    ULONGLONG start_wait = 0;
    const ULONGLONG MAX_WAIT_MS = 60000; // 60s 总超时

    while(total < len && g_proxyRunning) {
        n = send(s, buf+total, bytesleft, 0);
        
        if (n == -1) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { 
                if (start_wait == 0) start_wait = GetTickCount64();
                if (GetTickCount64() - start_wait > MAX_WAIT_MS) return -1;

                fd_set wfd; 
                FD_ZERO(&wfd); 
                FD_SET(s, &wfd);
                
                // [Fix] 1ms 轮询，消除停止代理时的卡顿
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = IO_POLL_INTERVAL_US; 
                
                select(0, NULL, &wfd, NULL, &tv);
                continue; 
            }
            return -1; // Real error
        }
        
        start_wait = 0; // 成功发送，重置超时计时
        total += n; 
        bytesleft -= n;
    }
    
    return g_proxyRunning ? total : -1;
}

// 7. Base64 编码 (用于 WS Key)
void base64_encode_key(const unsigned char* src, char* dst) {
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;
    
    // Process 15 bytes (3 * 5)
    for(i = 0; i < 15; i += 3) {
        int n = (src[i] << 16) + (src[i+1] << 8) + src[i+2];
        dst[j++] = table[(n >> 18) & 0x3F];
        dst[j++] = table[(n >> 12) & 0x3F];
        dst[j++] = table[(n >> 6) & 0x3F];
        dst[j++] = table[n & 0x3F];
    }
    
    // Last byte (index 15)
    int n = src[15] << 16;
    dst[j++] = table[(n >> 18) & 0x3F];
    dst[j++] = table[(n >> 12) & 0x3F];
    dst[j++] = '=';
    dst[j++] = '=';
    
    dst[j] = 0;
}
