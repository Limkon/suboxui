/* src/utils_net.c */
// [Refactor] 2026-01-29: 锁分离优化 (g_configLock -> s_netLock)
// [Refactor] 2026-01-22: 引入 UtilsNet_InitGlobal 实现 SSL 资源预加载
// [Fix] 2026-01-28: 增加 HTTP Chunked 解码支持与内存泄漏修复

#include "utils.h"
#include "config.h" 
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h> 

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

// --- ECH 缓存定义 ---
#define MAX_ECH_CACHE 64
#define ECH_CACHE_TTL 3600 // 1小时缓存

typedef struct {
    char domain[256];
    unsigned char* config;
    size_t len;
    time_t expires_at;
    BOOL in_use;
} ECHCacheEntry;

static ECHCacheEntry s_echCache[MAX_ECH_CACHE] = {0};
static SSL_CTX* g_utils_ctx = NULL;

// [Optimization] 初始化状态控制: 0=Uninit, 1=Initializing, 2=Done
static volatile LONG s_ctxInitState = 0; 

// [Lifecycle] 活跃请求计数与清理标志
static volatile LONG s_active_requests = 0;
static volatile BOOL s_is_cleaning_up = FALSE;

// [Lock Separation] 专用网络锁，避免阻塞 GUI
static CRITICAL_SECTION s_netLock;
static volatile LONG s_netLockInited = 0;

// --- 内部辅助函数 ---

// [Lock] 确保网络锁已初始化
static void EnsureNetLockInited() {
    if (s_netLockInited == 2) return;
    
    // 0 -> 1: 抢占初始化权
    if (InterlockedCompareExchange(&s_netLockInited, 1, 0) == 0) {
        InitializeCriticalSection(&s_netLock);
        s_netLockInited = 2; // 初始化完成
    } else {
        // 等待其他线程完成初始化
        while (s_netLockInited != 2) Sleep(0);
    }
}

// 清理单条缓存
static void FreeCacheEntry(int idx) {
    if (idx < 0 || idx >= MAX_ECH_CACHE) return;
    if (s_echCache[idx].config) {
        free(s_echCache[idx].config);
        s_echCache[idx].config = NULL;
    }
    s_echCache[idx].len = 0;
    s_echCache[idx].in_use = FALSE;
    memset(s_echCache[idx].domain, 0, sizeof(s_echCache[idx].domain));
}

// 查找缓存
static unsigned char* GetCachedECH(const char* domain, size_t* out_len) {
    EnsureNetLockInited();
    time_t now = time(NULL);
    unsigned char* ret = NULL;
    
    EnterCriticalSection(&s_netLock); // 使用 s_netLock
    for (int i = 0; i < MAX_ECH_CACHE; i++) {
        if (s_echCache[i].in_use) {
            if (now > s_echCache[i].expires_at) {
                FreeCacheEntry(i); // 过期清理
                continue;
            }
            if (_stricmp(s_echCache[i].domain, domain) == 0) {
                if (s_echCache[i].config && s_echCache[i].len > 0) {
                    ret = (unsigned char*)malloc(s_echCache[i].len);
                    if (ret) {
                        memcpy(ret, s_echCache[i].config, s_echCache[i].len);
                        *out_len = s_echCache[i].len;
                    }
                }
                break;
            }
        }
    }
    LeaveCriticalSection(&s_netLock);
    return ret;
}

// 写入缓存
static void SetCachedECH(const char* domain, const unsigned char* data, size_t len) {
    if (!domain || !data || len == 0) return;
    
    EnsureNetLockInited();
    EnterCriticalSection(&s_netLock); // 使用 s_netLock
    
    // 1. 检查是否已存在，存在则更新
    int empty_slot = -1;
    int oldest_slot = 0;
    time_t oldest_time = time(NULL) + ECH_CACHE_TTL * 2;

    for (int i = 0; i < MAX_ECH_CACHE; i++) {
        if (!s_echCache[i].in_use) {
            if (empty_slot == -1) empty_slot = i;
        } else {
            if (_stricmp(s_echCache[i].domain, domain) == 0) {
                FreeCacheEntry(i);
                empty_slot = i;
                break;
            }
            if (s_echCache[i].expires_at < oldest_time) {
                oldest_time = s_echCache[i].expires_at;
                oldest_slot = i;
            }
        }
    }

    if (empty_slot == -1) {
        FreeCacheEntry(oldest_slot);
        empty_slot = oldest_slot;
    }

    if (empty_slot >= 0 && empty_slot < MAX_ECH_CACHE) {
        strncpy(s_echCache[empty_slot].domain, domain, 255);
        s_echCache[empty_slot].domain[255] = '\0';
        
        s_echCache[empty_slot].config = (unsigned char*)malloc(len);
        if (s_echCache[empty_slot].config) {
            memcpy(s_echCache[empty_slot].config, data, len);
            s_echCache[empty_slot].len = len;
            s_echCache[empty_slot].expires_at = time(NULL) + ECH_CACHE_TTL;
            s_echCache[empty_slot].in_use = TRUE;
        }
    }
    
    LeaveCriticalSection(&s_netLock);
}

// [New] 全局初始化函数
void UtilsNet_InitGlobal() {
    if (s_is_cleaning_up) return;
    
    EnsureNetLockInited();

    if (InterlockedCompareExchange(&s_ctxInitState, 1, 0) == 0) {
        SSL_CTX* temp_ctx = SSL_CTX_new(TLS_client_method());
        if (temp_ctx) {
            // 预加载证书
            if (SSL_CTX_load_verify_locations(temp_ctx, "resources/cacert.pem", NULL) != 1) {
                if (SSL_CTX_load_verify_locations(temp_ctx, "cacert.pem", NULL) != 1) {
                    SSL_CTX_set_verify(temp_ctx, SSL_VERIFY_NONE, NULL);
                } else {
                    SSL_CTX_set_verify(temp_ctx, SSL_VERIFY_PEER, NULL);
                }
            } else {
                SSL_CTX_set_verify(temp_ctx, SSL_VERIFY_PEER, NULL);
            }
            
            EnterCriticalSection(&s_netLock); // 使用 s_netLock
            if (!s_is_cleaning_up) {
                g_utils_ctx = temp_ctx;
                InterlockedExchange(&s_ctxInitState, 2);
            } else {
                SSL_CTX_free(temp_ctx);
                InterlockedExchange(&s_ctxInitState, 0);
            }
            LeaveCriticalSection(&s_netLock);
        } else {
             InterlockedExchange(&s_ctxInitState, 0);
        }
    }
}

// 显式清理全局资源 (Safe Cleanup)
void CleanupUtilsNet() {
    s_is_cleaning_up = TRUE;

    // 等待活跃请求归零
    for (int i = 0; i < 300; i++) {
        if (InterlockedCompareExchange(&s_active_requests, 0, 0) == 0) break;
        Sleep(10);
    }

    if (s_netLockInited == 2) {
        EnterCriticalSection(&s_netLock);
        if (g_utils_ctx) {
            SSL_CTX_free(g_utils_ctx);
            g_utils_ctx = NULL;
        }
        
        for (int i = 0; i < MAX_ECH_CACHE; i++) {
            FreeCacheEntry(i);
        }
        LeaveCriticalSection(&s_netLock);
        
        DeleteCriticalSection(&s_netLock);
        s_netLockInited = 0;
    }
    
    InterlockedExchange(&s_ctxInitState, 0);
}

typedef struct { char host[256]; int port; char path[1024]; } URL_COMPONENTS_SIMPLE;

static BOOL ParseUrl(const char* url, URL_COMPONENTS_SIMPLE* out) {
    if (!url || !out) return FALSE;
    memset(out, 0, sizeof(URL_COMPONENTS_SIMPLE));
    const char* p = url;
    if (strncmp(p, "http://", 7) == 0) { p += 7; out->port = 80; }
    else if (strncmp(p, "https://", 8) == 0) { p += 8; out->port = 443; }
    else return FALSE;
    
    const char* slash = strchr(p, '/');
    int hostLen = slash ? (int)(slash - p) : (int)strlen(p);
    
    if (hostLen <= 0 || hostLen >= (int)sizeof(out->host)) return FALSE;
    
    strncpy(out->host, p, hostLen); 
    out->host[hostLen] = 0; 
    
    char* colon = strchr(out->host, ':');
    if (colon) { 
        *colon = 0; 
        out->port = atoi(colon + 1); 
        if (out->port <= 0 || out->port > 65535) return FALSE;
    }
    
    if (slash) {
        if (strlen(slash) >= sizeof(out->path)) return FALSE;
        strcpy(out->path, slash);
    } else {
        strcpy(out->path, "/");
    }
    return TRUE;
}

static int WaitSock(SOCKET s, int forWrite, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int n;
    if (forWrite) n = select(0, NULL, &fds, NULL, &tv);
    else n = select(0, &fds, NULL, NULL, &tv);
    return n;
}

static int DechunkBody(const char* src, int src_len, char* dest) {
    const char* p = src;
    const char* end = src + src_len;
    int total_decoded = 0;
    
    while (p < end) {
        char* end_ptr = NULL;
        long chunk_size = strtol(p, &end_ptr, 16);
        
        if (end_ptr == p) break; 
        
        p = end_ptr;
        if (p + 2 > end) break; 
        if (*p == '\r') p++; 
        if (*p == '\n') p++;
        else break; 
        
        if (chunk_size == 0) break; 
        if (p + chunk_size > end) break; 
        
        if (dest) {
            memcpy(dest + total_decoded, p, chunk_size);
        }
        total_decoded += chunk_size;
        p += chunk_size;
        
        if (p + 2 > end) break;
        if (*p == '\r') p++;
        if (*p == '\n') p++;
    }
    return total_decoded;
}

// [Refactor] 核心 HTTPS GET
static char* InternalHttpsGet(const char* url, int timeout_ms, size_t max_size, size_t* out_len) {
    if (s_is_cleaning_up) return NULL;
    InterlockedIncrement(&s_active_requests);

    char* result = NULL;
    SOCKET s = INVALID_SOCKET;
    SSL *ssl = NULL;
    char* buf = NULL;
    struct addrinfo *res = NULL;
    ULONGLONG start_tick = GetTickCount64();

    URL_COMPONENTS_SIMPLE u;
    if (!ParseUrl(url, &u)) goto cleanup; 

    if (s_ctxInitState != 2) {
        UtilsNet_InitGlobal();
        int wait_loops = 0;
        while (s_ctxInitState != 2 && wait_loops < 200) { 
             if (s_is_cleaning_up) goto cleanup;
             Sleep(10);
             wait_loops++;
        }
        if (s_ctxInitState != 2) goto cleanup;
    }

    if (!g_utils_ctx || s_is_cleaning_up) goto cleanup; 

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM;
    
    char portStr[16]; snprintf(portStr, 16, "%d", u.port);
    if (getaddrinfo(u.host, portStr, &hints, &res) != 0) goto cleanup;
    
    struct addrinfo *ptr = NULL;
    for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
        if (s_is_cleaning_up) break;
        ULONGLONG passed = GetTickCount64() - start_tick;
        if (passed >= (ULONGLONG)timeout_ms) break;

        s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        unsigned long on = 1;
        ioctlsocket(s, FIONBIO, &on);

        int c_res = connect(s, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (c_res == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(s); s = INVALID_SOCKET; continue;
            }
            int remain = timeout_ms - (int)(GetTickCount64() - start_tick);
            if (remain <= 0) { closesocket(s); s = INVALID_SOCKET; break; }
            if (WaitSock(s, 1, remain) <= 0) {
                closesocket(s); s = INVALID_SOCKET; continue; 
            }
        }
        break; 
    }
    
    if (res) { freeaddrinfo(res); res = NULL; }
    if (s == INVALID_SOCKET) goto cleanup;

    ssl = SSL_new(g_utils_ctx);
    if (!ssl) goto cleanup;
    
    SSL_set_fd(ssl, (int)s);
    SSL_set_tlsext_host_name(ssl, u.host);

    while (TRUE) {
        if (s_is_cleaning_up) goto cleanup;
        int remain = timeout_ms - (int)(GetTickCount64() - start_tick);
        if (remain <= 0) goto cleanup;

        int ret = SSL_connect(ssl);
        if (ret == 1) break; 
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            if (WaitSock(s, 0, remain) <= 0) goto cleanup;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (WaitSock(s, 1, remain) <= 0) goto cleanup;
        } else goto cleanup; 
    }

    char req[2048];
    snprintf(req, sizeof(req), 
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mandala-Client/1.0\r\nAccept: application/dns-message, application/json\r\nConnection: close\r\n\r\n", 
        u.path, u.host);
    
    int written = 0;
    int req_len = (int)strlen(req);
    while (written < req_len) {
        if (s_is_cleaning_up) goto cleanup;
        int remain = timeout_ms - (int)(GetTickCount64() - start_tick);
        if (remain <= 0) goto cleanup;

        int ret = SSL_write(ssl, req + written, req_len - written);
        if (ret > 0) written += ret;
        else {
             int err = SSL_get_error(ssl, ret);
             if (err == SSL_ERROR_WANT_WRITE) {
                 if (WaitSock(s, 1, remain) <= 0) goto cleanup;
             } else if (err == SSL_ERROR_WANT_READ) {
                 if (WaitSock(s, 0, remain) <= 0) goto cleanup;
             } else goto cleanup;
        }
    }

    size_t total_cap = 4096; 
    size_t total_len = 0;
    buf = (char*)malloc(total_cap);
    if (!buf) goto cleanup;
    
    while (buf && !s_is_cleaning_up) { 
        int remain = timeout_ms - (int)(GetTickCount64() - start_tick);
        if (remain <= 0) goto cleanup;

        if (total_len >= total_cap - 1024) {
            size_t new_cap = total_cap * 2;
            if (new_cap > max_size) goto cleanup;
            char* new_buf = (char*)realloc(buf, new_cap);
            if (!new_buf) goto cleanup; 
            buf = new_buf;
            total_cap = new_cap;
        }
        
        int n = SSL_read(ssl, buf + total_len, (int)(total_cap - total_len - 1));
        
        if (n > 0) {
            total_len += n;
            // 简单的 Content-Length 预分配
            if (total_len < 2048) {
                buf[total_len] = 0;
                char* cl_ptr = strstr(buf, "Content-Length: ");
                if (cl_ptr) {
                    long cl_val = atol(cl_ptr + 16);
                    if (cl_val > 0 && cl_val < (long)max_size) {
                        size_t needed = total_len + cl_val + 1024; 
                        if (needed > total_cap && needed <= max_size) {
                             char* opt_buf = (char*)realloc(buf, needed);
                             if (opt_buf) { buf = opt_buf; total_cap = needed; }
                        }
                    }
                }
            }
        } else {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ) {
                if (WaitSock(s, 0, remain) <= 0) goto cleanup;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                if (WaitSock(s, 1, remain) <= 0) goto cleanup;
            } else {
                if (n == 0) break; 
                break; 
            }
        }
    }
    
    if (buf && total_len > 0 && !s_is_cleaning_up) { 
        buf[total_len] = 0;
        int http_code = 0;
        if (sscanf(buf, "HTTP/%*d.%*d %d", &http_code) == 1 && http_code == 200) {
            char* body_start = strstr(buf, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                
                BOOL is_chunked = FALSE;
                char* h_ptr = buf;
                while (h_ptr < body_start) {
                     char* chunk_header = strstr(h_ptr, "Transfer-Encoding: chunked");
                     if (chunk_header && chunk_header < body_start) {
                         is_chunked = TRUE; break;
                     }
                     h_ptr += 1;
                     if (h_ptr >= body_start) break;
                }

                if (is_chunked) {
                    size_t body_len_raw = total_len - (body_start - buf);
                    char* decoded_body = (char*)malloc(body_len_raw + 1);
                    if (decoded_body) {
                        int dec_len = DechunkBody(body_start, (int)body_len_raw, decoded_body);
                        if (dec_len >= 0) {
                            decoded_body[dec_len] = 0;
                            result = decoded_body; // Success
                            if (out_len) *out_len = dec_len;
                        } else {
                            free(decoded_body);
                        }
                    }
                } else {
                    size_t header_len = (size_t)(body_start - buf);
                    if (total_len > header_len) {
                        size_t content_len = total_len - header_len;
                        result = (char*)malloc(content_len + 1);
                        if (result) {
                            memcpy(result, body_start, content_len);
                            result[content_len] = 0; 
                            if (out_len) *out_len = content_len;
                        }
                    } else {
                        if (out_len) *out_len = 0;
                        result = (char*)calloc(1, 1);
                    }
                }
            }
        }
    }

cleanup:
    // [Audit Fix] 安全释放 buf，如果 result 指向 buf 的一部分或 buf 本身（本例 result 为新 malloc），则互不影响
    if (buf) free(buf);
    if (res) freeaddrinfo(res);
    if (ssl) SSL_free(ssl); 
    if (s != INVALID_SOCKET) closesocket(s);
    
    InterlockedDecrement(&s_active_requests);
    return result;
}

char* Utils_HttpGet(const char* url) {
    if (!url) return NULL;
    return InternalHttpsGet(url, 10000, 4 * 1024 * 1024, NULL);
}

static unsigned char* ParseHttpsRData(const unsigned char* ptr, const unsigned char* end, size_t* out_len) {
    if (ptr + 2 > end) return NULL;
    ptr += 2; 

    int safe_guard = 0; 
    while (ptr < end && *ptr != 0) {
        if (++safe_guard > 100) return NULL; 
        int label_len = *ptr;
        if (ptr + label_len + 1 > end) return NULL;
        ptr += label_len + 1;
    }
    if (ptr >= end) return NULL; 
    ptr++; 

    while (ptr + 4 <= end) {
        int key = (ptr[0] << 8) | ptr[1];
        int val_len = (ptr[2] << 8) | ptr[3];
        ptr += 4;

        if (ptr + val_len > end) return NULL; 

        if (key == 0x0005) { 
            unsigned char* ech = (unsigned char*)malloc(val_len);
            if (ech) {
                memcpy(ech, ptr, val_len);
                *out_len = val_len;
                return ech;
            }
            return NULL; 
        }
        ptr += val_len;
    }
    return NULL;
}

static unsigned char* ParseEchFromHex(const char* hexStr, size_t* out_len) {
    if (!hexStr || !out_len) return NULL;
    
    const char* p = hexStr;
    if (strncmp(p, "\\#", 2) == 0) p += 2;
    while (*p && !isxdigit((unsigned char)*p)) p++; 

    unsigned char rdata[4096];
    int rdata_len = HexToBin(p, rdata, sizeof(rdata));
    if (rdata_len <= 0) return NULL;

    return ParseHttpsRData(rdata, rdata + rdata_len, out_len);
}

static unsigned char* ParseEchFromDnsPacket(const unsigned char* pkt, size_t len, size_t* out_len) {
    if (!pkt || len < 12) return NULL;
    
    const unsigned char* ptr = pkt + 12;
    const unsigned char* end = pkt + len;
    
    int qdcount = (pkt[4] << 8) | pkt[5];
    int ancount = (pkt[6] << 8) | pkt[7];
    
    for (int i = 0; i < qdcount; i++) {
        int jump_limit = 0;
        while (ptr < end && *ptr != 0) {
            if (++jump_limit > 50) return NULL; 
            int L = *ptr;
            if ((L & 0xC0) == 0xC0) { 
                if (ptr + 2 > end) return NULL; 
                ptr += 2; goto name_done; 
            } 
            if (ptr + L + 1 > end) return NULL;
            ptr += L + 1;
        }
        if (ptr >= end) return NULL;
        if (*ptr == 0) ptr++;
        name_done:
        if (ptr + 4 > end) return NULL;
        ptr += 4; 
    }
    
    for (int i = 0; i < ancount; i++) {
        int jump_limit = 0;
        while (ptr < end && *ptr != 0) {
            if (++jump_limit > 50) return NULL; 
            int L = *ptr;
            if ((L & 0xC0) == 0xC0) { 
                if (ptr + 2 > end) return NULL;
                ptr += 2; goto an_name_done; 
            }
            if (ptr + L + 1 > end) return NULL;
            ptr += L + 1;
        }
        if (ptr >= end) return NULL;
        if (*ptr == 0) ptr++;
        an_name_done:
        if (ptr + 10 > end) return NULL;
        int type = (ptr[0] << 8) | ptr[1];
        int rdlen = (ptr[8] << 8) | ptr[9];
        ptr += 10;
        if (ptr + rdlen > end) return NULL;
        if (type == 65) { 
            unsigned char* res = ParseHttpsRData(ptr, ptr + rdlen, out_len);
            if (res) return res;
        }
        ptr += rdlen;
    }
    return NULL;
}

static void Base64UrlEncode(const unsigned char* src, int len, char* dst) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int i, j = 0;
    for (i = 0; i < len; i += 3) {
        int val = (src[i] << 16) + (i+1 < len ? src[i+1] << 8 : 0) + (i+2 < len ? src[i+2] : 0);
        dst[j++] = tbl[(val >> 18) & 0x3F];
        dst[j++] = tbl[(val >> 12) & 0x3F];
        if (i + 1 < len) dst[j++] = tbl[(val >> 6) & 0x3F];
        if (i + 2 < len) dst[j++] = tbl[val & 0x3F];
    }
    dst[j] = 0;
}

unsigned char* FetchECHConfig(const char* domain, const char* doh_server, size_t* out_len) {
    if (!domain || !doh_server || !out_len) return NULL;
    *out_len = 0;

    unsigned char* cached = GetCachedECH(domain, out_len);
    if (cached) return cached;

    BOOL use_rfc8484 = (strstr(doh_server, "/dns-query") != NULL);
    char* resp_body = NULL;
    size_t resp_len = 0;

    if (use_rfc8484) {
        unsigned char dns_req[512];
        int req_len = 0;
        memset(dns_req, 0, 12);
        dns_req[5] = 1; 
        dns_req[2] = 0x01; 
        req_len = 12;
        
        const char* p = domain;
        while (*p) {
            const char* next = strchr(p, '.');
            int label_len = next ? (int)(next - p) : (int)strlen(p);
            if (req_len + label_len + 1 >= sizeof(dns_req)) break;
            dns_req[req_len++] = (unsigned char)label_len;
            memcpy(dns_req + req_len, p, label_len);
            req_len += label_len;
            if (!next) break;
            p = next + 1;
        }
        dns_req[req_len++] = 0; 
        dns_req[req_len++] = 0; dns_req[req_len++] = 65;
        dns_req[req_len++] = 0; dns_req[req_len++] = 1;

        char b64[1024];
        Base64UrlEncode(dns_req, req_len, b64);
        char url[2048];
        snprintf(url, sizeof(url), "%s?dns=%s", doh_server, b64);
        resp_body = InternalHttpsGet(url, 2000, 65536, &resp_len); 

    } else {
        char url[2048]; 
        if (snprintf(url, sizeof(url), "%s?name=%s&type=65", doh_server, domain) >= sizeof(url)) return NULL;
        resp_body = InternalHttpsGet(url, 500, 65536, &resp_len);
    }

    if (!resp_body || resp_len == 0) { 
        if (resp_body) free(resp_body);
        return NULL; 
    }
    
    unsigned char* ech_config = NULL; 

    if (use_rfc8484) {
        ech_config = ParseEchFromDnsPacket((unsigned char*)resp_body, resp_len, out_len);
    } else {
        cJSON* root = cJSON_Parse(resp_body); 
        if (root) {
            cJSON* answer = cJSON_GetObjectItem(root, "Answer");
            if (answer && cJSON_IsArray(answer)) {
                int array_size = cJSON_GetArraySize(answer);
                for (int i = 0; i < array_size; i++) {
                    cJSON* record = cJSON_GetArrayItem(answer, i);
                    if (!record) continue;
                    cJSON* type = cJSON_GetObjectItem(record, "type");
                    if (type && type->valueint == 65) { 
                        cJSON* data = cJSON_GetObjectItem(record, "data");
                        if (data && data->valuestring) {
                            const char* data_str = data->valuestring;
                            const char* tag = "ech=\"";
                            char* p_start = strstr(data_str, tag);
                            if (p_start) {
                                p_start += strlen(tag);
                                char* p_end = strchr(p_start, '"');
                                while (p_end && p_end > p_start && *(p_end - 1) == '\\') {
                                    p_end = strchr(p_end + 1, '"');
                                }
                                if (p_end) {
                                    size_t b64_len = (size_t)(p_end - p_start);
                                    char* b64_str = (char*)malloc(b64_len + 1);
                                    if (b64_str) {
                                        memcpy(b64_str, p_start, b64_len);
                                        b64_str[b64_len] = 0;
                                        ech_config = Base64Decode(b64_str, out_len);
                                        free(b64_str);
                                    }
                                }
                            }
                            if (!ech_config) {
                                ech_config = ParseEchFromHex(data_str, out_len);
                            }
                        }
                    }
                    if (ech_config) break; 
                }
            }
            cJSON_Delete(root);
        }
    }
    free(resp_body);

    if (ech_config && *out_len > 0) {
        SetCachedECH(domain, ech_config, *out_len);
    }
    return ech_config;
}

BOOL IsIpStr(const char* s) {
    if (!s) return FALSE;
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, s, &a4) == 1) return TRUE;
    if (inet_pton(AF_INET6, s, &a6) == 1) return TRUE;
    return FALSE;
}

BOOL IsValidCidrOrIp(const char* input) {
    if (!input || strlen(input) == 0) return FALSE;
    char temp[128];
    strncpy(temp, input, sizeof(temp)-1);
    temp[sizeof(temp)-1] = 0;
    char* slash = strchr(temp, '/');
    if (slash) {
        *slash = 0; 
        int mask = atoi(slash + 1);
        if (mask < 0 || mask > 128) return FALSE;
    }
    return IsIpStr(temp);
}

static int check_bits_match(const unsigned char* target, const unsigned char* rule, int prefix_len) {
    int byte_len = prefix_len / 8;
    int bit_len = prefix_len % 8;
    if (memcmp(target, rule, byte_len) != 0) return 0;
    if (bit_len > 0) {
        unsigned char mask = (0xFF << (8 - bit_len));
        if ((target[byte_len] & mask) != (rule[byte_len] & mask)) return 0;
    }
    return 1; 
}

int CidrMatch(const char* target_ip_str, const char* rule_cidr) {
    if (!target_ip_str || !rule_cidr) return 0;

    char rule_ip_part[128];
    int prefix = -1;

    const char* slash = strchr(rule_cidr, '/');
    if (slash) {
        size_t len = slash - rule_cidr;
        if (len >= sizeof(rule_ip_part)) return 0;
        strncpy(rule_ip_part, rule_cidr, len);
        rule_ip_part[len] = 0;
        prefix = atoi(slash + 1);
    } else {
        strncpy(rule_ip_part, rule_cidr, sizeof(rule_ip_part)-1);
        rule_ip_part[sizeof(rule_ip_part)-1] = 0;
        prefix = -1; 
    }

    struct in_addr t4, r4;
    struct in6_addr t6, r6;

    if (inet_pton(AF_INET, target_ip_str, &t4) == 1) {
        if (inet_pton(AF_INET, rule_ip_part, &r4) == 1) {
            if (prefix == -1) prefix = 32;
            if (prefix > 32) prefix = 32;
            return check_bits_match((unsigned char*)&t4, (unsigned char*)&r4, prefix);
        }
        return 0; 
    }

    if (inet_pton(AF_INET6, target_ip_str, &t6) == 1) {
        if (inet_pton(AF_INET6, rule_ip_part, &r6) == 1) {
            if (prefix == -1) prefix = 128;
            if (prefix > 128) prefix = 128;
            return check_bits_match((unsigned char*)&t6, (unsigned char*)&r6, prefix);
        }
        return 0;
    }

    return 0; 
}
