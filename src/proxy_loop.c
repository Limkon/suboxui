/* src/proxy_loop.c */
// [Refactor] 2026-01-28: 修复 UDP 转发中的 DNS 阻塞问题，改为异步线程解析 + 丢包重试机制
// [Refactor] 2026-01-28: 修复 send_robust 的软超时问题，改为绝对时间截止 (Hard Timeout)
// [Fix] 2026-01-28: 修复 HTTP/1.1 循环中错误向纯 TCP 连接发送 WebSocket Ping 的问题
// [Refactor] 2026-01-17: 修复非阻塞 Socket 下的同步写风险，优化缓冲区管理
// [Fix] 2026-01-17: 优化 send_robust 超时策略，消除网络波动 (50ms -> 1ms)
// [Feature] 2026-01-20: 新增 Keep-Alive 心跳保活 (15-50s 随机间隔)
// [Mod] 2026: 新增 UDP Direct Loop 支持 SOCKS5 UDP Associate
// [Fix] 2026-01-24: 修复 Direct 直连模式下误用 TLS/WS 封装导致连接失败的问题
// [Fix] 2026-01-24: 补充 TCP 直连模式的空闲超时检测 (Idle Timeout)

#include "proxy_internal.h"
#include "utils.h"
#include "common.h" 
#include <stdlib.h> 
#include <assert.h> 
#include <stdint.h> 
#include <limits.h> 
#include <time.h>   
#include <ws2tcpip.h> // for getaddrinfo
#include <process.h>  // for _beginthreadex

#define WS_FRAME_OVERHEAD 16 
#define MAX_BURST_LOOPS 32
#define PAGE_ALIGN_SIZE 4096

// [New] 定义直连模式的空闲超时时间 (300秒)
#define TCP_DIRECT_IDLE_TIMEOUT 300000 

// --- DNS Cache (Async Implementation) ---
// 用于减少 UDP 转发循环中 getaddrinfo 的调用频率，并避免阻塞
typedef struct {
    char domain[256];
    struct in_addr ip;
    ULONGLONG expire_tick;
    // [Fix] 状态机：0=Empty/Expired, 1=Ready, 2=Resolving
    volatile int state; 
} DNSCacheEntry;

#define DNS_CACHE_SIZE 64
static DNSCacheEntry s_dnsCache[DNS_CACHE_SIZE];
static CRITICAL_SECTION s_dnsLock;
static volatile long s_dnsInitState = 0;

static void EnsureDnsCacheInited() {
    if (InterlockedCompareExchange(&s_dnsInitState, 1, 0) == 0) {
        InitializeCriticalSection(&s_dnsLock);
        memset(s_dnsCache, 0, sizeof(s_dnsCache));
        s_dnsInitState = 2; // Done
    }
    while (s_dnsInitState != 2) Sleep(1); 
}

// [New] 异步 DNS 解析线程
static unsigned __stdcall Thread_ResolveDNS(void* arg) {
    char* host_ptr = (char*)arg;
    char host[256];
    strncpy(host, host_ptr, 255); host[255] = 0;
    free(host_ptr); // 释放参数副本

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_DGRAM;

    struct in_addr resolved_addr;
    int success = 0;

    // 此处阻塞，但在独立线程中，不影响主循环
    if (getaddrinfo(host, NULL, &hints, &res) == 0) {
        resolved_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
        success = 1;
    }

    EnsureDnsCacheInited();
    EnterCriticalSection(&s_dnsLock);
    
    // 更新缓存
    // 找到对应的 Resolving 条目 (通过域名匹配)
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (s_dnsCache[i].state == 2 && _stricmp(s_dnsCache[i].domain, host) == 0) {
            if (success) {
                s_dnsCache[i].ip = resolved_addr;
                s_dnsCache[i].expire_tick = GetTickCount64() + 60000; // 60s TTL
                s_dnsCache[i].state = 1; // Ready
            } else {
                // 解析失败，重置为空，允许重试
                s_dnsCache[i].state = 0; 
                s_dnsCache[i].expire_tick = 0;
            }
            break;
        }
    }
    LeaveCriticalSection(&s_dnsLock);
    return 0;
}

// 带缓存的 DNS 解析 (IPv4) - [Fix] 非阻塞模式
// 返回值: 0=Success, -1=Pending/Fail (Should retry later)
static int resolve_hostname_cached(const char* host, struct in_addr* out_addr) {
    EnsureDnsCacheInited();
    ULONGLONG now = GetTickCount64();
    
    EnterCriticalSection(&s_dnsLock);
    
    int idx = -1;
    int empty_idx = -1;

    // 1. 查找现有条目
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (_stricmp(s_dnsCache[i].domain, host) == 0) {
            // 检查是否过期
            if (s_dnsCache[i].state == 1 && s_dnsCache[i].expire_tick < now) {
                s_dnsCache[i].state = 0; // 标记过期
            }
            idx = i;
            break;
        }
        if (s_dnsCache[i].state == 0 && empty_idx == -1) {
            empty_idx = i;
        }
    }

    // 2. 状态处理
    if (idx != -1) {
        if (s_dnsCache[idx].state == 1) { // Hit & Ready
            *out_addr = s_dnsCache[idx].ip;
            LeaveCriticalSection(&s_dnsLock);
            return 0;
        } else if (s_dnsCache[idx].state == 2) { // Resolving
            LeaveCriticalSection(&s_dnsLock);
            return -1; // 正在解析中，通知调用者丢包/等待
        }
    }

    // 3. Cache Miss or Expired -> 发起异步解析
    // 寻找可用槽位
    if (idx == -1) {
        if (empty_idx != -1) idx = empty_idx;
        else idx = rand() % DNS_CACHE_SIZE; // 随机驱逐
    }

    // 初始化槽位为 Resolving
    strncpy(s_dnsCache[idx].domain, host, 255);
    s_dnsCache[idx].domain[255] = 0;
    s_dnsCache[idx].state = 2; // Mark as Resolving
    s_dnsCache[idx].expire_tick = now + 10000; // 临时超时，防止线程挂死导致槽位永久占用
    
    // 复制域名传递给线程
    char* host_copy = _strdup(host);
    if (host_copy) {
        unsigned threadID;
        uintptr_t hThread = _beginthreadex(NULL, 0, Thread_ResolveDNS, host_copy, 0, &threadID);
        if (hThread) CloseHandle((HANDLE)hThread);
        else free(host_copy);
    } else {
        s_dnsCache[idx].state = 0; // OOM Revert
    }

    LeaveCriticalSection(&s_dnsLock);
    return -1; // Pending
}

// --- 内部辅助函数 ---

// [Safe] 安全的缓冲区扩容逻辑
static int buffer_ensure_capacity(char** buf, int* cap, int* is_pooled, int current_len, int min_required) {
    if (!buf || !cap || !is_pooled) return -1;
    
    if (*cap >= min_required) return 0;

    size_t current_cap_sz = (size_t)*cap;
    size_t min_req_sz = (size_t)min_required;
    
    // 1. 协议硬限制 (防止恶意大包导致 OOM)
    if (min_req_sz > MAX_WS_FRAME_SIZE) {
        log_msg("[Buffer] Request exceeds protocol limit: %zu", min_req_sz);
        return -1;
    }

    // 2. 扩容策略: 倍增 + 线性 + 4KB对齐
    size_t new_cap_sz = (current_cap_sz == 0) ? 4096 : current_cap_sz;
    
    while (new_cap_sz < min_req_sz) {
        if (new_cap_sz < 1048576) {
            new_cap_sz *= 2; // < 1MB: 倍增
        } else {
            new_cap_sz += 1048576; // > 1MB: 线性增加 1MB
        }
    }
    
    // 对齐到 4KB 边界
    if (new_cap_sz % PAGE_ALIGN_SIZE != 0) {
        new_cap_sz = ((new_cap_sz / PAGE_ALIGN_SIZE) + 1) * PAGE_ALIGN_SIZE;
    }

    // 最终兜底
    if (new_cap_sz > MAX_WS_FRAME_SIZE) new_cap_sz = MAX_WS_FRAME_SIZE;
    if (new_cap_sz < min_req_sz) return -1; // 无法满足

    // 3. 执行分配
    char* new_buf = NULL;
    if (*is_pooled) {
        // 从内存池迁移到堆
        new_buf = (char*)malloc(new_cap_sz);
        if (!new_buf) return -1;
        
        if (*buf && current_len > 0) {
            memcpy(new_buf, *buf, current_len);
        }
        
        Pool_Free_16K(*buf); // 归还旧块
        *is_pooled = 0;
    } else {
        // 堆上扩容
        new_buf = (char*)realloc(*buf, new_cap_sz);
        if (!new_buf) return -1; 
    }

    *buf = new_buf;
    *cap = (int)new_cap_sz;
    return 0;
}

// [Robust] 健壮的发送函数
// [Fix] 修复超时逻辑：使用绝对截止时间 (Total Transmission Timeout) 防止低速攻击
static int send_robust(SOCKET s, const char* data, int len) {
    int total_sent = 0;
    const ULONGLONG SEND_TIMEOUT_MS = 5000;
    
    // 设定绝对截止时间
    ULONGLONG deadline_tick = GetTickCount64() + SEND_TIMEOUT_MS;

    while (total_sent < len) {
        // 检查总超时
        if (GetTickCount64() > deadline_tick) {
            return -1; // 强制超时
        }

        int n = send(s, data + total_sent, len - total_sent, 0);
        
        if (n > 0) {
            total_sent += n;
            // 注意：不再重置超时时间，要求必须在 SEND_TIMEOUT_MS 内发完所有数据
        } else {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                // Socket 缓冲区满，使用 select 等待可写
                fd_set wfd;
                FD_ZERO(&wfd);
                FD_SET(s, &wfd);
                
                // 计算剩余时间
                ULONGLONG now = GetTickCount64();
                if (now >= deadline_tick) return -1;
                
                long wait_ms = (long)(deadline_tick - now);
                struct timeval tv;
                tv.tv_sec = wait_ms / 1000;
                tv.tv_usec = (wait_ms % 1000) * 1000;
                
                int sel_res = select(0, NULL, &wfd, NULL, &tv);
                
                if (sel_res > 0) {
                    continue; // 可写，重试
                } else if (sel_res == 0) {
                    return -1; // select 超时
                } else {
                    return -1; // select 错误
                }
            } else if (err == WSAEINTR) {
                continue;
            } else {
                return -1; // 真正的网络错误
            }
        }
    }
    return total_sent;
}

// --- [New] Keep-Alive 辅助函数 ---

static int get_next_keepalive_interval() {
    return 15000 + (rand() % 35001);
}

static int build_ws_ping_frame(char* buf) {
    buf[0] = (char)0x89; // Fin=1, Opcode=9 (PING)
    buf[1] = (char)0x80; // Mask=1, Len=0
    *(int*)(buf + 2) = rand(); 
    return 6; // 2 header + 4 mask
}

// =========================================================================================
// [Logic Branch New] UDP 直连转发循环
// =========================================================================================
void step_transfer_loop_udp_direct(ProxySession* s) {
    if (s->udpSock == INVALID_SOCKET) return;

    log_msg("[Conn-%d] Entering UDP Direct Loop", s->clientSock);
    
    SOCKET tcp = s->clientSock;
    SOCKET udp = s->udpSock;
    
    // 设置非阻塞
    u_long mode = 1;
    ioctlsocket(tcp, FIONBIO, &mode);
    ioctlsocket(udp, FIONBIO, &mode);
    
    fd_set rfds;
    struct timeval tv;
    
    // 复用 TCP 流程中的缓冲区
    if (!s->c_buf || !s->ws_send_buf) return;
    char* recv_buf = s->c_buf;
    char* send_buf_wrapper = s->ws_send_buf;
    int send_buf_cap = IO_BUFFER_SIZE; 
    
    while (g_proxyRunning) {
        FD_ZERO(&rfds);
        FD_SET(tcp, &rfds);
        FD_SET(udp, &rfds);
        
        tv.tv_sec = 1; tv.tv_usec = 0; 
        
        int n = select(0, &rfds, NULL, NULL, &tv);
        if (n < 0) break;
        if (n == 0 && !g_proxyRunning) break;
        
        // 1. 监控 TCP 连接 (用于感知客户端断开)
        if (FD_ISSET(tcp, &rfds)) {
            char probe[16];
            int rn = recv(tcp, probe, sizeof(probe), 0);
            if (rn <= 0) { // FIN or Error
                int err = WSAGetLastError();
                if (rn == 0 || err != WSAEWOULDBLOCK) {
                    break;
                }
            }
        }
        
        // 2. 处理 UDP 数据
        if (FD_ISSET(udp, &rfds)) {
            struct sockaddr_in src_addr;
            int src_len = sizeof(src_addr);
            int len = recvfrom(udp, recv_buf, IO_BUFFER_SIZE, 0, (struct sockaddr*)&src_addr, &src_len);
            
            if (len > 0) {
                // A. 客户端 -> 目标
                if (!s->has_client_udp_addr || 
                    (memcmp(&src_addr.sin_addr, &s->client_udp_addr.sin_addr, 4) == 0 && 
                     src_addr.sin_port == s->client_udp_addr.sin_port)) {
                    
                    if (!s->has_client_udp_addr) {
                        memcpy(&s->client_udp_addr, &src_addr, sizeof(src_addr));
                        s->has_client_udp_addr = 1;
                    }
                    
                    if (len < 10) continue; 
                    if (recv_buf[0] != 0x00 || recv_buf[1] != 0x00) continue; 
                    if (recv_buf[2] != 0x00) continue; 
                    
                    int header_len = 0;
                    struct sockaddr_in target;
                    memset(&target, 0, sizeof(target));
                    target.sin_family = AF_INET;
                    
                    if (recv_buf[3] == 0x01) { // IPv4
                        memcpy(&target.sin_addr, &recv_buf[4], 4);
                        target.sin_port = *(unsigned short*)&recv_buf[8]; 
                        header_len = 10;
                    } else if (recv_buf[3] == 0x03) { // Domain
                        int dlen = (unsigned char)recv_buf[4];
                        if (len < 5 + dlen + 2) continue;
                        
                        char domain[256];
                        memcpy(domain, &recv_buf[5], dlen); domain[dlen] = 0;
                        
                        // [Fix] 使用异步缓存解析，避免阻塞循环
                        struct in_addr resolved_ip;
                        int res_ret = resolve_hostname_cached(domain, &resolved_ip);
                        
                        if (res_ret == 0) {
                            target.sin_addr = resolved_ip;
                        } else {
                            // -1 表示正在解析或解析失败。
                            // 由于 UDP 是无连接且允许丢包的，我们在此处丢弃该包。
                            // 客户端超时后会重试，届时缓存可能已就绪 (DNS Thread done).
                            continue; 
                        }
                        
                        target.sin_port = *(unsigned short*)&recv_buf[5 + dlen];
                        header_len = 5 + dlen + 2;
                    } else {
                        continue; 
                    }
                    
                    if (len > header_len) {
                        sendto(udp, recv_buf + header_len, len - header_len, 0, (struct sockaddr*)&target, sizeof(target));
                    }
                } 
                // B. 目标 -> 客户端
                else {
                    if (!s->has_client_udp_addr) continue; 
                    
                    int payload_len = len;
                    int hlen = 0;
                    send_buf_wrapper[hlen++] = 0x00; send_buf_wrapper[hlen++] = 0x00; 
                    send_buf_wrapper[hlen++] = 0x00; 
                    send_buf_wrapper[hlen++] = 0x01; // IPv4
                    memcpy(&send_buf_wrapper[hlen], &src_addr.sin_addr, 4); hlen += 4;
                    memcpy(&send_buf_wrapper[hlen], &src_addr.sin_port, 2); hlen += 2;
                    
                    if (hlen + payload_len <= send_buf_cap) {
                        memcpy(send_buf_wrapper + hlen, recv_buf, payload_len);
                        sendto(udp, send_buf_wrapper, hlen + payload_len, 0, (struct sockaddr*)&s->client_udp_addr, sizeof(s->client_udp_addr));
                    }
                }
            }
        }
    }
}

// =========================================================================================
// [Logic Branch Direct] TCP 直连透传循环 (No TLS, No WS)
// [Fix] 增加 Idle Timeout 逻辑，防止僵尸连接
// =========================================================================================
static void step_transfer_loop_tcp_direct(ProxySession* s) {
    u_long mode = 1; 
    ioctlsocket(s->clientSock, FIONBIO, &mode); 
    ioctlsocket(s->remoteSock, FIONBIO, &mode);

    // [New] 开启 TCP Keep-Alive 以增强底层保活
    BOOL opt = TRUE;
    setsockopt(s->clientSock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(BOOL));
    setsockopt(s->remoteSock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(BOOL));

    log_msg("[Conn-%d] Entering TCP Direct Loop (Raw Forwarding)", s->clientSock);

    fd_set fds; 
    struct timeval tv; 
    
    // 使用 session 的 buffer
    char* buf = s->c_buf; 
    int buf_cap = IO_BUFFER_SIZE;
    
    // [New] 活跃时间追踪
    ULONGLONG last_activity_tick = GetTickCount64();

    while(g_proxyRunning) {
        FD_ZERO(&fds); 
        FD_SET(s->clientSock, &fds); 
        FD_SET(s->remoteSock, &fds);
        
        tv.tv_sec = 0; tv.tv_usec = 50000; // 50ms
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break; 
        
        // 检查空闲超时
        if (n == 0) {
            if (!g_proxyRunning) break;
            
            // 如果超时未活动，断开连接
            if (GetTickCount64() - last_activity_tick > TCP_DIRECT_IDLE_TIMEOUT) {
                log_msg("[Conn-%d] Direct connection timed out (Idle > %ds).", s->clientSock, TCP_DIRECT_IDLE_TIMEOUT / 1000);
                break;
            }
            continue; 
        }
        
        // 1. Client -> Remote (Direct)
        if (FD_ISSET(s->clientSock, &fds)) {
            int len = recv(s->clientSock, buf, buf_cap, 0);
            if (len > 0) {
                if (send_robust(s->remoteSock, buf, len) < 0) break;
                last_activity_tick = GetTickCount64(); // 更新活跃时间
            } else if (len == 0) {
                break; // Client closed
            } else {
                if (WSAGetLastError() != WSAEWOULDBLOCK) break;
            }
        }
        
        // 2. Remote -> Client (Direct)
        if (FD_ISSET(s->remoteSock, &fds)) {
            int len = recv(s->remoteSock, buf, buf_cap, 0);
            if (len > 0) {
                if (send_robust(s->clientSock, buf, len) < 0) break;
                last_activity_tick = GetTickCount64(); // 更新活跃时间
            } else if (len == 0) {
                break; // Remote closed
            } else {
                if (WSAGetLastError() != WSAEWOULDBLOCK) break;
            }
        }
    }
}

// =========================================================================================
// [Logic Branch 1] HTTP/1.1 传输循环 (含 Direct 分流)
// =========================================================================================
void step_transfer_loop_h1(ProxySession* s) {
    // [Fix] 检查是否为直连模式，如果是，则跳转到纯 TCP 循环
    if (_stricmp(s->config.type, "direct") == 0) {
        step_transfer_loop_tcp_direct(s);
        return;
    }

    // 确保 Socket 为非阻塞
    u_long mode = 1; 
    ioctlsocket(s->clientSock, FIONBIO, &mode); 
    ioctlsocket(s->remoteSock, FIONBIO, &mode);
    
    // [New] 初始化 Keep-Alive
    s->last_keepalive_tick = GetTickCount64();
    s->next_keepalive_interval = get_next_keepalive_interval();

    fd_set fds; 
    struct timeval tv; 
    BOOL is_vless = (_stricmp(s->config.type, "vless") == 0);
    int burst_limit = 0;

    // [Fix] 自动检测 WS 模式（如果未在握手时显式设置）
    // 为了兼容性，如果 ws_send_buf 存在且配置暗示 WS，则认为是 WS。
    // 但更安全的是依赖 s->is_ws_transport (由调用者/握手设置)。
    // 这里做兜底：如果 is_ws_transport 为 0，但 ws_send_buf 已分配，我们假定调用者可能忘了设 flag，
    // 除非 config 明确是 "tcp" 或 "grpc" 等非 WS 传输。
    // 鉴于此函数主要用于 VMess-WS / HTTPS-Proxy，我们严格遵守 is_ws_transport。
    // 如果 is_ws_transport 未初始化（旧代码路径），则保持原行为（视为 WS）可能会出错，
    // 但根据指令我们只修复 Keep-Alive 逻辑。

    while(g_proxyRunning) {
        FD_ZERO(&fds); 
        FD_SET(s->clientSock, &fds); 
        FD_SET(s->remoteSock, &fds);
        
        // 必须判空保护，防止 SSL 尚未建立时访问 (虽然非直连模式下应已建立)
        int pending = (s->tls.ssl) ? SSL_pending(s->tls.ssl) : 0;
        
        if (pending > 0 || burst_limit > 0) { 
            tv.tv_sec = 0; tv.tv_usec = 0; 
            if (burst_limit > 0) burst_limit--;
        } else {
            tv.tv_sec = 0; tv.tv_usec = 50000;
        }
        
        int n = select(0, &fds, NULL, NULL, &tv);
        if (n < 0) break; 
        if (n == 0 && !g_proxyRunning) break; 
        
        // --- Keep-Alive 逻辑 ---
        ULONGLONG now = GetTickCount64();
        if (now - s->last_keepalive_tick >= (ULONGLONG)s->next_keepalive_interval) {
            // [Fix] 仅当传输层为 WebSocket 时才发送 Ping 帧
            // 对于纯 TCP/TLS 连接，发送 WS Ping 是非法数据
            if (s->is_ws_transport) {
                if (s->ws_send_buf && s->ws_send_buf_is_pooled || s->ws_send_buf) {
                     int ping_len = build_ws_ping_frame(s->ws_send_buf);
                     if (tls_write(&s->tls, s->ws_send_buf, ping_len) < 0) break;
                }
            }
            s->last_keepalive_tick = now;
            s->next_keepalive_interval = get_next_keepalive_interval();
        }

        int did_work = 0;

        // 1. Browser -> Proxy (recv)
        if (FD_ISSET(s->clientSock, &fds)) {
            int max_recv = IO_BUFFER_SIZE - WS_FRAME_OVERHEAD;
            if (max_recv < 1024) max_recv = 1024; 

            int len = recv(s->clientSock, s->c_buf, max_recv, 0);
            if (len > 0) {
                did_work = 1;
                s->last_keepalive_tick = GetTickCount64();

                // [Fix] 根据传输层类型决定是否封装 WS 帧
                if (s->is_ws_transport) {
                    int flen = build_ws_frame(s->c_buf, len, s->ws_send_buf);
                    if (tls_write(&s->tls, s->ws_send_buf, flen) < 0) break;
                } else {
                    // 纯 TLS 模式，直接发送原始数据
                    if (tls_write(&s->tls, s->c_buf, len) < 0) break;
                }
            } else if (len == 0) {
                break; 
            } else {
                if (WSAGetLastError() != WSAEWOULDBLOCK) break;
            }
        }
        
        // 2. Proxy -> Browser (tls_read)
        if (FD_ISSET(s->remoteSock, &fds) || pending > 0) {
            int space_left = s->ws_read_buf_cap - s->ws_buf_len;
            
            if (space_left > 0) {
                int len = tls_read(&s->tls, s->ws_read_buf + s->ws_buf_len, space_left);
                if (len < 0) break; 
                if (len > 0) {
                    s->ws_buf_len += len;
                    did_work = 1;
                }
            }
            
            // [Fix] 分离 WS 解析逻辑与 Raw 数据逻辑
            if (s->is_ws_transport) {
                // 解析 WebSocket 帧
                while (s->ws_buf_len > 0) {
                    int hl, pl;
                    long long frame_total = check_ws_frame((unsigned char*)s->ws_read_buf, s->ws_buf_len, &hl, &pl);
                    
                    int required_cap = 0;
                    if (frame_total > 0) {
                        if (frame_total > MAX_WS_FRAME_SIZE) goto loop_end; 
                        if (frame_total > s->ws_read_buf_cap) required_cap = (int)frame_total;
                    } else {
                        if (s->ws_buf_len >= s->ws_read_buf_cap) {
                             required_cap = (s->ws_read_buf_cap < INT_MAX / 2) ? s->ws_read_buf_cap * 2 : INT_MAX;
                        }
                    }

                    if (required_cap > 0) {
                        if (buffer_ensure_capacity(&s->ws_read_buf, &s->ws_read_buf_cap, &s->ws_read_buf_is_pooled, s->ws_buf_len, required_cap) != 0) {
                            goto loop_end; // OOM
                        }
                        if (frame_total <= 0) break; 
                    }

                    if (frame_total <= 0 || frame_total > s->ws_buf_len) break; 
                    
                    // 处理控制帧
                    if ((s->ws_read_buf[0] & 0x0F) == 0x8) goto loop_end; 
                    
                    // 处理数据帧
                    if (((s->ws_read_buf[0] & 0x0F) <= 0x2) && pl > 0) {
                        char* payload = s->ws_read_buf + hl; 
                        int psize = pl;
                        
                        if (is_vless && !s->vless_response_header_stripped) {
                             if (psize >= 2) {
                                 int h = 2 + (unsigned char)payload[1];
                                 if (psize >= h) { 
                                     payload += h; psize -= h; 
                                     s->vless_response_header_stripped = 1; 
                                 } else psize = 0; 
                             } else psize = 0;
                        }
                        
                        if (psize > 0) {
                            if (send_robust(s->clientSock, payload, psize) < 0) goto loop_end;
                        }
                    }
                    
                    int remaining = s->ws_buf_len - (int)frame_total;
                    if (remaining > 0) memmove(s->ws_read_buf, s->ws_read_buf + frame_total, remaining);
                    s->ws_buf_len = remaining;
                    
                    burst_limit = MAX_BURST_LOOPS;
                }
            } else {
                // Raw TLS Mode: 直接透传收到的数据
                if (s->ws_buf_len > 0) {
                    if (send_robust(s->clientSock, s->ws_read_buf, s->ws_buf_len) < 0) goto loop_end;
                    s->ws_buf_len = 0; // 全部发送完毕
                    burst_limit = MAX_BURST_LOOPS;
                }
            }
        }
    }
loop_end:
    return;
}

// =========================================================================================
// [Logic Branch 2] HTTP/2 传输循环
// =========================================================================================
void step_transfer_loop_h2(ProxySession* s) {
    u_long mode = 1; 
    ioctlsocket(s->clientSock, FIONBIO, &mode); 
    ioctlsocket(s->remoteSock, FIONBIO, &mode);
    
    s->last_keepalive_tick = GetTickCount64();
    s->next_keepalive_interval = get_next_keepalive_interval();
    
    fd_set read_fds, write_fds; 
    struct timeval tv;
    int burst_limit = 0;
    
    while(g_proxyRunning && s->h2_handshake_done == 1) {
        FD_ZERO(&read_fds); FD_ZERO(&write_fds);
        
        int buffer_avail = IO_BUFFER_SIZE - s->h2_browser_len;
        if (buffer_avail < 0) buffer_avail = 0;

        if (buffer_avail >= 1024) { 
            FD_SET(s->clientSock, &read_fds); 
        }

        FD_SET(s->remoteSock, &read_fds);
        
        int pending = SSL_pending(s->tls.ssl);
        
        int want_write = nghttp2_session_want_write(s->h2_sess);
        if (want_write) FD_SET(s->remoteSock, &write_fds);

        if (pending > 0 || burst_limit > 0) { 
            tv.tv_sec = 0; tv.tv_usec = 0; 
            if (burst_limit > 0) burst_limit--;
        } else {
            tv.tv_sec = 0; tv.tv_usec = 50000;
        }

        int n = select(0, &read_fds, &write_fds, NULL, &tv);
        if (n < 0) break;
        if (n == 0 && !g_proxyRunning) break;
        
        // Keep-Alive
        ULONGLONG now = GetTickCount64();
        if (now - s->last_keepalive_tick >= (ULONGLONG)s->next_keepalive_interval) {
            int rv = nghttp2_submit_ping(s->h2_sess, NGHTTP2_FLAG_NONE, NULL);
            if (rv == 0) nghttp2_session_send(s->h2_sess); 
            s->last_keepalive_tick = now;
            s->next_keepalive_interval = get_next_keepalive_interval();
        }

        int did_work = 0;

        // 1. Browser -> H2 Buffer
        if (FD_ISSET(s->clientSock, &read_fds)) {
            int max_read = buffer_avail;
            if (max_read > IO_BUFFER_SIZE / 2) max_read = IO_BUFFER_SIZE / 2;
            
            if (max_read > 0) {
                int len = recv(s->clientSock, s->h2_browser_buf + s->h2_browser_len, max_read, 0);
                if (len > 0) {
                    did_work = 1;
                    s->h2_browser_len += len;
                    s->last_keepalive_tick = GetTickCount64();
                    nghttp2_session_resume_data(s->h2_sess, s->h2_stream_id);
                } else if (len == 0) {
                    break; 
                } else {
                    if (WSAGetLastError() != WSAEWOULDBLOCK) break;
                }
            }
        }

        // 2. H2 Send -> TLS
        if (want_write) {
            if (FD_ISSET(s->remoteSock, &write_fds)) {
                 int rv = nghttp2_session_send(s->h2_sess);
                 if (rv != 0 && rv != NGHTTP2_ERR_WOULDBLOCK) break;
                 if (rv == 0) did_work = 1;
            }
        }

        // 3. TLS Read -> H2 Recv
        if (FD_ISSET(s->remoteSock, &read_fds) || pending > 0) {
            int len = tls_read(&s->tls, s->ws_read_buf, s->ws_read_buf_cap);
            if (len < 0) break; 
            if (len > 0) {
                did_work = 1;
                int rv = nghttp2_session_mem_recv(s->h2_sess, (uint8_t*)s->ws_read_buf, len);
                if (rv < 0) {
                    log_msg("[H2] mem_recv error: %s", nghttp2_strerror(rv));
                    break;
                }
            }
        }

        if (did_work) burst_limit = MAX_BURST_LOOPS;
    }
}
