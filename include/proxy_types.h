/* include/proxy_types.h */
#ifndef PROXY_TYPES_H
#define PROXY_TYPES_H

#include "common.h"
#include "crypto.h"
#include <nghttp2/nghttp2.h>

// [Concurrency] 客户端线程上下文 - 用于主线程向子线程传递参数
typedef struct {
    SOCKET clientSock;
    ProxyConfig config;          
    char userAgent[512];         
    CryptoSettings cryptoSettings; 
} ClientContext;

// [Refactor] 代理会话上下文 - 核心状态机结构体
typedef struct {
    // 核心资源
    SOCKET clientSock;
    SOCKET remoteSock;
    TLSContext tls;
    
    // HTTP/2 相关资源
    nghttp2_session *h2_sess;
    int32_t h2_stream_id;
    // [Fix] 增加 volatile 修饰，防止编译器优化循环检测
    volatile int h2_handshake_done; // 0=Pending, 1=Success, -1=Fail
    volatile int h2_status_code;    // 记录握手响应的状态码
    
    // 配置信息
    ProxyConfig config;
    CryptoSettings cryptoSettings;
    char userAgent[512];
    
    // 缓冲区 (从内存池或堆分配)
    char *c_buf;       // 客户端数据缓冲 (Browser <-> Proxy)
    char *ws_read_buf; // WS 读取缓冲 / TLS 接收缓冲
    char *ws_send_buf; // WS 发送缓冲 / H2 帧构建缓冲
    
    // [Fix] 内存池归属标志 (1=来自内存池 Pool_Alloc_16K, 0=来自堆 malloc/realloc)
    int c_buf_is_pooled;
    int ws_read_buf_is_pooled;
    int ws_send_buf_is_pooled;

    int ws_read_buf_cap;
    int ws_buf_len;    // 当前 ws_read_buf 中的有效数据长度
    
    // H2 专用：浏览器数据暂存区 (用于 nghttp2 data provider 回调)
    char *h2_browser_buf; 
    int h2_browser_len;
    
    // 解析出的目标信息
    char method[16];
    char target_host[256];
    int target_port;
    int browser_header_len; // 浏览器发来的首包长度
    int header_len;         // HTTP头部长度
    
    // 状态标志
    int is_socks5;
    int is_connect_method;
    int vless_response_header_stripped;
    int alpn_is_h2; // 1=H2, 0=H1
    
    // [Fix] 明确标记传输层是否为 WebSocket，防止在纯 TCP 模式下发送 WS Ping
    int is_ws_transport; // 1=WebSocket Tunnel, 0=Raw TCP/TLS

    // [New] UDP 支持字段
    SOCKET udpSock;           // 本地 UDP 监听 Socket
    int is_udp_associate;     // 标记是否为 UDP 会话
    struct sockaddr_in client_udp_addr; // 记录客户端的 UDP 地址 (用于回包)
    int has_client_udp_addr;  // 是否已获知客户端 UDP 地址
    
    // [New] 降级状态标记
    int fallback_state; // 0=Normal, 1=Downgraded to H1

    // [New] Keep-Alive (心跳保活) 状态
    ULONGLONG last_keepalive_tick; // 上一次发送心跳或有数据传输的时间
    int next_keepalive_interval;   // 下一次心跳的随机间隔 (毫秒)
} ProxySession;

#endif // PROXY_TYPES_H
