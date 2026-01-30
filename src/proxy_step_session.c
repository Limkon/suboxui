/* src/proxy_step_session.c */
#include "proxy_internal.h"
#include "utils.h"
#include "config.h"
#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>

// 初始化会话
int session_init(ProxySession* s, ClientContext* ctx) {
    if (!s || !ctx) return -1;

    // [Safety] 彻底清空结构体
    memset(s, 0, sizeof(ProxySession));
    
    // [Init] 初始化 Socket 句柄
    s->udpSock = INVALID_SOCKET;
    s->remoteSock = INVALID_SOCKET;
    s->clientSock = ctx->clientSock;
    
    s->config = ctx->config; // Struct copy
    s->cryptoSettings = ctx->cryptoSettings;
    strncpy(s->userAgent, ctx->userAgent, sizeof(s->userAgent)-1);
    s->userAgent[sizeof(s->userAgent)-1] = 0; 
    
    s->ws_read_buf_cap = IO_BUFFER_SIZE;
    s->fallback_state = 0; 
    s->is_udp_associate = 0; 
    s->is_ws_transport = 0; 
    
    // 内存池分配
    s->c_buf = (char*)Pool_Alloc_16K();
    s->c_buf_is_pooled = 1;

    s->ws_read_buf = (char*)Pool_Alloc_16K();
    s->ws_read_buf_is_pooled = 1;

    s->ws_send_buf = (char*)Pool_Alloc_16K();
    s->ws_send_buf_is_pooled = 1;

    s->h2_browser_buf = (char*)proxy_malloc(IO_BUFFER_SIZE); 
    
    if (!s->c_buf || !s->ws_read_buf || !s->ws_send_buf || !s->h2_browser_buf) {
        log_msg("[Conn-%d] Failed to allocate session buffers (OOM)", s->clientSock);
        session_free(s); // 安全释放已分配部分
        return -1;
    }
    return 0;
}

// 清理会话
void session_free(ProxySession* s) {
    if (!s) return;

    if (s->h2_sess) { nghttp2_session_del(s->h2_sess); s->h2_sess = NULL; }
    
    if (s->c_buf) {
        if (s->c_buf_is_pooled) Pool_Free_16K(s->c_buf);
        else free(s->c_buf);
        s->c_buf = NULL;
    }

    if (s->ws_send_buf) {
        if (s->ws_send_buf_is_pooled) Pool_Free_16K(s->ws_send_buf);
        else free(s->ws_send_buf);
        s->ws_send_buf = NULL;
    }
    
    if (s->ws_read_buf) {
        if (s->ws_read_buf_is_pooled) Pool_Free_16K(s->ws_read_buf);
        else free(s->ws_read_buf);
        s->ws_read_buf = NULL;
    }
    
    if (s->h2_browser_buf) {
        proxy_free(s->h2_browser_buf, IO_BUFFER_SIZE);
        s->h2_browser_buf = NULL;
    }
    
    tls_close(&s->tls);
    
    if (s->udpSock != INVALID_SOCKET) { closesocket(s->udpSock); s->udpSock = INVALID_SOCKET; }
    if (s->remoteSock != INVALID_SOCKET) { closesocket(s->remoteSock); s->remoteSock = INVALID_SOCKET; }
    if (s->clientSock != INVALID_SOCKET) { closesocket(s->clientSock); s->clientSock = INVALID_SOCKET; }
}
