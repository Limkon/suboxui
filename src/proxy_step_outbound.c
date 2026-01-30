/* src/proxy_step_outbound.c */
#include "proxy_internal.h"
#include "utils.h"
#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

// 辅助函数：非阻塞连接
static int connect_with_timeout(SOCKET sock, const struct sockaddr* addr, int addrlen, int timeout_ms) {
    if (!g_proxyRunning) return -1;
    unsigned long on = 1;
    if (ioctlsocket(sock, FIONBIO, &on) != 0) return -1;

    int res = connect(sock, addr, addrlen);
    if (res == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) return -1;

        ULONGLONG start_tick = GetTickCount64();
        while (TRUE) {
            if (!g_proxyRunning) return -1;
            ULONGLONG now = GetTickCount64();
            if (now - start_tick > (ULONGLONG)timeout_ms) return -1; 

            fd_set wset, eset;
            FD_ZERO(&wset); FD_SET(sock, &wset);
            FD_ZERO(&eset); FD_SET(sock, &eset);

            struct timeval tv = {0, 50000}; 
            int n = select(0, NULL, &wset, &eset, &tv);
            
            if (n < 0) return -1; 
            if (n > 0) {
                if (FD_ISSET(sock, &eset)) return -1;
                if (FD_ISSET(sock, &wset)) {
                    int err = 0, len = sizeof(err);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len) < 0 || err != 0) return -1;
                    break; 
                }
            }
        }
    }
    return 0;
}

// Step 2: 连接上游代理
int step_connect_upstream(ProxySession* s) {
    if (!g_proxyRunning) return -1;

    BOOL is_direct = (_stricmp(s->config.type, "direct") == 0);

    if (is_direct) {
        log_msg("[Conn-%d] [Direct] Connecting directly to %s:%d...", s->clientSock, s->config.host, s->config.port);
    } else {
        if (s->fallback_state == 1) {
            log_msg("[Conn-%d] [Fallback] Retry upstream %s:%d (Force HTTP/1.1)...", 
                s->clientSock, s->config.host, s->config.port);
        } else {
            log_msg("[Conn-%d] Resolving upstream %s:%d", s->clientSock, s->config.host, s->config.port);
        }
    }
    
    struct addrinfo hints, *res = NULL, *ptr = NULL;
    char port_str[16];
    int flag = 1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_str, sizeof(port_str), "%d", s->config.port);

    if (getaddrinfo(s->config.host, port_str, &hints, &res) != 0) return -1;

    int success = 0;
    for (int retry = 0; retry < 3; retry++) {
        if (!g_proxyRunning) break; 
        
        for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
            if (!g_proxyRunning) break;

            s->remoteSock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (s->remoteSock == INVALID_SOCKET) continue;

            setsockopt(s->remoteSock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
            int rcv_timeout = 5000;
            setsockopt(s->remoteSock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcv_timeout, sizeof(int));
            setsockopt(s->remoteSock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&rcv_timeout, sizeof(int));

            if (connect_with_timeout(s->remoteSock, ptr->ai_addr, (int)ptr->ai_addrlen, 5000) == 0) {
                if (is_direct) {
                    log_msg("[Conn-%d] [Direct] TCP Connected.", s->clientSock);
                    success = 1;
                    break;
                }
                
                int effective_alpn = (s->fallback_state == 1) ? 1 : s->cryptoSettings.alpnOverride;
                int original_alpn = s->cryptoSettings.alpnOverride;
                s->cryptoSettings.alpnOverride = effective_alpn;

                const char* actual_sni = (strlen(s->config.sni) > 0) ? s->config.sni : s->config.host;
                log_msg("[Conn-%d] TLS Handshake... SNI: %s, ALPN_Mode: %s", 
                    s->clientSock, actual_sni, effective_alpn==1 ? "Force H1" : "Auto");
                
                s->tls.sock = s->remoteSock;
                
                if (tls_init_connect(&s->tls, s->config.sni, s->config.host, &s->cryptoSettings, s->config.allowInsecure) == 0) {
                    success = 1;
                    s->cryptoSettings.alpnOverride = original_alpn;
                    log_msg("[Conn-%d] TLS Success. Selected Protocol: %s", s->clientSock, tls_get_alpn_selected(&s->tls));
                    break;
                } else {
                    log_msg("[Conn-%d] TLS Handshake Failed.", s->clientSock);
                    tls_close(&s->tls); 
                    closesocket(s->remoteSock); 
                    s->remoteSock = INVALID_SOCKET;
                    s->cryptoSettings.alpnOverride = original_alpn;
                }
            } else {
                closesocket(s->remoteSock); 
                s->remoteSock = INVALID_SOCKET;
            }
        }
        if (success) break;
        log_msg("[Conn-%d] Connection retry %d...", s->clientSock, retry + 1);
        Sleep(200); 
    }
    freeaddrinfo(res);
    return success ? 0 : -1;
}
