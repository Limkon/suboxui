/* src/proxy_step_tunnel.c */
#include "proxy_internal.h"
#include "utils.h"
#include "config.h"
#include <openssl/rand.h>
#include <winsock2.h>
#include <stdio.h>

#ifndef NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL
#define NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL 0x08
#endif

// 辅助：带超时的 TLS 读取
static int tls_read_with_timeout(TLSContext* tls, char* buf, int max_len, int timeout_ms) {
    if (!tls || !tls->ssl) return -1;
    ULONGLONG start = GetTickCount64();
    int sock = SSL_get_fd(tls->ssl);

    while (g_proxyRunning) {
        int n = tls_read(tls, buf, max_len);
        if (n > 0) return n; 
        if (n < 0) return -1; 
        
        if (GetTickCount64() - start > (ULONGLONG)timeout_ms) return 0;

        fd_set rfds;
        FD_ZERO(&rfds); FD_SET(sock, &rfds);
        struct timeval tv = {0, 50000}; 
        int r = select(0, &rfds, NULL, NULL, &tv);
        if (r < 0) return -1; 
    }
    return -1; 
}

// 辅助：标准地址序列化
static int append_addr_standard(unsigned char* buf, int offset, const char* host, int port) {
    struct in_addr ip4;
    struct in6_addr ip6;
    int len = 0;

    if (inet_pton(AF_INET, host, &ip4) == 1) {
        buf[offset + len++] = 0x01; 
        memcpy(buf + offset + len, &ip4, 4); len += 4;
    } else if (inet_pton(AF_INET6, host, &ip6) == 1) {
        buf[offset + len++] = 0x04; 
        memcpy(buf + offset + len, &ip6, 16); len += 16;
    } else {
        size_t dlen = strlen(host);
        if (dlen > 255) return -1; 
        buf[offset + len++] = 0x03; buf[offset + len++] = (unsigned char)dlen;
        memcpy(buf + offset + len, host, dlen); len += (int)dlen;
    }
    buf[offset + len++] = (port >> 8) & 0xFF;
    buf[offset + len++] = (port & 0xFF);
    return len;
}

// Step 3 (H1): 普通 HTTP/1.1 WS 握手
static int step_handshake_ws_h1(ProxySession* s) {
    if (!g_proxyRunning) return -1;
    if (_stricmp(s->config.type, "direct") == 0) return 0;

    log_msg("[Conn-%d] Starting HTTP/1.1 WebSocket Handshake...", s->clientSock);
    
    unsigned char rnd_key[16]; char ws_key_str[32];
    if (RAND_bytes(rnd_key, 16) != 1) return -1;
    base64_encode_key(rnd_key, ws_key_str);

    const char* host_val = (strlen(s->config.sni) > 0) ? s->config.sni : s->config.host;
    char fixed_path[512]; const char* req_path = "/";
    if (strlen(s->config.path) > 0) {
        if (s->config.path[0] == '/') req_path = s->config.path;
        else { snprintf(fixed_path, sizeof(fixed_path), "/%s", s->config.path); req_path = fixed_path; }
    }

    int offset = snprintf(s->ws_send_buf, IO_BUFFER_SIZE, 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Pragma: no-cache\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n", 
        req_path, host_val, s->userAgent, ws_key_str);

    if (tls_write(&s->tls, s->ws_send_buf, offset) <= 0) return -1;
    int hlen = tls_read_with_timeout(&s->tls, s->ws_read_buf, s->ws_read_buf_cap - 1, 10000); 
    if (hlen <= 0) return -1;
    s->ws_read_buf[hlen] = 0;
    
    if (!strstr(s->ws_read_buf, "101")) return -1; 
    
    log_msg("[Conn-%d] WS Handshake Success (101).", s->clientSock);
    s->is_ws_transport = 1;

    char* body_start = strstr(s->ws_read_buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4; 
        int header_bytes = (int)(body_start - s->ws_read_buf);
        int remaining = hlen - header_bytes;
        if (remaining > 0) {
            memmove(s->ws_read_buf, body_start, remaining);
            s->ws_buf_len = remaining;
        } else s->ws_buf_len = 0;
    }
    return 0;
}

static int h2_poll_and_process(ProxySession* s, int wait_ms) {
    if (!s || !s->h2_sess) return -1;
    int sock = SSL_get_fd(s->tls.ssl);
    fd_set rfds; FD_ZERO(&rfds); FD_SET(sock, &rfds);
    struct timeval tv = {0, wait_ms * 1000}; 
    
    if (select(0, &rfds, NULL, NULL, &tv) > 0) {
        int n = tls_read(&s->tls, s->ws_read_buf, s->ws_read_buf_cap);
        if (n > 0) {
            if (nghttp2_session_mem_recv(s->h2_sess, (uint8_t*)s->ws_read_buf, n) < 0) return -1;
        } else if (n < 0) return -1;
    }
    if (nghttp2_session_send(s->h2_sess) != 0) return -1;
    return 0;
}

// Step 3 (H2): HTTP/2 握手
static int step_handshake_ws_h2(ProxySession* s) {
    if (!g_proxyRunning) return -1;
    if (_stricmp(s->config.type, "direct") == 0) return 0;

    BOOL is_rfc8441_ws = FALSE;
    if (s->config.path && (strchr(s->config.path, '?') || strstr(s->config.path, "sw"))) is_rfc8441_ws = TRUE;
    
    log_msg("[Conn-%d] Starting HTTP/2 Stream. Mode: %s...", s->clientSock, is_rfc8441_ws ? "WebSocket" : "Standard");
    
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_on_stream_close_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header_callback);
    
    nghttp2_session_client_new(&s->h2_sess, callbacks, s);
    nghttp2_session_callbacks_del(callbacks);

    nghttp2_settings_entry iv[] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }, { NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1 } };
    nghttp2_submit_settings(s->h2_sess, NGHTTP2_FLAG_NONE, iv, 2);
    if (nghttp2_session_send(s->h2_sess) != 0) return -1;

    char norm_path[256];
    const char* raw_path = (strlen(s->config.path) > 0) ? s->config.path : "/";
    if (raw_path[0] != '/') snprintf(norm_path, sizeof(norm_path), "/%s", raw_path);
    else { strncpy(norm_path, raw_path, sizeof(norm_path)-1); norm_path[sizeof(norm_path)-1] = 0; }

    const char* authority_val = (strlen(s->config.sni) > 0) ? s->config.sni : s->config.host;
    if (strlen(authority_val) == 0) authority_val = s->config.host;

    nghttp2_nv nva[16]; size_t nvlen = 0;
    if (is_rfc8441_ws) {
        nva[nvlen++] = (nghttp2_nv){ (uint8_t*)":method", (uint8_t*)"CONNECT", 7, 7, NGHTTP2_NV_FLAG_NONE };
        nva[nvlen++] = (nghttp2_nv){ (uint8_t*)":protocol", (uint8_t*)"websocket", 9, 9, NGHTTP2_NV_FLAG_NONE };
        nva[nvlen++] = (nghttp2_nv){ (uint8_t*)":scheme", (uint8_t*)"https", 7, 5, NGHTTP2_NV_FLAG_NONE };
    } else {
        nva[nvlen++] = (nghttp2_nv){ (uint8_t*)":method", (uint8_t*)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE };
        nva[nvlen++] = (nghttp2_nv){ (uint8_t*)":scheme", (uint8_t*)"https", 7, 5, NGHTTP2_NV_FLAG_NONE };
        nva[nvlen++] = (nghttp2_nv){ (uint8_t*)"content-type", (uint8_t*)"application/octet-stream", 12, 24, NGHTTP2_NV_FLAG_NONE };
    }
    nva[nvlen++] = (nghttp2_nv){ (uint8_t*)":path", (uint8_t*)norm_path, 5, strlen(norm_path), NGHTTP2_NV_FLAG_NONE };
    nva[nvlen++] = (nghttp2_nv){ (uint8_t*)":authority", (uint8_t*)authority_val, 10, strlen(authority_val), NGHTTP2_NV_FLAG_NONE };
    nva[nvlen++] = (nghttp2_nv){ (uint8_t*)"user-agent", (uint8_t*)s->userAgent, 10, strlen(s->userAgent), NGHTTP2_NV_FLAG_NONE };

    if (strlen(s->config.mode) > 0) {
         nva[nvlen++] = (nghttp2_nv){ (uint8_t*)"mode", (uint8_t*)s->config.mode, 4, strlen(s->config.mode), NGHTTP2_NV_FLAG_NONE };
    }

    nghttp2_data_provider rv; rv.read_callback = h2_data_provider_read;
    s->h2_stream_id = nghttp2_submit_request(s->h2_sess, NULL, nva, nvlen, &rv, s);
    if (s->h2_stream_id < 0) return -1;
    
    if (nghttp2_session_send(s->h2_sess) != 0) return -1;
    
    s->h2_status_code = 0; 
    ULONGLONG start_wait = GetTickCount64();
    while (GetTickCount64() - start_wait < 500 && g_proxyRunning) {
        if (h2_poll_and_process(s, 5) != 0) return -1; 
        if (s->h2_status_code > 0) {
            if (s->h2_status_code >= 400) return -1; 
            s->h2_handshake_done = 1;
            return 0;
        }
    }
    s->h2_handshake_done = 1;
    return 0;
}

// 智能握手分发
int step_handshake_ws(ProxySession* s) {
    if (!g_proxyRunning) return -1;
    if (_stricmp(s->config.type, "direct") == 0) return 0;

    const char* alpn = tls_get_alpn_selected(&s->tls);
    
    if (alpn && strcmp(alpn, "h2") == 0) {
        s->alpn_is_h2 = 1;
        int ret = step_handshake_ws_h2(s);
        
        // Auto-Fallback Logic
        if (ret != 0 && s->fallback_state == 0) {
            log_msg("[Conn-%d] [Fallback] H2 failed. Downgrading to HTTP/1.1...", s->clientSock);
            
            if (s->h2_sess) { nghttp2_session_del(s->h2_sess); s->h2_sess = NULL; }
            tls_close(&s->tls);
            if (s->remoteSock != INVALID_SOCKET) { closesocket(s->remoteSock); s->remoteSock = INVALID_SOCKET; }
            
            s->fallback_state = 1; 
            s->alpn_is_h2 = 0;     
            
            // Re-connect and recurse
            if (step_connect_upstream(s) == 0) return step_handshake_ws(s);
            else return -1;
        }
        return ret;
    }
    
    s->alpn_is_h2 = 0;
    return step_handshake_ws_h1(s);
}

// Step 4: 发送代理请求
int step_send_proxy_request(ProxySession* s) {
    if (!g_proxyRunning) return -1;
    if (_stricmp(s->config.type, "direct") == 0) return 0;

    log_msg("[Conn-%d] Sending proxy protocol header (%s)...", s->clientSock, s->config.type);
    
    unsigned char proto_buf[2048]; memset(proto_buf, 0, sizeof(proto_buf));
    int proto_len = 0, flen = 0;
    struct in_addr ip4; struct in6_addr ip6;
    
    BOOL is_vless = (_stricmp(s->config.type, "vless") == 0);
    BOOL is_trojan = (_stricmp(s->config.type, "trojan") == 0);
    BOOL is_shadowsocks = (_stricmp(s->config.type, "shadowsocks") == 0);
    BOOL is_mandala = (_stricmp(s->config.type, "mandala") == 0);

    if (is_vless) {
        proto_buf[proto_len++] = 0x00; 
        parse_uuid(s->config.user, proto_buf + proto_len); proto_len += 16; 
        proto_buf[proto_len++] = 0x00; proto_buf[proto_len++] = 0x01; 
        proto_buf[proto_len++] = (s->target_port >> 8) & 0xFF; proto_buf[proto_len++] = s->target_port & 0xFF;        
        if (inet_pton(AF_INET, s->target_host, &ip4) == 1) {
            proto_buf[proto_len++] = 0x01; memcpy(proto_buf + proto_len, &ip4, 4); proto_len += 4;
        } else if (inet_pton(AF_INET6, s->target_host, &ip6) == 1) {
            proto_buf[proto_len++] = 0x03; memcpy(proto_buf + proto_len, &ip6, 16); proto_len += 16;
        } else {
            proto_buf[proto_len++] = 0x02; proto_buf[proto_len++] = (unsigned char)strlen(s->target_host);
            memcpy(proto_buf + proto_len, s->target_host, strlen(s->target_host)); proto_len += (int)strlen(s->target_host);
        }
    } else if (is_trojan || is_mandala) {
        char hex_pass[SHA224_DIGEST_LENGTH * 2 + 1]; 
        trojan_password_hash(s->config.pass, hex_pass);
        
        if (is_mandala) { 
             unsigned char salt[4], plaintext[2048]; int p_len = 0;
             if(RAND_bytes(salt, 4) != 1) return -1;
             memcpy(plaintext, hex_pass, 56); p_len = 56;
             unsigned char rnd_byte; RAND_bytes(&rnd_byte, 1);
             int pad = rnd_byte % 16; 
             plaintext[p_len++] = (unsigned char)pad;
             if (pad > 0) RAND_bytes(plaintext + p_len, pad);
             p_len += pad;
             plaintext[p_len++] = 0x01; 
             int added = append_addr_standard(plaintext, p_len, s->target_host, s->target_port);
             if (added < 0) return -1; p_len += added;
             plaintext[p_len++] = 0x0D; plaintext[p_len++] = 0x0A;
             memcpy(proto_buf, salt, 4);
             for(int i=0; i<p_len; i++) proto_buf[4 + i] = plaintext[i] ^ salt[i % 4];
             proto_len = 4 + p_len;
        } else {
             memcpy(proto_buf, hex_pass, 56); proto_len = 56;
             proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
             proto_buf[proto_len++] = 0x01; 
             int added = append_addr_standard(proto_buf, proto_len, s->target_host, s->target_port);
             if (added < 0) return -1; proto_len += added;
             proto_buf[proto_len++] = 0x0D; proto_buf[proto_len++] = 0x0A;
        }
    } else if (is_shadowsocks) {
        int added = append_addr_standard(proto_buf, proto_len, s->target_host, s->target_port);
        if (added < 0) return -1; proto_len += added;
    } else {
        // SOCKS5 Outbound
        char auth[] = {0x05, 0x01, 0x00}; 
        if (strlen(s->config.user) > 0) auth[2] = 0x02; 
        if (s->alpn_is_h2) return -1;
        
        flen = build_ws_frame(auth, 3, s->ws_send_buf);
        tls_write(&s->tls, s->ws_send_buf, flen);
        
        char resp_buf[512]; 
        int rn = ws_read_frame(&s->tls, resp_buf, sizeof(resp_buf));
        if (rn < 2) return -1;
        
        if (resp_buf[1] == 0x02) { 
            int ulen = strlen(s->config.user); int plen = strlen(s->config.pass);
            unsigned char auth_pkg[512]; int ap_len = 0;
            auth_pkg[ap_len++] = 0x01; 
            auth_pkg[ap_len++] = ulen; memcpy(auth_pkg+ap_len, s->config.user, ulen); ap_len += ulen;
            auth_pkg[ap_len++] = plen; memcpy(auth_pkg+ap_len, s->config.pass, plen); ap_len += plen;
            flen = build_ws_frame((char*)auth_pkg, ap_len, s->ws_send_buf);
            tls_write(&s->tls, s->ws_send_buf, flen);
            
            rn = ws_read_frame(&s->tls, resp_buf, sizeof(resp_buf));
            if (rn < 2 || resp_buf[1] != 0x00) return -1;
        } 

        int slen = 0; unsigned char socks_req[512];
        socks_req[slen++] = 0x05; socks_req[slen++] = 0x01; socks_req[slen++] = 0x00; 
        int added = append_addr_standard(socks_req, slen, s->target_host, s->target_port);
        if (added < 0) return -1; slen += added;

        flen = build_ws_frame((char*)socks_req, slen, s->ws_send_buf);
        tls_write(&s->tls, s->ws_send_buf, flen);

        rn = ws_read_frame(&s->tls, resp_buf, sizeof(resp_buf));
        if (rn < 4 || resp_buf[1] != 0x00) return -1; 
        return 0;
    }

    if (s->alpn_is_h2) {
        if (s->h2_browser_len + proto_len < IO_BUFFER_SIZE) {
            memcpy(s->h2_browser_buf + s->h2_browser_len, proto_buf, proto_len);
            s->h2_browser_len += proto_len;
            nghttp2_session_resume_data(s->h2_sess, s->h2_stream_id);
            nghttp2_session_send(s->h2_sess);
        }
    } else {
        flen = build_ws_frame((char*)proto_buf, proto_len, s->ws_send_buf);
        tls_write(&s->tls, s->ws_send_buf, flen);
    }
    return 0;
}
