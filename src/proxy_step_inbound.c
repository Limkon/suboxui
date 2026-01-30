/* src/proxy_step_inbound.c */
#include "proxy_internal.h"
#include "utils.h"
#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <regex.h>

// [Refactor] 路由检查与应用函数
static int CheckRoutingAndApply(ProxySession* s) {
    if (g_routingRuleCount == 0) return 0; 

    BOOL target_is_ip = IsIpStr(s->target_host);
    EnterCriticalSection(&g_configLock);
    int ruleCount = g_routingRuleCount;
    RoutingRule* rules = g_routingRules;
    
    if (ruleCount == 0) {
        LeaveCriticalSection(&g_configLock);
        return 0; 
    }

    for (int i = 0; i < ruleCount; i++) {
        RoutingRule* r = &rules[i];
        for (int j = 0; j < r->contentCount; j++) {
            char* rule = r->contents[j];
            BOOL is_match = FALSE;

            // 1. 正则匹配
            if (strncmp(rule, "regexp:", 7) == 0) {
                if (target_is_ip) continue; 
                const char* pattern = rule + 7;
                regex_t regex;
                if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB) == 0) {
                    if (regexec(&regex, s->target_host, 0, NULL, 0) == 0) is_match = TRUE;
                    regfree(&regex);
                }
            }
            // 2. IP/CIDR 匹配
            else if (strncmp(rule, "ip:", 3) == 0 || strncmp(rule, "cidr:", 5) == 0 || 
                     strchr(rule, '/') != NULL || IsIpStr(rule)) {
                if (!target_is_ip) continue; 
                const char* rule_val = rule;
                if (strncmp(rule, "ip:", 3) == 0) rule_val += 3;
                else if (strncmp(rule, "cidr:", 5) == 0) rule_val += 5;

                if (CidrMatch(s->target_host, rule_val)) is_match = TRUE;
            }
            // 3. 域名后缀匹配
            else {
                if (target_is_ip) continue;
                const char* domain = rule;
                if (strncmp(domain, "domain:", 7) == 0) domain += 7;
                size_t hostLen = strlen(s->target_host);
                size_t ruleLen = strlen(domain);
                if (hostLen >= ruleLen) {
                    if (stricmp(s->target_host + hostLen - ruleLen, domain) == 0) {
                        if (hostLen == ruleLen || s->target_host[hostLen - ruleLen - 1] == '.') is_match = TRUE;
                    }
                }
            }

            if (is_match) {
                if (stricmp(r->outboundTag, "block") == 0) {
                    LeaveCriticalSection(&g_configLock);
                    log_msg("[Routing] Blocked request to %s (Rule: %s)", s->target_host, rule);
                    return -1; 
                }
                
                if (stricmp(r->outboundTag, "direct") == 0) {
                    LeaveCriticalSection(&g_configLock);
                    log_msg("[Routing] Direct rule hit for %s.", s->target_host);
                    if (!s->is_udp_associate) {
                        strncpy(s->config.host, s->target_host, sizeof(s->config.host) - 1);
                        s->config.host[sizeof(s->config.host) - 1] = 0;
                        s->config.port = s->target_port;
                        strcpy(s->config.type, "direct");
                        if (!target_is_ip) {
                            strncpy(s->config.sni, s->target_host, sizeof(s->config.sni) - 1);
                            s->config.sni[sizeof(s->config.sni) - 1] = 0;
                        } else {
                            s->config.sni[0] = 0;
                        }
                        s->cryptoSettings.alpnOverride = 0;
                    }
                    return 0; 
                }
                LeaveCriticalSection(&g_configLock);
                return 0; 
            }
        }
    }
    LeaveCriticalSection(&g_configLock);
    return 0; 
}

// Step 1: 处理浏览器握手与协议分析
int step_handshake_browser(ProxySession* s) {
    if (!g_proxyRunning) return -1;

    int flag = 1;
    setsockopt(s->clientSock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    s->browser_header_len = read_header_robust(s->clientSock, s->c_buf, IO_BUFFER_SIZE - 1, 10);
    if (s->browser_header_len <= 0) return -1; 
    s->c_buf[s->browser_header_len] = 0;

    // 协议探测
    if (s->c_buf[0] == 0x05) { 
        // Socks5 处理
        send(s->clientSock, "\x05\x00", 2, 0); 
        s->is_socks5 = 1;
        
        int n = recv_timeout(s->clientSock, s->c_buf, IO_BUFFER_SIZE, 5000);
        if (n <= 0) return -1;
        s->browser_header_len = n;
        
        if (s->c_buf[1] == 0x01) { // CONNECT
             if (s->c_buf[3] == 0x01) { // IPv4
                 inet_ntop(AF_INET, &s->c_buf[4], s->target_host, sizeof(s->target_host));
                 s->target_port = ntohs(*(unsigned short*)&s->c_buf[8]);
             } else if (s->c_buf[3] == 0x03) { // Domain
                 int dlen = (unsigned char)s->c_buf[4];
                 memcpy(s->target_host, &s->c_buf[5], dlen); s->target_host[dlen] = 0;
                 s->target_port = ntohs(*(unsigned short*)&s->c_buf[5+dlen]);
             } else if (s->c_buf[3] == 0x04) { // IPv6
                 char ip6_buf[16];
                 memcpy(ip6_buf, &s->c_buf[4], 16);
                 inet_ntop(AF_INET6, ip6_buf, s->target_host, sizeof(s->target_host));
                 s->target_port = ntohs(*(unsigned short*)&s->c_buf[20]);
             } else return -1;
             strcpy(s->method, "SOCKS5");

        } else if (s->c_buf[1] == 0x03) { // UDP ASSOCIATE
             log_msg("[Conn-%d] Handling SOCKS5 UDP ASSOCIATE...", s->clientSock);
             s->is_udp_associate = 1;
             
             if (s->c_buf[3] == 0x01) { 
                 inet_ntop(AF_INET, &s->c_buf[4], s->target_host, sizeof(s->target_host));
                 s->target_port = ntohs(*(unsigned short*)&s->c_buf[8]);
             } else if (s->c_buf[3] == 0x03) { 
                 int dlen = (unsigned char)s->c_buf[4];
                 memcpy(s->target_host, &s->c_buf[5], dlen); s->target_host[dlen] = 0;
                 s->target_port = ntohs(*(unsigned short*)&s->c_buf[5+dlen]);
             } else if (s->c_buf[3] == 0x04) { 
                 char ip6_buf[16];
                 memcpy(ip6_buf, &s->c_buf[4], 16);
                 inet_ntop(AF_INET6, ip6_buf, s->target_host, sizeof(s->target_host));
                 s->target_port = ntohs(*(unsigned short*)&s->c_buf[20]);
             } else strcpy(s->target_host, "IPv6-Address");

             if (CheckRoutingAndApply(s) == -1) {
                 unsigned char resp[10] = {0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0};
                 send(s->clientSock, (char*)resp, 10, 0);
                 return -1;
             }

             s->udpSock = socket(AF_INET, SOCK_DGRAM, 0);
             if (s->udpSock == INVALID_SOCKET) return -1;
             
             struct sockaddr_in bind_addr = {0};
             bind_addr.sin_family = AF_INET;
             bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
             
             if (bind(s->udpSock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
                 closesocket(s->udpSock); s->udpSock = INVALID_SOCKET;
                 return -1;
             }
             
             struct sockaddr_in assigned_addr;
             int addr_len = sizeof(assigned_addr);
             if (getsockname(s->udpSock, (struct sockaddr*)&assigned_addr, &addr_len) != 0) {
                 closesocket(s->udpSock); s->udpSock = INVALID_SOCKET;
                 return -1;
             }
             
             unsigned char resp[10];
             resp[0] = 0x05; resp[1] = 0x00; resp[2] = 0x00; resp[3] = 0x01;
             memset(&resp[4], 0, 4);
             memcpy(&resp[8], &assigned_addr.sin_port, 2);
             send(s->clientSock, (char*)resp, 10, 0);
             return 0; 
        } else return -1;
    } 
    else {
        // HTTP
        if (sscanf(s->c_buf, "%15s %255s", s->method, s->target_host) == 2) {
            char *p_col = strchr(s->target_host, ':');
            if (p_col) { *p_col = 0; s->target_port = atoi(p_col+1); }
            else if(stricmp(s->method, "CONNECT")==0) s->target_port = 443;
            else s->target_port = 80;
            
            if (stricmp(s->method, "CONNECT") == 0) s->is_connect_method = 1;
            char* header_end = strstr(s->c_buf, "\r\n\r\n");
            s->header_len = header_end ? (int)(header_end - s->c_buf) + 4 : s->browser_header_len;
        } else return -1;
    }
    
    // 日志
    char display_host[256]; 
    strncpy(display_host, s->target_host, sizeof(display_host)-1); 
    display_host[sizeof(display_host)-1] = 0;
#if LOG_DESENSITIZE
    if (strlen(display_host) > 4) {
        size_t dlen = strlen(display_host);
        if (dlen > 8) for(size_t i=3; i<dlen-3; i++) if(display_host[i]!='.') display_host[i] = '*';
    }
#endif
    log_msg("[Conn-%d] Request: %s -> %s:%d", s->clientSock, s->method, display_host, s->target_port);

    if (CheckRoutingAndApply(s) == -1) {
        if (s->is_socks5) {
            unsigned char resp[10] = {0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0};
            send(s->clientSock, (char*)resp, 10, 0);
        } else {
            const char* forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 16\r\n\r\nAccess Blocked.\n";
            send(s->clientSock, forbidden, strlen(forbidden), 0);
        }
        return -1;
    }
    return 0;
}

// Step 5: 响应浏览器
int step_respond_to_browser(ProxySession* s) {
    if (!g_proxyRunning) return -1;

    int flen;
    if (s->is_socks5) {
        unsigned char s5_ok[] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
        send(s->clientSock, (char*)s5_ok, 10, 0);
    } 
    else if (s->is_connect_method) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(s->clientSock, ok, strlen(ok), 0);
        
        if (s->browser_header_len > s->header_len) {
            int extra_len = s->browser_header_len - s->header_len;
            if (_stricmp(s->config.type, "direct") == 0) {
                 send(s->remoteSock, s->c_buf + s->header_len, extra_len, 0);
                 return 0;
            }
            if (s->alpn_is_h2) {
                 if (s->h2_browser_len + extra_len < IO_BUFFER_SIZE) {
                     memcpy(s->h2_browser_buf + s->h2_browser_len, s->c_buf + s->header_len, extra_len);
                     s->h2_browser_len += extra_len;
                     nghttp2_session_resume_data(s->h2_sess, s->h2_stream_id);
                     nghttp2_session_send(s->h2_sess);
                 }
            } else {
                 flen = build_ws_frame(s->c_buf + s->header_len, extra_len, s->ws_send_buf);
                 tls_write(&s->tls, s->ws_send_buf, flen);
            }
        }
    } 
    else {
        if (_stricmp(s->config.type, "direct") == 0) {
             send(s->remoteSock, s->c_buf, s->browser_header_len, 0);
             return 0;
        }
        if (s->alpn_is_h2) {
             if (s->h2_browser_len + s->browser_header_len < IO_BUFFER_SIZE) {
                 memcpy(s->h2_browser_buf + s->h2_browser_len, s->c_buf, s->browser_header_len);
                 s->h2_browser_len += s->browser_header_len;
                 nghttp2_session_resume_data(s->h2_sess, s->h2_stream_id);
                 nghttp2_session_send(s->h2_sess);
             }
        } else {
             flen = build_ws_frame(s->c_buf, s->browser_header_len, s->ws_send_buf);
             tls_write(&s->tls, s->ws_send_buf, flen);
        }
    }
    return 0;
}
