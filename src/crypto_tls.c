/* src/crypto_tls.c */
// [Refactor] 2026-01-22: 优化 ECH 触发逻辑，跳过 IP 直连的无效查询，减少首包延迟
// [Fix] 2026-01-17: 优化 TLS 轮询间隔 (50ms -> 1ms) 以消除传输波动
// [Security] 2026-01-29: 强化主机名验证失败时的连接终止逻辑

#include "crypto.h"
#include "config.h" 
#include "common.h"
#include "utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h> 
#include <openssl/x509_vfy.h> // [Add] for verify codes
#include <string.h>
#include <stdio.h>
#include <limits.h> 

extern CRITICAL_SECTION g_configLock; 
extern volatile BOOL g_proxyRunning;

// 超时设置 (毫秒)
#define HANDSHAKE_TIMEOUT_MS 10000
#define WRITE_TIMEOUT_MS     8000
#define READ_TIMEOUT_MS      8000

// [Fix] 将短轮询间隔从 50ms 降低到 1ms，保证高负载下的响应速度，消除锯齿波
// 这允许 socket 在 I/O 就绪时几乎立即被处理，而不是等待下一个 tick
#define SELECT_WAIT_MS       1     

static BOOL is_ip_address(const char* host) {
    if (!host) return FALSE;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET, host, &(sa.sin_addr)) == 1) return TRUE;
    if (inet_pton(AF_INET6, host, &(sa6.sin6_addr)) == 1) return TRUE;
    return FALSE;
}

// [Helper] 设置浏览器加密套件
static void ApplyBrowserCiphers(SSL* ssl, int browserType, const char* customCiphers) {
    const char *ciphers = NULL;
    const char *tls13_ciphers = NULL;

    ERR_clear_error();

    switch(browserType) {
        case BROWSER_TYPE_CHROME:
        case BROWSER_TYPE_EDGE: 
            tls13_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
            ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
            break;
            
        case BROWSER_TYPE_FIREFOX:
            tls13_ciphers = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384";
            ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
            break;

        case BROWSER_TYPE_SAFARI:
            tls13_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
            ciphers = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";
            break;

        case BROWSER_TYPE_CUSTOM:
            if (customCiphers && strlen(customCiphers) > 5) {
                if (SSL_set_ciphersuites(ssl, customCiphers) != 1) ERR_clear_error(); 
                if (SSL_set_cipher_list(ssl, customCiphers) != 1) {
                    log_msg("[TLS] Warning: Failed to apply custom cipher list");
                }
                ERR_clear_error();
                return;
            }
            break;
            
        case BROWSER_TYPE_NONE:
        default:
            return; 
    }

    if (tls13_ciphers) SSL_set_ciphersuites(ssl, tls13_ciphers);
    if (ciphers) SSL_set_cipher_list(ssl, ciphers);
    ERR_clear_error();
}

int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings, BOOL allowInsecure) {
    if (ctx->sock == INVALID_SOCKET) {
        log_msg("[Fatal] Invalid socket handle.");
        return -1;
    }

    ctx->ssl = Crypto_CreateSSL();
    if (!ctx->ssl) {
        log_msg("[Fatal] SSL_new failed");
        return -1;
    }
    
    if (settings) {
        ApplyBrowserCiphers(ctx->ssl, settings->browserType, settings->customCiphers);
    }

    const char *sni_name = (target_sni && strlen(target_sni)) ? target_sni : target_host;
    if (sni_name && !is_ip_address(sni_name)) {
        SSL_set_tlsext_host_name(ctx->ssl, sni_name);
    }

    // ALPN 设置
    int mode = g_alpnMode;
    if (settings && settings->alpnOverride > 0) mode = settings->alpnOverride; 

    if (mode > 0) {
        unsigned char alpn_protos[64];
        unsigned char* p = alpn_protos;
        if (mode == 3) { // H3, H2, H1
            *p++ = 2; *p++ = 'h'; *p++ = '3';
            *p++ = 2; *p++ = 'h'; *p++ = '2';
            *p++ = 8; memcpy(p, "http/1.1", 8); p += 8;
        } else if (mode == 2) { // H2, H1
            *p++ = 2; *p++ = 'h'; *p++ = '2';
            *p++ = 8; memcpy(p, "http/1.1", 8); p += 8;
        } else { // H1
            *p++ = 8; memcpy(p, "http/1.1", 8); p += 8;
        }
        SSL_set_alpn_protos(ctx->ssl, alpn_protos, (unsigned int)(p - alpn_protos));
    }

    // ECH 配置
    if (g_enableECH) {
        SSL_set_min_proto_version(ctx->ssl, TLS1_3_VERSION);
        SSL_set_max_proto_version(ctx->ssl, TLS1_3_VERSION);

        // [Optimization] 只有当 SNI 是域名时才尝试获取 ECH
        // 跳过 IP 直接访问的场景，避免无效的 DNS 查询导致的连接延迟
        if (sni_name && !is_ip_address(sni_name)) {
            const char* query_domain = (g_echPublicName && strlen(g_echPublicName)) ? g_echPublicName : sni_name;
            size_t ech_len = 0;
            unsigned char* ech_config = FetchECHConfig(query_domain, g_echConfigServer, &ech_len);
            
            if (ech_config && ech_len > 0) {
                SSL_set1_ech_config_list(ctx->ssl, ech_config, ech_len);
                free(ech_config);
            }
        }
    }

    if (allowInsecure) {
        SSL_set_verify(ctx->ssl, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_set_verify(ctx->ssl, SSL_VERIFY_PEER, NULL);
        #ifdef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
        SSL_set_hostflags(ctx->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        #endif
        if (sni_name && !is_ip_address(sni_name)) {
            // [Security] 必须检查返回值，如果设置失败则无法验证主机名，存在安全风险
            if (!SSL_set1_host(ctx->ssl, sni_name)) {
                log_msg("[TLS] Failed to set verify host: %s", sni_name);
                SSL_free(ctx->ssl); ctx->ssl = NULL; return -1;
            }
        }
    }

    // 绑定 BIO
    BIO *internal_bio = BIO_new_socket((int)ctx->sock, BIO_NOCLOSE);
    if (!internal_bio) { SSL_free(ctx->ssl); ctx->ssl = NULL; return -1; }

    BIO_METHOD *frag_method = BIO_f_fragment();
    if (frag_method && !g_enableECH) {
        BIO *frag_bio = BIO_new(frag_method);
        if (frag_bio) {
            BIO_set_params(frag_bio, settings);
            BIO_push(frag_bio, internal_bio); 
            SSL_set_bio(ctx->ssl, frag_bio, frag_bio);
        } else {
            SSL_set_bio(ctx->ssl, internal_bio, internal_bio);
        }
    } else {
        SSL_set_bio(ctx->ssl, internal_bio, internal_bio);
    }
    
    // 非阻塞握手循环
    int ret = -1;
    ULONGLONG start_time = GetTickCount64();
    
    while (g_proxyRunning) {
        ULONGLONG now = GetTickCount64();
        if (now - start_time > HANDSHAKE_TIMEOUT_MS) {
            log_msg("[TLS] Handshake timeout");
            break;
        }

        ERR_clear_error(); 
        ret = SSL_connect(ctx->ssl);
        
        if (ret == 1) return 0; // Success

        int err_code = SSL_get_error(ctx->ssl, ret);
        if (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE) {
            fd_set fds; 
            FD_ZERO(&fds); 
            FD_SET(ctx->sock, &fds);
            
            struct timeval tv;
            tv.tv_sec = 0; 
            // 保持 1ms 的极短轮询，确保握手阶段最快响应
            tv.tv_usec = SELECT_WAIT_MS * 1000; 

            int n;
            // 根据需要等待读或写
            if (err_code == SSL_ERROR_WANT_READ) n = select(0, &fds, NULL, NULL, &tv);
            else n = select(0, NULL, &fds, NULL, &tv);
            
            if (n < 0) {
                log_msg("[TLS] Handshake select error: %d", WSAGetLastError());
                break;
            }
            // n=0 (Timeout) continue to loop
        } else {
            unsigned long ssl_err = ERR_get_error();
            if (ssl_err != 0) {
                char err_buf[256];
                ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                log_msg("[TLS] Handshake failed: %s", err_buf);
                
                // [Added 2026-01-29] 打印详细验证结果，辅助排查证书问题
                long verify_res = SSL_get_verify_result(ctx->ssl);
                if (verify_res != X509_V_OK) {
                    const char* reason = X509_verify_cert_error_string(verify_res);
                    // Code 62 = Hostname Mismatch, Code 20 = Untrusted Issuer
                    log_msg("[TLS] Verify Detail: Code %ld (%s)", verify_res, reason);
                }
            }
            break; 
        }
    }

    if (ctx->ssl) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    return -1;
}

const char* tls_get_alpn_selected(TLSContext *ctx) {
    if (!ctx || !ctx->ssl) return NULL;
    const unsigned char *data = NULL;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ctx->ssl, &data, &len);
    if (len > 0 && data) {
        if (len == 2 && memcmp(data, "h2", 2) == 0) return "h2";
        if (len == 8 && memcmp(data, "http/1.1", 8) == 0) return "http/1.1";
        if (len == 2 && memcmp(data, "h3", 2) == 0) return "h3";
    }
    return NULL;
}

int tls_write(TLSContext *ctx, const char *data, int len) {
    if (!ctx || !ctx->ssl) return -1;
    int written = 0;
    ULONGLONG start_tick = GetTickCount64();

    ERR_clear_error();
    
    while (written < len) {
        if (!g_proxyRunning) return -1;

        if (GetTickCount64() - start_tick > WRITE_TIMEOUT_MS) {
            log_msg("[TLS] Write timeout");
            return -1;
        }

        int ret = SSL_write(ctx->ssl, data + written, len - written);
        if (ret > 0) { 
            written += ret; 
            // 只要有数据流动，重置超时，防止大文件传输中断
            start_tick = GetTickCount64(); 
        } else {
            int err = SSL_get_error(ctx->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) { 
                int sock = SSL_get_fd(ctx->ssl);
                fd_set rfds, wfds;
                struct timeval tv;
                tv.tv_sec = 0; tv.tv_usec = SELECT_WAIT_MS * 1000; // 1ms
                
                FD_ZERO(&rfds); FD_ZERO(&wfds);

                // 根据 SSL 需求设置 FD_SET
                if (err == SSL_ERROR_WANT_READ) FD_SET(sock, &rfds);
                else FD_SET(sock, &wfds);
                
                int n = select(0, &rfds, &wfds, NULL, &tv);
                
                if (n < 0) return -1; // Select 错误
                // 如果 n==0 (超时)，循环继续检查 g_proxyRunning
            } else {
                return -1; // 致命错误
            }
        }
    }
    return written;
}

// 返回值: 
// > 0: 读取字节数
// 0: 暂无数据 (Retry)
// -1: EOF 或 错误
int tls_read(TLSContext *ctx, char *out, int max) {
    if (!ctx || !ctx->ssl) return -1;
    ERR_clear_error();
    int ret = SSL_read(ctx->ssl, out, max);
    
    if (ret > 0) return ret; 

    int err = SSL_get_error(ctx->ssl, ret);
    
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0; // 指示上层重试
    }
    
    if (err == SSL_ERROR_ZERO_RETURN) {
        return -1; // EOF (CloseNotify)
    }
    
    return -1; // Error
}

int tls_read_exact(TLSContext *ctx, char *buf, int len) {
    int total = 0;
    ULONGLONG start_tick = GetTickCount64();

    while (total < len) {
        if (!g_proxyRunning) return 0;
        
        if (GetTickCount64() - start_tick > READ_TIMEOUT_MS) {
            return 0;
        }

        int ret = tls_read(ctx, buf + total, len - total);
        
        if (ret < 0) return 0; // EOF or Error
        
        if (ret == 0) { 
            // 暂无数据，使用 select 等待
            int sock = SSL_get_fd(ctx->ssl);
            
            // 如果 SSL 缓冲区里有数据，立即重试 (OpenSSL Internal Buffering)
            if (SSL_pending(ctx->ssl) > 0) continue; 
            
            fd_set rfds, wfds; 
            FD_ZERO(&rfds); FD_ZERO(&wfds);
            
            if (SSL_want_read(ctx->ssl)) FD_SET(sock, &rfds);
            if (SSL_want_write(ctx->ssl)) FD_SET(sock, &wfds);
            
            struct timeval tv;
            tv.tv_sec = 0; tv.tv_usec = SELECT_WAIT_MS * 1000; 

            int n = select(0, &rfds, &wfds, NULL, &tv);
            if (n < 0) return 0;
            
            continue; 
        } 
        
        total += ret;
        start_tick = GetTickCount64(); 
    }
    return 1; 
}

void tls_close(TLSContext *ctx) {
    if (ctx->ssl) { 
        // 快速关闭，不等待对端响应 (Quiet Shutdown)
        SSL_set_shutdown(ctx->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(ctx->ssl); 
        ctx->ssl = NULL; 
    }
}
