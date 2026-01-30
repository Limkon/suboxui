/* src/crypto_core.c */
// [Refactor] 2026-01-11: 采用 Swap 模式重构 SSL 上下文重载，缩短锁持有时间，防止服务中断

#include "crypto.h"
#include "common.h"
#include "utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>

// 引入 BoringSSL/OpenSSL 兼容层
#ifndef SSL_OP_NO_RENEGOTIATION
#define SSL_OP_NO_RENEGOTIATION 0
#endif

// 全局变量定义
CRITICAL_SECTION g_sslLock;
static BOOL g_lib_inited = FALSE;

// 引用全局 SSL_CTX (定义在 src/globals.c 中)
extern SSL_CTX *g_ssl_ctx;

// [Internal] 创建一个新的 Context 并返回，不触碰全局变量
// 包含耗时的证书加载和初始化操作
static SSL_CTX* CreateNewSSLContext() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log_msg("[Fatal] SSL_CTX_new failed");
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // [Config] 默认加密套件配置 (Chrome Modern)
    const char *chrome_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA";
    if (SSL_CTX_set_cipher_list(ctx, chrome_ciphers) != 1) {
        log_msg("[Warn] Failed to set cipher list.");
    }

    const char *tls13_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    if (SSL_CTX_set_ciphersuites(ctx, tls13_ciphers) != 1) {
         log_msg("[Warn] Failed to set TLS 1.3 ciphersuites");
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_ENABLE_MIDDLEBOX_COMPAT | SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    unsigned char sid_ctx[32];
    if (RAND_bytes(sid_ctx, sizeof(sid_ctx)) == 1) {
        SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx));
    }

    // 加载内置 CA 证书 (涉及资源锁和内存操作)
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(2), RT_RCDATA);
    if (hRes) {
        HGLOBAL hData = LoadResource(NULL, hRes);
        void* pData = LockResource(hData);
        DWORD dataSize = SizeofResource(NULL, hRes);
        if (pData && dataSize > 0) {
            BIO *cbio = BIO_new_mem_buf(pData, dataSize);
            if (cbio) {
                X509_STORE *cts = SSL_CTX_get_cert_store(ctx);
                X509 *x = NULL;
                int count = 0;
                while ((x = PEM_read_bio_X509(cbio, NULL, 0, NULL)) != NULL) {
                    X509_STORE_add_cert(cts, x);
                    X509_free(x);
                    count++;
                }
                BIO_free(cbio);
                log_msg("[Crypto] Loaded %d CA certificates from resource.", count);
            }
        }
    }
    
    return ctx;
}

static void InitCryptoLibrary() {
    if (g_lib_inited) return;
    
    ERR_clear_error();
    
    SSL_library_init(); 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
    
    // 初始化 BIO Method (定义在 crypto_bio.c)
    Crypto_InitBIOMethod(); 
    
    g_lib_inited = TRUE;
    log_msg("[Crypto] OpenSSL Library initialized.");
}

void init_crypto_global() {
    InitializeCriticalSection(&g_sslLock);
    InitCryptoLibrary();
    
    // 初始创建，直接赋值
    g_ssl_ctx = CreateNewSSLContext();
}

void ReloadSSLContext() {
    log_msg("[System] Preparing to reload SSL Context...");
    
    // 1. 在锁外创建新 Context (耗时操作)
    // 这样不会阻塞正在请求 Crypto_CreateSSL 的工作线程
    SSL_CTX* new_ctx = CreateNewSSLContext();
    if (!new_ctx) {
        log_msg("[Err] Failed to create new SSL Context. Reload aborted, keeping old context.");
        return;
    }

    // 2. 刷新随机数种子
    RAND_poll();

    SSL_CTX* old_ctx = NULL;

    // 3. 进入临界区，仅进行指针交换 (极快)
    EnterCriticalSection(&g_sslLock);
    
    old_ctx = g_ssl_ctx;
    g_ssl_ctx = new_ctx;
    
    LeaveCriticalSection(&g_sslLock);
    
    // 4. 在锁外释放旧 Context
    // OpenSSL 引用计数机制保证：如果仍有 SSL 对象在使用 old_ctx，它不会被立即物理销毁
    if (old_ctx) { 
        SSL_CTX_free(old_ctx); 
    }
    
    log_msg("[System] SSL Context Reloaded successfully.");
}

void cleanup_crypto_global() {
    DeleteCriticalSection(&g_sslLock);
    if (g_ssl_ctx) { SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL; }
}

void ClearSSLCache() {
    EnterCriticalSection(&g_sslLock);
    if (g_ssl_ctx) {
        #ifdef __GNUC__
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        
        SSL_CTX_flush_sessions(g_ssl_ctx, 0);

        #ifdef __GNUC__
        #pragma GCC diagnostic pop
        #endif
    }
    LeaveCriticalSection(&g_sslLock);
    log_msg("[System] SSL Session Cache Cleared");
}

// 线程安全的 SSL 对象创建函数
SSL* Crypto_CreateSSL() {
    SSL* ssl = NULL;
    
    EnterCriticalSection(&g_sslLock);
    if (g_ssl_ctx) {
        ssl = SSL_new(g_ssl_ctx);
    } else {
        log_msg("[Crypto] Error: g_ssl_ctx is NULL during SSL creation");
    }
    LeaveCriticalSection(&g_sslLock);
    
    return ssl;
}
