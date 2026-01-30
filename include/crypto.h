/* include/crypto.h */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/bio.h> 

// [Fix] 引入 common.h 以获取 TLSContext 定义
#include "common.h"

// 加密配置结构体
typedef struct {
    // [Refactor] 移除 enableChromeCiphers，改为更丰富的类型支持
    int browserType;          // 对应 BrowserType 枚举
    char customCiphers[2048]; // 自定义加密套件
    
    BOOL enableFragment;
    int fragMin;
    int fragMax;
    int fragDelay;
    BOOL enablePadding;
    int padMin;
    int padMax;
    
    // [New] ALPN 覆盖设置 (用于降级重试)
    // 0: 使用全局 g_alpnMode 设置
    // 1: 强制 HTTP/1.1 (降级模式)
    // 2: 强制 H2
    // 3: 强制 H3
    int alpnOverride; 
} CryptoSettings;

// --- 全局初始化与清理 (crypto_core.c) ---
void init_crypto_global();
void cleanup_crypto_global();
void ReloadSSLContext();
void ClearSSLCache();

// [New] 线程安全的 SSL 创建函数 (解决 Reload 竞态崩溃)
// 替代直接调用 SSL_new(g_ssl_ctx)
SSL* Crypto_CreateSSL(void);

// --- BIO 与 碎片化功能 (crypto_bio.c) ---
// [Internal] 初始化 BIO Method (供 core 初始化调用)
void Crypto_InitBIOMethod(void);
// [Internal] 获取碎片化 BIO Method
BIO_METHOD *BIO_f_fragment(void);
// [Internal] 设置 BIO 参数
void BIO_set_params(BIO *b, const CryptoSettings *s);

// --- TLS 连接相关 (crypto_tls.c) ---
int tls_init_connect(TLSContext *ctx, const char* target_sni, const char* target_host, const CryptoSettings* settings, BOOL allowInsecure);
const char* tls_get_alpn_selected(TLSContext *ctx);
int tls_write(TLSContext *ctx, const char *data, int len);
int tls_read(TLSContext *ctx, char *out, int max);
int tls_read_exact(TLSContext *ctx, char *buf, int len);
void tls_close(TLSContext *ctx);

// --- WebSocket 辅助 (crypto_ws.c) ---
int build_ws_frame(const char *in, int len, char *out);
long long check_ws_frame(unsigned char *in, int len, int *head_len, int *payload_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expected_len);

#endif // CRYPTO_H
