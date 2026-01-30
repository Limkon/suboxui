/* src/crypto_bio.c */
#include "crypto.h"
#include "utils.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/bio.h> 
#include <string.h>

// TLS 常量定义
#define TLS_HEADER_LEN 5
#define HANDSHAKE_HEADER_LEN 4
#define TLS_RECORD_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define CLIENT_HELLO_FIXED_OFFSET 43
#define MAX_FRAG_COUNT 32 

// BIO Method 指针
static BIO_METHOD *method_frag = NULL;

typedef struct {
    int first_packet_sent;
    int frag_min;
    int frag_max;
    int frag_delay;
    int enable_padding;
    int pad_min;
    int pad_max;
    
    // [Fix] 状态保持：用于断点续传 Padding 数据
    char* pending_buf;      // 缓存已生成的带 Padding 的数据
    int pending_total_len;  // 总长度
    int pending_sent;       // 已发送长度
} FragCtx;

// 前向声明
static int frag_write(BIO *b, const char *in, int inl);
static int frag_read(BIO *b, char *out, int outl);
static long frag_ctrl(BIO *b, int cmd, long num, void *ptr);
static int frag_new(BIO *b);
static int frag_free(BIO *b);

// 获取 BIO Method
BIO_METHOD *BIO_f_fragment(void) { 
    return method_frag; 
}

static int frag_new(BIO *b) {
    FragCtx *ctx = (FragCtx *)malloc(sizeof(FragCtx));
    if(!ctx) return 0;
    memset(ctx, 0, sizeof(FragCtx));
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    return 1;
}

static int frag_free(BIO *b) {
    if (b == NULL) return 0;
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    if (ctx) { 
        // [Fix] 清理残留的缓存
        if (ctx->pending_buf) {
            free(ctx->pending_buf);
            ctx->pending_buf = NULL;
        }
        free(ctx); 
        BIO_set_data(b, NULL); 
    }
    return 1;
}

// 设置 BIO 参数
// [Fix] 2026-01-29: 修复了忽略 enableFragment 开关导致强制分片变慢的 Bug
void BIO_set_params(BIO *b, const CryptoSettings *s) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    if (ctx && s) { 
        // 关键修复：只有当开关开启时，才应用分片参数
        if (s->enableFragment) {
            ctx->frag_min = s->fragMin; 
            ctx->frag_max = s->fragMax; 
            ctx->frag_delay = s->fragDelay;
        } else {
            // 否则强制归零，防止意外进入分片延时逻辑
            ctx->frag_min = 0;
            ctx->frag_max = 0;
            ctx->frag_delay = 0;
        }

        ctx->enable_padding = s->enablePadding;
        ctx->pad_min = s->padMin;
        ctx->pad_max = s->padMax;
    }
}

// 在 ClientHello 中注入随机 Padding (抗指纹)
static char* inject_padding(const char* in, int in_len, int* out_len, int pad_min, int pad_max) {
    if (in_len < TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN + CLIENT_HELLO_FIXED_OFFSET) return NULL;
    unsigned char* data = (unsigned char*)in;
    
    if (data[0] != TLS_RECORD_TYPE_HANDSHAKE) return NULL; 
    if (data[5] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) return NULL;

    int offset = CLIENT_HELLO_FIXED_OFFSET; 
    if (in_len < offset + 1) return NULL;
    int sess_id_len = data[offset];
    offset += 1 + sess_id_len;
    
    if (in_len < offset + 2) return NULL;
    int cipher_len = (data[offset] << 8) | data[offset+1];
    offset += 2 + cipher_len;
    
    if (in_len < offset + 1) return NULL;
    int comp_len = data[offset];
    offset += 1 + comp_len;
    
    if (in_len < offset + 2) return NULL;
    int ext_len_offset = offset;
    int ext_total_len = (data[offset] << 8) | data[offset+1];
    offset += 2;
    
    if (offset + ext_total_len != in_len - TLS_HEADER_LEN) return NULL;

    int range = pad_max - pad_min;
    if (range < 0) range = 0;
    unsigned char rnd; 
    if (RAND_bytes(&rnd, 1) != 1) rnd = 0; 
    int pad_data_len = pad_min + (range > 0 ? (rnd % (range + 1)) : 0);
    if (pad_data_len <= 0) return NULL;

    int pad_ext_len = 4 + pad_data_len; 
    int new_total_len = in_len + pad_ext_len;
    char* new_buf = (char*)malloc(new_total_len);
    if (!new_buf) return NULL;

    memcpy(new_buf, in, in_len);
    
    unsigned char* p = (unsigned char*)new_buf + in_len;
    *p++ = 0x00; *p++ = 0x15; // Extension Type: Padding
    *p++ = (pad_data_len >> 8) & 0xFF;
    *p++ = pad_data_len & 0xFF;
    memset(p, 0, pad_data_len);

    unsigned char* ptr = (unsigned char*)new_buf;
    
    int old_rec_len = (ptr[3] << 8) | ptr[4];
    int new_rec_len = old_rec_len + pad_ext_len;
    ptr[3] = (new_rec_len >> 8) & 0xFF;
    ptr[4] = new_rec_len & 0xFF;
    
    int old_hs_len = (ptr[6] << 16) | (ptr[7] << 8) | ptr[8];
    int new_hs_len = old_hs_len + pad_ext_len;
    ptr[6] = (new_hs_len >> 16) & 0xFF;
    ptr[7] = (new_hs_len >> 8) & 0xFF;
    ptr[8] = new_hs_len & 0xFF;
    
    int new_ext_total_len = ext_total_len + pad_ext_len;
    ptr[ext_len_offset] = (new_ext_total_len >> 8) & 0xFF;
    ptr[ext_len_offset+1] = new_ext_total_len & 0xFF;

    *out_len = new_total_len;
    return new_buf;
}

static int frag_write(BIO *b, const char *in, int inl) {
    FragCtx *ctx = (FragCtx *)BIO_get_data(b);
    BIO *next = BIO_next(b);
    if (!ctx || !next) return 0;
    BIO_clear_retry_flags(b);

    const char* send_buf = in;
    int send_len = inl;
    int is_padding_task = 0; // 标记是否正在处理 Padding 任务

    // 1. 检查是否有未完成的 Padding 任务 (断点续传)
    if (ctx->pending_buf) {
        send_buf = ctx->pending_buf + ctx->pending_sent;
        send_len = ctx->pending_total_len - ctx->pending_sent;
        is_padding_task = 1;
    } 
    // 2. 如果是首包且需要注入 Padding (新任务)
    else if (inl > 0 && ctx->first_packet_sent == 0) {
        if (ctx->enable_padding && !g_enableECH) { 
            int new_len = 0;
            char* padded = inject_padding(in, inl, &new_len, ctx->pad_min, ctx->pad_max);
            if (padded) {
                // 保存到 Context，接管发送权
                ctx->pending_buf = padded;
                ctx->pending_total_len = new_len;
                ctx->pending_sent = 0;
                
                send_buf = ctx->pending_buf;
                send_len = ctx->pending_total_len;
                is_padding_task = 1;
            }
        }
        // 如果没有生成 padding，则继续普通发送，但在函数末尾会标记 first_packet_sent
    }

    // 3. 执行分片发送逻辑
    int total_sent_this_round = 0;
    
    if (ctx->frag_min > 0 && ctx->frag_max >= ctx->frag_min) {
        int bytes_processed = 0;
        int remaining = send_len;
        int frag_count = 0;
        
        while (remaining > 0) {
            // 限制单次调用的分片数量，防止长时间占用
            if (frag_count >= MAX_FRAG_COUNT) {
                // 对于非 Padding 模式，这里直接返回已发送量，OpenSSL 会稍后继续
                // 对于 Padding 模式，这也算作一次“中断”，需要保持 retry 状态
                break; 
            }

            int range = ctx->frag_max - ctx->frag_min; 
            if (range < 0) range = 0;
            unsigned char rnd_byte; 
            if (RAND_bytes(&rnd_byte, 1) != 1) rnd_byte = 0;
            int chunk_size = ctx->frag_min + (range > 0 ? (rnd_byte % (range + 1)) : 0);
            
            if (chunk_size < 1) chunk_size = 1;
            if (chunk_size > remaining) chunk_size = remaining;
            
            int ret = BIO_write(next, send_buf + bytes_processed, chunk_size);
            
            if (ret <= 0) { 
                // 遇到阻塞或错误
                if (BIO_should_retry(next)) {
                    BIO_copy_next_retry(b);
                }
                
                // 如果之前已经发了一些数据，则返回这些数据的长度
                if (bytes_processed > 0) {
                    total_sent_this_round = bytes_processed;
                    break;
                } else {
                    return ret; // 直接返回错误/retry
                }
            }
            
            bytes_processed += ret; 
            remaining -= ret; 
            frag_count++;
            
            // 延迟模拟
            if (remaining > 0 && ctx->frag_delay > 0) {
                unsigned char dly_rnd; 
                if (RAND_bytes(&dly_rnd, 1) != 1) dly_rnd = 0;
                int actual_delay = dly_rnd % (ctx->frag_delay + 1);
                if (actual_delay > 100) actual_delay = 100;
                if (actual_delay > 0) Sleep(actual_delay);
            }
        }
        total_sent_this_round = bytes_processed;
    } else {
        // 无分片，直接发送
        total_sent_this_round = BIO_write(next, send_buf, send_len);
    }
    
    // 4. 结果处理与状态更新
    
    if (is_padding_task) {
        if (total_sent_this_round > 0) {
            ctx->pending_sent += total_sent_this_round;
        }

        if (ctx->pending_sent >= ctx->pending_total_len) {
            // [Success] Padding 数据全部发送完毕
            free(ctx->pending_buf);
            ctx->pending_buf = NULL;
            ctx->pending_total_len = 0;
            ctx->pending_sent = 0;
            
            ctx->first_packet_sent = 1;
            
            // 重要：告诉 OpenSSL 我们完成了它请求的 inl 字节发送
            return inl; 
        } else {
            // [Pending] 还没发完，告诉 OpenSSL 需要重试 (WANT_WRITE)
            // 即使底层返回了部分写入，我们也返回 -1 + Retry，
            // 这样 OpenSSL 会再次调用我们，进入步骤 1 继续发送 pending_buf
            BIO_set_retry_write(b);
            return -1;
        }
    } else {
        // 普通模式
        if (total_sent_this_round > 0) {
            if (ctx->first_packet_sent == 0) ctx->first_packet_sent = 1;
        }
        
        BIO_copy_next_retry(b);
        return total_sent_this_round;
    }
}

static int frag_read(BIO *b, char *out, int outl) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    BIO_clear_retry_flags(b);
    int ret = BIO_read(next, out, outl);
    BIO_copy_next_retry(b);
    return ret;
}

static long frag_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO *next = BIO_next(b);
    if (!next) return 0;
    return BIO_ctrl(next, cmd, num, ptr);
}

// 初始化 BIO Method
void Crypto_InitBIOMethod(void) {
    if (method_frag) {
        BIO_meth_free(method_frag);
        method_frag = NULL;
    }
    
    method_frag = BIO_meth_new(BIO_TYPE_FILTER, "Fragmentation Filter");
    if (method_frag) {
        BIO_meth_set_write(method_frag, frag_write);
        BIO_meth_set_read(method_frag, frag_read);
        BIO_meth_set_ctrl(method_frag, frag_ctrl);
        BIO_meth_set_create(method_frag, frag_new);
        BIO_meth_set_destroy(method_frag, frag_free);
        log_msg("[Crypto] BIO Method initialized.");
    } else {
        log_msg("[Fatal] Failed to create BIO Method.");
    }
}
