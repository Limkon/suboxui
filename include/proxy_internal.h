/* include/proxy_internal.h */
#ifndef PROXY_INTERNAL_H
#define PROXY_INTERNAL_H

// [Critical Fix] 必须首先包含这些系统头文件，以确保 SOCKET, ssize_t, size_t 等类型已定义
// 否则编译器会因为类型未识别而跳过后续的函数声明
#include <winsock2.h>
#include <windows.h>
#include <sys/types.h> // 必须包含：用于定义 ssize_t (MinGW 环境)
#include <stdlib.h>    // 必须包含：用于定义 size_t
#include <stdint.h>    // 必须包含：用于定义 uint8_t, int32_t

// 引入项目类型定义
#include "proxy_types.h"

// ============================================================================
// 全局变量声明
// ============================================================================
extern volatile LONG g_active_connections;
extern volatile LONG64 g_total_allocated_mem; 

// ============================================================================
// proxy_utils.c - 基础工具函数
// ============================================================================
void* proxy_malloc(size_t size);
void proxy_free(void* p, size_t size);
void parse_uuid(const char* uuid_str, unsigned char* out);
void trojan_password_hash(const char* password, char* out_hex);
int recv_timeout(SOCKET s, char *buf, int len, int timeout_sec);
int read_header_robust(SOCKET s, char* buf, int max_len, int timeout_sec);
int send_all(SOCKET s, const char *buf, int len);
void base64_encode_key(const unsigned char* src, char* dst);

// ============================================================================
// crypto_ws.c - WebSocket 封装
// ============================================================================
int build_ws_frame(const char* data, int len, char* out_buf);
long long check_ws_frame(unsigned char* buf, int len, int* header_len, int* payload_len);
int ws_read_frame(TLSContext *tls, char *out_buf, int max_len);
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expect_len);

// ============================================================================
// proxy_h2.c - HTTP/2 回调函数
// ============================================================================
// [Fix] 这里的 ssize_t 需要 sys/types.h 支持
ssize_t h2_send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data);
int h2_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data);
int h2_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);
int h2_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data);
int h2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data);
ssize_t h2_data_provider_read(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data);

// ============================================================================
// proxy_steps.c - 核心握手流程
// ============================================================================
int session_init(ProxySession* s, ClientContext* ctx);
void session_free(ProxySession* s);
int step_handshake_browser(ProxySession* s);
int step_connect_upstream(ProxySession* s);
int step_handshake_ws(ProxySession* s);
int step_send_proxy_request(ProxySession* s);
int step_respond_to_browser(ProxySession* s);

// ============================================================================
// proxy_loop.c - 数据传输循环
// ============================================================================
void step_transfer_loop_h1(ProxySession* s);
void step_transfer_loop_h2(ProxySession* s);
void step_transfer_loop_udp_direct(ProxySession* s);

#endif // PROXY_INTERNAL_H
