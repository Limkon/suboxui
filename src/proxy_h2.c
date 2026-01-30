/* src/proxy_h2.c */
// [Refactor] 2026-01-29: 优化 HTTP/2 发送逻辑，消除界面卡顿
// [Fix] 2026-01-29: 将 send_blocking_retry 超时从 2s 降至 1ms 轮询，支持快速退出
// [Fix] 2026-01-29: 增强 h2_send_callback 的非阻塞错误码映射

#include "proxy_internal.h"
#include "utils.h" 
#include <winsock2.h>

extern volatile BOOL g_proxyRunning; 

// [Config] 微秒级轮询间隔，与 crypto_tls.c 保持一致
#define H2_SELECT_WAIT_MS 1 

// [Helper] 针对非阻塞 Socket 的健壮发送函数
// [Fix] 使用短超时循环，确保能及时响应 g_proxyRunning 退出信号
static int send_blocking_retry(SOCKET sock, const char* data, int len) {
    int sent = 0;
    while (sent < len && g_proxyRunning) {
        int n = send(sock, data + sent, len - sent, 0);
        if (n > 0) {
            sent += n;
        } else if (n == 0) {
            return -1; // Connection closed
        } else {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                fd_set wfd;
                FD_ZERO(&wfd);
                FD_SET(sock, &wfd);
                
                // [Fix] 1ms 超时，快速循环以检查 g_proxyRunning
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = H2_SELECT_WAIT_MS * 1000; 
                
                int res = select(0, NULL, &wfd, NULL, &tv);
                if (res < 0) {
                    log_msg("[Conn-%d] [H2] Select error: %d", sock, WSAGetLastError());
                    return -1;
                }
                // res == 0 (Timeout) -> Continue loop to check g_proxyRunning
                continue;
            } else if (err == WSAEINTR) {
                continue;
            } else {
                log_msg("[Conn-%d] [H2] Send error: %d", sock, err);
                return -1;
            }
        }
    }
    return (g_proxyRunning ? sent : -1);
}

// --- NGHTTP2 Callbacks 实现 ---

// [Crucial Fix] 正确映射 TLS 非阻塞错误码到 NGHTTP2
ssize_t h2_send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    ProxySession *s = (ProxySession*)user_data;
    if (!g_proxyRunning) return NGHTTP2_ERR_CALLBACK_FAILURE; 
    
    // tls_write 内部已处理了部分重试，但如果底层 SSLbuffer 满，仍可能返回 -1
    int ret = tls_write(&s->tls, (const char*)data, (int)length);
    
    if (ret < 0) {
        // 检查是否为临时性阻塞
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        // 严重错误
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return (ssize_t)ret;
}

int h2_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data) {
    ProxySession *s = (ProxySession*)user_data;
    
    // 仅处理属于当前流的 Headers
    if (frame->hd.type == NGHTTP2_HEADERS && frame->hd.stream_id == s->h2_stream_id) {
        // 提取 :status 伪头
        if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
            char status_buf[16];
            size_t copy_len = valuelen < 15 ? valuelen : 15;
            memcpy(status_buf, value, copy_len);
            status_buf[copy_len] = 0;
            s->h2_status_code = atoi(status_buf);
            log_msg("[Conn-%d] [H2] Handshake Status: %d", s->clientSock, s->h2_status_code);
        }
    }
    return 0;
}

int h2_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    ProxySession *s = (ProxySession*)user_data;
    
    // 监听 HEADERS 帧结束，判断握手是否成功
    if (frame->hd.type == NGHTTP2_HEADERS && frame->hd.stream_id == s->h2_stream_id) {
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE || frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
            if (s->h2_status_code == 200) {
                s->h2_handshake_done = 1;
            } else {
                s->h2_handshake_done = -1; // 握手失败
                log_msg("[Conn-%d] [H2] Stream Error: Server returned status %d", s->clientSock, s->h2_status_code);
            }
        }
    }
    return 0;
}

int h2_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
    ProxySession *s = (ProxySession*)user_data;
    
    // 收到上游数据 -> 转发给浏览器
    if (stream_id == s->h2_stream_id && len > 0) {
        if (send_blocking_retry(s->clientSock, (const char*)data, (int)len) < 0) {
            // 发送失败通常意味着浏览器断开了连接
            // log_msg("[Conn-%d] [H2] Failed to forward data to browser", s->clientSock);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}

int h2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    ProxySession *s = (ProxySession*)user_data;
    if (stream_id == s->h2_stream_id) {
        s->h2_handshake_done = -1; // 标记流结束，通知主循环退出
    }
    return 0;
}

ssize_t h2_data_provider_read(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    ProxySession *s = (ProxySession*)user_data;
    
    // 将浏览器发来的数据 (已存入 h2_browser_buf) 提供给 nghttp2 发送
    if (s->h2_browser_len > 0) {
        size_t copy_len = (size_t)s->h2_browser_len;
        if (copy_len > length) copy_len = length;
        
        memcpy(buf, s->h2_browser_buf, copy_len);
        
        // 移动剩余数据 (如果有)
        if (copy_len < (size_t)s->h2_browser_len) {
            memmove(s->h2_browser_buf, s->h2_browser_buf + copy_len, s->h2_browser_len - copy_len);
            s->h2_browser_len -= copy_len;
        } else {
            s->h2_browser_len = 0;
        }
        
        // 注意：不设置 NGHTTP2_DATA_FLAG_EOF，因为这是一个长连接隧道
        return (ssize_t)copy_len;
    }
    
    // 如果没有数据，返回 DEFERRED，暂停 DATA 帧发送
    // 当 proxy_loop.c 收到新数据时，会调用 nghttp2_session_resume_data 唤醒
    return NGHTTP2_ERR_DEFERRED;
}
