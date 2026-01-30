/* src/crypto_ws.c */
// [Refactor] 2026-01-29: 重构 WebSocket 帧封装，强制实施 RFC 6455 掩码标准
// [Fix] 2026-01-29: 修复大负载下的长度编码逻辑错误 (64-bit length)
// [Security] 2026-01-29: 使用 RAND_bytes 替代 rand() 生成掩码，增强抗识别能力
// [Refactor] 2026-01-29: 新增 ws_read_frame 支持读取完整帧，修复 SOCKS5 握手过严导致的断连
// [Fix] 2026-01-29: 修正 Strict Aliasing 潜在风险

#include "crypto.h"
#include "common.h"
#include "utils.h"
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h> 

// RFC 6455 Frame Header
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+

// [Refactor] 构建 WebSocket 帧 (客户端模式：必须 Mask)
// 返回: 帧总长度 (Header + Mask + Payload)
int build_ws_frame(const char* data, int len, char* out_buf) {
    if (!data || !out_buf || len < 0) return -1;

    int header_len = 0;
    
    // FIN=1, RSV=0, Opcode=1 (Text) or 2 (Binary)
    // 这里默认使用 Binary (0x82) 用于代理传输
    out_buf[0] = (char)0x82;

    // Mask=1 (Client MUST mask)
    if (len < 126) {
        out_buf[1] = (char)(0x80 | len);
        header_len = 2;
    } else if (len <= 65535) {
        out_buf[1] = (char)(0x80 | 126);
        out_buf[2] = (len >> 8) & 0xFF;
        out_buf[3] = len & 0xFF;
        header_len = 4;
    } else {
        out_buf[1] = (char)(0x80 | 127);
        // 64-bit length (Network Byte Order)
        // 假设 size_t 不超过 64位且这里只处理 int 范围，高位补0
        out_buf[2] = 0; out_buf[3] = 0; out_buf[4] = 0; out_buf[5] = 0;
        out_buf[6] = (len >> 24) & 0xFF;
        out_buf[7] = (len >> 16) & 0xFF;
        out_buf[8] = (len >> 8) & 0xFF;
        out_buf[9] = len & 0xFF;
        header_len = 10;
    }

    // Generate Masking Key
    unsigned char mask[4];
    if (RAND_bytes(mask, 4) != 1) {
        // Fallback if RAND fails (unlikely)
        int r = rand();
        memcpy(mask, &r, 4);
    }

    memcpy(out_buf + header_len, mask, 4);
    header_len += 4;

    // Payload Masking (XOR)
    const unsigned char* src = (const unsigned char*)data;
    unsigned char* dst = (unsigned char*)(out_buf + header_len);
    
    for (int i = 0; i < len; i++) {
        dst[i] = src[i] ^ mask[i % 4];
    }

    return header_len + len;
}

// [Helper] 检查接收到的 WS 帧 (用于 Loop 中被动接收)
// 返回: 帧总长度 (Header + Payload)，0表示不完整，-1表示错误
long long check_ws_frame(unsigned char* buf, int len, int* header_len, int* payload_len) {
    if (len < 2) return 0;

    int h_len = 2;
    // buf[0]: FIN, Opcode
    // buf[1]: Mask(1), PayloadLen(7)
    
    int masked = (buf[1] & 0x80) >> 7;
    long long p_len = buf[1] & 0x7F;

    if (p_len == 126) {
        if (len < 4) return 0;
        p_len = (buf[2] << 8) | buf[3];
        h_len = 4;
    } else if (p_len == 127) {
        if (len < 10) return 0;
        // 64-bit length
        unsigned long long high = ((unsigned long long)buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
        unsigned long long low = ((unsigned long long)buf[6] << 24) | (buf[7] << 16) | (buf[8] << 8) | buf[9];
        
        // 检查最高位，WebSocket 协议规定最高位必须为0
        if (high & 0x80000000) return -1;

        p_len = (high << 32) | low;
        h_len = 10;
    }

    if (masked) {
        h_len += 4; // Masking Key
    }

    if (p_len > MAX_WS_FRAME_SIZE) {
        return -1;
    }

    // 检查是否已接收完整
    if (len < h_len + p_len) {
        return 0; // Incomplete
    }

    *header_len = h_len;
    *payload_len = (int)p_len;
    
    return h_len + p_len;
}

// [New] 读取并解包一个完整的 WebSocket 帧
// 功能：自动处理控制帧(Ping/Pong)，返回下一个数据帧的 Payload 长度
// 返回: 实际读取的 payload 长度，-1 表示错误/关闭
int ws_read_frame(TLSContext *tls, char *out_buf, int max_len) {
    if (!tls || !out_buf || max_len <= 0) return -1;

    while (1) {
        unsigned char header[14];
        // 1. 读取基础头部 (2 bytes)
        if (tls_read_exact(tls, (char*)header, 2) != 1) return -1;

        unsigned char opcode = header[0] & 0x0F;
        unsigned char masked = (header[1] & 0x80) >> 7;
        uint64_t payload_len = header[1] & 0x7F;

        // 2. 解析扩展长度
        if (payload_len == 126) {
            if (tls_read_exact(tls, (char*)header + 2, 2) != 1) return -1;
            payload_len = (header[2] << 8) | header[3];
        } else if (payload_len == 127) {
            if (tls_read_exact(tls, (char*)header + 2, 8) != 1) return -1;
            // 简单处理 64 位长度，忽略极高位检查，假设在 int 范围内
            payload_len = 0;
            for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | header[2 + i];
        }

        // 3. 读取掩码
        unsigned char mask_key[4] = {0};
        if (masked) {
            if (tls_read_exact(tls, (char*)mask_key, 4) != 1) return -1;
        }

        // 4. 处理控制帧 (Ping/Pong/Close)
        if (opcode >= 0x8) {
            if (opcode == 0x8) return -1; // Close
            
            // Ping/Pong: 读掉并丢弃
            if (payload_len > 125) return -1; // Protocol Error
            char junk;
            for (uint64_t i = 0; i < payload_len; i++) {
                if (tls_read_exact(tls, &junk, 1) != 1) return -1;
            }
            continue; // 忽略控制帧，继续读取下一帧数据
        }

        // 5. 数据帧处理
        if (payload_len > (uint64_t)max_len) return -1; // 缓冲区不足

        if (payload_len > 0) {
            if (tls_read_exact(tls, out_buf, (int)payload_len) != 1) return -1;
            
            if (masked) {
                for (uint64_t i = 0; i < payload_len; i++) {
                    out_buf[i] ^= mask_key[i % 4];
                }
            }
        }
        
        return (int)payload_len;
    }
}

// [Refactor] 兼容旧接口：保留该函数用于定长读取场景
// 注意：SOCKS5 握手现在应使用 ws_read_frame，此函数仅作为 fallback 或用于严格长度校验场景
int ws_read_payload_exact(TLSContext *tls, char *out_buf, int expect_len) {
    if (!tls || !out_buf || expect_len <= 0) return 0;
    
    // 这里保留旧的严格实现，因为有些协议确实需要严格匹配长度
    int total_collected = 0;
    while (total_collected < expect_len) {
        unsigned char header[14]; 
        
        if (tls_read_exact(tls, (char*)header, 2) != 1) return 0;

        unsigned char opcode = header[0] & 0x0F;
        unsigned char masked = (header[1] & 0x80) >> 7;
        uint64_t payload_len = header[1] & 0x7F;

        if (payload_len == 126) {
            if (tls_read_exact(tls, (char*)header + 2, 2) != 1) return 0;
            payload_len = (header[2] << 8) | header[3];
        } else if (payload_len == 127) {
            if (tls_read_exact(tls, (char*)header + 2, 8) != 1) return 0;
            payload_len = 0;
            for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | header[2 + i];
        }

        unsigned char mask_key[4] = {0};
        if (masked) {
            if (tls_read_exact(tls, (char*)mask_key, 4) != 1) return 0;
        }

        if (opcode >= 0x8) {
            if (opcode == 0x8) return 0; 
            if (payload_len > 125) return 0; 
            char junk;
            for (uint64_t i = 0; i < payload_len; i++) {
                if (tls_read_exact(tls, &junk, 1) != 1) return 0;
            }
            continue; 
        }

        // 严格检查：如果单帧数据导致总量超过预期，视为协议错误
        if (total_collected + payload_len > (uint64_t)expect_len) {
            return 0; 
        }

        if (payload_len > 0) {
            if (tls_read_exact(tls, out_buf + total_collected, (int)payload_len) != 1) return 0;
            if (masked) {
                for (uint64_t i = 0; i < payload_len; i++) {
                    out_buf[total_collected + i] ^= mask_key[i % 4];
                }
            }
            total_collected += (int)payload_len;
        }
    }
    return 1;
}
