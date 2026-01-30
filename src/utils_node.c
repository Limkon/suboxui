/* src/utils_node.c */
#include "utils.h"
#include "config.h" // for CONFIG_FILE
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

// --------------------------------------------------------------------------
// TCP 测速与节点信息获取
// --------------------------------------------------------------------------

int TcpPing(const char* address, int port, int timeout_ms) {
    SOCKET sockfd = INVALID_SOCKET;
    int ret = -1;
    DWORD start_time, end_time;

    struct addrinfo hints, *res = NULL, *ptr = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // 允许 IPv4 或 IPv6
    hints.ai_socktype = SOCK_STREAM;
    
    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%d", port);

    // [Warn] getaddrinfo 可能在 DNS 解析时阻塞，请勿在 UI 线程直接调用
    if (getaddrinfo(address, portStr, &hints, &res) != 0) {
        return -1;
    }

    // 遍历所有可能的地址
    for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == INVALID_SOCKET) continue;

        // 设置非阻塞
        unsigned long on = 1;
        ioctlsocket(sockfd, FIONBIO, &on);

        start_time = GetTickCount();
        int conn_res = connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen);

        if (conn_res == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(sockfd);
                sockfd = INVALID_SOCKET;
                continue;
            }
        }

        fd_set write_fds, except_fds;
        FD_ZERO(&write_fds); FD_ZERO(&except_fds);
        FD_SET(sockfd, &write_fds); FD_SET(sockfd, &except_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel_ret = select(0, NULL, &write_fds, &except_fds, &tv);

        if (sel_ret > 0) {
            if (FD_ISSET(sockfd, &except_fds)) {
                // Connect failed for this address
            } else if (FD_ISSET(sockfd, &write_fds)) {
                int error = 0; int len = sizeof(error);
                if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == 0) {
                    if (error == 0) {
                        end_time = GetTickCount();
                        ret = (int)(end_time - start_time);
                        if (ret == 0) ret = 1; 
                        closesocket(sockfd);
                        break; // Success!
                    }
                }
            }
        }
        closesocket(sockfd);
        sockfd = INVALID_SOCKET;
    }

    freeaddrinfo(res);
    return ret;
}

void GetNodeDetailInfo(const wchar_t* nodeTag, char* outType, int typeLen, char* outAddr, int addrLen) {
    if (!nodeTag) return;
    
    char tagUtf8[512];
    WideCharToMultiByte(CP_UTF8, 0, nodeTag, -1, tagUtf8, sizeof(tagUtf8), NULL, NULL);

    char* buffer = NULL; 
    long size = 0;
    
    // 使用 utils_base.c 中的 ReadFileToBuffer
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;

    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) return;

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* node = NULL;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) {
            cJSON* type = cJSON_GetObjectItem(node, "type");
            cJSON* server = cJSON_GetObjectItem(node, "server");
            cJSON* port = cJSON_GetObjectItem(node, "server_port");
            
            if (outType) {
                const char* typeStr = (type && type->valuestring) ? type->valuestring : "unknown";
                strncpy(outType, typeStr, typeLen - 1);
                outType[typeLen - 1] = '\0';
            }
            
            if (outAddr) {
                const char* host = (server && server->valuestring) ? server->valuestring : "?";
                int p = 0;
                if (port) {
                    if (cJSON_IsNumber(port)) p = port->valueint;
                    else if (cJSON_IsString(port)) p = atoi(port->valuestring);
                }
                snprintf(outAddr, addrLen, "%s:%d", host, p);
            }
            break;
        }
    }
    cJSON_Delete(root);
}

void GetNodeAddressInfo(const wchar_t* nodeTag, char* outAddr, int addrLen, int* outPort) {
    if (!nodeTag || !outAddr || !outPort) return;

    char tagUtf8[512];
    WideCharToMultiByte(CP_UTF8, 0, nodeTag, -1, tagUtf8, sizeof(tagUtf8), NULL, NULL);

    char* buffer = NULL; 
    long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return;

    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) return;

    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* node = NULL;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) {
            cJSON* server = cJSON_GetObjectItem(node, "server");
            cJSON* port = cJSON_GetObjectItem(node, "server_port");
            
            if (server && server->valuestring) {
                strncpy(outAddr, server->valuestring, addrLen - 1);
                outAddr[addrLen - 1] = '\0';
            }
            
            if (port) {
                if (cJSON_IsNumber(port)) *outPort = port->valueint;
                else if (cJSON_IsString(port)) *outPort = atoi(port->valuestring);
                else *outPort = 0;
            }
            break;
        }
    }
    cJSON_Delete(root);

}

// 获取节点历史测速结果 (返回 -999 表示无记录)
int GetNodeLatency(const wchar_t* nodeTag) {
    if (!nodeTag) return -999;
    
    char tagUtf8[512];
    WideCharToMultiByte(CP_UTF8, 0, nodeTag, -1, tagUtf8, sizeof(tagUtf8), NULL, NULL);

    char* buffer = NULL; 
    long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) return -999;

    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) return -999;

    int latency = -999;
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* node = NULL;
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) {
            cJSON* l = cJSON_GetObjectItem(node, "latency");
            if (l) {
                latency = l->valueint;
            }
            break;
        }
    }
    cJSON_Delete(root);
    return latency;
}
