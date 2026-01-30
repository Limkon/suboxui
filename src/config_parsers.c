/* src/config_parsers.c */
// [Refactor] 2026-01-29: 完整全功能版 - 修复缓冲区溢出
// [Scope] 移除 VMess，完整恢复 Socks5 / SS / VLESS / Trojan / Mandala
// [Security] 引入 SafeUrlDecode 替代不安全的 UrlDecode，增加边界检查

#include "config.h"
#include "utils.h"
#include "common.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// [Safety] 定义最大字段长度
#define MAX_URL_FIELD_LEN 2048
#define MAX_HOST_LEN 256

// --- 内部辅助函数 ---

// [New] 内部安全 URL 解码函数 (带边界检查)
// 替代原 utils.h 中的 UrlDecode，防止 UriParts 结构体溢出
static void SafeUrlDecode(char* dest, size_t dest_sz, const char* src) {
    if (!dest || dest_sz == 0) return;
    if (!src) { dest[0] = '\0'; return; }

    char* d = dest;
    const char* s = src;
    const char* d_end = dest + dest_sz - 1; // 预留 \0 空间

    while (*s && d < d_end) {
        if (*s == '+') {
            *d++ = ' ';
            s++;
        } else if (*s == '%' && s[1] && s[2] && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
            char hex[3] = { s[1], s[2], 0 };
            *d++ = (char)strtol(hex, NULL, 16);
            s += 3;
        } else {
            *d++ = *s++;
        }
    }
    *d = '\0';
}

// [Helper] 本地安全字符串复制
static void SafeStrCpy(char* dest, size_t size, const char* src) {
    if (!dest || size == 0) return;
    if (!src) { dest[0] = '\0'; return; }
    strncpy(dest, src, size - 1);
    dest[size - 1] = '\0';
}

// [Helper] Base64 URL-Safe 规范化 (替换 -_ 为 +/)
static void NormalizeBase64(char* str) {
    if (!str) return;
    int len = (int)strlen(str);
    for (int i = 0; i < len; i++) {
        if (str[i] == '-') str[i] = '+';
        else if (str[i] == '_') str[i] = '/';
    }
}

// [Helper] 创建标准节点对象 (初始化默认值)
static cJSON* CreateNodeObject(const char* remarks, const char* server, int port, const char* type) {
    cJSON* node = cJSON_CreateObject();
    if (!node) return NULL;
    
    cJSON_AddStringToObject(node, "tag", remarks ? remarks : "New Node");
    cJSON_AddStringToObject(node, "type", type ? type : "socks");
    cJSON_AddStringToObject(node, "server", server ? server : "");
    cJSON_AddNumberToObject(node, "server_port", port);
    
    // 初始化空字段
    cJSON_AddStringToObject(node, "uuid", "");
    cJSON_AddStringToObject(node, "password", "");
    cJSON_AddStringToObject(node, "username", "");
    cJSON_AddStringToObject(node, "security", "auto");
    cJSON_AddNumberToObject(node, "alterId", 0);
    
    cJSON* tls = cJSON_CreateObject();
    cJSON_AddStringToObject(tls, "server_name", "");
    cJSON_AddBoolToObject(tls, "allowInsecure", FALSE);
    cJSON_AddItemToObject(node, "tls", tls);
    
    cJSON* transport = cJSON_CreateObject();
    cJSON_AddStringToObject(transport, "type", "tcp");
    cJSON_AddStringToObject(transport, "path", "/");
    cJSON_AddStringToObject(transport, "host", "");
    cJSON_AddStringToObject(transport, "mode", ""); 
    cJSON_AddItemToObject(node, "transport", transport);

    return node;
}

// [Helper] 安全获取或创建 JSON 对象
static cJSON* GetOrCreateObj(cJSON* parent, const char* name) {
    if (!parent) return NULL;
    cJSON* item = cJSON_GetObjectItem(parent, name);
    if (!item) {
        item = cJSON_CreateObject();
        if (item) cJSON_AddItemToObject(parent, name, item);
    }
    return item;
}

// [Helper] 获取 Query 参数 (使用安全解码)
static char* GetParamValue(const char* params, const char* key) {
    if (!params || !key) return NULL;
    char search[128]; snprintf(search, sizeof(search), "%s=", key);
    const char* p = strstr(params, search);
    while (p) {
        if (p == params || *(p - 1) == '&') {
            p += strlen(search);
            const char* end = strchr(p, '&');
            int len = end ? (int)(end - p) : (int)strlen(p);
            if (len > 0) {
                // 分配内存时多留一个字节给 \0
                char* val = (char*)malloc(len + 1);
                if (val) {
                    strncpy(val, p, len); val[len] = 0;
                    // 使用 SafeUrlDecode 原地解码或新分配
                    // 由于解码后长度一定 <= 编码长度，可以原地解码或分配相同大小
                    char* decoded = (char*)malloc(len + 1);
                    if(decoded) { 
                        SafeUrlDecode(decoded, len + 1, val); 
                        free(val); 
                        return decoded; 
                    }
                    return val; // 如果解码分配失败，返回原始值 (Fallback)
                }
            }
            return NULL;
        }
        p = strstr(p + 1, search);
    }
    return NULL;
}

// ===========================================================================
// 通用 URI 解析工具 (核心部分)
// ===========================================================================

typedef struct {
    char user[128];
    char pass[128];
    char host[256];
    int port;
    char params[1024];
    char fragment[256];
} UriParts;

// [Fix] 增强版 URI 解析：支持 [IPv6]:Port 和 user:pass 格式
// [Security] 使用 SafeUrlDecode 防止缓冲区溢出
static BOOL ParseUri(const char* uri, UriParts* out) {
    if (!uri || !out) return FALSE;
    memset(out, 0, sizeof(UriParts));
    
    char temp[2048];
    SafeStrCpy(temp, sizeof(temp), uri);
    
    char* p = temp;
    
    // 1. Fragment (#)
    char* hash = strchr(p, '#');
    if (hash) { 
        *hash = 0; 
        SafeUrlDecode(out->fragment, sizeof(out->fragment), hash + 1); 
    }
    
    // 2. Params (?)
    char* qmark = strchr(p, '?');
    if (qmark) { 
        *qmark = 0; 
        SafeStrCpy(out->params, sizeof(out->params), qmark + 1); 
    }
    
    // 3. UserInfo (@) - 从后向前查找，因为密码可能含转义字符
    char* at = strrchr(p, '@'); 
    if (at) {
        *at = 0;
        char* colon = strchr(p, ':');
        if (colon) { 
            *colon = 0; 
            SafeUrlDecode(out->user, sizeof(out->user), p); 
            SafeUrlDecode(out->pass, sizeof(out->pass), colon + 1); 
        } else { 
            SafeUrlDecode(out->user, sizeof(out->user), p); 
        }
        p = at + 1;
    }
    
    // 4. Host & Port (IPv6 Safe)
    if (*p == '[') {
        char* closeBr = strchr(p, ']');
        if (closeBr) {
            *closeBr = 0; 
            SafeStrCpy(out->host, sizeof(out->host), p + 1);
            p = closeBr + 1;
            if (*p == ':') out->port = atoi(p + 1); else out->port = 443; 
        } else return FALSE;
    } else {
        char* colon = strrchr(p, ':');
        if (colon) { 
            *colon = 0; 
            SafeStrCpy(out->host, sizeof(out->host), p); 
            out->port = atoi(colon + 1); 
        } else { 
            SafeStrCpy(out->host, sizeof(out->host), p); 
            out->port = 443; 
        }
    }
    return TRUE;
}

// ===========================================================================
// 协议解析器
// ===========================================================================

// 1. Socks5 解析 (含 Base64 User:Pass 支持)
cJSON* ParseSocks(const char* link) {
    if (!link || strncmp(link, "socks://", 8) != 0) return NULL;
    const char* body = link + 8;
    
    UriParts parts;
    if (!ParseUri(body, &parts)) return NULL;
    
    // 特殊逻辑：某些客户端会把 base64(user:pass) 放在 user 字段
    if (strlen(parts.pass) == 0 && strlen(parts.user) > 0) {
        size_t dLen = 0;
        char b64Temp[256];
        SafeStrCpy(b64Temp, sizeof(b64Temp), parts.user);
        NormalizeBase64(b64Temp);
        
        unsigned char* decoded = Base64Decode(b64Temp, &dLen);
        if (decoded) {
            char* decStr = (char*)malloc(dLen + 1);
            if (decStr) {
                memcpy(decStr, decoded, dLen); decStr[dLen] = 0;
                char* colon = strchr(decStr, ':');
                if (colon) {
                    *colon = 0;
                    SafeStrCpy(parts.user, sizeof(parts.user), decStr);
                    SafeStrCpy(parts.pass, sizeof(parts.pass), colon + 1);
                }
                free(decStr);
            }
            free(decoded);
        }
    }

    cJSON* node = CreateNodeObject(
        strlen(parts.fragment) > 0 ? parts.fragment : "Socks5 Node",
        parts.host, parts.port, "socks"
    );
    if (!node) return NULL;

    cJSON_ReplaceItemInObject(node, "username", cJSON_CreateString(parts.user));
    cJSON_ReplaceItemInObject(node, "password", cJSON_CreateString(parts.pass));
    
    return node;
}

// 2. Shadowsocks 解析器
static void ParseSSPlugin(cJSON* outbound, const char* pluginParam) {
    if (!pluginParam || !outbound) return;
    char* pluginCopy = _strdup(pluginParam);
    if (!pluginCopy) return;

    char host[256] = {0}, path[256] = {0}, sni[256] = {0}, mode[64] = {0};
    BOOL isTls = FALSE;
    BOOL isV2ray = (strstr(pluginCopy, "v2ray-plugin") != NULL);
    
    char* start = pluginCopy;
    char* end = NULL;
    while (start && *start) {
        end = strchr(start, ';');
        if (end) *end = '\0'; 
        
        if (strncmp(start, "host=", 5) == 0) SafeStrCpy(host, sizeof(host), start+5);
        else if (strncmp(start, "obfs-host=", 10) == 0) SafeStrCpy(host, sizeof(host), start+10);
        else if (strncmp(start, "path=", 5) == 0) {
            char* temp = (char*)malloc(strlen(start+5)+1);
            if(temp) { 
                SafeUrlDecode(temp, strlen(start+5)+1, start+5); 
                SafeStrCpy(path, sizeof(path), temp); 
                free(temp); 
            }
        }
        else if (strncmp(start, "sni=", 4) == 0) SafeStrCpy(sni, sizeof(sni), start+4);
        else if (strncmp(start, "mode=", 5) == 0) SafeStrCpy(mode, sizeof(mode), start+5);
        else if (strcmp(start, "tls") == 0) isTls = TRUE;
        else if (strncmp(start, "obfs=", 5) == 0 && strcmp(start+5, "tls") == 0) isTls = TRUE;

        if (end) start = end + 1; else start = NULL;
    }

    if (isTls) {
        cJSON* tlsObj = GetOrCreateObj(outbound, "tls");
        cJSON_AddBoolToObject(tlsObj, "enabled", cJSON_True);
        if (strlen(sni) > 0) cJSON_AddStringToObject(tlsObj, "server_name", sni);
        else if (strlen(host) > 0) cJSON_AddStringToObject(tlsObj, "server_name", host);
    }

    if (isV2ray && strcmp(mode, "quic") != 0) {
        cJSON* trans = GetOrCreateObj(outbound, "transport");
        cJSON_AddStringToObject(trans, "type", "ws");
        if (strlen(path) > 0) cJSON_AddStringToObject(trans, "path", path);
        if (strlen(host) > 0) {
            cJSON* headers = GetOrCreateObj(trans, "headers");
            cJSON_AddStringToObject(headers, "Host", host);
        }
    }
    free(pluginCopy);
}

cJSON* ParseShadowsocks(const char* link) {
    if (!link || strncmp(link, "ss://", 5) != 0) return NULL;
    const char* body = link + 5;
    
    UriParts parts;
    if (!ParseUri(body, &parts)) return NULL;
    
    char method[64] = "aes-256-gcm";
    char password[128] = "";
    
    // 兼容 SIP002 (Base64 User) 和 Legacy (Base64 User:Pass)
    char* colon = strchr(parts.user, ':');
    if (!colon) {
        char b64Temp[256];
        SafeStrCpy(b64Temp, sizeof(b64Temp), parts.user);
        NormalizeBase64(b64Temp);
        size_t dLen;
        unsigned char* decoded = Base64Decode(b64Temp, &dLen);
        if (decoded) {
            char* decStr = (char*)malloc(dLen+1);
            if (decStr) {
                memcpy(decStr, decoded, dLen); decStr[dLen]=0;
                char* c2 = strchr(decStr, ':');
                if (c2) { 
                    *c2 = 0; 
                    SafeStrCpy(method, sizeof(method), decStr); 
                    SafeStrCpy(password, sizeof(password), c2+1); 
                }
                free(decStr);
            }
            free(decoded);
        }
    } else {
        SafeStrCpy(method, sizeof(method), parts.user);
        SafeStrCpy(password, sizeof(password), parts.pass);
    }
    
    cJSON* node = CreateNodeObject(
        strlen(parts.fragment)>0 ? parts.fragment : "SS Node",
        parts.host, parts.port, "shadowsocks"
    );
    if (!node) return NULL;
    
    cJSON_ReplaceItemInObject(node, "method", cJSON_CreateString(method));
    cJSON_ReplaceItemInObject(node, "password", cJSON_CreateString(password));
    
    char* plugin = GetParamValue(parts.params, "plugin");
    if (plugin) {
        char* decodedPlugin = (char*)malloc(strlen(plugin)+1);
        if(decodedPlugin) {
            SafeUrlDecode(decodedPlugin, strlen(plugin)+1, plugin);
            ParseSSPlugin(node, decodedPlugin);
            free(decodedPlugin);
        }
        free(plugin);
    }
    return node;
}

// 3. VLESS / Trojan 解析
static cJSON* InternalParseVlessTrojan(const char* link, const char* proto) {
    const char* pBody = strstr(link, "://");
    if (!pBody) return NULL;
    pBody += 3;
    
    UriParts parts;
    if (!ParseUri(pBody, &parts)) return NULL;
    
    cJSON* node = CreateNodeObject(
        strlen(parts.fragment) > 0 ? parts.fragment : "Imported Node",
        parts.host, parts.port, proto
    );
    if (!node) return NULL;

    // VLESS 用 uuid, Trojan 用 password (统一存到 uuid 和 password 字段)
    cJSON_ReplaceItemInObject(node, "uuid", cJSON_CreateString(parts.user));
    cJSON_ReplaceItemInObject(node, "password", cJSON_CreateString(parts.user)); 
    
    char* type = GetParamValue(parts.params, "type");
    char* security = GetParamValue(parts.params, "security");
    char* sni = GetParamValue(parts.params, "sni");
    char* path = GetParamValue(parts.params, "path");
    char* alpn = GetParamValue(parts.params, "alpn");
    char* mode = GetParamValue(parts.params, "mode"); 
    char* serviceName = GetParamValue(parts.params, "serviceName");
    
    cJSON* jTrans = cJSON_GetObjectItem(node, "transport");
    cJSON* jTls = cJSON_GetObjectItem(node, "tls");
    
    if (type) { cJSON_ReplaceItemInObject(jTrans, "type", cJSON_CreateString(type)); free(type); }
    if (path) { cJSON_ReplaceItemInObject(jTrans, "path", cJSON_CreateString(path)); free(path); }
    if (mode) { cJSON_AddStringToObject(jTrans, "mode", mode); free(mode); }
    if (serviceName) { cJSON_AddStringToObject(jTrans, "service_name", serviceName); free(serviceName); }
    
    if (sni) { cJSON_ReplaceItemInObject(jTls, "server_name", cJSON_CreateString(sni)); free(sni); } 
    else { cJSON_ReplaceItemInObject(jTls, "server_name", cJSON_CreateString(parts.host)); }
    
    if (alpn) {
        cJSON* alpnArr = cJSON_CreateArray();
        cJSON_AddItemToArray(alpnArr, cJSON_CreateString(alpn));
        cJSON_AddItemToObject(jTls, "alpn", alpnArr);
        free(alpn);
    }
    
    if (security) {
        if (strcmp(security, "tls") == 0 || strcmp(security, "xtls") == 0 || strcmp(security, "reality") == 0) {
             cJSON_ReplaceItemInObject(jTls, "allowInsecure", cJSON_CreateBool(FALSE));
        }
        free(security);
    }
    
    return node;
}

cJSON* ParseVlessOrTrojan(const char* link) {
    if (!link) return NULL;
    if (strncmp(link, "vless://", 8) == 0) return InternalParseVlessTrojan(link, "vless");
    if (strncmp(link, "trojan://", 9) == 0) return InternalParseVlessTrojan(link, "trojan");
    return NULL;
}

// 4. Mandala 特定解析 (复用 Vless/Trojan 逻辑)
cJSON* ParseMandala(const char* link) {
    if (strncmp(link, "mandala://", 10) == 0) return InternalParseVlessTrojan(link, "mandala");
    return NULL;
}

// 5. VMess 存根 (Stub)
cJSON* ParseVmess(const char* link) {
    (void)link; 
    return NULL; 
}
