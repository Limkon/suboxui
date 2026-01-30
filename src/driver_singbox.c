#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "driver_singbox.h"
#include "config.h"  // 假设 node_t 和 program_settings_t 在此处定义
#include "utils.h"   // 假设包含常规工具函数

static PROCESS_INFORMATION g_pi = { 0 };
static int g_is_running = 0;

// 辅助函数：构建 Log 配置
static cJSON* build_log_config(void) {
    cJSON *log = cJSON_CreateObject();
    cJSON_AddStringToObject(log, "level", "info");
    cJSON_AddStringToObject(log, "output", "singbox.log");
    cJSON_AddBoolToObject(log, "timestamp", 1);
    return log;
}

// 辅助函数：构建 DNS 配置 (基础)
static cJSON* build_dns_config(void) {
    cJSON *dns = cJSON_CreateObject();
    cJSON *servers = cJSON_CreateArray();
    
    // 添加默认 DNS 服务器
    cJSON *s1 = cJSON_CreateObject();
    cJSON_AddStringToObject(s1, "address", "8.8.8.8");
    cJSON_AddStringToObject(s1, "tag", "google-dns");
    cJSON_AddItemToArray(servers, s1);

    cJSON_AddItemToObject(dns, "servers", servers);
    return dns;
}

// 辅助函数：构建 Inbounds (入站)
static cJSON* build_inbounds(const program_settings_t *settings) {
    cJSON *inbounds = cJSON_CreateArray();
    
    // Mixed 入站 (SOCKS5 + HTTP)
    cJSON *mixed = cJSON_CreateObject();
    cJSON_AddStringToObject(mixed, "type", "mixed");
    cJSON_AddStringToObject(mixed, "tag", "mixed-in");
    
    // 如果允许局域网连接，则监听 0.0.0.0，否则监听 127.0.0.1
    cJSON_AddStringToObject(mixed, "listen", settings->allow_lan ? "0.0.0.0" : "127.0.0.1");
    cJSON_AddNumberToObject(mixed, "listen_port", settings->local_port);
    
    // 开启 set_system_proxy 时通常不需要 sniff，但为了更好兼容性可以开启
    cJSON_AddBoolToObject(mixed, "sniff", 1);
    
    cJSON_AddItemToArray(inbounds, mixed);
    return inbounds;
}

// 辅助函数：根据 node_t 构建 Outbound (出站)
static cJSON* build_outbound_node(const node_t *node) {
    cJSON *out = cJSON_CreateObject();
    
    cJSON_AddStringToObject(out, "tag", "proxy");
    
    // === 基础字段映射 ===
    // 注意：请根据实际 node_t 结构体成员名称调整以下字段
    cJSON_AddStringToObject(out, "server", node->address);
    cJSON_AddNumberToObject(out, "server_port", node->port);
    
    // === 协议适配 ===
    // 假设 node->type 枚举值: 1=VMess, 2=VLESS, 3=Shadowsocks, 4=Trojan
    // 注意：这里的判断逻辑需根据 MandaleECH 实际定义的协议常量进行调整
    
    if (node->type == 1) { // VMess
        cJSON_AddStringToObject(out, "type", "vmess");
        cJSON_AddStringToObject(out, "uuid", node->uuid);
        cJSON_AddStringToObject(out, "security", "auto"); 
        cJSON_AddNumberToObject(out, "alter_id", 0);
        
        // 传输层配置
        if (node->net_type == 1) { // 假设 1=WebSocket
            cJSON *transport = cJSON_CreateObject();
            cJSON_AddStringToObject(transport, "type", "ws");
            cJSON_AddStringToObject(transport, "path", node->path);
            if (strlen(node->host) > 0) {
                 cJSON *headers = cJSON_CreateObject();
                 cJSON_AddStringToObject(headers, "Host", node->host);
                 cJSON_AddItemToObject(transport, "headers", headers);
            }
            cJSON_AddItemToObject(out, "transport", transport);
        }
    } 
    else if (node->type == 2) { // VLESS
        cJSON_AddStringToObject(out, "type", "vless");
        cJSON_AddStringToObject(out, "uuid", node->uuid);
        // VLESS Flow (如有)
        if (node->flow && strlen(node->flow) > 0) {
             cJSON_AddStringToObject(out, "flow", node->flow);
        }
    }
    else if (node->type == 3) { // Shadowsocks
        cJSON_AddStringToObject(out, "type", "shadowsocks");
        cJSON_AddStringToObject(out, "method", node->security); // 加密方式 e.g. aes-256-gcm
        cJSON_AddStringToObject(out, "password", node->uuid);   // 复用 uuid 字段存密码
    }
    else if (node->type == 4) { // Trojan
        cJSON_AddStringToObject(out, "type", "trojan");
        cJSON_AddStringToObject(out, "password", node->uuid);
    }
    else {
        // 未知协议默认 Direct，防止配置错误导致启动失败
        cJSON_AddStringToObject(out, "type", "direct");
    }

    // === TLS 配置 (通用) ===
    // 假设 node->tls 为 1 表示开启 TLS
    if (node->tls == 1) {
        cJSON *tls = cJSON_CreateObject();
        cJSON_AddBoolToObject(tls, "enabled", 1);
        cJSON_AddStringToObject(tls, "server_name", strlen(node->host) > 0 ? node->host : node->address);
        cJSON_AddBoolToObject(tls, "insecure", 1); // 允许不安全证书，生产环境可改为0
        cJSON_AddStringToObject(tls, "utls", "enabled"); // 启用 uTLS 指纹模拟
        cJSON_AddStringToObject(tls, "fingerprint", "chrome");
        cJSON_AddItemToObject(out, "tls", tls);
    }

    return out;
}

// 生成 config.json 文件
static int generate_config_file(const node_t *node, const program_settings_t *settings) {
    cJSON *root = cJSON_CreateObject();
    
    cJSON_AddItemToObject(root, "log", build_log_config());
    cJSON_AddItemToObject(root, "dns", build_dns_config());
    cJSON_AddItemToObject(root, "inbounds", build_inbounds(settings));
    
    cJSON *outbounds = cJSON_CreateArray();
    cJSON_AddItemToArray(outbounds, build_outbound_node(node));
    
    // 添加直连出口
    cJSON *direct = cJSON_CreateObject();
    cJSON_AddStringToObject(direct, "type", "direct");
    cJSON_AddStringToObject(direct, "tag", "direct");
    cJSON_AddItemToArray(outbounds, direct);
    
    // 添加阻止出口
    cJSON *block = cJSON_CreateObject();
    cJSON_AddStringToObject(block, "type", "block");
    cJSON_AddStringToObject(block, "tag", "block");
    cJSON_AddItemToArray(outbounds, block);
    
    cJSON_AddItemToObject(root, "outbounds", outbounds);
    
    // 简单的路由规则
    cJSON *route = cJSON_CreateObject();
    cJSON_AddBoolToObject(route, "auto_detect_interface", 1);
    cJSON_AddItemToObject(root, "route", route);

    char *json_str = cJSON_Print(root);
    if (!json_str) {
        cJSON_Delete(root);
        return 0;
    }

    FILE *fp = fopen("config.json", "w");
    if (fp) {
        fputs(json_str, fp);
        fclose(fp);
        free(json_str);
        cJSON_Delete(root);
        return 1;
    }
    
    free(json_str);
    cJSON_Delete(root);
    return 0;
}

void singbox_init(void) {
    g_is_running = 0;
    memset(&g_pi, 0, sizeof(g_pi));
}

void singbox_stop(void) {
    if (g_is_running && g_pi.hProcess) {
        // 尝试优雅关闭，但在 Windows 上 Terminate 最直接
        TerminateProcess(g_pi.hProcess, 0);
        WaitForSingleObject(g_pi.hProcess, 1000); // 等待最多1秒
        CloseHandle(g_pi.hProcess);
        CloseHandle(g_pi.hThread);
        memset(&g_pi, 0, sizeof(g_pi));
        g_is_running = 0;
    }
}

int singbox_start(const node_t *node, const program_settings_t *settings) {
    singbox_stop(); // 启动前先停止旧进程

    if (!node) {
        return -1;
    }
    
    // 假设 settings->singbox_path 存储了可执行文件路径
    // 如果为空，使用默认文件名
    const char *exe_path = (strlen(settings->singbox_path) > 0) ? settings->singbox_path : "sing-box.exe";

    // 1. 生成配置文件
    if (!generate_config_file(node, settings)) {
        return -2; // Config 写入失败
    }

    // 2. 启动进程
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // 隐藏控制台窗口

    char cmd[2048];
    // 命令格式: "path/to/sing-box.exe" run -c config.json
    snprintf(cmd, sizeof(cmd), "\"%s\" run -c config.json", exe_path);

    // 尝试创建进程
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &g_pi)) {
        g_is_running = 1;
        return 0;
    }

    // 启动失败
    g_is_running = 0;
    return -3; 
}

int singbox_is_running(void) {
    if (!g_is_running) return 0;
    
    DWORD exit_code = 0;
    if (g_pi.hProcess && GetExitCodeProcess(g_pi.hProcess, &exit_code)) {
        if (exit_code == STILL_ACTIVE) {
            return 1;
        }
    }
    
    // 如果进程已退出，更新状态
    g_is_running = 0;
    if (g_pi.hProcess) {
        CloseHandle(g_pi.hProcess);
        CloseHandle(g_pi.hThread);
        memset(&g_pi, 0, sizeof(g_pi));
    }
    return 0;
}
