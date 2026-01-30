/* src/gui_node_edit.c */
// [Refactor] 2026-01-29: 增强长链接支持，防止缓冲区溢出
// [Fix] 2026-01-29: 修复 JSON 序列化时的潜在内存泄漏

#include "gui.h"
#include "gui_utils.h"
#include "config.h"
#include "utils.h"
#include "common.h"
#include "resource.h"
#include "cJSON.h"
#include <stdio.h>

#define ID_BTN_SAVE     4010
#define ID_BTN_CANCEL   4011

// [Config] 增加缓冲区大小以支持长链接 (VLESS/Trojan URL 可达 1KB+)
#define MAX_EDIT_FIELD_LEN 2048

void LoadNodeToEdit(HWND hWnd, const wchar_t* tag) {
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; long size = 0;
    if (!ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    // [Safety] 解析前检查 buffer
    cJSON* root = buffer ? cJSON_Parse(buffer) : NULL;
    if (buffer) free(buffer);
    
    if (!root) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    
    char tagUtf8[MAX_EDIT_FIELD_LEN];
    WideCharToMultiByte(CP_UTF8, 0, tag, -1, tagUtf8, MAX_EDIT_FIELD_LEN, NULL, NULL);
    
    cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
    cJSON* target = NULL;
    cJSON* node = NULL;
    
    cJSON_ArrayForEach(node, outbounds) {
        cJSON* t = cJSON_GetObjectItem(node, "tag");
        if (t && t->valuestring && strcmp(t->valuestring, tagUtf8) == 0) { 
            target = node; 
            break; 
        }
    }
    
    if (target) {
        SetDlgItemTextW(hWnd, ID_EDIT_TAG, tag);
        
        cJSON* server = cJSON_GetObjectItem(target, "server");
        if(server && server->valuestring) SetDlgItemTextUtf8(hWnd, ID_EDIT_ADDR, server->valuestring);
        
        cJSON* port = cJSON_GetObjectItem(target, "server_port");
        if(port) SetDlgItemInt(hWnd, ID_EDIT_PORT, port->valueint, FALSE);
        
        // 兼容 username / uuid 字段
        cJSON* user = cJSON_GetObjectItem(target, "username");
        if(!user) user = cJSON_GetObjectItem(target, "uuid");
        if(user && user->valuestring) SetDlgItemTextUtf8(hWnd, ID_EDIT_USER, user->valuestring);
        
        cJSON* pass = cJSON_GetObjectItem(target, "password");
        if(pass && pass->valuestring) SetDlgItemTextUtf8(hWnd, ID_EDIT_PASS, pass->valuestring);
        
        // Transport 设置
        cJSON* trans = cJSON_GetObjectItem(target, "transport"); 
        if (!trans) trans = cJSON_GetObjectItem(target, "streamSettings"); // 兼容旧格式
        
        HWND hNet = GetDlgItem(hWnd, ID_EDIT_NET);
        SendMessage(hNet, CB_SETCURSEL, 0, 0); // Default TCP
        
        cJSON* netType = trans ? cJSON_GetObjectItem(trans, "type") : cJSON_GetObjectItem(target, "network");
        if (netType && netType->valuestring && strcmp(netType->valuestring, "ws") == 0) {
            SendMessage(hNet, CB_SETCURSEL, 1, 0);
        }
        
        // WS Settings
        cJSON* wsSettings = NULL;
        if (trans) wsSettings = cJSON_GetObjectItem(trans, "wsSettings"); // nested
        if (!wsSettings && trans && netType && netType->valuestring && strcmp(netType->valuestring, "ws") == 0) {
             // 扁平结构
             wsSettings = trans;
        }
        
        if (wsSettings) {
             cJSON* path = cJSON_GetObjectItem(wsSettings, "path");
             if (path && path->valuestring) SetDlgItemTextUtf8(hWnd, ID_EDIT_PATH, path->valuestring);
             
             cJSON* headers = cJSON_GetObjectItem(wsSettings, "headers");
             if (headers) {
                 cJSON* host = cJSON_GetObjectItem(headers, "Host");
                 if (host && host->valuestring) SetDlgItemTextUtf8(hWnd, ID_EDIT_HOST, host->valuestring);
             }
        }
        
        // TLS 设置
        HWND hTls = GetDlgItem(hWnd, ID_EDIT_TLS);
        SendMessage(hTls, CB_SETCURSEL, 0, 0); 
        cJSON* tls = cJSON_GetObjectItem(target, "tls");
        cJSON* security = cJSON_GetObjectItem(target, "security");
        
        if (tls || (security && security->valuestring && strcmp(security->valuestring, "tls") == 0)) {
             SendMessage(hTls, CB_SETCURSEL, 1, 0);
             cJSON* sni = tls ? cJSON_GetObjectItem(tls, "server_name") : NULL;
             if (sni && sni->valuestring) SetDlgItemTextUtf8(hWnd, ID_EDIT_HOST, sni->valuestring);
        }

        BOOL bInsecure = FALSE;
        if (tls) {
            cJSON* insec = cJSON_GetObjectItem(tls, "allowInsecure");
            if (insec && cJSON_IsTrue(insec)) bInsecure = TRUE;
        }
        SendMessage(GetDlgItem(hWnd, ID_CHK_INSECURE), BM_SETCHECK, bInsecure ? BST_CHECKED : BST_UNCHECKED, 0);
    }
    
    cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
}

void SaveEditedNode(HWND hWnd, const wchar_t* originalTagW) {
    // [Fix] 使用大缓冲区防止截断
    wchar_t wTag[MAX_EDIT_FIELD_LEN], wAddr[MAX_EDIT_FIELD_LEN], wUser[MAX_EDIT_FIELD_LEN];
    wchar_t wPass[MAX_EDIT_FIELD_LEN], wHost[MAX_EDIT_FIELD_LEN], wPath[MAX_EDIT_FIELD_LEN];
    
    char tag[MAX_EDIT_FIELD_LEN], addr[MAX_EDIT_FIELD_LEN], user[MAX_EDIT_FIELD_LEN];
    char pass[MAX_EDIT_FIELD_LEN], host[MAX_EDIT_FIELD_LEN], path[MAX_EDIT_FIELD_LEN];
    
    int port = GetDlgItemInt(hWnd, ID_EDIT_PORT, NULL, FALSE);
    if (port <= 0 || port > 65535) {
        MessageBoxW(hWnd, L"端口必须在 1-65535 之间", L"参数错误", MB_OK|MB_ICONERROR); 
        return;
    }

    GetDlgItemTextW(hWnd, ID_EDIT_TAG, wTag, MAX_EDIT_FIELD_LEN);
    GetDlgItemTextW(hWnd, ID_EDIT_ADDR, wAddr, MAX_EDIT_FIELD_LEN);
    GetDlgItemTextW(hWnd, ID_EDIT_USER, wUser, MAX_EDIT_FIELD_LEN);
    GetDlgItemTextW(hWnd, ID_EDIT_PASS, wPass, MAX_EDIT_FIELD_LEN);
    GetDlgItemTextW(hWnd, ID_EDIT_HOST, wHost, MAX_EDIT_FIELD_LEN);
    GetDlgItemTextW(hWnd, ID_EDIT_PATH, wPath, MAX_EDIT_FIELD_LEN);
    
    // 安全转换
    WideCharToMultiByte(CP_UTF8, 0, wTag, -1, tag, MAX_EDIT_FIELD_LEN, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wAddr, -1, addr, MAX_EDIT_FIELD_LEN, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wUser, -1, user, MAX_EDIT_FIELD_LEN, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wPass, -1, pass, MAX_EDIT_FIELD_LEN, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wHost, -1, host, MAX_EDIT_FIELD_LEN, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wPath, -1, path, MAX_EDIT_FIELD_LEN, NULL, NULL);
    
    if (strlen(addr) == 0) {
        MessageBoxW(hWnd, L"服务器地址不能为空", L"参数错误", MB_OK|MB_ICONERROR); 
        return;
    }

    int netIdx = (int)SendMessage(GetDlgItem(hWnd, ID_EDIT_NET), CB_GETCURSEL, 0, 0);
    int tlsIdx = (int)SendMessage(GetDlgItem(hWnd, ID_EDIT_TLS), CB_GETCURSEL, 0, 0);
    BOOL bInsecure = (SendMessage(GetDlgItem(hWnd, ID_CHK_INSECURE), BM_GETCHECK, 0, 0) == BST_CHECKED);

    EnterCriticalSection(&g_configLock);

    // 1. 获取原始类型（如果存在）
    char originalType[64] = {0};
    char* buffer = NULL; long size = 0;
    
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer); 
        free(buffer);
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            char oldTagUtf8[MAX_EDIT_FIELD_LEN];
            WideCharToMultiByte(CP_UTF8, 0, originalTagW, -1, oldTagUtf8, MAX_EDIT_FIELD_LEN, NULL, NULL);
            
            cJSON* node = NULL;
            cJSON_ArrayForEach(node, outbounds) {
                cJSON* t = cJSON_GetObjectItem(node, "tag");
                if (t && t->valuestring && strcmp(t->valuestring, oldTagUtf8) == 0) {
                    cJSON* type = cJSON_GetObjectItem(node, "type");
                    if (type && type->valuestring) {
                        strncpy(originalType, type->valuestring, 63);
                    }
                    break;
                }
            }
            cJSON_Delete(root);
        }
    }

    // 2. 构建新节点
    cJSON* newNode = cJSON_CreateObject();
    cJSON_AddStringToObject(newNode, "tag", tag);
    cJSON_AddStringToObject(newNode, "server", addr);
    cJSON_AddNumberToObject(newNode, "server_port", port);

    // 智能推断类型
    if (strlen(originalType) > 0) {
        cJSON_AddStringToObject(newNode, "type", originalType);
        if (strcmp(originalType, "vless") == 0 || strcmp(originalType, "vmess") == 0 || strcmp(originalType, "trojan") == 0) {
             cJSON_AddStringToObject(newNode, "uuid", user);
             cJSON_AddStringToObject(newNode, "password", user); // Trojan compat
        } else {
             if (strlen(user)>0) cJSON_AddStringToObject(newNode, "username", user);
             if (strlen(pass)>0) cJSON_AddStringToObject(newNode, "password", pass);
        }
    } else {
        // Fallback logic
        if (strlen(user) > 20) { // Assume UUID -> vmess
            cJSON_AddStringToObject(newNode, "type", "vmess");
            cJSON_AddStringToObject(newNode, "uuid", user);
        } else {
            cJSON_AddStringToObject(newNode, "type", "socks");
            if (strlen(user)>0) cJSON_AddStringToObject(newNode, "username", user);
            if (strlen(pass)>0) cJSON_AddStringToObject(newNode, "password", pass);
        }
    }

    // Transport: WS / TCP
    if (netIdx == 1) { // WebSocket
        cJSON* trans = cJSON_CreateObject();
        cJSON_AddStringToObject(trans, "type", "ws");
        if (strlen(path) > 0) cJSON_AddStringToObject(trans, "path", path);
        if (strlen(host) > 0) {
            cJSON* h = cJSON_CreateObject();
            cJSON_AddStringToObject(h, "Host", host);
            cJSON_AddItemToObject(trans, "headers", h);
        }
        cJSON_AddItemToObject(newNode, "transport", trans);
    } else { 
        cJSON_AddStringToObject(newNode, "network", "tcp"); 
    }

    // TLS Settings
    if (tlsIdx == 1 || bInsecure) { 
        cJSON* tlsObj = cJSON_CreateObject();
        cJSON_AddBoolToObject(tlsObj, "enabled", cJSON_True);
        if (strlen(host) > 0) cJSON_AddStringToObject(tlsObj, "server_name", host);
        if (bInsecure) cJSON_AddBoolToObject(tlsObj, "allowInsecure", cJSON_True);
        cJSON_AddItemToObject(newNode, "tls", tlsObj);
    }

    // 3. 写入文件 (覆盖旧节点)
    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        cJSON* root = cJSON_Parse(buffer); 
        free(buffer);
        
        if (root) {
            cJSON* outbounds = cJSON_GetObjectItem(root, "outbounds");
            char oldTagUtf8[MAX_EDIT_FIELD_LEN];
            WideCharToMultiByte(CP_UTF8, 0, originalTagW, -1, oldTagUtf8, MAX_EDIT_FIELD_LEN, NULL, NULL);
            
            int count = cJSON_GetArraySize(outbounds);
            int idxToReplace = -1;
            
            for (int i=0; i<count; i++) {
                cJSON* item = cJSON_GetArrayItem(outbounds, i);
                cJSON* t = cJSON_GetObjectItem(item, "tag");
                if (t && t->valuestring && strcmp(t->valuestring, oldTagUtf8) == 0) {
                    idxToReplace = i; 
                    break;
                }
            }
            
            if (idxToReplace != -1) cJSON_ReplaceItemInArray(outbounds, idxToReplace, newNode);
            else cJSON_AddItemToArray(outbounds, newNode);
            
            char* out = cJSON_Print(root);
            if (out) {
                WriteBufferToFile(CONFIG_FILE, out);
                free(out); 
            }
            cJSON_Delete(root);
        } else {
            cJSON_Delete(newNode); // Parse error cleanup
        }
    } else {
        cJSON_Delete(newNode); // Read error cleanup
    }

    LeaveCriticalSection(&g_configLock);
}

// 窗口过程保持大部分不变，仅增加字体和布局微调
LRESULT CALLBACK NodeEditWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            wchar_t* tagCopy = _wcsdup(g_editingTag); 
            SetPropW(hWnd, L"NodeTag", tagCopy);

            // [Layout] 稍微增加间距
            int y = 20;
            int hLabel = 20;
            int hEdit = 24;
            int gap = 35;
            
            CreateWindowW(L"STATIC", L"节点备注:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 100, y, 220, hEdit, hWnd, (HMENU)ID_EDIT_TAG, NULL,NULL);
            
            y += gap;
            CreateWindowW(L"STATIC", L"服务器地址:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 100, y, 220, hEdit, hWnd, (HMENU)ID_EDIT_ADDR, NULL,NULL);
            
            y += gap;
            CreateWindowW(L"STATIC", L"端口:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER, 100, y, 80, hEdit, hWnd, (HMENU)ID_EDIT_PORT, NULL,NULL);
            
            y += gap;
            CreateWindowW(L"STATIC", L"用户/UUID:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 100, y, 220, hEdit, hWnd, (HMENU)ID_EDIT_USER, NULL,NULL);
            
            y += gap;
            CreateWindowW(L"STATIC", L"密码:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_PASSWORD, 100, y, 220, hEdit, hWnd, (HMENU)ID_EDIT_PASS, NULL,NULL);
            
            y += gap;
            CreateWindowW(L"STATIC", L"传输协议:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            HWND hNet = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, 100, y, 100, 100, hWnd, (HMENU)ID_EDIT_NET, NULL,NULL);
            SendMessageW(hNet, CB_ADDSTRING, 0, (LPARAM)L"TCP");
            SendMessageW(hNet, CB_ADDSTRING, 0, (LPARAM)L"WebSocket");
            SendMessage(hNet, CB_SETCURSEL, 0, 0);

            CreateWindowW(L"STATIC", L"TLS安全:", WS_CHILD|WS_VISIBLE, 210, y+3, 50, hLabel, hWnd, NULL,NULL,NULL);
            HWND hTls = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, 260, y, 60, 100, hWnd, (HMENU)ID_EDIT_TLS, NULL,NULL);
            SendMessageW(hTls, CB_ADDSTRING, 0, (LPARAM)L"关闭");
            SendMessageW(hTls, CB_ADDSTRING, 0, (LPARAM)L"开启");
            SendMessage(hTls, CB_SETCURSEL, 0, 0);
            
            y += gap;
            CreateWindowW(L"STATIC", L"Host/SNI:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 100, y, 220, hEdit, hWnd, (HMENU)ID_EDIT_HOST, NULL,NULL);
            
            y += gap;
            CreateWindowW(L"BUTTON", L"跳过证书验证 (不安全)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 100, y, 220, hEdit, hWnd, (HMENU)ID_CHK_INSECURE, NULL, NULL);

            y += gap;
            CreateWindowW(L"STATIC", L"WS Path:", WS_CHILD|WS_VISIBLE, 20, y+3, 70, hLabel, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 100, y, 220, hEdit, hWnd, (HMENU)ID_EDIT_PATH, NULL,NULL);
            
            y += 45;
            CreateWindowW(L"BUTTON", L"保存", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 60, y, 80, 30, hWnd, (HMENU)ID_BTN_SAVE, NULL,NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE, 180, y, 80, 30, hWnd, (HMENU)ID_BTN_CANCEL, NULL,NULL);
            
            if (tagCopy && wcslen(tagCopy) > 0) LoadNodeToEdit(hWnd, tagCopy);
            
            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            break;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id == ID_BTN_SAVE) {
                wchar_t* tag = (wchar_t*)GetPropW(hWnd, L"NodeTag");
                if (tag) {
                    SaveEditedNode(hWnd, tag);
                    HWND hMgr = FindWindowW(L"NodeMgr", NULL);
                    if (hMgr) PostMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
                }
                DestroyWindow(hWnd);
            } else if (id == ID_BTN_CANCEL) {
                DestroyWindow(hWnd);
            }
            break;
        }
        case WM_DESTROY: {
            wchar_t* tag = (wchar_t*)GetPropW(hWnd, L"NodeTag");
            if(tag) { free(tag); RemovePropW(hWnd, L"NodeTag"); }
            break;
        }
        case WM_CLOSE: DestroyWindow(hWnd); break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenNodeEditWindow(const wchar_t* tag) {
    if (tag) wcsncpy(g_editingTag, tag, 255); else g_editingTag[0] = 0;
    
    WNDCLASSW wc = {0};
    if (!GetClassInfoW(GetModuleHandle(NULL), L"NodeEditWnd", &wc)) {
        wc.lpfnWndProc = NodeEditWndProc; wc.hInstance = GetModuleHandle(NULL); 
        wc.lpszClassName = L"NodeEditWnd"; wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        RegisterClassW(&wc);
    }
    HWND hEdit = CreateWindowW(L"NodeEditWnd", L"编辑节点", WS_VISIBLE|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT,0,360,420, NULL,NULL,GetModuleHandle(NULL),NULL);
    ShowWindow(hEdit, SW_SHOW);
}
