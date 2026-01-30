// 文件名: src/gui_settings.c
#include "gui.h"
#include "gui_utils.h"
#include "config.h"
#include "proxy.h"
#include "common.h"
#include "resource.h"
#include <stdio.h>
#include <commctrl.h>

// 定义控件 ID
#define ID_COMBO_BROWSER 3001
#define ID_EDIT_CUSTOM_CIPHERS 3002
#define ID_EDIT_CORE_PATH 3005 // [New] 核心路径输入框 ID

// [Mod] 更新模板数量为 8 (含 Custom)
#define UA_TEMPLATE_COUNT 8

static HWND hSettingsWnd = NULL;

DWORD WINAPI SettingsApplyThread(LPVOID lpParam) {
    SaveSettings();
    if (g_proxyRunning) {
        StopProxyCore();
        StartProxyCore();
    }
    return 0;
}

LRESULT CALLBACK SettingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hHotkey, hPortEdit, hAddrEdit, hCorePathEdit;
    switch(msg) {
        case WM_CREATE: {
            EnterCriticalSection(&g_configLock);
            int localPort = g_localPort;
            char localAddr[64];
            strcpy(localAddr, g_localAddr);
            
            // [New] 读取核心路径
            char corePath[512];
            strcpy(corePath, global_settings.singbox_path);

            int modifiers = g_hotkeyModifiers;
            int vk = g_hotkeyVk;
            
            int browserType = g_browserType;
            char customCiphers[2048];
            strcpy(customCiphers, g_customCiphers);
            
            int alpnMode = g_alpnMode;
            BOOL frag = g_enableFragment;
            BOOL pad = g_enablePadding;
            BOOL ech = g_enableECH; 
            int fMin = g_fragSizeMin, fMax = g_fragSizeMax, fDly = g_fragDelayMs;
            int pMin = g_padSizeMin, pMax = g_padSizeMax;
            int uaIdx = g_uaPlatformIndex;
            char uaStr[512], echServer[256], echPub[256];
            strcpy(uaStr, g_userAgentStr);
            strcpy(echServer, g_echConfigServer);
            strcpy(echPub, g_echPublicName);
            LeaveCriticalSection(&g_configLock);

            int y = 20;
            CreateWindowW(L"STATIC", L"隐藏图标快捷键:", WS_CHILD|WS_VISIBLE, 25, y, 140, 20, hWnd, NULL,NULL,NULL);
            hHotkey = CreateWindowExW(0, HOTKEY_CLASSW, NULL, WS_CHILD|WS_VISIBLE|WS_BORDER, 160, y-3, 270, 25, hWnd, (HMENU)ID_HOTKEY_CTRL, NULL,NULL);
            UINT hkMod = 0; 
            if (modifiers & MOD_SHIFT) hkMod |= HOTKEYF_SHIFT;
            if (modifiers & MOD_CONTROL) hkMod |= HOTKEYF_CONTROL;
            if (modifiers & MOD_ALT) hkMod |= HOTKEYF_ALT;
            SendMessage(hHotkey, HKM_SETHOTKEY, MAKEWORD(vk, hkMod), 0);
            
            y += 40;
            // [New] 代理地址输入框
            CreateWindowW(L"STATIC", L"本地代理地址:", WS_CHILD|WS_VISIBLE, 25, y, 140, 20, hWnd, NULL,NULL,NULL);
            hAddrEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 160, y-3, 150, 25, hWnd, (HMENU)ID_EDIT_ADDR, NULL,NULL);
            SetDlgItemTextA(hWnd, ID_EDIT_ADDR, localAddr);

            y += 35;
            CreateWindowW(L"STATIC", L"本地代理端口:", WS_CHILD|WS_VISIBLE, 25, y, 140, 20, hWnd, NULL,NULL,NULL);
            hPortEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD|WS_VISIBLE|ES_NUMBER, 160, y-3, 100, 25, hWnd, (HMENU)ID_PORT_EDIT, NULL,NULL);
            SetDlgItemInt(hWnd, ID_PORT_EDIT, localPort, FALSE);

            // [New] Sing-box 核心路径配置
            y += 35;
            CreateWindowW(L"STATIC", L"Sing-box 核心:", WS_CHILD|WS_VISIBLE, 25, y, 140, 20, hWnd, NULL,NULL,NULL);
            hCorePathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 160, y-3, 270, 25, hWnd, (HMENU)ID_EDIT_CORE_PATH, NULL,NULL);
            SetDlgItemTextA(hWnd, ID_EDIT_CORE_PATH, corePath);

            // 抗封锁配置 GroupBox (整体下移)
            y += 50;
            CreateWindowW(L"BUTTON", L"抗封锁策略配置", WS_CHILD|WS_VISIBLE|BS_GROUPBOX, 20, y, 420, 480, hWnd, NULL, NULL, NULL);
            
            y += 30;
            CreateWindowW(L"STATIC", L"浏览器指纹模拟:", WS_CHILD|WS_VISIBLE, 35, y+3, 110, 20, hWnd, NULL, NULL, NULL);
            HWND hComboBrowser = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, 150, y, 270, 200, hWnd, (HMENU)ID_COMBO_BROWSER, NULL, NULL);
            
            SendMessageW(hComboBrowser, CB_ADDSTRING, 0, (LPARAM)L"禁用 (Disable)");
            SendMessageW(hComboBrowser, CB_ADDSTRING, 0, (LPARAM)L"Chrome (推荐)");
            SendMessageW(hComboBrowser, CB_ADDSTRING, 0, (LPARAM)L"Firefox");
            SendMessageW(hComboBrowser, CB_ADDSTRING, 0, (LPARAM)L"Safari");
            SendMessageW(hComboBrowser, CB_ADDSTRING, 0, (LPARAM)L"Edge");
            SendMessageW(hComboBrowser, CB_ADDSTRING, 0, (LPARAM)L"自定义 (Custom)");
            SendMessage(hComboBrowser, CB_SETCURSEL, browserType, 0);

            // 自定义 Cipher 输入框
            y += 30;
            HWND hEditCustom = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 35, y, 385, 22, hWnd, (HMENU)ID_EDIT_CUSTOM_CIPHERS, NULL, NULL);
            SetDlgItemTextUtf8(hWnd, ID_EDIT_CUSTOM_CIPHERS, customCiphers);
            
            if (browserType == 5) ShowWindow(hEditCustom, SW_SHOW);
            else ShowWindow(hEditCustom, SW_HIDE);

            // ALPN
            y += 35;
            CreateWindowW(L"STATIC", L"ALPN 协议伪装:", WS_CHILD|WS_VISIBLE, 35, y+3, 100, 20, hWnd, (HMENU)ID_STATIC_ALPN, NULL, NULL);
            HWND hComboALPN = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, 140, y, 200, 120, hWnd, (HMENU)ID_COMBO_ALPN, NULL, NULL);
            SendMessageW(hComboALPN, CB_ADDSTRING, 0, (LPARAM)L"禁用 (Disable)");
            SendMessageW(hComboALPN, CB_ADDSTRING, 0, (LPARAM)L"http/1.1");
            SendMessageW(hComboALPN, CB_ADDSTRING, 0, (LPARAM)L"h2, http/1.1 (推荐)");
            SendMessageW(hComboALPN, CB_ADDSTRING, 0, (LPARAM)L"h2, http/1.1, h3");
            
            if (alpnMode >= 0 && alpnMode <= 3) SendMessage(hComboALPN, CB_SETCURSEL, alpnMode, 0);
            else SendMessage(hComboALPN, CB_SETCURSEL, 1, 0);

            // 分片
            y += 35;
            HWND hChk3 = CreateWindowW(L"BUTTON", L"启用 TCP 随机分片 (对抗 SNI 阻断)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 380, 22, hWnd, (HMENU)ID_CHK_FRAG, NULL, NULL);
            y += 30;
            CreateWindowW(L"STATIC", L"分片长度(字节):", WS_CHILD|WS_VISIBLE, 55, y+2, 110, 20, hWnd, NULL,NULL,NULL);
            SetDlgItemInt(hWnd, ID_EDIT_FRAG_MIN, fMin, FALSE);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 170, y, 40, 22, hWnd, (HMENU)ID_EDIT_FRAG_MIN, NULL, NULL);
            CreateWindowW(L"STATIC", L"-", WS_CHILD|WS_VISIBLE, 215, y+2, 10, 20, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 230, y, 40, 22, hWnd, (HMENU)ID_EDIT_FRAG_MAX, NULL, NULL);
            CreateWindowW(L"STATIC", L"延迟(ms):", WS_CHILD|WS_VISIBLE, 290, y+2, 60, 20, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 355, y, 40, 22, hWnd, (HMENU)ID_EDIT_FRAG_DLY, NULL, NULL);

            // Padding
            y += 40;
            HWND hChkPad = CreateWindowW(L"BUTTON", L"启用 TLS 流量填充 (随机包长度)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 380, 22, hWnd, (HMENU)ID_CHK_PADDING, NULL, NULL);
            y += 30;
            CreateWindowW(L"STATIC", L"随机填充(块):", WS_CHILD|WS_VISIBLE, 55, y+2, 110, 20, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 170, y, 40, 22, hWnd, (HMENU)ID_EDIT_PAD_MIN, NULL, NULL);
            CreateWindowW(L"STATIC", L"-", WS_CHILD|WS_VISIBLE, 215, y+2, 10, 20, hWnd, NULL,NULL,NULL);
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_CENTER, 230, y, 40, 22, hWnd, (HMENU)ID_EDIT_PAD_MAX, NULL, NULL);

            // ECH
            y += 40;
            HWND hChkECH = CreateWindowW(L"BUTTON", L"启用 ECH (Encrypted Client Hello)", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 35, y, 380, 22, hWnd, (HMENU)ID_CHK_ECH, NULL, NULL);
            y += 30;
            CreateWindowW(L"STATIC", L"DoH服务器:", WS_CHILD|WS_VISIBLE, 55, y+2, 80, 20, hWnd, NULL,NULL,NULL);
            HWND hEchSrv = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 140, y, 255, 22, hWnd, (HMENU)ID_EDIT_ECH_SERVER, NULL, NULL);
            y += 30;
            CreateWindowW(L"STATIC", L"ECH域名:", WS_CHILD|WS_VISIBLE, 55, y+2, 80, 20, hWnd, NULL,NULL,NULL);
            HWND hEchPub = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 140, y, 255, 22, hWnd, (HMENU)ID_EDIT_ECH_DOMAIN, NULL, NULL);

            // User-Agent
            y += 45;
            CreateWindowW(L"STATIC", L"伪装平台:", WS_CHILD|WS_VISIBLE, 35, y+3, 80, 20, hWnd, NULL,NULL,NULL);
            HWND hCombo = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL, 120, y, 280, 200, hWnd, (HMENU)ID_COMBO_PLATFORM, NULL, NULL);
            y += 30;
            CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 35, y, 365, 25, hWnd, (HMENU)ID_EDIT_UA_STR, NULL, NULL);

            // Buttons (整体下移)
            y += 60;
            CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 110, y, 100, 32, hWnd, (HMENU)IDOK, NULL,NULL);
            CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE, 250, y, 100, 32, hWnd, (HMENU)IDCANCEL, NULL,NULL);

            SendMessage(hChk3, BM_SETCHECK, frag ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChkPad, BM_SETCHECK, pad ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessage(hChkECH, BM_SETCHECK, ech ? BST_CHECKED : BST_UNCHECKED, 0);

            SetDlgItemInt(hWnd, ID_EDIT_FRAG_MIN, fMin, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_FRAG_MAX, fMax, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_FRAG_DLY, fDly, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_PAD_MIN, pMin, FALSE);
            SetDlgItemInt(hWnd, ID_EDIT_PAD_MAX, pMax, FALSE);

            SetDlgItemTextUtf8(hWnd, ID_EDIT_ECH_SERVER, echServer);
            SetDlgItemTextUtf8(hWnd, ID_EDIT_ECH_DOMAIN, echPub);

            // [Mod] 填充 UA 平台列表 (含 Custom)
            for(int i=0; i < UA_TEMPLATE_COUNT; i++) {
                SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)UA_PLATFORMS[i]);
            }
            if (uaIdx >= UA_TEMPLATE_COUNT) uaIdx = 0; 
            SendMessage(hCombo, CB_SETCURSEL, uaIdx, 0);
            SetDlgItemTextUtf8(hWnd, ID_EDIT_UA_STR, uaStr);
            
            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont);
            SendMessage(hWnd, WM_SETFONT, (WPARAM)hAppFont, TRUE);
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_COMBO_BROWSER && HIWORD(wParam) == CBN_SELCHANGE) {
                int browserIdx = SendMessage((HWND)lParam, CB_GETCURSEL, 0, 0);
                HWND hEditCustom = GetDlgItem(hWnd, ID_EDIT_CUSTOM_CIPHERS);
                
                // 1. 自定义 Cipher 输入框逻辑
                if (browserIdx == 5) ShowWindow(hEditCustom, SW_SHOW);
                else ShowWindow(hEditCustom, SW_HIDE);

                // 2. 伪装平台联动逻辑
                // 仅当用户未选中 "自定义 (Custom)" 平台时，才自动切换
                // 如果用户当前平台是 "自定义" (Index 7)，则保持不变，不干扰
                HWND hComboUA = GetDlgItem(hWnd, ID_COMBO_PLATFORM);
                int currentUaIdx = SendMessage(hComboUA, CB_GETCURSEL, 0, 0);
                
                if (currentUaIdx != 7) { // 7 = Custom Platform
                    int targetUaIdx = -1;
                    switch(browserIdx) {
                        case 1: targetUaIdx = 0; break; // Chrome -> Windows Chrome
                        case 2: targetUaIdx = 2; break; // Firefox -> Windows Firefox
                        case 3: targetUaIdx = 3; break; // Safari -> macOS Safari
                        case 4: targetUaIdx = 1; break; // Edge -> Windows Edge
                    }

                    if (targetUaIdx != -1) {
                        SendMessage(hComboUA, CB_SETCURSEL, targetUaIdx, 0);
                        SetDlgItemTextUtf8(hWnd, ID_EDIT_UA_STR, UA_TEMPLATES[targetUaIdx]);
                    }
                }
            }
            if (LOWORD(wParam) == ID_COMBO_PLATFORM && HIWORD(wParam) == CBN_SELCHANGE) {
                int idx = SendMessage((HWND)lParam, CB_GETCURSEL, 0, 0);
                // [Mod] 如果选择的是预设 (0-6)，则更新文本框
                // 如果选择的是自定义 (7)，则保留当前文本框内容供用户编辑
                if (idx >= 0 && idx < 7) { 
                    SetDlgItemTextUtf8(hWnd, ID_EDIT_UA_STR, UA_TEMPLATES[idx]);
                }
            }
            if (LOWORD(wParam) == IDOK) {
                int fMin = GetDlgItemInt(hWnd, ID_EDIT_FRAG_MIN, NULL, FALSE);
                int fMax = GetDlgItemInt(hWnd, ID_EDIT_FRAG_MAX, NULL, FALSE);
                int fDly = GetDlgItemInt(hWnd, ID_EDIT_FRAG_DLY, NULL, FALSE);
                int pMin = GetDlgItemInt(hWnd, ID_EDIT_PAD_MIN, NULL, FALSE);
                int pMax = GetDlgItemInt(hWnd, ID_EDIT_PAD_MAX, NULL, FALSE);
                int port = GetDlgItemInt(hWnd, ID_PORT_EDIT, NULL, FALSE);

                if (fMin < 1) fMin = 1; if (fMax < fMin) fMax = fMin;
                if (pMin < 0) pMin = 0; if (pMax < pMin) pMax = pMin;

                LRESULT res = SendMessage(hHotkey, HKM_GETHOTKEY, 0, 0);
                UINT vk = LOBYTE(res); UINT mod = HIBYTE(res);
                UINT newMod = 0;
                if (mod & HOTKEYF_SHIFT) newMod |= MOD_SHIFT;
                if (mod & HOTKEYF_CONTROL) newMod |= MOD_CONTROL;
                if (mod & HOTKEYF_ALT) newMod |= MOD_ALT;

                EnterCriticalSection(&g_configLock);

                g_fragSizeMin = fMin; g_fragSizeMax = fMax; g_fragDelayMs = fDly;
                g_padSizeMin = pMin; g_padSizeMax = pMax;
                if (port > 0 && port < 65535) g_localPort = port;
                
                // [Sync] 同步到 global_settings
                global_settings.local_port = g_localPort;

                // [New] 保存代理地址
                wchar_t wAddr[64] = {0};
                GetDlgItemTextW(hWnd, ID_EDIT_ADDR, wAddr, 64);
                WideCharToMultiByte(CP_UTF8, 0, wAddr, -1, g_localAddr, 64, NULL, NULL);

                // [New] 保存 Sing-box 核心路径
                wchar_t wCorePath[512] = {0};
                GetDlgItemTextW(hWnd, ID_EDIT_CORE_PATH, wCorePath, 512);
                WideCharToMultiByte(CP_UTF8, 0, wCorePath, -1, global_settings.singbox_path, 512, NULL, NULL);

                g_browserType = SendMessage(GetDlgItem(hWnd, ID_COMBO_BROWSER), CB_GETCURSEL, 0, 0);
                
                wchar_t wBuf[2048];
                GetDlgItemTextW(hWnd, ID_EDIT_CUSTOM_CIPHERS, wBuf, 2047);
                WideCharToMultiByte(CP_UTF8, 0, wBuf, -1, g_customCiphers, 2048, NULL, NULL);
                
                g_alpnMode = SendMessage(GetDlgItem(hWnd, ID_COMBO_ALPN), CB_GETCURSEL, 0, 0);
                if (g_alpnMode < 0) g_alpnMode = 1;

                g_enableFragment = (IsDlgButtonChecked(hWnd, ID_CHK_FRAG) == BST_CHECKED);
                g_enablePadding = (IsDlgButtonChecked(hWnd, ID_CHK_PADDING) == BST_CHECKED);
                g_enableECH = (IsDlgButtonChecked(hWnd, ID_CHK_ECH) == BST_CHECKED);

                GetDlgItemTextW(hWnd, ID_EDIT_ECH_SERVER, wBuf, 256);
                WideCharToMultiByte(CP_UTF8, 0, wBuf, -1, g_echConfigServer, 256, NULL, NULL);
                
                GetDlgItemTextW(hWnd, ID_EDIT_ECH_DOMAIN, wBuf, 256);
                WideCharToMultiByte(CP_UTF8, 0, wBuf, -1, g_echPublicName, 256, NULL, NULL);

                g_uaPlatformIndex = SendMessage(GetDlgItem(hWnd, ID_COMBO_PLATFORM), CB_GETCURSEL, 0, 0);
                
                GetDlgItemTextW(hWnd, ID_EDIT_UA_STR, wBuf, 511);
                WideCharToMultiByte(CP_UTF8, 0, wBuf, -1, g_userAgentStr, 512, NULL, NULL);

                if (vk != 0 && newMod != 0) {
                    UnregisterHotKey(hwnd, ID_GLOBAL_HOTKEY);
                    if (RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, newMod, vk)) { 
                        g_hotkeyVk = vk; g_hotkeyModifiers = newMod; 
                    }
                }
                LeaveCriticalSection(&g_configLock);

                CreateThread(NULL, 0, SettingsApplyThread, NULL, 0, NULL);
                DestroyWindow(hWnd);
            } else if (LOWORD(wParam) == IDCANCEL) DestroyWindow(hWnd);
            break;
        case WM_CLOSE: DestroyWindow(hWnd); break;
        case WM_DESTROY: hSettingsWnd = NULL; break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenSettingsWindow() {
    if (hSettingsWnd && IsWindow(hSettingsWnd)) {
        ShowWindow(hSettingsWnd, SW_RESTORE); 
        SetForegroundWindow(hSettingsWnd); 
        return;
    }
    
    WNDCLASSW wc = {0}; 
    wc.lpfnWndProc = SettingsWndProc; 
    wc.hInstance = GetModuleHandle(NULL); 
    wc.lpszClassName = L"Settings"; 
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc.hIcon = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_APP_ICON)); 

    WNDCLASSW temp; 
    if (!GetClassInfoW(GetModuleHandle(NULL), L"Settings", &temp)) {
        RegisterClassW(&wc);
    }
    
    hSettingsWnd = CreateWindowW(L"Settings", L"软件设置", WS_VISIBLE|WS_CAPTION|WS_SYSMENU, 
        CW_USEDEFAULT, 0, 480, 770, hwnd, NULL, wc.hInstance, NULL); // [Mod] 增加窗口高度以容纳新控件
        
    ShowWindow(hSettingsWnd, SW_SHOW);
}
