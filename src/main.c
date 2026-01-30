/* src/main.c */
// [Refactor] 2026-01-29: 紧急修复 - 恢复 GetRealTagFromDisplay 调用
// [Fix] 修复因移除 GetRealTagFromDisplay 导致的节点切换失效问题
// [Fix] 保持字符串操作的安全性 (wcscpy_s)

#include "gui.h"
#include "gui_utils.h" // 包含 GetRealTagFromDisplay
#include "config.h"
#include "proxy.h"
#include "utils.h"
#include "crypto.h"
#include "common.h" 
#include "resource.h" 
#include <commctrl.h>
#include <stdio.h>
#include <wchar.h> 
#include <time.h> 
#include <process.h> 

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib") 

#define WM_IMPORT_RESULT (WM_USER + 200)

// [Config] 菜单可视区域显示的节点数量
#define MENU_VISIBLE_COUNT 20
// [Config] 最大支持的节点 ID 偏移
#define MAX_MENU_NODES 20000

#ifndef ID_TRAY_NODE_BASE
#define ID_TRAY_NODE_BASE 40000
#endif

#define ID_TRAY_SCROLL_UP   5501
#define ID_TRAY_SCROLL_DOWN 5502
#define TIMER_HOVER_SCROLL  999

extern void CleanupUtilsNet(); 
extern DWORD WINAPI AutoUpdateThread(LPVOID lpParam);

static FILETIME s_lastConfigTime = {0}; 
static HANDLE g_hExitEvent = NULL;      
HANDLE hConfigMonitorThread = NULL;     
static HANDLE hStartupThread = NULL;
static HANDLE hImportThread = NULL;
static HANDLE hAutoUpdateThread = NULL; 

static int s_menuOffset = 0;           
static BOOL s_isMenuOpen = FALSE;      

// --- 辅助函数声明 ---
void ShowTrayMenu(HWND hWnd);
void HandleTrayCommand(HWND hWnd, int id);
void StartImportThread(HWND hWnd); 
void ScrollMenuStep(HMENU hSubMenu, int direction); 

// [Safe] 安全等待并关闭线程句柄
static BOOL SafeWaitAndCloseThread(HANDLE* phThread, DWORD timeoutMs) {
    BOOL bCleanExit = TRUE;
    if (phThread && *phThread) {
        DWORD dwRet = WaitForSingleObject(*phThread, timeoutMs);
        if (dwRet == WAIT_TIMEOUT || dwRet == WAIT_FAILED) {
            bCleanExit = FALSE;
        } else { 
            CloseHandle(*phThread); 
            *phThread = NULL; 
        }
    }
    return bCleanExit;
}

// [Thread] 启动更新线程
unsigned WINAPI StartupUpdateThread(void* lpParam) {
    if (WaitForSingleObject(g_hExitEvent, 0) == WAIT_OBJECT_0) return 0;
    
    EnterCriticalSection(&g_configLock);
    BOOL hasOnStart = FALSE;
    for (int i = 0; i < g_subCount; i++) {
        if (g_subs[i].enabled && g_subs[i].update_cycle == UPDATE_MODE_ON_START) {
            hasOnStart = TRUE; break;
        }
    }
    LeaveCriticalSection(&g_configLock);
    
    if (hasOnStart && WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0) {
        UpdateAllSubscriptions(FALSE, FALSE);
        if (WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0) {
            HWND hMgr = FindWindowW(L"NodeMgr", NULL);
            if (hMgr && IsWindow(hMgr)) PostMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
        }
    }
    return 0;
}

void UpdateOnStartupSubscriptions() {
    if (hStartupThread) {
        if (WaitForSingleObject(hStartupThread, 0) == WAIT_OBJECT_0) {
            CloseHandle(hStartupThread); hStartupThread = NULL;
        } else return; 
    }
    hStartupThread = (HANDLE)_beginthreadex(NULL, 0, StartupUpdateThread, NULL, 0, NULL);
}

// [Thread] 配置文件监控线程
unsigned WINAPI ConfigMonitorThread(void* lpParam) {
    wchar_t configDir[MAX_PATH];
    
    // [Fix] 安全拷贝路径
    if (wcscpy_s(configDir, MAX_PATH, g_iniFilePath) != 0) {
        configDir[0] = 0; 
    }
    
    // [Robust] 路径处理
    wchar_t* p = wcsrchr(configDir, L'\\');
    if (p) {
        *p = 0; 
    } else {
        wcscpy_s(configDir, MAX_PATH, L".");
    }

    HANDLE hChange = FindFirstChangeNotificationW(
        configDir, 
        FALSE, 
        FILE_NOTIFY_CHANGE_LAST_WRITE
    );

    if (hChange == INVALID_HANDLE_VALUE) {
        WaitForSingleObject(g_hExitEvent, INFINITE);
        return 0;
    }

    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExW(CONFIG_FILE, GetFileExInfoStandard, &fileInfo)) {
        EnterCriticalSection(&g_configLock);
        if (CompareFileTime(&fileInfo.ftLastWriteTime, &s_lastConfigTime) != 0) {
            ParseTags(); 
            s_lastConfigTime = fileInfo.ftLastWriteTime; 
            HWND hMgr = FindWindowW(L"NodeMgr", NULL);
            if (hMgr && IsWindow(hMgr)) PostMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
        }
        LeaveCriticalSection(&g_configLock);
    }

    HANDLE handles[2] = { g_hExitEvent, hChange };

    while (TRUE) {
        DWORD dwWait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        if (dwWait == WAIT_OBJECT_0) {
            break; 
        }
        else if (dwWait == WAIT_OBJECT_0 + 1) {
            if (WaitForSingleObject(g_hExitEvent, 100) == WAIT_OBJECT_0) break;

            if (GetFileAttributesExW(CONFIG_FILE, GetFileExInfoStandard, &fileInfo)) {
                EnterCriticalSection(&g_configLock);
                BOOL changed = (CompareFileTime(&fileInfo.ftLastWriteTime, &s_lastConfigTime) != 0);
                
                if (changed) {
                    ParseTags(); 
                    s_lastConfigTime = fileInfo.ftLastWriteTime;
                    HWND hMgr = FindWindowW(L"NodeMgr", NULL);
                    if (hMgr && IsWindow(hMgr)) PostMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
                }
                LeaveCriticalSection(&g_configLock);
            }
            if (!FindNextChangeNotification(hChange)) break;
        }
        else {
            break; 
        }
    }

    FindCloseChangeNotification(hChange);
    return 0;
}

// [Thread] 剪贴板导入线程
unsigned WINAPI ImportClipboardThread(void* lpParam) {
    HWND hWnd = (HWND)lpParam;
    if (WaitForSingleObject(g_hExitEvent, 0) == WAIT_OBJECT_0) return 0;
    
    int count = ImportFromClipboard(); 
    
    if (count > 0) {
        EnterCriticalSection(&g_configLock);
        ParseTags();
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (GetFileAttributesExW(CONFIG_FILE, GetFileExInfoStandard, &fileInfo)) 
            s_lastConfigTime = fileInfo.ftLastWriteTime;
        LeaveCriticalSection(&g_configLock);
    }
    
    if (IsWindow(hWnd) && WaitForSingleObject(g_hExitEvent, 0) != WAIT_OBJECT_0) 
        PostMessage(hWnd, WM_IMPORT_RESULT, (WPARAM)count, 0);
    return 0;
}

void StartImportThread(HWND hWnd) {
    if (hImportThread) {
        if (WaitForSingleObject(hImportThread, 0) == WAIT_OBJECT_0) {
            CloseHandle(hImportThread); hImportThread = NULL;
        } else {
            MessageBoxW(hWnd, L"后台导入正在进行中...", L"提示", MB_OK);
            return;
        }
    }
    hImportThread = (HANDLE)_beginthreadex(NULL, 0, ImportClipboardThread, (void*)hWnd, 0, NULL);
}

void InitConfigTimestamp() {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExW(CONFIG_FILE, GetFileExInfoStandard, &fileInfo)) 
        s_lastConfigTime = fileInfo.ftLastWriteTime;
}

// --- 核心逻辑：单步平滑滚动 ---
void ScrollMenuStep(HMENU hSubMenu, int direction) {
    if (!hSubMenu || !s_isMenuOpen) return;

    EnterCriticalSection(&g_configLock);

    int maxVisible = MENU_VISIBLE_COUNT;
    int totalItems = nodeCount;
    
    if (totalItems <= maxVisible) {
        LeaveCriticalSection(&g_configLock);
        return;
    }

    int newOffset = s_menuOffset;
    if (direction == 1) newOffset--;      
    else if (direction == 2) newOffset++; 

    if (newOffset < 0) newOffset = 0;
    if (newOffset > totalItems - maxVisible) newOffset = totalItems - maxVisible;

    if (newOffset == s_menuOffset) {
        LeaveCriticalSection(&g_configLock);
        return;
    }

    if (direction == 1) { 
        DeleteMenu(hSubMenu, 2 + maxVisible - 1, MF_BYPOSITION);
        int idx = newOffset;
        UINT f = MF_STRING | MF_BYPOSITION;
        if (wcscmp(nodeTags[idx], currentNode) == 0) f |= MF_CHECKED;
        InsertMenuW(hSubMenu, 2, f, ID_TRAY_NODE_BASE + idx, nodeTags[idx]);
    } else { 
        DeleteMenu(hSubMenu, 2, MF_BYPOSITION);
        int idx = newOffset + maxVisible - 1;
        UINT f = MF_STRING | MF_BYPOSITION;
        if (wcscmp(nodeTags[idx], currentNode) == 0) f |= MF_CHECKED;
        InsertMenuW(hSubMenu, 2 + maxVisible - 1, f, ID_TRAY_NODE_BASE + idx, nodeTags[idx]);
    }

    s_menuOffset = newOffset;
    
    UINT upFlags = MF_STRING | MF_BYPOSITION;
    if (s_menuOffset <= 0) upFlags |= MF_GRAYED | MF_DISABLED;
    ModifyMenuW(hSubMenu, 0, upFlags, ID_TRAY_SCROLL_UP, L"▲ 向上翻动"); 

    int count = GetMenuItemCount(hSubMenu);
    UINT downFlags = MF_STRING | MF_BYPOSITION;
    if (s_menuOffset >= totalItems - maxVisible) downFlags |= MF_GRAYED | MF_DISABLED;
    ModifyMenuW(hSubMenu, count - 1, downFlags, ID_TRAY_SCROLL_DOWN, L"▼ 向下翻动");

    LeaveCriticalSection(&g_configLock);
}

// --- 消息处理 ---

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_TRAY && LOWORD(lParam) == WM_RBUTTONUP) {
        ShowTrayMenu(hWnd);
    }
    else if (msg == WM_MENUSELECT) {
        UINT uItem = LOWORD(wParam);
        UINT uFlags = HIWORD(wParam);
        HMENU hMenu = (HMENU)lParam;
        
        static int s_hoverDirection = 0; 

        if (uFlags == 0xFFFF && hMenu == NULL) {
            KillTimer(hWnd, TIMER_HOVER_SCROLL);
            s_hoverDirection = 0;
        }
        else {
            int newDir = 0;
            if (uItem == ID_TRAY_SCROLL_UP) newDir = 1;
            else if (uItem == ID_TRAY_SCROLL_DOWN) newDir = 2;

            if (newDir != 0) {
                if (s_hoverDirection != newDir) {
                    s_hoverDirection = newDir;
                    SetPropW(hWnd, L"HoverDir", (HANDLE)(INT_PTR)newDir);
                    SetTimer(hWnd, TIMER_HOVER_SCROLL, 200, NULL);
                }
            } else {
                KillTimer(hWnd, TIMER_HOVER_SCROLL);
                s_hoverDirection = 0;
                RemovePropW(hWnd, L"HoverDir");
            }
        }
    }
    else if (msg == WM_TIMER && wParam == TIMER_HOVER_SCROLL) {
        int dir = (int)(INT_PTR)GetPropW(hWnd, L"HoverDir");
        if (dir == 1 || dir == 2) {
            ScrollMenuStep(hNodeSubMenu, dir);
            SetTimer(hWnd, TIMER_HOVER_SCROLL, 200, NULL);
        }
    }
    else if (msg == WM_EXITMENULOOP) {
        s_isMenuOpen = FALSE;
        KillTimer(hWnd, TIMER_HOVER_SCROLL);
        RemovePropW(hWnd, L"HoverDir");
    }
    else if (msg == WM_COMMAND) {
        HandleTrayCommand(hWnd, LOWORD(wParam));
    }
    else if (msg == WM_HOTKEY && wParam == ID_GLOBAL_HOTKEY) {
        ToggleTrayIcon();
    }
    else if (msg == WM_IMPORT_RESULT) {
        int count = (int)wParam;
        SafeWaitAndCloseThread(&hImportThread, 0);
        if (count > 0) {
            HWND hMgr = FindWindowW(L"NodeMgr", NULL);
            if (hMgr && IsWindow(hMgr)) PostMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
            
            wchar_t msgBuf[64]; 
            swprintf_s(msgBuf, 64, L"导入 %d 个节点", count);
            MessageBoxW(hWnd, msgBuf, L"成功", MB_OK);
            
            EnterCriticalSection(&g_configLock);
            if (wcslen(currentNode) == 0 && nodeCount > 0) {
                // [Fix] 恢复 GetRealTagFromDisplay (1/2)
                wchar_t* tag = _wcsdup(GetRealTagFromDisplay(nodeTags[0]));
                LeaveCriticalSection(&g_configLock); 
                SwitchNode(tag); 
                free(tag);
            } else {
                LeaveCriticalSection(&g_configLock);
            }
        } else {
            MessageBoxW(hWnd, L"未发现有效链接", L"提示", MB_OK);
        }
    }
    else if (msg == WM_DESTROY) PostQuitMessage(0);
    
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void ShowTrayMenu(HWND hWnd) {
    POINT pt; GetCursorPos(&pt); SetForegroundWindow(hWnd);
    EnterCriticalSection(&g_configLock); 
    
    if (hMenu) DestroyMenu(hMenu); 
    hMenu = CreatePopupMenu(); 
    hNodeSubMenu = CreatePopupMenu(); 

    s_isMenuOpen = TRUE;

    int currentIdx = -1;
    if (nodeCount > 0) {
        for(int i=0; i<nodeCount; i++) {
            if(wcscmp(nodeTags[i], currentNode) == 0) { currentIdx = i; break; }
        }
    }
    
    if (currentIdx >= 0) s_menuOffset = currentIdx - (MENU_VISIBLE_COUNT / 2);
    else s_menuOffset = 0;

    if (s_menuOffset < 0) s_menuOffset = 0;
    if (nodeCount > MENU_VISIBLE_COUNT && s_menuOffset > nodeCount - MENU_VISIBLE_COUNT) 
        s_menuOffset = nodeCount - MENU_VISIBLE_COUNT;

    int itemsToShow = (nodeCount < MENU_VISIBLE_COUNT) ? nodeCount : MENU_VISIBLE_COUNT;
    
    UINT upFlags = MF_STRING;
    if (s_menuOffset <= 0) upFlags |= MF_GRAYED | MF_DISABLED;
    AppendMenuW(hNodeSubMenu, upFlags, ID_TRAY_SCROLL_UP, L"▲ 向上翻动");
    AppendMenuW(hNodeSubMenu, MF_SEPARATOR, 0, NULL);
    
    for (int i = 0; i < itemsToShow; i++) {
        int realIdx = s_menuOffset + i;
        if (realIdx < nodeCount) {
            UINT f = MF_STRING;
            if (wcscmp(nodeTags[realIdx], currentNode) == 0) f |= MF_CHECKED;
            AppendMenuW(hNodeSubMenu, f, ID_TRAY_NODE_BASE + realIdx, nodeTags[realIdx]);
        }
    }
    
    AppendMenuW(hNodeSubMenu, MF_SEPARATOR, 0, NULL);
    UINT downFlags = MF_STRING;
    if (s_menuOffset >= nodeCount - MENU_VISIBLE_COUNT) downFlags |= MF_GRAYED | MF_DISABLED;
    AppendMenuW(hNodeSubMenu, downFlags, ID_TRAY_SCROLL_DOWN, L"▼ 向下翻动");

    LeaveCriticalSection(&g_configLock);

    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hNodeSubMenu, L"切换节点");
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_MANAGE_NODES, L"节点管理");
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_IMPORT_CLIPBOARD, L"节点导入");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    
    UINT proxyFlags = MF_STRING; 
    if (IsSystemProxyEnabled()) proxyFlags |= MF_CHECKED;
    AppendMenuW(hMenu, proxyFlags, ID_TRAY_SYSTEM_PROXY, L"系统代理");
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_SETTINGS, L"软件设置");
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW_CONSOLE, L"查看日志");
    AppendMenuW(hMenu, CheckAutoStartup() ? MF_CHECKED : MF_UNCHECKED, ID_TRAY_AUTORUN, L"开机启动");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出");

    TrackPopupMenu(hMenu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, NULL);
}

void HandleTrayCommand(HWND hWnd, int id) {
    if (id == ID_TRAY_EXIT) { Shell_NotifyIconW(NIM_DELETE, &nid); PostQuitMessage(0); }
    else if (id == ID_TRAY_SYSTEM_PROXY) SetSystemProxy(!IsSystemProxyEnabled());
    else if (id == ID_TRAY_SHOW_CONSOLE) OpenLogViewer(TRUE);
    else if (id == ID_TRAY_MANAGE_NODES) OpenNodeManager();
    else if (id == ID_TRAY_SETTINGS) OpenSettingsWindow();
    else if (id == ID_TRAY_AUTORUN) SetAutoStartup(!CheckAutoStartup());
    else if (id == ID_TRAY_IMPORT_CLIPBOARD) StartImportThread(hWnd);
    
    else if (id == ID_TRAY_SCROLL_UP) {
        ScrollMenuStep(hNodeSubMenu, 1);
        PostMessage(hWnd, WM_TRAY, 0, WM_RBUTTONUP);
    }
    else if (id == ID_TRAY_SCROLL_DOWN) {
        ScrollMenuStep(hNodeSubMenu, 2);
        PostMessage(hWnd, WM_TRAY, 0, WM_RBUTTONUP);
    }
    
    else if (id >= ID_TRAY_NODE_BASE && id < ID_TRAY_NODE_BASE + MAX_MENU_NODES) {
        int idx = id - ID_TRAY_NODE_BASE;
        EnterCriticalSection(&g_configLock);
        if (idx >= 0 && idx < nodeCount) {
            // [Fix] 恢复 GetRealTagFromDisplay (2/2)
            // 确保点击菜单时获取的是真实 Tag，而不是显示名称
            wchar_t* tag = _wcsdup(GetRealTagFromDisplay(nodeTags[idx]));
            LeaveCriticalSection(&g_configLock); 
            SwitchNode(tag); 
            free(tag);
        } else {
            LeaveCriticalSection(&g_configLock);
        }
    }
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\MandalaECH_Instance_Mutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"程序已在运行中，请检查系统托盘。", L"提示", MB_OK | MB_ICONINFORMATION);
        if (hMutex) CloseHandle(hMutex); 
        return 0; 
    }

    srand((unsigned)time(NULL));
    InitGlobalLocks(); 
    InitMemoryPool(); 
    
    wchar_t exePath[MAX_PATH]; 
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) return 1; 
    
    wchar_t* pDir = wcsrchr(exePath, L'\\'); 
    if (pDir) { 
        *pDir = 0; 
        SetCurrentDirectoryW(exePath); 
    }
    
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa); 
    init_crypto_global(); 
    
    INITCOMMONCONTROLSEX ic = {sizeof(ic), ICC_HOTKEY_CLASS|ICC_TAB_CLASSES|ICC_LISTVIEW_CLASSES}; 
    InitCommonControlsEx(&ic);
    
    NONCLIENTMETRICSW ncm = {sizeof(ncm)}; 
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) 
        hAppFont = CreateFontIndirectW(&ncm.lfMenuFont);
    else 
        hAppFont = CreateFontW(16,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Microsoft YaHei");
    hLogFont = CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,0,0,L"Consolas");
    
    OpenLogViewer(FALSE); 
    
    // [Fix] 安全构造配置路径
    g_iniFilePath[0] = 0;
    if (wcslen(exePath) + 12 < MAX_PATH) {
        wcscpy_s(g_iniFilePath, MAX_PATH, exePath);
        wcscat_s(g_iniFilePath, MAX_PATH, L"\\set.ini");
    }
    
    LoadSettings(); 
    InitConfigTimestamp(); 
    ParseTags();
    
    g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    UpdateOnStartupSubscriptions();
    
    hConfigMonitorThread = (HANDLE)_beginthreadex(NULL, 0, ConfigMonitorThread, NULL, 0, NULL);
    
    WNDCLASSW wc = {0}; 
    wc.lpfnWndProc = WndProc; 
    wc.hInstance = hInst; 
    wc.lpszClassName = L"TrayProxyClass";
    wc.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(1)); 
    if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);
    
    hwnd = CreateWindowW(L"TrayProxyClass", L"App", 0,0,0,0,0, NULL,NULL,hInst,NULL);
    if (!RegisterHotKey(hwnd, ID_GLOBAL_HOTKEY, g_hotkeyModifiers, g_hotkeyVk)) {
        MessageBoxW(NULL, L"热键注册失败!", L"警告", MB_OK);
    }
    
    nid.cbSize = sizeof(nid); 
    nid.hWnd = hwnd; 
    nid.uID = 1; 
    nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP;
    nid.uCallbackMessage = WM_TRAY; 
    nid.hIcon = wc.hIcon; 
    
    if (wcscpy_s(nid.szTip, ARRAYSIZE(nid.szTip), L"Mandala Client") != 0) {
        nid.szTip[0] = 0;
    }
    
    if (g_hideTrayStart != 1) Shell_NotifyIconW(NIM_ADD, &nid);
    
    hAutoUpdateThread = CreateThread(NULL, 0, AutoUpdateThread, NULL, 0, NULL);
    
    if (wcslen(currentNode) > 0) {
        SwitchNode(currentNode);
    } else if (nodeCount > 0) {
        EnterCriticalSection(&g_configLock);
        // [Fix] 恢复 GetRealTagFromDisplay (3/2)
        // 自动连接第一个节点时，同样需要转换 Tag
        wchar_t* tag = _wcsdup(GetRealTagFromDisplay(nodeTags[0]));
        LeaveCriticalSection(&g_configLock); 
        SwitchNode(tag); 
        free(tag);
    }

    MSG msg; 
    while(GetMessage(&msg, NULL, 0, 0)) { 
        TranslateMessage(&msg); 
        DispatchMessage(&msg); 
    }
    
    BOOL bSafe = TRUE;
    if (IsSystemProxyEnabled()) SetSystemProxy(FALSE);
    if (g_hExitEvent) SetEvent(g_hExitEvent);
    StopProxyCore();
    
    if (!SafeWaitAndCloseThread(&hStartupThread, 5000)) bSafe = FALSE;
    if (!SafeWaitAndCloseThread(&hImportThread, 2000)) bSafe = FALSE;
    if (!SafeWaitAndCloseThread(&hConfigMonitorThread, 2000)) bSafe = FALSE;
    if (!SafeWaitAndCloseThread(&hAutoUpdateThread, 5000)) bSafe = FALSE;
    
    if (g_hExitEvent) CloseHandle(g_hExitEvent);
    
    if (bSafe) { 
        CleanupUtilsNet(); 
        cleanup_crypto_global(); 
        CleanupMemoryPool(); 
        DeleteGlobalLocks(); 
        WSACleanup(); 
    }
    
    if (hAppFont) DeleteObject(hAppFont);
    if (hLogFont) DeleteObject(hLogFont);
    if (hMutex) { ReleaseMutex(hMutex); CloseHandle(hMutex); }

    return 0;
}
