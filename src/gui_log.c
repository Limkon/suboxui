/* src/gui_log.c */
#include "gui.h"
#include "gui_utils.h"
#include "common.h"
#include "resource.h"
#include <wchar.h>
#include <commctrl.h> // 为了更标准的控件控制

// 日志等级定义
enum {
    LOG_LEVEL_ALL = 0,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
};

// 日志条目结构，用于历史回溯
typedef struct {
    int level;
    wchar_t* msg;
} LogEntry;

// 历史记录配置
#define MAX_LOG_HISTORY 500
static LogEntry s_logHistory[MAX_LOG_HISTORY] = {0};
static int s_logHead = 0;   // 下一个写入位置
static int s_logCount = 0;  // 当前存储数量
static int s_currentFilter = LOG_LEVEL_ALL; // 当前筛选等级

// 静态缓存：保存上一条日志的完整内容（含时间戳，为了界面可能需要重绘等情况，保留原样）
static wchar_t s_lastLogMsg[4096] = {0};

// 辅助函数：获取日志核心签名（跳过时间戳和动态变化的连接ID）
static const wchar_t* GetContentSignature(const wchar_t* msg) {
    if (!msg) return L"";
    
    const wchar_t* p = msg;

    // 1. 跳过时间戳 [HH:MM:SS] (固定长度 11 字符)
    if (wcslen(msg) > 11 && msg[0] == L'[' && msg[3] == L':' && msg[6] == L':' && msg[9] == L']') {
        p = msg + 11;
    }

    // 2. 检测并跳过 [Conn-XXX] ID 部分
    if (wcsncmp(p, L"[Conn-", 6) == 0) {
        const wchar_t* close_bracket = wcschr(p, L']');
        if (close_bracket) {
            return close_bracket + 1;
        }
    }

    return p;
}

// 辅助函数：解析日志等级
static int ParseLogLevel(const wchar_t* msg) {
    if (!msg) return LOG_LEVEL_INFO;
    
    // 简单关键词匹配，可根据实际日志格式调整
    // 注意：匹配项需与 utils.h 中的 LOG_XXX 宏定义一致
    if (wcsstr(msg, L"[ERR") || wcsstr(msg, L"Error") || wcsstr(msg, L"ERROR")) return LOG_LEVEL_ERROR;
    if (wcsstr(msg, L"[WRN") || wcsstr(msg, L"Warn") || wcsstr(msg, L"WARN")) return LOG_LEVEL_WARN;
    if (wcsstr(msg, L"[INF") || wcsstr(msg, L"Info") || wcsstr(msg, L"INFO")) return LOG_LEVEL_INFO;
    if (wcsstr(msg, L"[DBG") || wcsstr(msg, L"Debug") || wcsstr(msg, L"DEBUG")) return LOG_LEVEL_DEBUG;
    
    // 未匹配到标签的日志（如旧代码产生的），在"全部"模式下显示
    return LOG_LEVEL_ALL; 
}

// 辅助函数：向编辑框追加文本
static void AppendToLogView(HWND hEdit, const wchar_t* text) {
    int len = GetWindowTextLength(hEdit);
    // 保持原来的长度限制逻辑
    if (len > 20000) { 
        SendMessage(hEdit, EM_SETSEL, 0, 10000); 
        SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)L""); 
        len = GetWindowTextLength(hEdit);
    } 
    SendMessage(hEdit, EM_SETSEL, len, len); 
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)text); 
}

// 辅助函数：根据当前过滤器重绘整个日志视图
static void RefillLogView(HWND hEdit) {
    SendMessage(hEdit, WM_SETREDRAW, FALSE, 0); // 暂停重绘以防闪烁
    SetWindowTextW(hEdit, L""); // 清空

    int count = s_logCount;
    // 计算起始索引（环形缓冲区）
    int idx = (s_logHead - count + MAX_LOG_HISTORY) % MAX_LOG_HISTORY;

    for (int i = 0; i < count; i++) {
        if (s_logHistory[idx].msg && s_logHistory[idx].level >= s_currentFilter) {
            AppendToLogView(hEdit, s_logHistory[idx].msg);
        }
        idx = (idx + 1) % MAX_LOG_HISTORY;
    }

    SendMessage(hEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hEdit, NULL, TRUE);
}

// 辅助函数：安全复制宽字符串
static wchar_t* SafeWcsDup(const wchar_t* src) {
    if (!src) return NULL;
    size_t len = wcslen(src) + 1;
    wchar_t* dst = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (dst) wcscpy(dst, src);
    return dst;
}

LRESULT CALLBACK LogWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    static HWND hCombo;

    switch(msg) {
        case WM_CREATE: {
            // Checkbox: 开启日志记录
            CreateWindowW(L"BUTTON", L"开启日志记录", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 10, 5, 120, 20, hWnd, (HMENU)ID_LOG_CHK, NULL, NULL);
            SendMessage(GetDlgItem(hWnd, ID_LOG_CHK), BM_SETCHECK, g_enableLog ? BST_CHECKED : BST_UNCHECKED, 0);
            
            // Combobox: 日志等级筛选
            // Y坐标设置为1，预留空间给3D边框
            hCombo = CreateWindowW(L"COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL, 140, 1, 100, 200, hWnd, (HMENU)ID_LOG_LEVEL_COMBO, NULL, NULL);
            
            // 设置下拉框Item高度，使其总高度接近 28px (24内容 + 4边框)
            // 这提供了足够的垂直空间来与 Checkbox 对齐
            SendMessageW(hCombo, CB_SETITEMHEIGHT, (WPARAM)-1, (LPARAM)24);

            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"全部 (All)");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"调试 (Debug)");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"信息 (Info)");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"警告 (Warn)");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"错误 (Error)");
            SendMessageW(hCombo, CB_SETCURSEL, 0, 0); // 默认选全选
            SendMessageW(hCombo, WM_SETFONT, (WPARAM)hAppFont, 0);

            // Edit: 日志显示区
            hEdit = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY, 0, 30, 0, 0, hWnd, (HMENU)ID_LOGVIEWER_EDIT, NULL, NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hLogFont, 0); 
            
            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont);
            break;
        }
        case WM_SIZE: 
            MoveWindow(hEdit, 0, 30, LOWORD(lParam), HIWORD(lParam) - 30, TRUE); 
            break;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);

            // [修复] 避免局部变量遮蔽静态变量，重命名为 hCmb
            HWND hChk = GetDlgItem(hWnd, ID_LOG_CHK);
            HWND hCmb = GetDlgItem(hWnd, ID_LOG_LEVEL_COMBO);

            if (hChk && hCmb) {
                RECT rcCheck, rcCombo;
                
                // 获取“开启日志记录”的坐标
                GetWindowRect(hChk, &rcCheck);
                MapWindowPoints(NULL, hWnd, (LPPOINT)&rcCheck, 2);

                // 获取“日志等级下拉框”的坐标
                GetWindowRect(hCmb, &rcCombo);
                MapWindowPoints(NULL, hWnd, (LPPOINT)&rcCombo, 2);

                RECT rcDraw;
                // [重点] 垂直方向：直接使用下拉框的 Top 和 Bottom
                // 确保两个控件的边框在同一水平线上，且高度完全一致
                rcDraw.top = rcCombo.top;
                rcDraw.bottom = rcCombo.bottom;
                
                // 水平方向：基于 Checkbox，左右保留舒适的间距 (各扩展 8px)
                rcDraw.left = rcCheck.left - 8;
                rcDraw.right = rcCheck.right + 8;

                // 绘制立体突起边缘
                DrawEdge(hdc, &rcDraw, EDGE_RAISED, BF_RECT);
            }

            EndPaint(hWnd, &ps);
            return 0;
        }

        case WM_COMMAND: 
            if (LOWORD(wParam) == ID_LOG_CHK) {
                g_enableLog = (IsDlgButtonChecked(hWnd, ID_LOG_CHK) == BST_CHECKED); 
            }
            else if (LOWORD(wParam) == ID_LOG_LEVEL_COMBO && HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = (int)SendMessage(hCombo, CB_GETCURSEL, 0, 0);
                if (sel >= 0) {
                    // 映射 Combobox 索引到 Filter Level
                    switch(sel) {
                        case 0: s_currentFilter = LOG_LEVEL_ALL; break;
                        case 1: s_currentFilter = LOG_LEVEL_DEBUG; break;
                        case 2: s_currentFilter = LOG_LEVEL_INFO; break;
                        case 3: s_currentFilter = LOG_LEVEL_WARN; break;
                        case 4: s_currentFilter = LOG_LEVEL_ERROR; break;
                        default: s_currentFilter = LOG_LEVEL_ALL; break;
                    }
                    RefillLogView(hEdit);
                }
            }
            break;
        case WM_LOG_UPDATE: {
            wchar_t* p = (wchar_t*)lParam; 
            
            if (p) {
                // [优化] 智能去重逻辑
                const wchar_t* newContent = GetContentSignature(p);
                const wchar_t* oldContent = GetContentSignature(s_lastLogMsg);

                if (wcscmp(newContent, oldContent) == 0) {
                    free(p);
                    break; 
                }

                wcsncpy(s_lastLogMsg, p, (sizeof(s_lastLogMsg) / sizeof(wchar_t)) - 1);
                s_lastLogMsg[(sizeof(s_lastLogMsg) / sizeof(wchar_t)) - 1] = L'\0';
                
                // --- 保存到历史记录 ---
                int level = ParseLogLevel(p);
                
                if (s_logHistory[s_logHead].msg) {
                    free(s_logHistory[s_logHead].msg);
                    s_logHistory[s_logHead].msg = NULL;
                }
                
                s_logHistory[s_logHead].msg = SafeWcsDup(p);
                s_logHistory[s_logHead].level = level;
                
                s_logHead = (s_logHead + 1) % MAX_LOG_HISTORY;
                if (s_logCount < MAX_LOG_HISTORY) s_logCount++;
                
                // --- 根据当前过滤等级决定是否显示 ---
                if (level >= s_currentFilter) {
                    AppendToLogView(hEdit, p);
                }
            }
            
            free(p); break;
        }
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
        case WM_DESTROY: 
            // 清理历史记录内存
            for (int i = 0; i < MAX_LOG_HISTORY; i++) {
                if (s_logHistory[i].msg) {
                    free(s_logHistory[i].msg);
                    s_logHistory[i].msg = NULL;
                }
            }
            hLogViewerWnd = NULL; 
            break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

void OpenLogViewer(BOOL bShow) {
    if (hLogViewerWnd && IsWindow(hLogViewerWnd)) {
        if (bShow) { 
            ShowWindow(hLogViewerWnd, SW_SHOW); 
            SetForegroundWindow(hLogViewerWnd); 
        } 
        return;
    }
    
    WNDCLASSW wc = {0}; 
    if (!GetClassInfoW(GetModuleHandle(NULL), L"LogWnd", &wc)) {
        wc.lpfnWndProc = LogWndProc; 
        wc.hInstance = GetModuleHandle(NULL); 
        wc.lpszClassName = L"LogWnd"; 
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hIcon = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
        RegisterClassW(&wc);
    }
    
    hLogViewerWnd = CreateWindowW(L"LogWnd", L"运行日志", WS_OVERLAPPEDWINDOW, 
        CW_USEDEFAULT, 0, 600, 400, NULL, NULL, GetModuleHandle(NULL), NULL);
        
    if (bShow) ShowWindow(hLogViewerWnd, SW_SHOW);
}
