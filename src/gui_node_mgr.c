// 文件名: src/gui_node_mgr.c
// 描述: Node Manager 主窗口入口、Tab 管理、消息分发
// [Mod] 2026: 增加路由(Routes)管理标签页
// [Mod] 2026: 移除订阅更新完成后的弹窗
// [Mod] 2026: 完善 WM_NOTIFY 分发，支持 Custom Draw 返回值

#include "gui_node_mgr_private.h"

HWND hNodeMgrWnd = NULL;
static HWND hTabCtrl = NULL;

// --- 标签页切换逻辑 ---
static void SwitchTab(int index) {
    BOOL showNode = (index == 0);
    BOOL showSub = (index == 1);
    BOOL showRoute = (index == 2); // [New] 路由页索引
    
    ShowNodeControls(showNode ? SW_SHOW : SW_HIDE);
    ShowSubControls(showSub ? SW_SHOW : SW_HIDE);
    ShowRouteControls(showRoute ? SW_SHOW : SW_HIDE); // [New] 显示路由控件
}

// --- 窗口过程 ---

LRESULT CALLBACK NodeMgrProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
    case WM_CREATE:
        {
            RECT rcClient; GetClientRect(hWnd, &rcClient);
            hTabCtrl = CreateWindowW(WC_TABCONTROLW, L"", 
                WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE, 
                0, 0, rcClient.right, rcClient.bottom, 
                hWnd, (HMENU)ID_TAB_CTRL, GetModuleHandle(NULL), NULL);
            SendMessage(hTabCtrl, WM_SETFONT, (WPARAM)hAppFont, TRUE);

            TCITEMW tie; tie.mask = TCIF_TEXT;
            // [Tab 0]
            tie.pszText = L"节点列表"; TabCtrl_InsertItem(hTabCtrl, 0, &tie);
            // [Tab 1]
            tie.pszText = L"订阅管理"; TabCtrl_InsertItem(hTabCtrl, 1, &tie);
            // [Tab 2] [New] 在此处添加路由标签
            tie.pszText = L"路由设置"; TabCtrl_InsertItem(hTabCtrl, 2, &tie); 

            RECT rcPage; GetClientRect(hTabCtrl, &rcPage);
            TabCtrl_AdjustRect(hTabCtrl, FALSE, &rcPage);
            
            int x = rcPage.left + 5;
            int y = rcPage.top + 5;
            int w = rcPage.right - rcPage.left - 10;
            int h = rcPage.bottom - rcPage.top - 50; 
            int btnY = y + h + 10;

            // 1. 初始化 Node Tab 控件
            InitNodeControls(hWnd, x, y, w, h, btnY);
            
            // 2. 初始化 Sub Tab 控件
            int hSubListArea = h - 65;
            InitSubControls(hWnd, x, y, w, hSubListArea);

            // 3. 初始化 Route Tab 控件 [New]
            InitRouteControls(hWnd, x, y, w, hSubListArea);

            // 设置字体
            EnumChildWindows(hWnd, EnumSetFont, (LPARAM)hAppFont);

            SwitchTab(0);
        }
        break;

    case WM_NOTIFY:
        {
            NMHDR* pnm = (NMHDR*)lParam;
            if (pnm->idFrom == ID_TAB_CTRL && pnm->code == TCN_SELCHANGE) {
                SwitchTab(TabCtrl_GetCurSel(hTabCtrl));
            }
            else {
                // [Mod] 优先处理节点列表消息，如果 HandleNodeNotify 返回非 0 (例如 Custom Draw 需要)，则直接返回给系统
                LRESULT resNode = HandleNodeNotify(hWnd, pnm);
                if (resNode != 0) {
                    return resNode;
                }

                // 其他模块目前不需要返回值，照常调用
                HandleSubNotify(hWnd, pnm);
                HandleRouteNotify(hWnd, pnm); 
            }
        }
        break;
        
    case WM_REFRESH_NODELIST:
        RefreshNodeList(hListNodes);
        break;
    
    case WM_UPDATE_FINISH: {
        // 更新完成回调
        EnableWindow(hSubBtnUpd, TRUE);
        SetWindowTextW(hSubBtnUpd, L"立即更新");
        
        RefreshSubList(hListSubs);
        RefreshNodeList(hListNodes); // 同时刷新节点列表
        break;
    }

    case WM_COMMAND:
        {
            int id = LOWORD(wParam);
            int code = HIWORD(wParam);

            // 分发命令到各个子模块
            // 如果某一个模块处理了该命令，返回 TRUE，跳出 break
            if (HandleNodeCommand(hWnd, id)) break;
            if (HandleSubCommand(hWnd, id, code)) break;
            if (HandleRouteCommand(hWnd, id, code)) break; 
        }
        break;
        
    case WM_CLOSE:
        // 清理资源
        DestroyWindow(hWnd);
        hNodeMgrWnd = NULL;
        break;
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

void OpenNodeManager() {
    if (hNodeMgrWnd) {
        SetForegroundWindow(hNodeMgrWnd);
        return;
    }
    
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = NodeMgrProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"NodeMgr";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.hIcon = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    RegisterClassW(&wc);
    
    // 稍微增加默认高度以容纳底部控件
    hNodeMgrWnd = CreateWindowW(L"NodeMgr", L"节点与订阅管理", WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 540, NULL, NULL, wc.hInstance, NULL);
        
    ShowWindow(hNodeMgrWnd, SW_SHOW);
}
