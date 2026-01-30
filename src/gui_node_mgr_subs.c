// 文件名: src/gui_node_mgr_subs.c
// 描述: 订阅管理 UI、编辑、更新线程逻辑
// [Fix] 2026: 优化 RefreshSubList，修正 ES_AUTOHSCROLL 拼写错误并解决闪烁问题
// [Mod] 2026: 增加右键菜单（全选/删除），支持批量删除

#include "gui_node_mgr_private.h"
#include <commctrl.h>

// 定义右键菜单命令 ID
#define ID_MENU_SUB_ALL 4501
#define ID_MENU_SUB_DEL 4502

HWND hListSubs = NULL;
HWND hSubUrl = NULL, hSubName = NULL, hSubCycle = NULL, hSubCustom = NULL;
HWND hSubBtnAddSave = NULL, hSubBtnDel = NULL, hSubBtnUpd = NULL, hSubBtnReset = NULL, hSubUnitLabel = NULL;
HWND hSubLabelUrl = NULL, hSubLabelCycle = NULL, hSubLabelName = NULL;

static int g_subEditingIndex = -1; 

static void GetCycleStr(int cycle, int interval, wchar_t* buf, int size) {
    if (cycle == UPDATE_MODE_DAILY) wcscpy_s(buf, size, L"每天");
    else if (cycle == UPDATE_MODE_WEEKLY) wcscpy_s(buf, size, L"每周");
    else if (cycle == UPDATE_MODE_ON_START) wcscpy_s(buf, size, L"启动"); 
    else if (cycle == UPDATE_MODE_MANUAL) wcscpy_s(buf, size, L"手动"); 
    else if (cycle == UPDATE_MODE_CUSTOM) swprintf_s(buf, size, L"每 %d 天", interval / 24); 
    else wcscpy_s(buf, size, L"每天");
}

static DWORD WINAPI ManualUpdateThread(LPVOID param) {
    HWND hWnd = (HWND)param;
    int count = UpdateAllSubscriptions(TRUE, FALSE); 
    if (IsWindow(hWnd)) PostMessage(hWnd, WM_UPDATE_FINISH, (WPARAM)count, 0);
    return 0;
}

DWORD WINAPI AutoUpdateThread(LPVOID lpParam) {
    Sleep(5000); 
    while (TRUE) {
        int updated = UpdateAllSubscriptions(FALSE, TRUE); 
        if (updated > 0) {
            HWND hMgr = FindWindowW(L"NodeMgr", NULL);
            if (hMgr && IsWindow(hMgr)) {
                PostMessage(hMgr, WM_REFRESH_NODELIST, 0, 0);
            }
        }
        Sleep(60000); 
    }
    return 0;
}

static void UpdateSubEditorUI(HWND hCombo, HWND hEditCustom, HWND hLabelUnit) {
    int sel = SendMessage(hCombo, CB_GETCURSEL, 0, 0);
    BOOL isCustom = (sel == UPDATE_MODE_CUSTOM); 
    ShowWindow(hEditCustom, isCustom ? SW_SHOW : SW_HIDE);
    ShowWindow(hLabelUnit, isCustom ? SW_SHOW : SW_HIDE);
}

static void LoadSubToEdit(int index) {
    if (index < 0 || index >= g_subCount) return;
    
    EnterCriticalSection(&g_configLock);
    char urlBuf[512], nameBuf[64];
    strncpy(urlBuf, g_subs[index].url, 511); urlBuf[511] = '\0';
    strncpy(nameBuf, g_subs[index].name, 63); nameBuf[63] = '\0';
    int cycle = g_subs[index].update_cycle;
    BOOL enabled = g_subs[index].enabled;
    LeaveCriticalSection(&g_configLock);

    SetWindowTextA(hSubUrl, urlBuf);
    wchar_t wName[64];
    MultiByteToWideChar(CP_UTF8, 0, nameBuf, -1, wName, 64);
    SetWindowTextW(hSubName, wName);

    SendMessage(hSubCycle, CB_SETCURSEL, cycle, 0);
    if (cycle == UPDATE_MODE_CUSTOM) {
        int days = g_subUpdateInterval / 24;
        if (days < 1) days = 1;
        wchar_t numBuf[16]; swprintf(numBuf, 16, L"%d", days);
        SetWindowTextW(hSubCustom, numBuf);
    }
    
    UpdateSubEditorUI(hSubCycle, hSubCustom, hSubUnitLabel);
    g_subEditingIndex = index;
    SetWindowTextW(hSubBtnAddSave, L"保存修改");
    EnableWindow(hSubBtnReset, TRUE);
    SetWindowTextW(hSubBtnReset, enabled ? L"禁用订阅" : L"启用订阅");
}

static void ResetSubEdit() {
    g_subEditingIndex = -1;
    SetWindowTextA(hSubUrl, "");
    SetWindowTextW(hSubName, L"");
    SendMessage(hSubCycle, CB_SETCURSEL, 0, 0);
    UpdateSubEditorUI(hSubCycle, hSubCustom, hSubUnitLabel);
    SetWindowTextW(hSubBtnAddSave, L"添加订阅");
    EnableWindow(hSubBtnReset, FALSE);
    SetWindowTextW(hSubBtnReset, L"禁用订阅");
    // [Fix] 多选模式下重置时不强制选中
    // ListView_SetItemState(hListSubs, -1, 0, LVIS_SELECTED);
}

void RefreshSubList(HWND hList) {
    if (!hList || !IsWindow(hList)) return;

    // [Fix] 同样在订阅列表刷新时禁用重绘，防止“变灰”
    SendMessage(hList, WM_SETREDRAW, FALSE, 0);

    ListView_DeleteAllItems(hList);
    
    EnterCriticalSection(&g_configLock);
    for (int i = 0; i < g_subCount; i++) {
        LVITEMW lvI = {0};
        lvI.mask = LVIF_TEXT; lvI.iItem = i;
        
        wchar_t wName[64];
        MultiByteToWideChar(CP_UTF8, 0, g_subs[i].name, -1, wName, 64);
        lvI.pszText = wName;
        ListView_InsertItem(hList, &lvI);
        
        wchar_t wUrl[512];
        MultiByteToWideChar(CP_UTF8, 0, g_subs[i].url, -1, wUrl, 512);
        ListView_SetItemText(hList, i, 1, wUrl);
        ListView_SetItemText(hList, i, 2, g_subs[i].enabled ? L"启用" : L"已禁用");
        
        wchar_t wCycle[64];
        GetCycleStr(g_subs[i].update_cycle, g_subUpdateInterval, wCycle, 64);
        ListView_SetItemText(hList, i, 3, wCycle);
    }
    LeaveCriticalSection(&g_configLock);

    // [Fix] 恢复重绘并使用 RDW_NOERASE 消除闪烁
    SendMessage(hList, WM_SETREDRAW, TRUE, 0);
    RedrawWindow(hList, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_FRAME | RDW_NOERASE);
}

void InitSubControls(HWND hParent, int x, int y, int w, int hListHeight) {
    // [Mod] 移除 LVS_SINGLESEL 以支持多选
    hListSubs = CreateWindowW(WC_LISTVIEWW, L"", 
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 
        x, y, w, hListHeight, hParent, (HMENU)ID_LIST_SUBS, GetModuleHandle(NULL), NULL);
    ListView_SetExtendedListViewStyle(hListSubs, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    SendMessage(hListSubs, WM_SETFONT, (WPARAM)hAppFont, TRUE);

    LVCOLUMNW lvc; 
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; 
    lvc.fmt = LVCFMT_CENTER;

    lvc.pszText = L"名称"; lvc.cx = 100;  ListView_InsertColumn(hListSubs, 0, &lvc); 
    lvc.pszText = L"订阅地址"; lvc.cx = 300; ListView_InsertColumn(hListSubs, 1, &lvc);
    lvc.pszText = L"状态"; lvc.cx = 60;  ListView_InsertColumn(hListSubs, 2, &lvc);
    lvc.pszText = L"更新周期"; lvc.cx = 100; ListView_InsertColumn(hListSubs, 3, &lvc);

    {
        RECT rcList; GetClientRect(hListSubs, &rcList);
        int listW = rcList.right - rcList.left;
        int dynamicW = listW - 260; 
        if (dynamicW > 50) ListView_SetColumnWidth(hListSubs, 1, dynamicW);
    }

    RefreshSubList(hListSubs);

    int yEdit = y + hListHeight + 10;
    int nameLabelW = 35;
    int nameInputW = 100; 
    int leftBlockW = nameLabelW + nameInputW;
    int midGap = 20;
    int urlLabelW = 35;
    int rightInputX = x + leftBlockW + midGap + urlLabelW; 
    int availableRightW = w - (rightInputX - x) - 5;
    if (availableRightW < 200) availableRightW = 200; 

    int xNameLabel = x;
    int xNameInput = x + nameLabelW;
    int xUrlLabel = x + leftBlockW + midGap;
    
    hSubLabelName = CreateWindowW(L"STATIC", L"名称:", WS_CHILD, xNameLabel, yEdit+4, nameLabelW, 20, hParent, NULL,NULL,NULL);
    hSubName = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, xNameInput, yEdit, nameInputW, 24, hParent, (HMENU)ID_SUB_NAME_EDIT, NULL,NULL);
    hSubLabelUrl = CreateWindowW(L"STATIC", L"地址:", WS_CHILD, xUrlLabel, yEdit+4, urlLabelW, 20, hParent, NULL,NULL,NULL);
    
    // [Fix] 修正 ES_AUTOHSCROLL 拼写错误
    hSubUrl = CreateWindowW(L"EDIT", NULL, WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, rightInputX, yEdit, availableRightW, 24, hParent, (HMENU)ID_SUB_URL_EDIT, NULL,NULL);
    
    int yBtns = yEdit + 30;
    hSubLabelCycle = CreateWindowW(L"STATIC", L"周期:", WS_CHILD, xNameLabel, yBtns+4, nameLabelW, 20, hParent, NULL,NULL,NULL);
    hSubCycle = CreateWindowW(WC_COMBOBOXW, L"", WS_CHILD|CBS_DROPDOWNLIST, xNameInput, yBtns, nameInputW, 120, hParent, (HMENU)ID_SUB_CYCLE_COMBO, NULL, NULL);
    SendMessage(hSubCycle, CB_ADDSTRING, 0, (LPARAM)L"每天");
    SendMessage(hSubCycle, CB_ADDSTRING, 0, (LPARAM)L"每周");
    SendMessage(hSubCycle, CB_ADDSTRING, 0, (LPARAM)L"自定义");
    SendMessage(hSubCycle, CB_ADDSTRING, 0, (LPARAM)L"启动"); 
    SendMessage(hSubCycle, CB_ADDSTRING, 0, (LPARAM)L"手动"); 
    SendMessage(hSubCycle, CB_SETCURSEL, 0, 0);

    int xCustom = xNameInput + nameInputW + 5;
    hSubCustom = CreateWindowW(L"EDIT", L"1", WS_CHILD|WS_BORDER|ES_NUMBER|ES_CENTER, xCustom, yBtns, 30, 24, hParent, (HMENU)ID_SUB_CUSTOM_EDIT, NULL, NULL);
    hSubUnitLabel = CreateWindowW(L"STATIC", L"天", WS_CHILD, xCustom + 35, yBtns+4, 20, 20, hParent, NULL,NULL,NULL);

    int btnGap = 5;
    int btnW = (availableRightW - (btnGap * 3)) / 4;
    if (btnW < 40) btnW = 40; 
    int btnX = rightInputX;

    hSubBtnReset   = CreateWindowW(L"BUTTON", L"禁用订阅", WS_CHILD, btnX, yBtns, btnW, 28, hParent, (HMENU)ID_SUB_BTN_RESET, NULL, NULL);
    btnX += btnW + btnGap;
    hSubBtnDel     = CreateWindowW(L"BUTTON", L"删除选中", WS_CHILD, btnX, yBtns, btnW, 28, hParent, (HMENU)ID_SUB_BTN_DEL, NULL, NULL);
    btnX += btnW + btnGap;
    hSubBtnAddSave = CreateWindowW(L"BUTTON", L"添加订阅", WS_CHILD, btnX, yBtns, btnW, 28, hParent, (HMENU)ID_SUB_BTN_ADD_SAVE, NULL, NULL);
    btnX += btnW + btnGap;
    
    int lastBtnW = availableRightW - (btnW * 3 + btnGap * 3);
    hSubBtnUpd     = CreateWindowW(L"BUTTON", L"立即更新", WS_CHILD, btnX, yBtns, lastBtnW, 28, hParent, (HMENU)ID_SUB_BTN_UPD, NULL, NULL);
}

void ShowSubControls(int cmdShow) {
    ShowWindow(hListSubs, cmdShow);
    ShowWindow(hSubUrl, cmdShow);
    ShowWindow(hSubName, cmdShow); 
    ShowWindow(hSubCycle, cmdShow);
    ShowWindow(hSubBtnAddSave, cmdShow);
    ShowWindow(hSubBtnDel, cmdShow);
    ShowWindow(hSubBtnUpd, cmdShow);
    ShowWindow(hSubBtnReset, cmdShow);
    ShowWindow(hSubLabelUrl, cmdShow);
    ShowWindow(hSubLabelName, cmdShow); 
    ShowWindow(hSubLabelCycle, cmdShow);
    
    if (cmdShow == SW_SHOW) UpdateSubEditorUI(hSubCycle, hSubCustom, hSubUnitLabel);
    else {
        ShowWindow(hSubCustom, SW_HIDE);
        ShowWindow(hSubUnitLabel, SW_HIDE);
    }
}

void HandleSubNotify(HWND hWnd, NMHDR* pnm) {
    if (pnm->idFrom == ID_LIST_SUBS) {
        if (pnm->code == LVN_ITEMCHANGED) {
            LPNMLISTVIEW pNMLV = (LPNMLISTVIEW)pnm;
            if ((pNMLV->uChanged & LVIF_STATE)) {
                BOOL isSelected = (pNMLV->uNewState & LVIS_SELECTED);
                // 多选模式下，只有当选中项且只选中一项时才加载编辑，否则重置
                if (isSelected && ListView_GetSelectedCount(hListSubs) == 1) {
                    LoadSubToEdit(pNMLV->iItem);
                } else if (ListView_GetSelectedCount(hListSubs) == 0) {
                    ResetSubEdit();
                } else if (ListView_GetSelectedCount(hListSubs) > 1) {
                    // 多选时清空编辑框，避免歧义
                    ResetSubEdit(); 
                }
            }
        }
        else if (pnm->code == NM_CLICK) {
            LPNMITEMACTIVATE pnmItem = (LPNMITEMACTIVATE)pnm;
            if (pnmItem->iItem == -1) {
                ResetSubEdit();
            }
        }
        else if (pnm->code == NM_RCLICK) { // [New] 右键菜单
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, ID_MENU_SUB_ALL, L"全选");
            
            if (ListView_GetSelectedCount(hListSubs) > 0) {
                AppendMenuW(hMenu, MF_STRING, ID_MENU_SUB_DEL, L"删除选中");
            } else {
                AppendMenuW(hMenu, MF_STRING | MF_GRAYED, ID_MENU_SUB_DEL, L"删除选中");
            }
            
            POINT pt; GetCursorPos(&pt);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
    }
}

BOOL HandleSubCommand(HWND hWnd, int id, int code) {
    if (id == ID_SUB_CYCLE_COMBO && code == CBN_SELCHANGE) {
        UpdateSubEditorUI(hSubCycle, hSubCustom, hSubUnitLabel);
        return TRUE;
    }
    else if (id == ID_MENU_SUB_ALL) { // [New] 全选处理
        ListView_SetItemState(hListSubs, -1, LVIS_SELECTED, LVIS_SELECTED);
        return TRUE;
    }
    else if (id == ID_SUB_BTN_RESET) {
        if (g_subEditingIndex != -1 && g_subEditingIndex < g_subCount) {
            EnterCriticalSection(&g_configLock);
            g_subs[g_subEditingIndex].enabled = !g_subs[g_subEditingIndex].enabled;
            LeaveCriticalSection(&g_configLock);
            SaveSettings();
            RefreshSubList(hListSubs);
            LoadSubToEdit(g_subEditingIndex); 
        }
        return TRUE;
    }
    else if (id == ID_SUB_BTN_ADD_SAVE) {
        wchar_t btnText[32];
        GetWindowTextW(hSubBtnAddSave, btnText, 32);
        if (wcscmp(btnText, L"添加订阅") == 0) {
            g_subEditingIndex = -1;
        }

        char newUrl[512]; GetWindowTextA(hSubUrl, newUrl, 512);
        TrimString(newUrl);
        
        wchar_t wNewName[64];
        GetWindowTextW(hSubName, wNewName, 64);
        char newName[256]; 
        WideCharToMultiByte(CP_UTF8, 0, wNewName, -1, newName, sizeof(newName), NULL, NULL);
        TrimString(newName);
        
        if (strlen(newUrl) < 4) { MessageBoxW(hWnd, L"请输入有效地址", L"错误", MB_OK); return TRUE; }

        int cycleMode = SendMessage(hSubCycle, CB_GETCURSEL, 0, 0);
        int days = GetDlgItemInt(hWnd, ID_SUB_CUSTOM_EDIT, NULL, FALSE);
        if (days < 1) days = 1;

        EnterCriticalSection(&g_configLock);
        int targetIdx = -1;
        
        if (g_subEditingIndex != -1 && g_subEditingIndex < g_subCount) {
            targetIdx = g_subEditingIndex;
        } else {
            if (g_subCount < MAX_SUBS) {
                targetIdx = g_subCount;
                g_subCount++;
                g_subs[targetIdx].enabled = TRUE;
            } else {
                MessageBoxW(hWnd, L"已达最大订阅限制", L"提示", MB_OK);
            }
        }
        
        if (targetIdx != -1) {
            strncpy(g_subs[targetIdx].url, newUrl, 511); g_subs[targetIdx].url[511] = '\0';
            g_subs[targetIdx].update_cycle = cycleMode;
            if (strlen(newName) > 0) strncpy(g_subs[targetIdx].name, newName, 63);
            else snprintf(g_subs[targetIdx].name, 64, "订阅 %d", targetIdx + 1);
            g_subs[targetIdx].name[63] = '\0';
        }
        
        if (cycleMode == UPDATE_MODE_CUSTOM) {
            g_subUpdateInterval = days * 24; 
        }
        LeaveCriticalSection(&g_configLock);

        SaveSettings();
        RefreshSubList(hListSubs);
        if (g_subEditingIndex == -1) ResetSubEdit(); 
        return TRUE;
    }
    else if (id == ID_SUB_BTN_DEL || id == ID_MENU_SUB_DEL) { // [Mod] 支持批量删除
        int selCount = ListView_GetSelectedCount(hListSubs);
        if (selCount > 0) {
            wchar_t msg[64];
            swprintf(msg, 64, L"确定删除选中的 %d 个订阅?", selCount);
            if (MessageBoxW(hWnd, msg, L"确认", MB_YESNO) == IDYES) {
                EnterCriticalSection(&g_configLock);
                // 倒序删除以避免索引移位问题
                for (int i = g_subCount - 1; i >= 0; i--) {
                    if (ListView_GetItemState(hListSubs, i, LVIS_SELECTED) & LVIS_SELECTED) {
                        for (int k = i; k < g_subCount - 1; k++) {
                            g_subs[k] = g_subs[k+1];
                        }
                        g_subCount--;
                    }
                }
                LeaveCriticalSection(&g_configLock);
                SaveSettings();
                RefreshSubList(hListSubs);
                ResetSubEdit();
            }
        }
        return TRUE;
    }
    else if (id == ID_SUB_BTN_UPD) {
        SaveSettings(); 
        SetWindowTextW(hSubBtnUpd, L"更新中...");
        EnableWindow(hSubBtnUpd, FALSE);
        CreateThread(NULL, 0, ManualUpdateThread, (LPVOID)hWnd, 0, NULL);
        return TRUE;
    }
    return FALSE;
}
