/* src/gui_node_mgr_routes.c */
// 文件名: src/gui_node_mgr_routes.c
// 状态: 已修复 (Fix: 增加 CloseAllActiveSockets 解决 Keep-Alive 导致规则不生效问题)
// 功能: 路由管理, 支持通配符(*), 修复内存崩溃

#include "gui_node_mgr_private.h"
#include "cJSON.h"
#include "utils.h"
#include "proxy.h" 
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>

// 定义右键菜单命令 ID
#define ID_MENU_ROUTE_ALL 4601
#define ID_MENU_ROUTE_DEL 4602

// --- 全局控件变量 ---
HWND hListRoutes = NULL;
HWND hRouteType = NULL, hRouteContent = NULL, hRouteOutbound = NULL;
HWND hBtnRouteAdd = NULL, hBtnRouteMod = NULL, hBtnRouteDel = NULL, hBtnRouteUp = NULL, hBtnRouteDown = NULL;
HWND hLabelRouteType = NULL, hLabelRouteContent = NULL, hLabelRouteOut = NULL;

// --- 排序状态变量 ---
// -1: 默认(按优先级), 0:优先级列(恢复默认), 1:类型, 2:内容, 3:策略
static int s_routeSortCol = -1; 
static BOOL s_routeSortAsc = TRUE;

// --- 路由缓存项结构 ---
typedef struct {
    int originalIndex;     // 核心：JSON 中的真实索引 (优先级)
    wchar_t type[32];
    wchar_t content[512];
    wchar_t outbound[32];
} RouteCacheItem;

// --- 辅助逻辑：通配符转正则 (写入时使用) ---
static void WildcardToRegex(const char* input, char* buffer) {
    char temp[512] = "regexp:";
    int j = 7; 
    int len = strlen(input);

    for (int i = 0; i < len; i++) {
        if (j >= 510) break; 
        if (input[i] == '*') {
            temp[j++] = '.'; temp[j++] = '*';
        } else if (input[i] == '.') {
            temp[j++] = '\\'; temp[j++] = '.';
        } else if (strchr("?+()[]{}|^$|", input[i])) {
            temp[j++] = '\\'; temp[j++] = input[i];
        } else {
            temp[j++] = input[i];
        }
    }
    temp[j] = '\0';
    strcpy(buffer, temp);
}

// --- 辅助逻辑：正则转通配符显示 (读取时使用) ---
// 功能：将 regexp:.*\.baidu\.com 转换为 *.baidu.com 以便人类阅读
static void FormatRouteDisplay(const char* input, wchar_t* output, int maxLen) {
    // 检查是否为正则格式
    if (strncmp(input, "regexp:", 7) == 0) {
        char temp[512];
        int j = 0;
        const char* src = input + 7; // 跳过 "regexp:"
        
        while (*src && j < 510) {
            // 还原 .* 为 *
            if (src[0] == '.' && src[1] == '*') {
                temp[j++] = '*';
                src += 2;
            }
            // 还原 \. 为 .
            else if (src[0] == '\\' && src[1] == '.') {
                temp[j++] = '.';
                src += 2;
            }
            // 还原其他转义字符 (如 \? -> ?)
            else if (src[0] == '\\') {
                src++; // 跳过反斜杠
                if (*src) temp[j++] = *src++;
            }
            else {
                temp[j++] = *src++;
            }
        }
        temp[j] = '\0';
        MultiByteToWideChar(CP_UTF8, 0, temp, -1, output, maxLen);
    } else {
        // 非正则格式，直接转换
        MultiByteToWideChar(CP_UTF8, 0, input, -1, output, maxLen);
    }
}

// --- 辅助：读取与保存 JSON ---
static cJSON* LoadConfigJson(char** outBuffer) {
    long size = 0;
    if (ReadFileToBuffer(CONFIG_FILE, outBuffer, &size)) {
        return cJSON_Parse(*outBuffer);
    }
    return NULL;
}

static void SaveConfigJson(cJSON* root) {
    if (!root) return;
    char* out = cJSON_Print(root);
    if (out) {
        WriteBufferToFile(CONFIG_FILE, out);
        free(out);
    }
}

// --- 排序比较函数 ---
static int CompareRouteItems(const void* a, const void* b) {
    const RouteCacheItem* ra = (const RouteCacheItem*)a;
    const RouteCacheItem* rb = (const RouteCacheItem*)b;
    int cmp = 0;
    
    // Column 0: 优先级 (Original Index)
    if (s_routeSortCol == 0 || s_routeSortCol == -1) {
        cmp = (ra->originalIndex < rb->originalIndex) ? -1 : 1;
    }
    // Column 1: 类型
    else if (s_routeSortCol == 1) cmp = wcscmp(ra->type, rb->type);
    // Column 2: 内容
    else if (s_routeSortCol == 2) cmp = wcscmp(ra->content, rb->content);
    // Column 3: 策略
    else if (s_routeSortCol == 3) cmp = wcscmp(ra->outbound, rb->outbound);
    
    // 稳定性保证：如果主键相同，按优先级排序
    if (cmp == 0) {
        return (ra->originalIndex < rb->originalIndex) ? -1 : 1;
    }
    
    return s_routeSortAsc ? cmp : -cmp;
}

// --- 刷新路由列表 ---
void RefreshRouteList(HWND hList) {
    if (!hList || !IsWindow(hList)) return;

    SendMessage(hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(hList);

    EnterCriticalSection(&g_configLock);
    
    char* buffer = NULL;
    cJSON* root = LoadConfigJson(&buffer);
    RouteCacheItem* cache = NULL;
    int ruleCount = 0;

    if (root) {
        cJSON* routing = cJSON_GetObjectItem(root, "routing");
        cJSON* rules = cJSON_GetObjectItem(routing, "rules");
        
        if (cJSON_IsArray(rules)) {
            ruleCount = cJSON_GetArraySize(rules);
            if (ruleCount > 0) {
                cache = (RouteCacheItem*)malloc(ruleCount * sizeof(RouteCacheItem));
            }

            if (cache) {
                for (int i = 0; i < ruleCount; i++) {
                    cJSON* item = cJSON_GetArrayItem(rules, i);
                    if (!item) {
                        memset(&cache[i], 0, sizeof(RouteCacheItem));
                        continue; 
                    }

                    // 1. 记录原始索引 (这就是优先级)
                    cache[i].originalIndex = i;
                    
                    // 2. 解析其他字段
                    wcscpy(cache[i].type, L"未知");
                    wcscpy(cache[i].content, L"");
                    wcscpy(cache[i].outbound, L"默认");

                    cJSON* domains = cJSON_GetObjectItem(item, "domain");
                    cJSON* ips = cJSON_GetObjectItem(item, "ip");
                    cJSON* outTag = cJSON_GetObjectItem(item, "outboundTag");

                    if (domains && cJSON_GetArraySize(domains) > 0) {
                        wcscpy(cache[i].type, L"域名");
                        cJSON* first = cJSON_GetArrayItem(domains, 0);
                        if (first && first->valuestring) {
                            FormatRouteDisplay(first->valuestring, cache[i].content, 512);
                            if (cJSON_GetArraySize(domains) > 1) wcscat(cache[i].content, L", ...");
                        }
                    } else if (ips && cJSON_GetArraySize(ips) > 0) {
                        wcscpy(cache[i].type, L"IP");
                        cJSON* first = cJSON_GetArrayItem(ips, 0);
                        if (first && first->valuestring) {
                            MultiByteToWideChar(CP_UTF8, 0, first->valuestring, -1, cache[i].content, 512);
                        }
                    }

                    if (outTag && outTag->valuestring) {
                        MultiByteToWideChar(CP_UTF8, 0, outTag->valuestring, -1, cache[i].outbound, 32);
                    }
                }
            }
        }
        cJSON_Delete(root);
    }
    
    // 2. 排序 (仅影响 cache 数组的顺序，不影响 JSON)
    if (cache && ruleCount > 0 && s_routeSortCol != -1) {
        qsort(cache, ruleCount, sizeof(RouteCacheItem), CompareRouteItems);
    }

    // 3. 填充列表
    if (cache && ruleCount > 0) {
        wchar_t wIdx[16];
        for (int i = 0; i < ruleCount; i++) {
            swprintf(wIdx, 16, L"%d", cache[i].originalIndex + 1); // 显示为 1-based 序号

            LVITEMW lvI = {0};
            lvI.mask = LVIF_TEXT | LVIF_PARAM; 
            lvI.iItem = i;
            lvI.pszText = wIdx; // 第0列：优先级
            lvI.lParam = (LPARAM)cache[i].originalIndex; // 绑定真实索引，供删除/编辑使用
            
            ListView_InsertItem(hList, &lvI);
            ListView_SetItemText(hList, i, 1, cache[i].type);    // 第1列：类型
            ListView_SetItemText(hList, i, 2, cache[i].content); // 第2列：内容
            ListView_SetItemText(hList, i, 3, cache[i].outbound);// 第3列：策略
        }
        free(cache);
    }

    if (buffer) free(buffer);
    LeaveCriticalSection(&g_configLock);

    SendMessage(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, NULL, FALSE);
}

// --- 初始化控件 ---
void InitRouteControls(HWND hParent, int x, int y, int w, int hListHeight) {
    hListRoutes = CreateWindowW(WC_LISTVIEWW, L"", 
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 
        x, y, w, hListHeight, hParent, (HMENU)ID_LIST_ROUTES, GetModuleHandle(NULL), NULL);
    ListView_SetExtendedListViewStyle(hListRoutes, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    SendMessage(hListRoutes, WM_SETFONT, (WPARAM)hAppFont, TRUE);

    LVCOLUMNW lvc; 
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; 
    lvc.fmt = LVCFMT_CENTER;

    // Column 0: 优先级
    lvc.pszText = L"优先级"; lvc.cx = 60; ListView_InsertColumn(hListRoutes, 0, &lvc); 
    // Column 1: 类型
    lvc.pszText = L"类型"; lvc.cx = 80;  ListView_InsertColumn(hListRoutes, 1, &lvc); 
    // Column 2: 内容 (动态宽度)
    lvc.pszText = L"内容 (域名/IP)"; lvc.cx = 300; ListView_InsertColumn(hListRoutes, 2, &lvc);
    // Column 3: 策略
    lvc.pszText = L"策略"; lvc.cx = 100; ListView_InsertColumn(hListRoutes, 3, &lvc);

    RECT rcList; GetClientRect(hListRoutes, &rcList);
    int dynamicW = (rcList.right - rcList.left) - 240; // 60+80+100 = 240
    if (dynamicW > 50) ListView_SetColumnWidth(hListRoutes, 2, dynamicW);

    RefreshRouteList(hListRoutes);

    // 计算下方控件位置
    int yEdit = y + hListHeight + 10;
    int hEdit = 24;
    int labelW = 40; int typeW = 80; int outW = 80; int btnW = 70; int gap = 10;
    int curX = x;

    hLabelRouteType = CreateWindowW(L"STATIC", L"类型:", WS_CHILD, curX, yEdit+4, labelW, 20, hParent, NULL, NULL, NULL); curX += labelW;
    hRouteType = CreateWindowW(WC_COMBOBOXW, L"", WS_CHILD | WS_BORDER | CBS_DROPDOWNLIST, curX, yEdit, typeW, 100, hParent, (HMENU)ID_ROUTE_TYPE, NULL, NULL);
    SendMessage(hRouteType, CB_ADDSTRING, 0, (LPARAM)L"域名");
    SendMessage(hRouteType, CB_ADDSTRING, 0, (LPARAM)L"IP");
    SendMessage(hRouteType, CB_SETCURSEL, 0, 0);

    curX += typeW + gap;
    hLabelRouteContent = CreateWindowW(L"STATIC", L"内容:", WS_CHILD, curX, yEdit+4, labelW, 20, hParent, NULL, NULL, NULL); curX += labelW;
    
    int rightControlsW = labelW + outW + gap + 10; 
    int contentW = w - (curX - x) - rightControlsW;
    hRouteContent = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, curX, yEdit, contentW, hEdit, hParent, (HMENU)ID_ROUTE_CONTENT, NULL, NULL);
    
    curX += contentW + gap;
    hLabelRouteOut = CreateWindowW(L"STATIC", L"策略:", WS_CHILD, curX, yEdit+4, labelW, 20, hParent, NULL, NULL, NULL); curX += labelW;
    hRouteOutbound = CreateWindowW(WC_COMBOBOXW, L"", WS_CHILD | WS_BORDER | CBS_DROPDOWNLIST, curX, yEdit, outW, 100, hParent, (HMENU)ID_ROUTE_OUTBOUND, NULL, NULL);
    SendMessage(hRouteOutbound, CB_ADDSTRING, 0, (LPARAM)L"proxy");
    SendMessage(hRouteOutbound, CB_ADDSTRING, 0, (LPARAM)L"direct");
    SendMessage(hRouteOutbound, CB_ADDSTRING, 0, (LPARAM)L"block");
    SendMessage(hRouteOutbound, CB_SETCURSEL, 0, 0);

    int yBtn = yEdit + hEdit + 10;
    // 5个按钮: 添加、修改、删除、上移、下移
    int totalBtnW = (btnW * 5) + (gap * 4);
    int startBtnX = x + (w - totalBtnW) / 2;

    hBtnRouteAdd = CreateWindowW(L"BUTTON", L"添加规则", WS_CHILD, startBtnX, yBtn, btnW, 30, hParent, (HMENU)ID_BTN_ROUTE_ADD, NULL, NULL); startBtnX += btnW + gap;
    hBtnRouteMod = CreateWindowW(L"BUTTON", L"修改选中", WS_CHILD, startBtnX, yBtn, btnW, 30, hParent, (HMENU)ID_BTN_ROUTE_MOD, NULL, NULL); startBtnX += btnW + gap;
    hBtnRouteDel = CreateWindowW(L"BUTTON", L"删除选中", WS_CHILD, startBtnX, yBtn, btnW, 30, hParent, (HMENU)ID_BTN_ROUTE_DEL, NULL, NULL); startBtnX += btnW + gap;
    hBtnRouteUp = CreateWindowW(L"BUTTON", L"上移", WS_CHILD, startBtnX, yBtn, btnW, 30, hParent, (HMENU)ID_BTN_ROUTE_UP, NULL, NULL); startBtnX += btnW + gap;
    hBtnRouteDown = CreateWindowW(L"BUTTON", L"下移", WS_CHILD, startBtnX, yBtn, btnW, 30, hParent, (HMENU)ID_BTN_ROUTE_DOWN, NULL, NULL);
}

void ShowRouteControls(int cmdShow) {
    ShowWindow(hListRoutes, cmdShow);
    ShowWindow(hRouteType, cmdShow); ShowWindow(hLabelRouteType, cmdShow);
    ShowWindow(hRouteContent, cmdShow); ShowWindow(hLabelRouteContent, cmdShow);
    ShowWindow(hRouteOutbound, cmdShow); ShowWindow(hLabelRouteOut, cmdShow);
    ShowWindow(hBtnRouteAdd, cmdShow); 
    ShowWindow(hBtnRouteMod, cmdShow); 
    ShowWindow(hBtnRouteDel, cmdShow);
    ShowWindow(hBtnRouteUp, cmdShow); ShowWindow(hBtnRouteDown, cmdShow);
}

void HandleRouteNotify(HWND hWnd, NMHDR* pnm) {
    if (pnm->idFrom == ID_LIST_ROUTES) {
        if (pnm->code == NM_CLICK) {
            int sel = ListView_GetNextItem(hListRoutes, -1, LVNI_SELECTED);
            if (sel != -1) {
                // 选中列表项时，回填所有字段到输入框
                wchar_t buf[512];
                
                // 1. 回填类型
                ListView_GetItemText(hListRoutes, sel, 1, buf, 512);
                if (wcscmp(buf, L"IP") == 0) SendMessage(hRouteType, CB_SETCURSEL, 1, 0);
                else SendMessage(hRouteType, CB_SETCURSEL, 0, 0); 

                // 2. 回填内容
                ListView_GetItemText(hListRoutes, sel, 2, buf, 512); 
                SetWindowTextW(hRouteContent, buf);

                // 3. 回填策略
                ListView_GetItemText(hListRoutes, sel, 3, buf, 512);
                if (wcscmp(buf, L"direct") == 0) SendMessage(hRouteOutbound, CB_SETCURSEL, 1, 0);
                else if (wcscmp(buf, L"block") == 0) SendMessage(hRouteOutbound, CB_SETCURSEL, 2, 0);
                else SendMessage(hRouteOutbound, CB_SETCURSEL, 0, 0); 
            }
        }
        else if (pnm->code == LVN_COLUMNCLICK) { 
            NMLISTVIEW* pnmv = (NMLISTVIEW*)pnm;
            
            // 点击表头逻辑
            if (s_routeSortCol == pnmv->iSubItem) {
                if (s_routeSortAsc) {
                    s_routeSortAsc = FALSE; // 升序 -> 降序
                } else {
                    // 第三次点击或点击优先级列：取消排序，恢复默认
                    s_routeSortCol = -1; 
                    s_routeSortAsc = TRUE;
                }
            } else {
                s_routeSortCol = pnmv->iSubItem;
                s_routeSortAsc = TRUE;
            }
            RefreshRouteList(hListRoutes);
        }
        else if (pnm->code == NM_RCLICK) { 
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, ID_MENU_ROUTE_ALL, L"全选");
            
            if (ListView_GetSelectedCount(hListRoutes) > 0) {
                AppendMenuW(hMenu, MF_STRING, ID_MENU_ROUTE_DEL, L"删除选中");
            } else {
                AppendMenuW(hMenu, MF_STRING | MF_GRAYED, ID_MENU_ROUTE_DEL, L"删除选中");
            }
            
            POINT pt; GetCursorPos(&pt);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
    }
}

// 整数比较函数 (用于 qsort 降序排列索引)
static int CompareIntDesc(const void* a, const void* b) {
    return (*(int*)b - *(int*)a);
}

BOOL HandleRouteCommand(HWND hWnd, int id, int code) {
    if (id == ID_BTN_ROUTE_ADD || id == ID_BTN_ROUTE_MOD) { 
        BOOL isModify = (id == ID_BTN_ROUTE_MOD);
        int sel = -1;
        int originalIndex = -1;

        if (isModify) {
            sel = ListView_GetNextItem(hListRoutes, -1, LVNI_SELECTED);
            if (sel == -1) {
                MessageBoxW(hWnd, L"请先选择要修改的规则", L"提示", MB_OK);
                return TRUE;
            }
            // 获取真实索引
            LVITEMW lvI = {0};
            lvI.iItem = sel;
            lvI.mask = LVIF_PARAM;
            if (ListView_GetItem(hListRoutes, &lvI)) {
                originalIndex = (int)lvI.lParam;
            } else {
                return TRUE;
            }
        }

        char content[256];
        GetWindowTextA(hRouteContent, content, 256);
        TrimString(content);
        if (strlen(content) == 0) {
            MessageBoxW(hWnd, L"请输入域名或IP内容", L"提示", MB_OK);
            return TRUE;
        }

        int typeIdx = SendMessage(hRouteType, CB_GETCURSEL, 0, 0); 
        
        // IP/CIDR 校验
        if (typeIdx == 1) { 
             char* checkVal = content;
             if (strncmp(content, "ip:", 3) == 0) checkVal += 3;
             else if (strncmp(content, "cidr:", 5) == 0) checkVal += 5;
             
             if (!IsValidCidrOrIp(checkVal)) {
                 MessageBoxW(hWnd, L"IP 或 CIDR 格式无效。\n\n支持示例:\nIPv4: 192.168.1.1 或 192.168.0.0/16\nIPv6: 2001:db8::1 或 2001:db8::/32", L"输入错误", MB_ICONWARNING);
                 return TRUE;
             }
        }

        int outIdx = SendMessage(hRouteOutbound, CB_GETCURSEL, 0, 0);
        const char* outTagStr = (outIdx == 1) ? "direct" : ((outIdx == 2) ? "block" : "proxy");
        const char* typeKey = (typeIdx == 1) ? "ip" : "domain";

        char finalContent[512];
        // 如果是域名且包含通配符，自动转正则
        if (typeIdx == 0 && strchr(content, '*') != NULL) {
            WildcardToRegex(content, finalContent);
        } else {
            strcpy(finalContent, content);
        }

        EnterCriticalSection(&g_configLock);
        char* buffer = NULL;
        cJSON* root = LoadConfigJson(&buffer);
        if (root) {
            cJSON* routing = cJSON_GetObjectItem(root, "routing");
            if (!routing) routing = cJSON_AddObjectToObject(root, "routing");
            cJSON* rules = cJSON_GetObjectItem(routing, "rules");
            if (!rules) rules = cJSON_AddArrayToObject(routing, "rules");

            cJSON* targetRule = NULL;
            if (isModify && originalIndex >= 0) {
                targetRule = cJSON_GetArrayItem(rules, originalIndex);
                // 修改模式：清理旧的 domain/ip 字段
                if (targetRule) {
                    cJSON_DeleteItemFromObject(targetRule, "domain");
                    cJSON_DeleteItemFromObject(targetRule, "ip");
                }
            } else {
                // 添加模式：创建新对象
                targetRule = cJSON_CreateObject();
                cJSON_AddItemToArray(rules, targetRule);
            }

            if (targetRule) {
                // 设置通用字段
                if (cJSON_HasObjectItem(targetRule, "type")) cJSON_ReplaceItemInObject(targetRule, "type", cJSON_CreateString("field"));
                else cJSON_AddStringToObject(targetRule, "type", "field");

                if (cJSON_HasObjectItem(targetRule, "outboundTag")) cJSON_ReplaceItemInObject(targetRule, "outboundTag", cJSON_CreateString(outTagStr));
                else cJSON_AddStringToObject(targetRule, "outboundTag", outTagStr);
                
                // 设置内容字段 (domain or ip)
                const char* strArr[1];
                strArr[0] = finalContent;
                cJSON* contentList = cJSON_CreateStringArray(strArr, 1);
                cJSON_AddItemToObject(targetRule, typeKey, contentList);
            }
            
            SaveConfigJson(root);
            cJSON_Delete(root);
        }
        if (buffer) free(buffer);
        LeaveCriticalSection(&g_configLock);

        g_needReloadRoutes = TRUE;
        // [Fix] 立即同步内存中的路由规则
        ReloadRoutingRules(); 
        // [Fix] 强制断开当前所有连接，消除 Keep-Alive 导致的规则不生效问题
        CloseAllActiveSockets();
        
        RefreshRouteList(hListRoutes);
        if (!isModify) SetWindowTextW(hRouteContent, L""); // 仅在添加后清空
        return TRUE;
    }
    else if (id == ID_MENU_ROUTE_ALL) { 
        ListView_SetItemState(hListRoutes, -1, LVIS_SELECTED, LVIS_SELECTED);
        return TRUE;
    }
    else if (id == ID_BTN_ROUTE_DEL || id == ID_MENU_ROUTE_DEL) { 
        int selCount = ListView_GetSelectedCount(hListRoutes);
        if (selCount == 0) return TRUE;

        // 使用 lParam (originalIndex) 进行删除，不受 UI 排序影响
        int* indicesToDelete = (int*)malloc(selCount * sizeof(int));
        int count = 0;
        int iPos = ListView_GetNextItem(hListRoutes, -1, LVNI_SELECTED);
        while (iPos != -1) {
            LVITEMW lvI = {0};
            lvI.iItem = iPos;
            lvI.mask = LVIF_PARAM; 
            if (ListView_GetItem(hListRoutes, &lvI)) {
                indicesToDelete[count++] = (int)lvI.lParam;
            }
            iPos = ListView_GetNextItem(hListRoutes, iPos, LVNI_SELECTED);
        }

        // 降序排列索引，防止删除时后续索引前移
        qsort(indicesToDelete, count, sizeof(int), CompareIntDesc);

        EnterCriticalSection(&g_configLock);
        char* buffer = NULL;
        cJSON* root = LoadConfigJson(&buffer);
        if (root) {
            cJSON* rules = cJSON_GetObjectItem(cJSON_GetObjectItem(root, "routing"), "rules");
            if (rules) {
                for (int i = 0; i < count; i++) {
                    cJSON_DeleteItemFromArray(rules, indicesToDelete[i]);
                }
                SaveConfigJson(root);
            }
            cJSON_Delete(root);
        }
        if (buffer) free(buffer);
        free(indicesToDelete);
        LeaveCriticalSection(&g_configLock);

        g_needReloadRoutes = TRUE;
        // [Fix] 立即同步内存中的路由规则
        ReloadRoutingRules();
        // [Fix] 强制断开当前所有连接
        CloseAllActiveSockets();

        RefreshRouteList(hListRoutes);
        return TRUE;
    }
    else if (id == ID_BTN_ROUTE_UP || id == ID_BTN_ROUTE_DOWN) {
        // [Safety] 排序模式下禁止移动
        if (s_routeSortCol != -1) {
            MessageBoxW(hWnd, L"当前处于排序视图。\n\n为了防止意外破坏规则优先级，请先点击【优先级】表头恢复默认顺序，然后再进行上下移动操作。", L"操作受限", MB_OK | MB_ICONINFORMATION);
            return TRUE;
        }

        int sel = ListView_GetNextItem(hListRoutes, -1, LVNI_SELECTED);
        if (sel == -1) return TRUE;
        
        BOOL isUp = (id == ID_BTN_ROUTE_UP);
        if (isUp && sel == 0) return TRUE;

        EnterCriticalSection(&g_configLock);
        char* buffer = NULL;
        cJSON* root = LoadConfigJson(&buffer);
        int newSel = sel;
        if (root) {
            cJSON* rules = cJSON_GetObjectItem(cJSON_GetObjectItem(root, "routing"), "rules");
            int count = cJSON_GetArraySize(rules);
            
            if (rules && count > 1) {
                if (isUp && sel > 0) {
                    cJSON* item = cJSON_DetachItemFromArray(rules, sel);
                    cJSON_InsertItemInArray(rules, sel - 1, item);
                    newSel = sel - 1;
                } else if (!isUp && sel < count - 1) {
                    cJSON* item = cJSON_DetachItemFromArray(rules, sel);
                    cJSON_InsertItemInArray(rules, sel + 1, item);
                    newSel = sel + 1;
                }
                SaveConfigJson(root);
            }
            cJSON_Delete(root);
        }
        if (buffer) free(buffer);
        LeaveCriticalSection(&g_configLock);
        
        g_needReloadRoutes = TRUE;
        // [Fix] 立即同步内存中的路由规则
        ReloadRoutingRules();
        // [Fix] 强制断开当前所有连接
        CloseAllActiveSockets();

        RefreshRouteList(hListRoutes);
        ListView_SetItemState(hListRoutes, newSel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hListRoutes, newSel, FALSE);
        return TRUE;
    }

    return FALSE;
}
