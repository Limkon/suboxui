// 文件名: src/gui_node_mgr_nodes.c
// 描述: 节点列表 UI 逻辑 (虚拟列表 + 线程池 + 流量控制调度器)
// [Refactor] 2026: 引入任务调度器，限制最大并发数为 20
// [Safety Fix] 2026: 修复排序竞态风险，增加测速期间的 UI 锁定机制
// [Bug Fix] 2026: 修复全选删除后列表不刷新的问题 (移除 LVSICF_NOINVALIDATEALL)
// [UI] 2026: 为当前选中节点增加背景高亮 (NM_CUSTOMDRAW 修复版 - 天蓝色)
// [Logic] 点击测速 -> 锁定UI -> 入队 -> Timer轮询 -> 保持20并发 -> 全部完成 -> 解锁UI

#include "gui_node_mgr_private.h"
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"   
#include "config.h"  
#include "utils.h"   

// --- 外部函数引用 ---
extern void SwitchNode(const wchar_t* tag);
extern void UpdateNodeLatency(const wchar_t* tag, int latency);
extern int GetNodeLatency(const wchar_t* tag);
extern void GetNodeAddressInfo(const wchar_t* tag, char* outAddr, int addrLen, int* outPort); 
extern int BatchDeleteNodes(wchar_t** tagsToDelete, int count);
extern void ClearAllNodeLatency();
extern int BatchRemoveInvalidNodes();
extern wchar_t currentNode[256]; // [Added] 引用全局当前节点变量，用于判断高亮

// --- 宏定义 ---
#ifndef ID_MENU_SET_ACTIVE
#define ID_MENU_SET_ACTIVE 40012
#endif
#ifndef ID_MENU_CLEAR_LATENCY
#define ID_MENU_CLEAR_LATENCY  40010
#endif
#ifndef ID_MENU_REMOVE_INVALID
#define ID_MENU_REMOVE_INVALID 40011
#endif

// --- 测速并发配置 ---
#define MAX_CONCURRENT_TESTS 20  // 限制最大并发连接数
#define SCHEDULER_INTERVAL   100 // 调度器检查间隔 (ms)

// --- 全局变量 ---
HWND hListNodes = NULL;
HWND hBtnAdd = NULL, hBtnDel = NULL, hBtnEdit = NULL, hBtnUp = NULL, hBtnDown = NULL, hBtnTest = NULL;

static int s_sortCol = -1;
static BOOL s_sortAsc = TRUE;
static BOOL s_isTesting = FALSE; // [Safety] 测速状态锁，用于禁止排序

// --- 缓存结构 (虚拟列表的数据源) ---
typedef struct {
    wchar_t tag[256];
    wchar_t type[32];
    wchar_t addr[128];
    wchar_t latency[32];
    int latencyVal; 
} NodeCacheItem;

static NodeCacheItem* s_nodeCache = NULL;
static int s_cacheCount = 0;
static int s_cacheCapacity = 0;

// --- 待测速任务队列 (生产者-消费者模式) ---
typedef struct PendingTask {
    wchar_t tag[256];
    char address[256];
    int port;
    struct PendingTask* next;
} PendingTask;

static PendingTask* s_pPendingHead = NULL; // 待处理任务头
static PendingTask* s_pPendingTail = NULL; // 待处理任务尾
static CRITICAL_SECTION s_csPendingQueue;  // 保护待处理队列
static volatile LONG s_activeWorkers = 0;  // 当前正在运行的线程数
static UINT_PTR s_hSchedulerTimer = 0;     // 调度器定时器ID
static BOOL s_sysInited = FALSE;

// --- 辅助：调整缓存容量 ---
static void EnsureCacheCapacity(int count) {
    if (count > s_cacheCapacity) {
        int newCap = count + 1024; 
        NodeCacheItem* newPtr = (NodeCacheItem*)realloc(s_nodeCache, newCap * sizeof(NodeCacheItem));
        if (newPtr) {
            s_nodeCache = newPtr;
            s_cacheCapacity = newCap;
        }
    }
}

// --- 辅助：JSON索引项 ---
typedef struct {
    char* tag;
    cJSON* node;
} JsonIndexItem;

static int CompareJsonIndex(const void* a, const void* b) {
    return strcmp(((JsonIndexItem*)a)->tag, ((JsonIndexItem*)b)->tag);
}

// --- 核心：重建显示缓存 ---
static void RebuildNodeCache() {
    EnterCriticalSection(&g_configLock);

    char* buffer = NULL; 
    long size = 0;
    cJSON* root = NULL;
    cJSON* outbounds = NULL;

    if (ReadFileToBuffer(CONFIG_FILE, &buffer, &size)) {
        root = cJSON_Parse(buffer);
        free(buffer);
    }
    if (root) {
        outbounds = cJSON_GetObjectItem(root, "outbounds");
    }

    JsonIndexItem* indexArr = NULL;
    int jsonCount = 0;
    if (outbounds) {
        int arrSize = cJSON_GetArraySize(outbounds);
        if (arrSize > 0) {
            indexArr = (JsonIndexItem*)malloc(arrSize * sizeof(JsonIndexItem));
            if (indexArr) {
                cJSON* it = NULL;
                cJSON_ArrayForEach(it, outbounds) {
                    cJSON* t = cJSON_GetObjectItem(it, "tag");
                    if (t && t->valuestring) {
                        indexArr[jsonCount].tag = t->valuestring;
                        indexArr[jsonCount].node = it;
                        jsonCount++;
                    }
                }
                qsort(indexArr, jsonCount, sizeof(JsonIndexItem), CompareJsonIndex);
            }
        }
    }

    EnsureCacheCapacity(nodeCount);
    s_cacheCount = nodeCount;

    char tagUtf8[512];
    for (int i = 0; i < nodeCount; i++) {
        NodeCacheItem* item = &s_nodeCache[i];
        
        wcscpy(item->tag, nodeTags[i]);
        wcscpy(item->type, L"unknown");
        wcscpy(item->addr, L"?");
        wcscpy(item->latency, L"-");
        item->latencyVal = 999999;

        WideCharToMultiByte(CP_UTF8, 0, nodeTags[i], -1, tagUtf8, 512, NULL, NULL);
        
        cJSON* node = NULL;
        if (indexArr && jsonCount > 0) {
            JsonIndexItem key = { tagUtf8, NULL };
            JsonIndexItem* found = (JsonIndexItem*)bsearch(&key, indexArr, jsonCount, sizeof(JsonIndexItem), CompareJsonIndex);
            if (found) node = found->node;
        }

        if (node) {
            cJSON* type = cJSON_GetObjectItem(node, "type");
            if (type && type->valuestring) {
                MultiByteToWideChar(CP_UTF8, 0, type->valuestring, -1, item->type, 32);
            }

            cJSON* server = cJSON_GetObjectItem(node, "server");
            cJSON* port = cJSON_GetObjectItem(node, "server_port");
            char addrRaw[128] = {0};
            const char* host = (server && server->valuestring) ? server->valuestring : "?";
            int p = 0;
            if (port) {
                if (cJSON_IsNumber(port)) p = port->valueint;
                else if (cJSON_IsString(port)) p = atoi(port->valuestring);
            }
            snprintf(addrRaw, 128, "%s:%d", host, p);
            MultiByteToWideChar(CP_UTF8, 0, addrRaw, -1, item->addr, 128);

            cJSON* lat = cJSON_GetObjectItem(node, "latency");
            int latency = (lat) ? lat->valueint : -999;
            
            if (latency == -999) {
                wcscpy(item->latency, L"-");
                item->latencyVal = 999999;
            } else if (latency < 0) {
                wcscpy(item->latency, L"超时");
                item->latencyVal = 999990;
            } else {
                swprintf(item->latency, 32, L"%d ms", latency);
                item->latencyVal = latency;
            }
        }
    }

    if (indexArr) free(indexArr);
    if (root) cJSON_Delete(root);
    LeaveCriticalSection(&g_configLock);
}

// --- 排序相关 ---
static int CompareCacheItems(const void* a, const void* b) {
    const NodeCacheItem* ia = (const NodeCacheItem*)a;
    const NodeCacheItem* ib = (const NodeCacheItem*)b;
    
    int cmp = 0;
    if (s_sortCol == 0) cmp = _wcsicmp(ia->tag, ib->tag);
    else if (s_sortCol == 1) cmp = _wcsicmp(ia->type, ib->type);
    else if (s_sortCol == 2) cmp = _wcsicmp(ia->addr, ib->addr);
    else if (s_sortCol == 3) {
        if (ia->latencyVal < ib->latencyVal) cmp = -1;
        else if (ia->latencyVal > ib->latencyVal) cmp = 1;
        else cmp = 0;
    }
    
    return s_sortAsc ? cmp : -cmp;
}

static void SyncOrderFromCache() {
    if (s_cacheCount <= 0) return;
    
    EnterCriticalSection(&g_configLock);
    if (s_cacheCount != nodeCount) {
        LeaveCriticalSection(&g_configLock);
        return;
    }
    for (int i = 0; i < nodeCount; i++) {
        if (nodeTags[i]) free(nodeTags[i]);
    }
    for (int i = 0; i < s_cacheCount; i++) {
        nodeTags[i] = _wcsdup(s_nodeCache[i].tag);
    }
    SaveNodeOrder(nodeTags, nodeCount);
    LeaveCriticalSection(&g_configLock);
}

// --- 线程工作结构体 ---
typedef struct {
    wchar_t tag[256];
    char address[256];
    int port;
} WorkerTaskArgs;

// --- Worker Thread ---
static DWORD WINAPI PingWorkerThread(LPVOID lpParam) {
    WorkerTaskArgs* args = (WorkerTaskArgs*)lpParam;
    if (!args) {
        InterlockedDecrement(&s_activeWorkers);
        return 0;
    }

    // 执行测速 (阻塞)
    int latency = TcpPing(args->address, args->port, 3000); 
    UpdateNodeLatency(args->tag, latency);
    
    // 更新 UI 缓存
    // [Safety] 仅更新数据，不计算索引，避免因排序造成的索引偏差
    int updateIndex = -1;
    EnterCriticalSection(&g_configLock);
    if (s_nodeCache && s_cacheCount > 0) {
        for (int i = 0; i < s_cacheCount; i++) {
            if (wcscmp(s_nodeCache[i].tag, args->tag) == 0) {
                if (latency < 0) {
                    wcscpy(s_nodeCache[i].latency, L"超时");
                    s_nodeCache[i].latencyVal = 999990;
                } else {
                    swprintf(s_nodeCache[i].latency, 32, L"%d ms", latency);
                    s_nodeCache[i].latencyVal = latency;
                }
                updateIndex = i;
                break;
            }
        }
    }
    LeaveCriticalSection(&g_configLock);

    // 发送重绘请求
    if (updateIndex != -1 && IsWindow(hListNodes)) {
        ListView_RedrawItems(hListNodes, updateIndex, updateIndex);
    }

    free(args);
    
    // 任务完成，减少计数器
    InterlockedDecrement(&s_activeWorkers);
    return 0;
}

// --- 任务调度器 (Timer Callback) ---
VOID CALLBACK SchedulerTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    LONG active = InterlockedCompareExchange(&s_activeWorkers, 0, 0); // Read
    if (active >= MAX_CONCURRENT_TESTS) {
        return; 
    }

    int needed = MAX_CONCURRENT_TESTS - (int)active;
    EnterCriticalSection(&s_csPendingQueue);
    
    while (needed > 0 && s_pPendingHead) {
        PendingTask* task = s_pPendingHead;
        s_pPendingHead = task->next;
        if (!s_pPendingHead) s_pPendingTail = NULL;

        WorkerTaskArgs* args = (WorkerTaskArgs*)malloc(sizeof(WorkerTaskArgs));
        if (args) {
            wcscpy(args->tag, task->tag);
            strcpy(args->address, task->address);
            args->port = task->port;
            
            InterlockedIncrement(&s_activeWorkers);
            HANDLE hThread = CreateThread(NULL, 0, PingWorkerThread, args, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            } else {
                InterlockedDecrement(&s_activeWorkers);
                free(args);
            }
        }

        free(task);
        needed--;
    }

    if (s_pPendingHead == NULL) {
        LONG currentActive = InterlockedCompareExchange(&s_activeWorkers, 0, 0);
        if (currentActive == 0) {
            if (s_hSchedulerTimer) {
                KillTimer(NULL, s_hSchedulerTimer);
                s_hSchedulerTimer = 0;
            }
            s_isTesting = FALSE; 
            EnableWindow(hBtnTest, TRUE);
        }
    }
    
    LeaveCriticalSection(&s_csPendingQueue);
}

// --- 生产者：入队 ---
static void EnqueueTask(const wchar_t* tag, const char* addr, int port) {
    PendingTask* newTask = (PendingTask*)malloc(sizeof(PendingTask));
    if (!newTask) return;

    wcscpy(newTask->tag, tag);
    strncpy(newTask->address, addr, 255);
    newTask->address[255] = 0;
    newTask->port = port;
    newTask->next = NULL;

    EnterCriticalSection(&s_csPendingQueue);
    if (!s_pPendingHead) {
        s_pPendingHead = newTask;
        s_pPendingTail = newTask;
    } else {
        s_pPendingTail->next = newTask;
        s_pPendingTail = newTask;
    }
    LeaveCriticalSection(&s_csPendingQueue);
}

// --- 主刷新函数 ---
void RefreshNodeList(HWND hList) {
    if (!hList || !IsWindow(hList)) return;

    RebuildNodeCache();
    
    if (s_sortCol != -1) {
        qsort(s_nodeCache, s_cacheCount, sizeof(NodeCacheItem), CompareCacheItems);
    }

    ListView_SetItemCountEx(hList, s_cacheCount, 0);
    InvalidateRect(hList, NULL, FALSE);
}

// --- 初始化 ---
void InitNodeControls(HWND hParent, int x, int y, int w, int h, int btnY) {
    if (!s_sysInited) {
        InitializeCriticalSection(&s_csPendingQueue);
        s_sysInited = TRUE;
    }

    hListNodes = CreateWindowW(WC_LISTVIEWW, L"", 
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
        x, y, w, h, hParent, (HMENU)ID_LIST_NODES, GetModuleHandle(NULL), NULL);
    
    ListView_SetExtendedListViewStyle(hListNodes, 
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        
    SendMessage(hListNodes, WM_SETFONT, (WPARAM)hAppFont, TRUE);
    
    LVCOLUMNW lvc; 
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; 
    lvc.fmt = LVCFMT_CENTER;

    lvc.pszText = L"名称"; lvc.cx = 150; ListView_InsertColumn(hListNodes, 0, &lvc);
    lvc.pszText = L"类型"; lvc.cx = 80;  ListView_InsertColumn(hListNodes, 1, &lvc);
    lvc.pszText = L"地址"; lvc.cx = 250; ListView_InsertColumn(hListNodes, 2, &lvc);
    lvc.pszText = L"延迟"; lvc.cx = 80;  ListView_InsertColumn(hListNodes, 3, &lvc);
    
    RECT rcList; GetClientRect(hListNodes, &rcList);
    int listW = rcList.right - rcList.left;
    int dynamicW = listW - 310;
    if (dynamicW > 50) ListView_SetColumnWidth(hListNodes, 2, dynamicW);

    RefreshNodeList(hListNodes);

    int btnCount = 6;
    int gap = 5; 
    int availableW = w - 5;
    int btnW = (availableW - (gap * (btnCount - 1))) / btnCount;
    if (btnW < 40) btnW = 40; 

    int currentX = x;
    hBtnAdd  = CreateWindowW(L"BUTTON", L"添加/导入", WS_CHILD|WS_VISIBLE, currentX, btnY, btnW, 30, hParent, (HMENU)ID_BTN_ADD, NULL, NULL);
    currentX += btnW + gap;
    hBtnDel  = CreateWindowW(L"BUTTON", L"删除", WS_CHILD|WS_VISIBLE, currentX, btnY, btnW, 30, hParent, (HMENU)ID_BTN_DEL, NULL, NULL);
    currentX += btnW + gap;
    hBtnEdit = CreateWindowW(L"BUTTON", L"编辑", WS_CHILD|WS_VISIBLE, currentX, btnY, btnW, 30, hParent, (HMENU)ID_BTN_EDIT, NULL, NULL);
    currentX += btnW + gap;
    hBtnUp   = CreateWindowW(L"BUTTON", L"上移", WS_CHILD|WS_VISIBLE, currentX, btnY, btnW, 30, hParent, (HMENU)ID_BTN_UP, NULL, NULL);
    currentX += btnW + gap;
    hBtnDown = CreateWindowW(L"BUTTON", L"下移", WS_CHILD|WS_VISIBLE, currentX, btnY, btnW, 30, hParent, (HMENU)ID_BTN_DOWN, NULL, NULL);
    currentX += btnW + gap;
    int lastBtnW = availableW - (currentX - x);
    if (lastBtnW < 40) lastBtnW = btnW;
    hBtnTest = CreateWindowW(L"BUTTON", L"测速", WS_CHILD|WS_VISIBLE, currentX, btnY, lastBtnW, 30, hParent, (HMENU)ID_BTN_TEST, NULL, NULL);
}

void ShowNodeControls(int cmdShow) {
    ShowWindow(hListNodes, cmdShow);
    ShowWindow(hBtnAdd, cmdShow); ShowWindow(hBtnDel, cmdShow);
    ShowWindow(hBtnEdit, cmdShow); ShowWindow(hBtnUp, cmdShow);
    ShowWindow(hBtnDown, cmdShow); ShowWindow(hBtnTest, cmdShow);
}

// --- 事件处理 ---
void HandleGetDispInfo(NMLVDISPINFO* plvdi) {
    if (plvdi->item.iItem < 0 || plvdi->item.iItem >= s_cacheCount) return;

    NodeCacheItem* item = &s_nodeCache[plvdi->item.iItem];

    if (plvdi->item.mask & LVIF_TEXT) {
        switch (plvdi->item.iSubItem) {
            case 0: plvdi->item.pszText = item->tag; break;
            case 1: plvdi->item.pszText = item->type; break;
            case 2: plvdi->item.pszText = item->addr; break;
            case 3: plvdi->item.pszText = item->latency; break;
            default: break;
        }
    }
}

// [Mod] 2026: 修改返回值为 LRESULT 并正确处理 Custom Draw
LRESULT HandleNodeNotify(HWND hWnd, NMHDR* pnm) {
    if (pnm->idFrom == ID_LIST_NODES) {
        // [New] Custom Draw Logic: 高亮当前使用的节点
        if (pnm->code == NM_CUSTOMDRAW) {
             LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)pnm;
             switch (lplvcd->nmcd.dwDrawStage) {
                case CDDS_PREPAINT:
                    // 告诉系统我们需要对每个 Item 进行绘制前处理
                    return CDRF_NOTIFYITEMDRAW;
                    
                case CDDS_ITEMPREPAINT:
                    {
                        int i = (int)lplvcd->nmcd.dwItemSpec;
                        BOOL isCurrent = FALSE;
                        
                        // [Safety] 检查索引是否越界
                        if (s_nodeCache && i >= 0 && i < s_cacheCount) {
                             // 对比 tag，注意可能需要忽略大小写或完全匹配，这里使用完全匹配
                             if (wcscmp(s_nodeCache[i].tag, currentNode) == 0) {
                                 isCurrent = TRUE;
                             }
                        }
                        
                        if (isCurrent) {
                            // [Mod] 天蓝色背景 (Sky Blue: RGB(205, 240, 255))
                            lplvcd->clrTextBk = RGB(205, 240, 255); 
                            // [Mod] 深蓝色文字 (Dark Blue: RGB(0, 60, 180)) 增加对比度
                            lplvcd->clrText = RGB(0, 60, 180);
                            
                            // 告诉系统我们修改了字体/颜色，请使用新属性进行绘制
                            return CDRF_NEWFONT;
                        } else {
                            // 非当前节点，默认绘制
                            return CDRF_DODEFAULT;
                        }
                    }
                    
                default:
                    return CDRF_DODEFAULT;
             }
        }
        else if (pnm->code == LVN_GETDISPINFO) {
            HandleGetDispInfo((NMLVDISPINFO*)pnm);
        }
        else if (pnm->code == LVN_COLUMNCLICK) {
            if (s_isTesting) return 0;

            NMLISTVIEW* pnmv = (NMLISTVIEW*)pnm;
            if (s_sortCol == pnmv->iSubItem) s_sortAsc = !s_sortAsc;
            else { s_sortCol = pnmv->iSubItem; s_sortAsc = TRUE; }
            
            if (s_cacheCount > 0) {
                qsort(s_nodeCache, s_cacheCount, sizeof(NodeCacheItem), CompareCacheItems);
                SyncOrderFromCache();
                InvalidateRect(hListNodes, NULL, FALSE);
            }
        }
        else if (pnm->code == NM_RCLICK) {
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, ID_MENU_SET_ACTIVE, L"设为活动");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, ID_MENU_SELECT_ALL, L"全选");
            AppendMenuW(hMenu, MF_STRING, ID_MENU_PIN, L"置顶选中");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, ID_MENU_DEDUP, L"去重 (类型+SNI+端口)");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, ID_MENU_CLEAR_LATENCY, L"清除测速结果");
            AppendMenuW(hMenu, MF_STRING, ID_MENU_REMOVE_INVALID, L"移除无效节点");
            
            POINT pt; GetCursorPos(&pt);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
    }
    return 0; // 其他情况返回默认
}

// --- 按钮功能函数 ---
static void MoveNode(HWND hList, BOOL up) {
    if (s_isTesting) return;

    if (s_sortCol != -1) {
        MessageBoxW(GetParent(hList), L"请先取消排序（点击表头直到恢复默认顺序）再进行移动操作。", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }

    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel == -1) return;

    if (up && sel > 0) {
        NodeCacheItem temp = s_nodeCache[sel];
        s_nodeCache[sel] = s_nodeCache[sel-1];
        s_nodeCache[sel-1] = temp;
        SyncOrderFromCache();
        ListView_SetItemState(hList, sel-1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hList, sel-1, FALSE);
        InvalidateRect(hList, NULL, FALSE);
    }
    else if (!up && sel < s_cacheCount - 1) {
        NodeCacheItem temp = s_nodeCache[sel];
        s_nodeCache[sel] = s_nodeCache[sel+1];
        s_nodeCache[sel+1] = temp;
        SyncOrderFromCache();
        ListView_SetItemState(hList, sel+1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hList, sel+1, FALSE);
        InvalidateRect(hList, NULL, FALSE);
    }
}

static BOOL ParseCacheAddr(const wchar_t* wAddr, char* outHost, int maxHostLen, int* outPort) {
    if (!wAddr || !outHost || !outPort) return FALSE;
    wchar_t temp[256];
    wcsncpy(temp, wAddr, 255);
    temp[255] = 0;
    wchar_t* pColon = wcsrchr(temp, L':');
    if (pColon) {
        *pColon = 0; 
        *outPort = _wtoi(pColon + 1);
    } else {
        return FALSE;
    }
    WideCharToMultiByte(CP_UTF8, 0, temp, -1, outHost, maxHostLen, NULL, NULL);
    return TRUE;
}

static void TestSelectedNodes(HWND hList) {
    int selCount = ListView_GetSelectedCount(hList);
    if (selCount == 0) {
        MessageBoxW(GetParent(hList), L"请先选择要测速的节点", L"提示", MB_OK);
        return;
    }

    if (s_isTesting) return;

    if (s_hSchedulerTimer) {
        KillTimer(NULL, s_hSchedulerTimer);
        s_hSchedulerTimer = 0;
    }
    EnterCriticalSection(&s_csPendingQueue);
    while (s_pPendingHead) {
        PendingTask* t = s_pPendingHead;
        s_pPendingHead = t->next;
        free(t);
    }
    s_pPendingTail = NULL;
    LeaveCriticalSection(&s_csPendingQueue);

    s_isTesting = TRUE;
    EnableWindow(hBtnTest, FALSE);

    int i = -1;
    int minUpdateIdx = s_cacheCount, maxUpdateIdx = -1;

    EnterCriticalSection(&g_configLock); 
    while ((i = ListView_GetNextItem(hList, i, LVNI_SELECTED)) != -1) {
        if (i >= s_cacheCount) continue;
        
        NodeCacheItem* item = &s_nodeCache[i];
        char addr[256] = {0}; 
        int port = 0;
        
        if (ParseCacheAddr(item->addr, addr, 256, &port) && port > 0) {
            wcscpy(item->latency, L"等待中...");
            EnqueueTask(item->tag, addr, port);
            
            if (i < minUpdateIdx) minUpdateIdx = i;
            if (i > maxUpdateIdx) maxUpdateIdx = i;
        }
    }
    LeaveCriticalSection(&g_configLock);

    if (maxUpdateIdx >= minUpdateIdx) {
        ListView_RedrawItems(hList, minUpdateIdx, maxUpdateIdx);
    }

    s_hSchedulerTimer = SetTimer(NULL, 0, SCHEDULER_INTERVAL, SchedulerTimerProc);
    SchedulerTimerProc(NULL, 0, 0, 0);
}

static void BatchPinSelectedNodes(HWND hList) {
    if (s_isTesting) return; 

    int selCount = ListView_GetSelectedCount(hList);
    if (selCount == 0) return;

    wchar_t** selectedTags = (wchar_t**)malloc(selCount * sizeof(wchar_t*));
    int found = 0;
    int iPos = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    while (iPos != -1) {
        if (iPos < s_cacheCount) {
            selectedTags[found++] = _wcsdup(s_nodeCache[iPos].tag);
        }
        iPos = ListView_GetNextItem(hList, iPos, LVNI_SELECTED);
    }
    
    for (int i = found - 1; i >= 0; i--) {
        SetNodeToTop(selectedTags[i]);
        free(selectedTags[i]);
    }
    free(selectedTags);
    
    s_sortCol = -1; 
    RefreshNodeList(hList);
    ListView_EnsureVisible(hList, 0, FALSE);
}

static void SelectAllNodes(HWND hList) {
    ListView_SetItemState(hList, -1, LVIS_SELECTED, LVIS_SELECTED);
}

BOOL HandleNodeCommand(HWND hWnd, int id) {
    if (id == ID_MENU_SELECT_ALL) {
        SelectAllNodes(hListNodes);
        return TRUE;
    }
    else if (id == ID_MENU_SET_ACTIVE) {
        int sel = ListView_GetNextItem(hListNodes, -1, LVNI_SELECTED);
        if (sel != -1 && sel < s_cacheCount) {
            SwitchNode(s_nodeCache[sel].tag);
            InvalidateRect(hListNodes, NULL, FALSE);
        }
        return TRUE;
    }
    else if (id == ID_MENU_PIN) {
        BatchPinSelectedNodes(hListNodes);
        return TRUE;
    }
    else if (id == ID_MENU_DEDUP) {
        if (s_isTesting) return TRUE;

        if (MessageBoxW(hWnd, L"确定要进行去重操作吗？\n将根据类型、SNI和端口移除重复节点。", L"确认", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            int count = DeduplicateNodes();
            RefreshNodeList(hListNodes); 
            wchar_t msg[64];
            swprintf(msg, 64, L"已移除 %d 个重复节点。", count);
            MessageBoxW(hWnd, msg, L"完成", MB_OK);
        }
        return TRUE;
    }
    else if (id == ID_MENU_CLEAR_LATENCY) {
        if (s_isTesting) return TRUE;

        if (MessageBoxW(hWnd, L"确定要清除所有节点的测速结果吗？", L"确认", MB_YESNO | MB_ICONQUESTION) == IDYES) {
             ClearAllNodeLatency(); 
             RefreshNodeList(hListNodes);
        }
        return TRUE;
    }
    else if (id == ID_MENU_REMOVE_INVALID) {
        if (s_isTesting) return TRUE;

        if (MessageBoxW(hWnd, L"确定要移除所有 Ping 不通 (超时) 的节点吗？", L"确认", MB_YESNO | MB_ICONWARNING) == IDYES) {
             int removedCount = BatchRemoveInvalidNodes();
             if (removedCount > 0) {
                 RefreshNodeList(hListNodes);
                 wchar_t msg[128];
                 swprintf(msg, 128, L"已移除 %d 个无效节点。", removedCount);
                 MessageBoxW(hWnd, msg, L"完成", MB_OK);
             } else {
                 MessageBoxW(hWnd, L"未发现无效节点。", L"提示", MB_OK);
             }
        }
        return TRUE;
    }
    else if (id == ID_BTN_ADD) {
        if (s_isTesting) return TRUE;

        HMENU hSub = CreatePopupMenu();
        AppendMenuW(hSub, MF_STRING, 1, L"从剪贴板导入");
        POINT pt; GetCursorPos(&pt);
        int cmd = TrackPopupMenu(hSub, TPM_RETURNCMD, pt.x, pt.y, 0, hWnd, NULL);
        DestroyMenu(hSub);
        if (cmd == 1) SendMessage(GetParent(hWnd), WM_COMMAND, ID_TRAY_IMPORT_CLIPBOARD, 0); 
        return TRUE;
    }
    else if (id == ID_BTN_DEL) {
        if (s_isTesting) return TRUE;

        int selCount = ListView_GetSelectedCount(hListNodes);
        if (selCount > 0) {
            wchar_t confirmMsg[64];
            swprintf(confirmMsg, 64, L"确定删除选中的 %d 个节点?", selCount);
            if (MessageBoxW(hWnd, confirmMsg, L"确认", MB_YESNO) == IDYES) {
                wchar_t** tagsToDelete = (wchar_t**)malloc(selCount * sizeof(wchar_t*));
                int idx = -1;
                int count = 0;
                while((idx = ListView_GetNextItem(hListNodes, idx, LVNI_SELECTED)) != -1) {
                    if (idx < s_cacheCount) {
                        tagsToDelete[count++] = _wcsdup(s_nodeCache[idx].tag);
                    }
                }
                BatchDeleteNodes(tagsToDelete, count);
                for(int i = 0; i < count; i++) free(tagsToDelete[i]);
                free(tagsToDelete);
                RefreshNodeList(hListNodes);
            }
        }
        return TRUE;
    }
    else if (id == ID_BTN_EDIT) {
        int sel = ListView_GetNextItem(hListNodes, -1, LVNI_SELECTED);
        if (sel != -1 && sel < s_cacheCount) {
            OpenNodeEditWindow(s_nodeCache[sel].tag); 
        }
        return TRUE;
    }
    else if (id == ID_BTN_UP) { MoveNode(hListNodes, TRUE); return TRUE; }
    else if (id == ID_BTN_DOWN) { MoveNode(hListNodes, FALSE); return TRUE; }
    else if (id == ID_BTN_TEST) { TestSelectedNodes(hListNodes); return TRUE; }

    return FALSE;
}

void CleanupNodeManagerNodes() {
    if (s_hSchedulerTimer) {
        KillTimer(NULL, s_hSchedulerTimer);
        s_hSchedulerTimer = 0;
    }
    
    EnterCriticalSection(&s_csPendingQueue);
    while (s_pPendingHead) {
        PendingTask* t = s_pPendingHead;
        s_pPendingHead = t->next;
        free(t);
    }
    s_pPendingTail = NULL;
    LeaveCriticalSection(&s_csPendingQueue);
}
