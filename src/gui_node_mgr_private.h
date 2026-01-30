/* src/gui_node_mgr_private.h */
// 文件名: src/gui_node_mgr_private.h
// 描述: 节点管理器内部共享定义 (宏、变量声明、函数原型)

#ifndef GUI_NODE_MGR_PRIVATE_H
#define GUI_NODE_MGR_PRIVATE_H

#include "gui.h"
#include "gui_utils.h"
#include "config.h"
#include "utils.h"
#include "resource.h"
#include "common.h"
#include <commctrl.h>
#include <stdio.h>
#include <wchar.h>

// --- 控件 ID 定义 ---
#define ID_TAB_CTRL         3000

// 节点管理页 ID
#define ID_LIST_NODES       3001
#define ID_BTN_ADD          3002
#define ID_BTN_DEL          3003
#define ID_BTN_EDIT         3004
#define ID_BTN_UP           3005
#define ID_BTN_DOWN         3006
#define ID_BTN_TEST         3007

// 右键菜单 ID
#define ID_MENU_SELECT_ALL  3201
#define ID_MENU_PIN         3202
#define ID_MENU_DEDUP       3203

// 订阅管理页 ID
#define ID_LIST_SUBS        3101
#define ID_SUB_URL_EDIT     3102
#define ID_SUB_CYCLE_COMBO  3103
#define ID_SUB_CUSTOM_EDIT  3104
#define ID_SUB_BTN_ADD_SAVE 3105
#define ID_SUB_BTN_DEL      3106
#define ID_SUB_BTN_UPD      3107
#define ID_SUB_BTN_RESET    3108
#define ID_SUB_UNIT_LABEL   3109
#define ID_SUB_NAME_EDIT    3110

// [New] 路由管理页 ID
#define ID_LIST_ROUTES      3301
#define ID_ROUTE_TYPE       3302
#define ID_ROUTE_CONTENT    3303
#define ID_ROUTE_OUTBOUND   3304
#define ID_BTN_ROUTE_ADD    3305
#define ID_BTN_ROUTE_DEL    3306
#define ID_BTN_ROUTE_UP     3307
#define ID_BTN_ROUTE_DOWN   3308
#define ID_BTN_ROUTE_MOD    3309 // [New] 修改按钮 ID

// 自定义消息
#define WM_UPDATE_FINISH    (WM_USER + 200)

// --- 全局变量声明 (在各子模块中定义) ---
extern HWND hNodeMgrWnd;

// Node 模块全局变量
extern HWND hListNodes;
extern HWND hBtnAdd, hBtnDel, hBtnEdit, hBtnUp, hBtnDown, hBtnTest;

// Sub 模块全局变量
extern HWND hListSubs;
extern HWND hSubUrl, hSubName, hSubCycle, hSubCustom, hSubBtnAddSave, hSubBtnDel, hSubBtnUpd, hSubBtnReset, hSubUnitLabel;
extern HWND hSubLabelUrl, hSubLabelCycle, hSubLabelName;

// [New] Route 模块全局变量
extern HWND hListRoutes;
extern HWND hRouteType, hRouteContent, hRouteOutbound;
extern HWND hBtnRouteAdd, hBtnRouteMod, hBtnRouteDel, hBtnRouteUp, hBtnRouteDown; // [Mod] 增加 hBtnRouteMod
extern HWND hLabelRouteType, hLabelRouteContent, hLabelRouteOut;

// --- 函数原型 ---

// Nodes 模块 (gui_node_mgr_nodes.c)
// [Mod] 2026: 修改返回值为 LRESULT 以支持 Custom Draw
void InitNodeControls(HWND hParent, int x, int y, int w, int h, int btnY);
void RefreshNodeList(HWND hList);
BOOL HandleNodeCommand(HWND hWnd, int id);
LRESULT HandleNodeNotify(HWND hWnd, NMHDR* pnm);
void ShowNodeControls(int cmdShow);

// Subs 模块 (gui_node_mgr_subs.c)
void InitSubControls(HWND hParent, int x, int y, int w, int hListHeight);
void RefreshSubList(HWND hList);
BOOL HandleSubCommand(HWND hWnd, int id, int code);
void HandleSubNotify(HWND hWnd, NMHDR* pnm);
void ShowSubControls(int cmdShow);
DWORD WINAPI AutoUpdateThread(LPVOID lpParam); 

// [New] Routes 模块 (gui_node_mgr_routes.c)
void InitRouteControls(HWND hParent, int x, int y, int w, int hListHeight);
void RefreshRouteList(HWND hList);
BOOL HandleRouteCommand(HWND hWnd, int id, int code);
void HandleRouteNotify(HWND hWnd, NMHDR* pnm);
void ShowRouteControls(int cmdShow);

#endif // GUI_NODE_MGR_PRIVATE_H
