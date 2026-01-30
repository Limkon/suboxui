/* include/resource.h */
#ifndef RESOURCE_H
#define RESOURCE_H

#define IDI_APP_ICON 1

// 設置窗口控件 ID
#define ID_HOTKEY_CTRL      1101
#define ID_PORT_EDIT        1102
#define ID_CHK_CIPHERS      1103
// [Mod] ALPN 下拉列表 ID (替代原有的 Checkbox)
#define ID_COMBO_ALPN       1104
#define ID_CHK_FRAG         1105
#define ID_EDIT_FRAG_MIN    1106
#define ID_EDIT_FRAG_MAX    1107
#define ID_EDIT_FRAG_DLY    1108
#define ID_CHK_PADDING      1109
#define ID_EDIT_PAD_MIN     1110
#define ID_EDIT_PAD_MAX     1111
#define ID_COMBO_PLATFORM   1112
#define ID_EDIT_UA_STR      1113
// [Mod] ALPN 标签 ID
#define ID_STATIC_ALPN      1114

// 節點編輯窗口 ID
#define ID_EDIT_TAG         2201
#define ID_EDIT_ADDR        2202
#define ID_EDIT_PORT        2203
#define ID_EDIT_USER        2204
#define ID_EDIT_PASS        2205
#define ID_EDIT_NET         2206
#define ID_EDIT_TYPE        2207
#define ID_EDIT_HOST        2208
#define ID_EDIT_PATH        2209
#define ID_EDIT_TLS         2210
#define ID_EDIT_ECH_SNI     2050

// 節點管理與訂閱
#define ID_NODEMGR_LIST     3001
#define ID_NODEMGR_EDIT     3002
#define ID_NODEMGR_DEL      3003
#define ID_NODEMGR_SUB      2003

// 节点列表右键菜单 ID
#define ID_MENU_PIN_TOP     3010
#define ID_MENU_SORT_NAME   3011

// 订阅设置窗口新增 ID
#define IDC_GROUP_SUB_UPDATE    3100 // 分组框
#define IDC_RADIO_DAILY         3101 // 每天
#define IDC_RADIO_WEEKLY        3102 // 每周
#define IDC_RADIO_CUSTOM        3103 // 自定义
#define IDC_EDIT_CUSTOM_TIME    3104 // 自定义时间输入框
#define IDC_STATIC_CUSTOM_UNIT  3105 // 单位提示

// 日誌窗口
#define ID_LOG_CHK          4001
#define ID_LOGVIEWER_EDIT   4002
// [New] 日志等级下拉列表
#define ID_LOG_LEVEL_COMBO  4003

// [New] 托盘菜单 ID
#define ID_TRAY_EXIT            5001
#define ID_TRAY_SHOW_CONSOLE    5002
#define ID_TRAY_SETTINGS        5003
#define ID_TRAY_SYSTEM_PROXY    5004
#define ID_TRAY_AUTORUN         5005
#define ID_TRAY_IMPORT_CLIPBOARD 5006
#define ID_TRAY_MANAGE_NODES    5007
#define ID_TRAY_NODE_BASE       6000

#endif
