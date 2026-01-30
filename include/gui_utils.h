#ifndef GUI_UTILS_H
#define GUI_UTILS_H

// [Fix] 必须先包含 winsock2.h
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>

// 字体回调
BOOL CALLBACK EnumSetFont(HWND hWnd, LPARAM lParam);

// UTF-8 文本设置辅助
void SetDlgItemTextUtf8(HWND hDlg, int nIDDlgItem, const char* lpString);

// 从显示名称获取真实 Tag (去除 "★ " 前缀)
const wchar_t* GetRealTagFromDisplay(const wchar_t* displayTag);

// ComboBox 添加项辅助
void AddComboItem(HWND hCombo, const wchar_t* text, BOOL select);

#endif // GUI_UTILS_H
