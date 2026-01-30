#include "gui_utils.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>

// --- 辅助：字体回调 ---
BOOL CALLBACK EnumSetFont(HWND hWnd, LPARAM lParam) {
    SendMessageW(hWnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

// --- 辅助：UTF-8 文本设置函数 (解决乱码) ---
void SetDlgItemTextUtf8(HWND hDlg, int nIDDlgItem, const char* lpString) {
    if (!lpString) {
        SetDlgItemTextW(hDlg, nIDDlgItem, L"");
        return;
    }
    int wLen = MultiByteToWideChar(CP_UTF8, 0, lpString, -1, NULL, 0);
    if (wLen > 0) {
        wchar_t* wBuf = (wchar_t*)malloc((wLen + 1) * sizeof(wchar_t));
        if (wBuf) {
            MultiByteToWideChar(CP_UTF8, 0, lpString, -1, wBuf, wLen);
            wBuf[wLen] = 0;
            SetDlgItemTextW(hDlg, nIDDlgItem, wBuf);
            free(wBuf);
        }
    } else {
        SetDlgItemTextW(hDlg, nIDDlgItem, L"");
    }
}

// --- 辅助：从显示名称获取真实 Tag (去除 "★ " 前缀) ---
// 返回的指针可能是原指针偏移，也可能是原指针，调用者无需释放新内存
const wchar_t* GetRealTagFromDisplay(const wchar_t* displayTag) {
    if (!displayTag) return NULL;
    // 检查是否以 "★ " (L"\u2605 ") 开头
    if (displayTag[0] == L'★' && displayTag[1] == L' ') {
        return displayTag + 2;
    }
    return displayTag;
}

void AddComboItem(HWND hCombo, const wchar_t* text, BOOL select) {
    int idx = SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)text);
    if (select) SendMessage(hCombo, CB_SETCURSEL, idx, 0);
}
