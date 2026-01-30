#ifndef GUI_H
#define GUI_H

#include "common.h"

void OpenLogViewer(BOOL bShow);
void OpenNodeManager();
void OpenNodeEditWindow(const wchar_t* tag);
void OpenSettingsWindow();
void OpenSubWindow(); // 确保声明了订阅窗口打开函数
void ToggleTrayIcon();

// 暴露自动更新线程给 main.c 使用
DWORD WINAPI AutoUpdateThread(LPVOID lpParam);

#endif // GUI_H
