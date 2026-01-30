#ifndef DRIVER_SINGBOX_H
#define DRIVER_SINGBOX_H

#include "proxy_types.h"
#include "config.h" // [Fix] 引入此头文件以识别 node_t 和 program_settings_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 初始化 Sing-box 驱动状态
 * * 在程序启动时调用，确保状态变量被重置。
 */
void singbox_init(void);

/**
 * @brief 启动或重启 Sing-box 进程
 * * 根据传入的节点信息生成 config.json 并启动进程。
 * 如果进程已在运行，会先停止旧进程。
 * * @param node 当前选中的节点信息
 * @param settings 全局设置信息（包含核心路径）
 * @return int 0 表示成功，非 0 表示失败
 */
int singbox_start(const node_t *node, const program_settings_t *settings);

/**
 * @brief 停止 Sing-box 进程
 * * 终止子进程并清理句柄。
 */
void singbox_stop(void);

/**
 * @brief 检查 Sing-box 是否正在运行
 * * @return int 1 表示正在运行，0 表示未运行
 */
int singbox_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // DRIVER_SINGBOX_H
