// 文件名: src/config_nodes_internal.h
#ifndef CONFIG_NODES_INTERNAL_H
#define CONFIG_NODES_INTERNAL_H

#include "config.h"
#include "cJSON.h"
#include <windows.h> 

// [Internal] 获取唯一标签名 
// 该函数在 config_nodes_crud.c 中实现
char* GetUniqueTagName(cJSON* outbounds, const char* type, const char* base_name);

// [Internal] 批量从文本解析节点
// 该函数在 config_nodes_manage.c 中实现
int Internal_BatchAddNodesFromText(const char* text, cJSON* outbounds);

// 声明 ParseNodeConfigToGlobal 以便 CRUD 模块调用 (在 config_nodes.c 中实现)
void ParseNodeConfigToGlobal(cJSON *node);

#endif // CONFIG_NODES_INTERNAL_H
