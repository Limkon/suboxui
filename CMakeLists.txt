cmake_minimum_required(VERSION 3.10)

# ==============================================================================
# 项目配置
# ==============================================================================
project(MandalaECH C)

# 设置 C 标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# MSVC 运行时库设置 (静态链接 CRT，减少运行时依赖)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ==============================================================================
# 架构检测与连接数限制
# ==============================================================================
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_FD_SETSIZE 1024)
    message(STATUS "Build Architecture: 64-bit (High Performance)")
else()
    set(ARCH_FD_SETSIZE 512)
    message(STATUS "Build Architecture: 32-bit (Compatibility Mode)")
endif()

add_definitions(
    -DUNICODE 
    -D_UNICODE 
    -DNGHTTP2_STATICLIB 
    -DFD_SETSIZE=${ARCH_FD_SETSIZE}
    -DMAX_CONNECTIONS=${ARCH_FD_SETSIZE}
)

# ==============================================================================
# [New] 性能优先优化配置 (Speed Optimization)
# ==============================================================================
# 注意：此配置必须放在 add_executable 之前

# 1. 开启 LTO (链接时优化) - 速度优化的关键
# LTO 允许编译器跨文件边界进行内联和分析，显著提升运行时性能
include(CheckIPOSupported)
check_ipo_supported(RESULT result OUTPUT output)
if(result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(WARNING "LTO not supported: ${output}")
endif()

# 2. 编译器特定优化 (追求极致速度)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # 编译选项:
    # -O3: 最高级别的速度优化 (启用循环展开、向量化、激进内联等)
    # -ffunction-sections/fdata-sections: 虽然主要用于减小体积，但有助于链接器
    # 优化内存布局 (Locality)，可能间接提升 CPU 缓存命中率
    add_compile_options(-O3 -ffunction-sections -fdata-sections)

    # 链接选项:
    # --gc-sections: 移除无用代码，减少内存占用
    add_link_options(-Wl,--gc-sections)
    
    # Release 模式下剥离符号 (不影响速度，但减小分发体积)
    if(CMAKE_BUILD_TYPE MATCHES "Release")
        add_link_options(-s)
    endif()
endif()

if(MSVC)
    # MSVC 速度优化
    # /O2: 最大化速度 (相当于 GCC -O3)
    # /Oi: 启用内部函数 (Intrinsic functions)
    # /Ot: 代码速度优先 (Favor fast code)
    add_compile_options(/O2 /Oi /Ot /Gw /Gy)
    add_link_options(/OPT:REF /OPT:ICF)
endif()

# ==============================================================================
# 依赖库查找
# ==============================================================================

# 1. OpenSSL
find_package(OpenSSL REQUIRED)

# 2. NGHTTP2
find_path(NGHTTP2_INCLUDE_DIR NAMES nghttp2/nghttp2.h)
if(MINGW)
    find_library(NGHTTP2_LIBRARY NAMES libnghttp2.a nghttp2)
else()
    find_library(NGHTTP2_LIBRARY NAMES nghttp2)
endif()

if (NOT NGHTTP2_INCLUDE_DIR OR NOT NGHTTP2_LIBRARY)
    message(WARNING "nghttp2 not found.\nHTTP/2 features might fail to link.")
endif()

# 3. Regex & 依赖项 (MinGW 专用修复)
# [CRITICAL FIX] 依赖链: libregex -> libtre -> libintl -> libiconv
if(MINGW)
    message(STATUS "Searching for static Regex libraries and dependencies for MinGW...")
    set(_ORIG_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a) # 强制查找静态库
    
    # 查找正则库
    find_library(REGEX_LIBRARY NAMES regex gnuregex)
    find_library(TRE_LIBRARY NAMES tre)
    
    # [Fix] 查找 libtre 的依赖库 (解决 undefined reference to libintl_gettext)
    find_library(INTL_LIBRARY NAMES intl libintl)
    find_library(ICONV_LIBRARY NAMES iconv libiconv)
    
    if(REGEX_LIBRARY AND TRE_LIBRARY)
        message(STATUS "  Found Regex:  ${REGEX_LIBRARY}")
        message(STATUS "  Found TRE:    ${TRE_LIBRARY}")
        if(INTL_LIBRARY)
            message(STATUS "  Found Intl:   ${INTL_LIBRARY}")
        endif()
    else()
        message(FATAL_ERROR "  Could NOT find static regex dependencies (libregex.a + libtre.a).")
    endif()
    
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_ORIG_SUFFIXES})
endif()

# ==============================================================================
# 头文件与源文件
# ==============================================================================

include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/resources
    ${OPENSSL_INCLUDE_DIR}
    ${NGHTTP2_INCLUDE_DIR}
)

set(SOURCES
    src/main.c
    src/globals.c
    src/gui_utils.c
    src/gui_log.c
    src/gui_settings.c
    src/gui_node_edit.c
    src/gui_node_mgr.c
    src/gui_node_mgr_nodes.c
    src/gui_node_mgr_subs.c
    src/gui_node_mgr_routes.c
    
    src/config_settings.c
    src/config_parsers.c
    src/config_sub.c
    src/config_nodes.c
    src/config_nodes_crud.c
    src/config_nodes_manage.c
    
    src/proxy.c
    src/proxy_utils.c
    src/proxy_step_session.c
    src/proxy_step_inbound.c
    src/proxy_step_outbound.c
    src/proxy_step_tunnel.c
    src/proxy_loop.c
    src/proxy_h2.c
    
    # [New] Sing-box 驱动实现
    src/driver_singbox.c
    
    src/crypto_core.c
    src/crypto_bio.c
    src/crypto_tls.c
    src/crypto_ws.c

    src/utils_base.c
    src/utils_sys.c
    src/utils_net.c
    src/utils_node.c
    src/cJSON.c
    
    resources/resource.rc
)

# ==============================================================================
# 平台库配置
# ==============================================================================
if(WIN32)
    set(PLATFORM_LIBS 
        ws2_32 crypt32 comctl32 gdi32 user32 kernel32 iphlpapi wininet shlwapi
    )
    enable_language(RC)
else()
    set(PLATFORM_LIBS pthread dl)
endif()

# ==============================================================================
# 构建目标
# ==============================================================================

add_executable(MandalaECH WIN32 ${SOURCES})
set_target_properties(MandalaECH PROPERTIES OUTPUT_NAME "Mandala")

# 链接核心库
target_link_libraries(MandalaECH 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${NGHTTP2_LIBRARY}
    ${PLATFORM_LIBS}
)

# [Fix] 链接正则库及其依赖 (顺序很重要: 依赖项在后)
if(REGEX_LIBRARY)
    target_link_libraries(MandalaECH ${REGEX_LIBRARY})
endif()
if(TRE_LIBRARY)
    target_link_libraries(MandalaECH ${TRE_LIBRARY})
endif()
if(INTL_LIBRARY)
    target_link_libraries(MandalaECH ${INTL_LIBRARY})
endif()
if(ICONV_LIBRARY)
    target_link_libraries(MandalaECH ${ICONV_LIBRARY})
endif()

# ==============================================================================
# 编译器选项
# ==============================================================================
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(MandalaECH PRIVATE "-finput-charset=UTF-8")
endif()

if(MINGW)
    # 静态链接所有依赖，防止 DLL 丢失
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -municode")
endif()

message(STATUS "=========================================")
message(STATUS "  Project:      ${PROJECT_NAME}")
message(STATUS "  Output:       Mandala.exe")
message(STATUS "  Mode:         Maximize Speed (-O3)")
if(MINGW)
    message(STATUS "  Regex Stack:  ${REGEX_LIBRARY} -> ${TRE_LIBRARY} -> ${INTL_LIBRARY}")
endif()
message(STATUS "=========================================")
