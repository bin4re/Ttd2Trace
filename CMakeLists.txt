cmake_minimum_required (VERSION 3.20)

# =========================================================
# 策略与编译器设置
# =========================================================
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("Ttd2Trace")

# =========================================================
# 1. vcpkg 查找 Zydis
# =========================================================
find_package(Zydis CONFIG REQUIRED)

# =========================================================
# 2. FetchContent 下载并配置 NuGet 包
# =========================================================
include(FetchContent)

FetchContent_Declare(
    ttd_pkg
    URL      https://www.nuget.org/api/v2/package/Microsoft.TimeTravelDebugging.Apis/0.9.5
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(ttd_pkg)

# --- 路径映射逻辑---
# 根目录: ${ttd_pkg_SOURCE_DIR}
# 头文件: sdk/include
# 库文件: sdk/lib/{架构}

# 设置头文件路径
# 设置为 'sdk/include' 后，你在代码中可以使用 #include <TTD/TTDReplay.h>
set(TTD_INCLUDE_DIR "${ttd_pkg_SOURCE_DIR}/sdk/include")

# 设置库文件路径 (根据编译架构自动判断 x64 或 x86)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TTD_ARCH_DIR "x64")
else()
    set(TTD_ARCH_DIR "x86")
endif()

set(TTD_LIB_DIR "${ttd_pkg_SOURCE_DIR}/sdk/lib/${TTD_ARCH_DIR}")

# 找到具体的 .lib 文件
# 根据你的目录树，主要有 TTDLiveRecorder.lib 和 TTDReplay.lib
find_library(LIB_TTD_REPLAY NAMES TTDReplay PATHS ${TTD_LIB_DIR} NO_DEFAULT_PATH)
find_library(LIB_TTD_RECORDER NAMES TTDLiveRecorder PATHS ${TTD_LIB_DIR} NO_DEFAULT_PATH)

# =========================================================
# 定义可执行文件
# =========================================================
add_executable (Ttd2Trace "Ttd2Trace/Ttd2Trace.cpp")

# =========================================================
# 链接依赖
# =========================================================

# --- 链接 Zydis ---
target_link_libraries(Ttd2Trace PRIVATE Zydis::Zydis)

# --- 链接 TTD ---
# 添加头文件包含目录
target_include_directories(Ttd2Trace PRIVATE ${TTD_INCLUDE_DIR})

# 链接库文件 (如果找到了就链接)
if(LIB_TTD_REPLAY AND LIB_TTD_RECORDER)
    target_link_libraries(Ttd2Trace PRIVATE ${LIB_TTD_REPLAY} ${LIB_TTD_RECORDER})
    message(STATUS "Found TTD Libs at: ${TTD_LIB_DIR}")
else()
    message(FATAL_ERROR "Could not find TTD libraries in ${TTD_LIB_DIR}. Please check the architecture.")
endif()

# =========================================================
# 设置 C++ 标准
# =========================================================
target_compile_features(Ttd2Trace PRIVATE cxx_std_20)