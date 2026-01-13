cmake_minimum_required (VERSION 3.20)

# =========================================================
# Policies and Compiler Settings
# =========================================================
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("Ttd2Trace")

# =========================================================
# Download and configure NuGet package via FetchContent
# =========================================================
include(FetchContent)

FetchContent_Declare(
    ttd_pkg
    URL      https://www.nuget.org/api/v2/package/Microsoft.TimeTravelDebugging.Apis/0.9.5
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(ttd_pkg)

# --- Path mapping logic ---
# Root directory: ${ttd_pkg_SOURCE_DIR}
# Header files: sdk/include
# Library files: sdk/lib/{architecture}

# Set header file path
# After setting to 'sdk/include', you can use #include <TTD/TTDReplay.h> in code
set(TTD_INCLUDE_DIR "${ttd_pkg_SOURCE_DIR}/sdk/include")

# Set library file path (automatically detect x64 or x86 based on build architecture)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TTD_ARCH_DIR "x64")
else()
    set(TTD_ARCH_DIR "x86")
endif()

set(TTD_LIB_DIR "${ttd_pkg_SOURCE_DIR}/sdk/lib/${TTD_ARCH_DIR}")

# Find specific .lib files
# Based on the directory tree, mainly TTDLiveRecorder.lib and TTDReplay.lib
find_library(LIB_TTD_REPLAY NAMES TTDReplay PATHS ${TTD_LIB_DIR} NO_DEFAULT_PATH)
find_library(LIB_TTD_RECORDER NAMES TTDLiveRecorder PATHS ${TTD_LIB_DIR} NO_DEFAULT_PATH)

# =========================================================
# Define Executable
# =========================================================
add_executable (Ttd2Trace "Ttd2Trace/Ttd2Trace.cpp")

# =========================================================
# Link Dependencies
# =========================================================

# --- Link TTD ---
# Add header file include directory
target_include_directories(Ttd2Trace PRIVATE ${TTD_INCLUDE_DIR})

# Link library files (if found)
if(LIB_TTD_REPLAY AND LIB_TTD_RECORDER)
    target_link_libraries(Ttd2Trace PRIVATE ${LIB_TTD_REPLAY} ${LIB_TTD_RECORDER})
    message(STATUS "Found TTD Libs at: ${TTD_LIB_DIR}")
else()
    message(FATAL_ERROR "Could not find TTD libraries in ${TTD_LIB_DIR}. Please check the architecture.")
endif()

# =========================================================
# Set C++ Standard
# =========================================================
target_compile_features(Ttd2Trace PRIVATE cxx_std_20)