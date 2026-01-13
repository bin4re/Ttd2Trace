// main.cpp
// TTD to Trace Converter
// Target: x64 Console App
// Standard: C++20

#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <iomanip> // For std::setprecision
#include <fstream>
#include <vector>
#include <string>
#include <string_view>
#include <filesystem>
#include <map>
#include <set>
#include <algorithm>
#include <format>
#include <shared_mutex>
#include <mutex> 
#include <optional>
#include <cassert>
#include <cwctype>

// TTD Headers
#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>

namespace fs = std::filesystem;
using namespace TTD;
using namespace TTD::Replay;

// ============================================================================
// 1. Data Structures & Globals
// ============================================================================

// Describe the existence range of target modules on the timeline
struct TargetModuleRange {
    GuestAddress StartAddress;
    GuestAddress EndAddress;
    Position LoadTime;
    Position UnloadTime;
    std::wstring ModuleName;

    // Used for sorting and binary search
    bool operator<(const TargetModuleRange& other) const {
        return StartAddress < other.StartAddress;
    }
};

// Describe the trace state of a single thread
struct ThreadTraceContext {
    uint32_t ThreadId;
    std::ofstream LogFile;
    std::vector<char> OutputBuffer; // Write buffer (64KB)
    std::vector<uint64_t> PrevRegValues; // Previous register values, used for Diff
    bool IsFirstLog = true;

    // [Safety] Add mutex to prevent vector race conditions during TTD parallel replay of same thread segments
    std::mutex Mutex;

    ThreadTraceContext(uint32_t tid, const fs::path& outDir, const std::wstring& prefix)
        : ThreadId(tid) {
        OutputBuffer.reserve(65536);

        // Construct filename: prefix_threadID.log
        auto filename = std::format(L"{}_{}.log", prefix, tid);
        fs::path fullPath = outDir / filename;

        LogFile.open(fullPath, std::ios::out | std::ios::trunc);
        if (!LogFile.is_open()) {
            std::wcerr << L"Failed to open log file: " << fullPath.c_str() << std::endl;
        }
    }

    ~ThreadTraceContext() {
        Flush();
        if (LogFile.is_open()) LogFile.close();
    }

    void Flush() {
        if (!OutputBuffer.empty() && LogFile.is_open()) {
            LogFile.write(OutputBuffer.data(), OutputBuffer.size());
            OutputBuffer.clear();
        }
    }

    // Helper: Write formatted string to Buffer
    template<typename... Args>
    void Write(std::format_string<Args...> fmt, Args&&... args) {
        std::format_to(std::back_inserter(OutputBuffer), fmt, std::forward<Args>(args)...);
        if (OutputBuffer.size() >= 64 * 1024) {
            Flush();
        }
    }
};

// Global Context
std::vector<TargetModuleRange> g_targetRanges;
std::map<uint32_t, std::unique_ptr<ThreadTraceContext>> g_threadContexts;
std::shared_mutex g_threadMutex; // Protect g_threadContexts map additions/deletions
fs::path g_outputDir = fs::current_path();
std::wstring g_tracePrefix = L"trace";
bool g_isX64 = true; // Guest Architecture

// ============================================================================
// 2. Helper Classes & Functions
// ============================================================================

// TTD Error Reporting
class ConsoleErrorReporting : public ErrorReporting {
public:
    void __fastcall VPrintError(_Printf_format_string_ char const* const pFmt, _In_ va_list argList) override {
        char buffer[2048];
        vsnprintf(buffer, sizeof(buffer), pFmt, argList);
        std::cerr << "[TTD Error] " << buffer << std::endl;
    }
};

// Case-insensitive wstring comparison
bool IsSameModuleName(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(), [](wchar_t c1, wchar_t c2) {
        return std::towlower(c1) == std::towlower(c2);
    });
}

// Parse TTD position string (format: "Sequence:Steps" or "Sequence", both in hexadecimal)
std::optional<Position> ParsePositionString(const std::string& str) {
    try {
        uint64_t seq = 0;
        uint64_t steps = 0;
        size_t colonPos = str.find(':');

        if (colonPos != std::string::npos) {
            std::string seqStr = str.substr(0, colonPos);
            std::string stepStr = str.substr(colonPos + 1);
            if (!seqStr.empty()) seq = std::stoull(seqStr, nullptr, 16);
            if (!stepStr.empty()) steps = std::stoull(stepStr, nullptr, 16);
        }
        else {
            seq = std::stoull(str, nullptr, 16);
        }

        return Position(static_cast<SequenceId>(seq), static_cast<StepCount>(steps));
    }
    catch (...) {
        return std::nullopt;
    }
}

struct AppConfig {
    fs::path TracePath;
    fs::path OutputPath; 
    std::set<std::wstring> TargetModules;
    std::optional<Position> StartPos;
    std::optional<Position> EndPos;
};

void PrintUsage() {
    std::cout << "Usage: Ttd2Trace.exe -f <trace.run> [-m <module1,module2>] [-o <output_dir>] [-s <start_pos>] [-e <end_pos>]\n";
    std::cout << "Example: Ttd2Trace.exe -f trace.run -m target.dll -s 10A:0 -e 10B:20 -o D:\\Logs\n";
    std::cout << "Note: If -m is omitted, ALL modules will be recorded.\n";
}

std::optional<AppConfig> ParseArgs(int argc, char* argv[]) {
    if (argc < 3) return std::nullopt;
    AppConfig config;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f" && i + 1 < argc) {
            config.TracePath = argv[++i];
        }
        else if (arg == "-m" && i + 1 < argc) {
            std::string mods = argv[++i];
            size_t pos = 0;
            while ((pos = mods.find(',')) != std::string::npos) {
                std::string token = mods.substr(0, pos);
                if (!token.empty()) {
                    config.TargetModules.insert(std::filesystem::path(token).wstring());
                }
                mods.erase(0, pos + 1);
            }
            if (!mods.empty()) config.TargetModules.insert(std::filesystem::path(mods).wstring());
        }
        else if (arg == "-o" && i + 1 < argc) {
            config.OutputPath = argv[++i];
        }
        else if (arg == "-s" && i + 1 < argc) {
            config.StartPos = ParsePositionString(argv[++i]);
            if (!config.StartPos) {
                std::cerr << "[Error] Invalid start position format. Use Hex:Hex (e.g., 12A:0)" << std::endl;
                return std::nullopt;
            }
        }
        else if (arg == "-e" && i + 1 < argc) {
            config.EndPos = ParsePositionString(argv[++i]);
            if (!config.EndPos) {
                std::cerr << "[Error] Invalid end position format." << std::endl;
                return std::nullopt;
            }
        }
    }
    // Only TracePath is mandatory
    if (config.TracePath.empty()) return std::nullopt;
    return config;
}

// ============================================================================
// 3. Register Formatting Logic
// ============================================================================

enum RegIdx64 {
    RAX = 0, RBX, RCX, RDX, RSI, RDI, RSP, RBP,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP, EFLAGS,
    COUNT_64
};

enum RegIdx86 {
    EAX = 0, EBX, ECX, EDX, ESI, EDI, ESP, EBP,
    EIP, EFLAGS_32,
    COUNT_86
};

void FormatRegistersX64(ThreadTraceContext& ctx, const AMD64_CONTEXT& regs, const Position& pos) {
    std::vector<uint64_t> currentVals(RegIdx64::COUNT_64);
    currentVals[RAX] = regs.Rax; currentVals[RBX] = regs.Rbx; currentVals[RCX] = regs.Rcx; currentVals[RDX] = regs.Rdx;
    currentVals[RSI] = regs.Rsi; currentVals[RDI] = regs.Rdi; currentVals[RSP] = regs.Rsp; currentVals[RBP] = regs.Rbp;
    currentVals[R8] = regs.R8;   currentVals[R9] = regs.R9;   currentVals[R10] = regs.R10; currentVals[R11] = regs.R11;
    currentVals[R12] = regs.R12; currentVals[R13] = regs.R13; currentVals[R14] = regs.R14; currentVals[R15] = regs.R15;
    currentVals[RIP] = regs.Rip; currentVals[EFLAGS] = regs.EFlags;

    const char* names[] = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "eflags"
    };

    bool needComma = false;

    if (ctx.IsFirstLog || ctx.PrevRegValues.size() != RegIdx64::COUNT_64) {
        ctx.PrevRegValues.resize(RegIdx64::COUNT_64, 0);
        for (int i = 0; i < RegIdx64::COUNT_64; ++i) {
            if (needComma) ctx.Write(",{}", "");
            ctx.Write("{}={:x}", names[i], currentVals[i]);
            needComma = true;
        }
        ctx.IsFirstLog = false;
    }
    else {
        for (int i = 0; i < RegIdx64::COUNT_64; ++i) {
            if (i == RegIdx64::RIP || currentVals[i] != ctx.PrevRegValues[i]) {
                if (needComma) ctx.Write(",{}", "");
                ctx.Write("{}={:x}", names[i], currentVals[i]);
                needComma = true;
            }
        }
    }

    ctx.Write(",position={:x}:{:x}", static_cast<uint64_t>(pos.Sequence), static_cast<uint64_t>(pos.Steps));
    ctx.Write("\n", "");
    ctx.PrevRegValues = currentVals;
}

void FormatRegistersX86(ThreadTraceContext& ctx, const X86_NT5_CONTEXT& regs, const Position& pos) {
    std::vector<uint64_t> currentVals(RegIdx86::COUNT_86);
    currentVals[EAX] = regs.Eax; currentVals[EBX] = regs.Ebx; currentVals[ECX] = regs.Ecx; currentVals[EDX] = regs.Edx;
    currentVals[ESI] = regs.Esi; currentVals[EDI] = regs.Edi; currentVals[ESP] = regs.Esp; currentVals[EBP] = regs.Ebp;
    currentVals[EIP] = regs.Eip; currentVals[EFLAGS_32] = regs.EFlags;

    const char* names[] = {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
        "eip", "eflags"
    };

    bool needComma = false;

    if (ctx.IsFirstLog || ctx.PrevRegValues.size() != RegIdx86::COUNT_86) {
        ctx.PrevRegValues.resize(RegIdx86::COUNT_86, 0);
        for (int i = 0; i < RegIdx86::COUNT_86; ++i) {
            if (needComma) ctx.Write(",{}", "");
            ctx.Write("{}={:x}", names[i], currentVals[i]);
            needComma = true;
        }
        ctx.IsFirstLog = false;
    }
    else {
        for (int i = 0; i < RegIdx86::COUNT_86; ++i) {
            if (i == RegIdx86::EIP || currentVals[i] != ctx.PrevRegValues[i]) {
                if (needComma) ctx.Write(",{}", "");
                ctx.Write("{}={:x}", names[i], currentVals[i]);
                needComma = true;
            }
        }
    }

    ctx.Write(",position={:x}:{:x}", static_cast<uint64_t>(pos.Sequence), static_cast<uint64_t>(pos.Steps));

    ctx.Write("\n", "");
    ctx.PrevRegValues = currentVals;
}

// ============================================================================
// 4. Core Logic Functions
// ============================================================================

void ProcessHit(IThreadView* threadView) {
    uint32_t tid = static_cast<uint32_t>(threadView->GetThreadInfo().UniqueId);
    ThreadTraceContext* ctx = nullptr;

    // Get ThreadContext (Shared Lock)
    {
        std::shared_lock<std::shared_mutex> readLock(g_threadMutex);
        auto it = g_threadContexts.find(tid);
        if (it != g_threadContexts.end()) {
            ctx = it->second.get();
        }
    }

    // Lazy Create (Unique Lock)
    if (!ctx) {
        std::unique_lock<std::shared_mutex> writeLock(g_threadMutex);
        auto it = g_threadContexts.find(tid);
        if (it != g_threadContexts.end()) {
            ctx = it->second.get();
        }
        else {
            auto newCtx = std::make_unique<ThreadTraceContext>(tid, g_outputDir, g_tracePrefix);
            ctx = newCtx.get();
            g_threadContexts[tid] = std::move(newCtx);
            std::cout << "\n[Info] New thread detected: " << tid << ", creating log file." << std::endl;
        }
    }

    // Lock Context to prevent concurrent vector write crashes
    std::lock_guard<std::mutex> contextLock(ctx->Mutex);

    RegisterContext regCtx = threadView->GetCrossPlatformContext();

    // Get current position and pass to Format function
    Position currentPos = threadView->GetPosition();

    if (g_isX64) {
        const AMD64_CONTEXT* regs = reinterpret_cast<const AMD64_CONTEXT*>(&regCtx);
        FormatRegistersX64(*ctx, *regs, currentPos);
    }
    else {
        const X86_NT5_CONTEXT* regs = reinterpret_cast<const X86_NT5_CONTEXT*>(&regCtx);
        FormatRegistersX86(*ctx, *regs, currentPos);
    }
}

// Core callback
bool __fastcall MemoryWatchpointCallback(
    uintptr_t /*context*/,
    const ICursorView::MemoryWatchpointResult& result,
    const IThreadView* threadView)
{
    GuestAddress pc = threadView->GetProgramCounter();
    Position currentPos = threadView->GetPosition();

    // 1. Spatial search
    TargetModuleRange searchKey;
    searchKey.StartAddress = pc;

    auto it = std::upper_bound(g_targetRanges.begin(), g_targetRanges.end(), searchKey);

    if (it == g_targetRanges.begin()) return false;

    const auto& candidate = *std::prev(it);

    // 2. Spatial verification
    if (pc >= candidate.StartAddress && pc < candidate.EndAddress) {
        // 3. Temporal verification
        if (currentPos >= candidate.LoadTime && currentPos < candidate.UnloadTime) {
            // Hit!
            ProcessHit(const_cast<IThreadView*>(threadView));
            return false;
        }
    }

    return false;
}

// ============================================================================
// 5. Main Execution Flow
// ============================================================================

int main(int argc, char* argv[]) {
    // 1. Parse Args
    auto configOpt = ParseArgs(argc, argv);
    if (!configOpt) {
        PrintUsage();
        return 1;
    }
    const auto& config = *configOpt;
    
    if (!config.OutputPath.empty()) {
        if (!fs::exists(config.OutputPath)) {
            std::cerr << "[Error] Output directory does not exist: " << config.OutputPath << std::endl;
            return -1;
        }
        g_outputDir = config.OutputPath;
    } else {
        // Default to trace file's parent path
        g_outputDir = config.TracePath.parent_path();
    }
    
    g_tracePrefix = config.TracePath.stem().wstring();

    std::cout << "[Init] Loading trace: " << config.TracePath << std::endl;

    // 2. Init Engine
    auto [enginePtr, hr] = MakeReplayEngine();
    if (hr != S_OK || !enginePtr) {
        std::cerr << "[Error] Failed to create replay engine. HRESULT: " << std::hex << hr << std::endl;
        return -1;
    }

    ConsoleErrorReporting errorRep;
    enginePtr->RegisterDebugModeAndLogging(DebugModeType::None, &errorRep);

    if (!enginePtr->Initialize(config.TracePath.c_str())) {
        std::cerr << "[Error] Failed to initialize trace file." << std::endl;
        return -1;
    }

    // 3. Check Architecture
    const auto& sysInfo = enginePtr->GetSystemInfo();
    if (sysInfo.System.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        g_isX64 = true;
        std::cout << "[Arch] Detected x64 Guest." << std::endl;
    }
    else if (sysInfo.System.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        g_isX64 = false;
        std::cout << "[Arch] Detected x86 Guest." << std::endl;
    }
    else {
        std::cerr << "[Error] Unsupported architecture (ARM/ARM64 or Unknown)." << std::endl;
        return -1;
    }

    // 4. Pre-scan Modules
    std::cout << "[Scan] Scanning module instances..." << std::endl;
    auto moduleCount = enginePtr->GetModuleInstanceCount();
    auto moduleList = enginePtr->GetModuleInstanceList();

    // Check if recording all modules
    bool recordAllModules = config.TargetModules.empty();
    if (recordAllModules) {
        std::cout << "[Config] No modules specified. Recording ALL modules." << std::endl;
    }

    for (size_t i = 0; i < moduleCount; ++i) {
        const auto& instance = moduleList[i];
        std::wstring modName = instance.pModule->pName;
        std::wstring baseName = std::filesystem::path(modName).filename().wstring();

        // Check target list
        bool isTarget = false;
        if (recordAllModules) {
            isTarget = true;
        }
        else {
            for (const auto& target : config.TargetModules) {
                if (IsSameModuleName(target, baseName) || IsSameModuleName(target, modName)) {
                    isTarget = true;
                    break;
                }
            }
        }

        if (isTarget) {
            TargetModuleRange range;
            range.StartAddress = instance.pModule->Address;
            range.EndAddress = instance.pModule->Address + instance.pModule->Size;
            range.LoadTime = instance.LoadTime;
            range.UnloadTime = instance.UnloadTime;
            range.ModuleName = baseName;

            g_targetRanges.push_back(range);

            std::wcout << L"[ASLR Hint] Module: " << baseName
                << L" | Base: 0x" << std::hex << static_cast<uint64_t>(range.StartAddress)
                << L" | Size: 0x" << instance.pModule->Size
                << L" | Time: " << static_cast<uint64_t>(range.LoadTime.Sequence) << L" -> " << static_cast<uint64_t>(range.UnloadTime.Sequence)
                << std::dec << std::endl;
        }
    }

    if (g_targetRanges.empty()) {
        std::cerr << "[Error] None of the specified modules were found in the trace!" << std::endl;
        return -1;
    }

    std::sort(g_targetRanges.begin(), g_targetRanges.end());

    // 5. Setup Cursor & Watchpoints
    auto cursor = enginePtr->NewCursor();
    cursor->SetReplayFlags(ReplayFlags::ReplayAllSegmentsWithoutFiltering);

    std::cout << "[Setup] Setting memory watchpoints on " << g_targetRanges.size() << " ranges..." << std::endl;

    for (const auto& range : g_targetRanges) {
        MemoryWatchpointData wp;
        wp.Address = range.StartAddress;
        wp.Size = static_cast<uint64_t>(range.EndAddress - range.StartAddress);
        wp.AccessMask = DataAccessMask::Execute;

        cursor->AddMemoryWatchpoint(wp);
    }

    // Determine Replay Range
    Position traceFirst = enginePtr->GetFirstPosition();
    Position traceLast = enginePtr->GetLastPosition();
    Position replayStart = traceFirst;
    Position replayEnd = traceLast;

    // Override with user args
    if (config.StartPos.has_value()) {
        if (*config.StartPos > traceFirst) replayStart = *config.StartPos;
    }
    if (config.EndPos.has_value()) {
        if (*config.EndPos < traceLast) replayEnd = *config.EndPos;
    }

    if (replayStart >= replayEnd) {
        std::cerr << "[Error] Start position must be less than end position." << std::endl;
        return -1;
    }

    cursor->SetMemoryWatchpointCallback(MemoryWatchpointCallback, 0);
    // [Removed] ProgressCallback is not registered

    std::cout << "[Run] Starting replay... (Output dir: " << g_outputDir << ")" << std::endl;
    // Debug print range
    std::cout << "[Debug] Replay Range: "
        << std::hex << static_cast<uint64_t>(replayStart.Sequence) << ":" << static_cast<uint64_t>(replayStart.Steps)
        << " -> "
        << static_cast<uint64_t>(replayEnd.Sequence) << ":" << static_cast<uint64_t>(replayEnd.Steps)
        << std::dec << std::endl;

    // Start from user specified position
    cursor->SetPosition(replayStart);

    // Run until user specified end position
    auto result = cursor->ReplayForward(replayEnd, StepCount::Max);

    std::cout << "\n[Done] Replay finished. Stop reason: " << (int)result.StopReason << std::endl;

    g_threadContexts.clear();

    return 0;
}