# Ttd2Trace

[English](README-en.md) / [中文](README.md)

从 TTD (Time Travel Debugging) 录制文件中提取程序执行过程的寄存器追踪记录，并导出为可分析的日志文件。

## 功能特性

- **选择性追踪**：支持指定目标模块，或追踪所有模块的执行过程
- **多线程支持**：每个线程生成独立的日志文件，支持并发追踪
- **差分记录**：仅记录变化的寄存器值，大幅减少输出数据量
- **灵活的时间范围**：支持指定开始和结束位置，精确控制追踪范围
- **架构兼容**：同时支持 x64 和 x86 架构
- **动态模块处理**：正确处理模块的动态加载和卸载

## 构建方法

### 前置要求

- Visual Studio 2022
- Developer PowerShell for VS 2022

### 构建步骤

1. **配置编译**
   ```powershell
   # 在 Developer PowerShell for VS 2022 中执行
   .\config_on_win.bat
   ```

2. **获取 TTD 运行时**
   ```powershell
   # 自动下载 TTD 运行时 DLL
   .\Get-Ttd\Get-Ttd.ps1
   ```

   或手动从 WinDbg TTD 目录复制以下文件到可执行文件同目录：
   - `TTDReplay.dll`
   - `TTDReplayCPU.dll`

## 使用方法

### 基本用法

```bash
# 追踪所有模块的执行
Ttd2Trace.exe -f trace.run

# 追踪指定模块
Ttd2Trace.exe -f trace.run -m target.dll

# 追踪多个模块
Ttd2Trace.exe -f trace.run -m module1.dll,module2.exe

# 指定输出目录
Ttd2Trace.exe -f trace.run -m target.dll -o D:\Logs

# 指定时间范围（格式为十六进制）
Ttd2Trace.exe -f trace.run -s a:0 -e ff:0
```

### 命令行参数

| 参数 | 说明 | 必需 |
|------|------|------|
| `-f <trace.run>` | 指定 TTD 录制文件路径 | 是 |
| `-m <module1,module2>` | 指定目标模块列表（逗号分隔） | 否 |
| `-o <output_dir>` | 指定输出目录 | 否 |
| `-s <pos>` | 指定开始位置（格式：十六进制序列:步数） | 否 |
| `-e <pos>` | 指定结束位置 | 否 |

### 输出文件

- **命名格式**：`{trace名}_{线程ID}.log`
- **示例**：`trace_1234.log`、`trace_5678.log`
- **输出目录**：默认为 trace 文件所在目录

## 输出格式

```
rax=1234,rbx=5678,rcx=0,rdx=0,rsi=0,rdi=0,rsp=7ffff0,rbp=0,r8=0,r9=0,r10=0,r11=0,r12=0,r13=0,r14=0,r15=0,rip=401000,eflags=202,position=a:5
rbx=9abc,rip=401005,position=a:6
```

**特点**：
- 首次记录所有寄存器值
- 后续仅记录变化的值（RIP 总是记录）
- 行尾包含位置信息 `position=序列号:步数`

## 依赖项

| 组件 | 版本 | 说明 |
|------|------|------|
| Microsoft.TimeTravelDebugging.Apis | 0.9.5 | TTD 回放引擎接口 |

## 性能优化

- **64KB 写缓冲区**：减少 I/O 操作次数
- **差分记录**：减少 70-90% 输出数据量
- **二分查找**：O(log n) 的断点命中检测
- **读写锁机制**：支持多线程并发追踪

## 典型应用场景

- **逆向工程**：提取目标模块的执行流程
- **性能分析**：追踪关键函数的执行路径
- **安全研究**：分析恶意代码的执行行为
- **调试辅助**：生成可读的执行日志供离线分析

## 许可证

MIT License - 详见 [LICENSE.txt](LICENSE.txt)

## 相关资源

- [TTD 官方文档](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview)
