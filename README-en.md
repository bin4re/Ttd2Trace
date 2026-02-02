# Ttd2Trace

[English](README-en.md) / [中文](README.md)

Extract register trace records from TTD (Time Travel Debugging) recordings and export them to analyzable log files.

## Features

- **Selective Tracking**: Target specific modules or trace all modules
- **Multi-threaded Support**: Independent log files per thread with concurrent tracing support
- **Differential Recording**: Only record changed register values, reducing output size by 70-90%
- **Flexible Time Range**: Specify start and end positions for precise trace control
- **Cross-Architecture**: Support for both x64 and x86 architectures
- **Dynamic Module Handling**: Correctly handle dynamic module loading and unloading

## Build

### Prerequisites

- Visual Studio 2022
- Developer PowerShell for VS 2022

### Build Steps

1. **Configure Build**
   ```powershell
   # Run in Developer PowerShell for VS 2022
   .\config_on_win.bat
   ```

2. **Get TTD Runtime**
   ```powershell
   # Automatically download TTD runtime DLLs
   .\Get-Ttd\Get-Ttd.ps1
   ```

   Or manually copy these files from WinDbg TTD directory to the executable folder:
   - `TTDReplay.dll`
   - `TTDReplayCPU.dll`

## Usage

### Basic Usage

```bash
# Trace all modules
Ttd2Trace.exe -f trace.run

# Trace specific module
Ttd2Trace.exe -f trace.run -m target.dll

# Trace multiple modules
Ttd2Trace.exe -f trace.run -m module1.dll,module2.exe

# Specify output directory
Ttd2Trace.exe -f trace.run -m target.dll -o D:\Logs

# Specify time range (hexadecimal format)
Ttd2Trace.exe -f trace.run -s a:0 -e ff:0
```

### Command Line Arguments

| Parameter | Description | Required |
|-----------|-------------|----------|
| `-f <trace.run>` | Specify TTD recording file path | Yes |
| `-m <module1,module2>` | Specify target module list (comma-separated) | No |
| `-o <output_dir>` | Specify output directory | No |
| `-s <pos>` | Specify start position (format: hex sequence:steps) | No |
| `-e <pos>` | Specify end position | No |

### Output Files

- **Naming Format**: `{trace_name}_{thread_id}.log`
- **Example**: `trace_1234.log`, `trace_5678.log`
- **Output Directory**: Default to trace file directory

## Output Format

```
rax=1234,rbx=5678,rcx=0,rdx=0,rsi=0,rdi=0,rsp=7ffff0,rbp=0,r8=0,r9=0,r10=0,r11=0,r12=0,r13=0,r14=0,r15=0,rip=401000,eflags=202,position=a:5
rbx=9abc,rip=401005,position=a:6
```

**Characteristics**:
- First log records all register values
- Subsequent logs only record changed values (RIP always recorded)
- Line ends with position info `position=sequence:steps`

## Dependencies

| Component | Version | Description |
|-----------|---------|-------------|
| Microsoft.TimeTravelDebugging.Apis | 0.9.5 | TTD Replay Engine Interface |

## Performance Optimizations

- **64KB Write Buffer**: Reduces I/O operations
- **Differential Recording**: Reduces output size by 70-90%
- **Binary Search**: O(log n) breakpoint hit detection
- **Read-Write Locks**: Supports multi-threaded concurrent tracing

## Use Cases

- **Reverse Engineering**: Extract execution flow of target modules
- **Performance Analysis**: Trace execution paths of critical functions
- **Security Research**: Analyze malware execution behavior
- **Debugging Assistance**: Generate readable execution logs for offline analysis

## License

MIT License - See [LICENSE.txt](LICENSE.txt) for details

## Resources

- [TTD Official Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview)
