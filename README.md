# 项目说明

可从 TTD 录制文件中获取执行过程的 Trace 记录到文件中。

# 构建方法

打开 Developer Powershell for VS 2022，执行 config_on_win.bat，随后即可使用 VS 2022 打开 build 目录生成的 Ttd2Trace.sln 进行编译。

执行 Get-Ttd.ps1 获取 TTDReplay.dll 和 TTDReplayCPU.dll，放在可执行文件同目录。