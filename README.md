# SysCalls
An example of using Windows System Calls (syscalls) in C# to inject a meterpreter shell.

# Introduction
This code is based upon the excellent [Red Team Tactics: Utilizing Syscalls in C#](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/) primer by **Jack Halon**, explaining the use of 'System Calls in windows malware for post-exploitation activities, as well as for the bypassing of EDR or Endpoint Detection and Response'. I recommend reading it, it's not an easy subject, but well worth the effort!

Some anti-malware products, such as Bit Defender inject user mode hooks in `ntdll.dll` when new processes are created. This means that whenever APIs such as `NtCreateThreadEx` are called in `ntdll.dll` Bit Defender intercepts the call, does its scanning, then returns execution to the thread.

If we use syscalls directly we can avoid the hooks, and effectively bypassing the anti-malware scan.

# Codez
If you just want to dig in to the code, go here:

[Native.cs](https://github.com/plackyhacker/SysCalls/blob/main/SysCall/Native.cs) - Native imports/structs from Win32 APIS

[Syscalls.cs](https://github.com/plackyhacker/SysCalls/blob/main/SysCall/Syscalls.cs) - The sycall implementation.

[Program.cs](https://github.com/plackyhacker/SysCalls/blob/main/SysCall/Program.cs) - The main routine.


# Important
Syscall codes can and do change between operating systems. You must change the the codes in the [Syscalls class](https://github.com/plackyhacker/SysCalls/blob/main/SysCall/Syscalls.cs) to match those of your target.

And remember, the code looks for an instance of notepad to inject into, it is trivial to change this, or even spawn a surregate process to inject in to.

# AV Scan Results

The binary was scanned using [antiscan.me](https://antiscan.me/scan/new/result?id=2kut9uVkyXQW) on 05/10/2021.

![AV Scan](https://github.com/plackyhacker/SysCalls/blob/main/Syscall_scan.png?raw=true)

# Notes

Tested with windows/x64/meterpreter/reverse_https on Windows 10 Pro (build 10.0.19042) with Defender.
