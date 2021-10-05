# SysCalls
An example of using Windows System Calls in C# to inject a meterpreter shell.

# Introduction
This code is based upon the excellent [Red Team Tactics: Utilizing Syscalls in C#](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/) primer by Jack Halon, explaining the use of System Calls in windows malware for post-exploitation activities, as well as for the bypassing of EDR or Endpoint Detection and Response. Some Anti-malware products, such as Bit Defender inject user mode hooks in `ntdll.dll` when new processes are created. This means that whenever APIs such as `NtCreateThreadEx` are called in `ntdll.dll` Bit Defender intercepts the call

