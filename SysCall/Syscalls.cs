using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using static SysCall.Native;

namespace SysCall
{
    /// <summary>
    /// The syscalls
    /// </summary>
    /// <remarks>The syscall codes are specifically for Windows 10 Pro (build 10.0.19042), make sure you use the right ones for your target!</remarks>
    class Syscalls
    {
        static byte[] bNtOpenProcess =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x26 (NtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtAllocateVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 0x18 (NtAllocateVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtWriteVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x3a, 0x00, 0x00, 0x00,   // mov eax, 0x3a (NtWriteVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtCreateThreadEx =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0xc1, 0x00, 0x00, 0x00,   // mov eax, 0xc1 (NtCreateThreadEx Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtProtectVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x50, 0x00, 0x00, 0x00,   // mov eax, 0x50 (NtCreateThreadEx Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId)
        {
            byte[] syscall = bNtOpenProcess;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtOpenProcess assembledFunction = (Delegates.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtOpenProcess));

                    return (NTSTATUS)assembledFunction(ref ProcessHandle, AccessMask, ref ObjectAttributes, ref ClientId);
                }
            }
        }

        public static NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect)
        {
            byte[] syscall = bNtAllocateVirtualMemory;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtAllocateVirtualMemory assembledFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)assembledFunction(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionZize, AllocationType, Protect);
                }
            }
        }

        public static NTSTATUS NtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress, IntPtr buffer, UInt32 Length, ref UInt32 bytesWritten)
        {
            byte[] syscall = bNtWriteVirtualMemory;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtWriteVirtualMemory assembledFunction = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWriteVirtualMemory));

                    return (NTSTATUS)assembledFunction(hProcess, baseAddress, buffer, (uint)Length, ref bytesWritten);
                }
            }
        }

        public static NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect)
        {
            byte[] syscall = bNtProtectVirtualMemory;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtProtectVirtualMemory assembledFunction = (Delegates.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtProtectVirtualMemory));

                    return (NTSTATUS)assembledFunction(ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, ref OldProtect);
                }
            }
        }

        public static NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            byte[] syscall = bNtCreateThreadEx;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtCreateThreadEx assembledFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));

                    return (NTSTATUS)assembledFunction(out threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits, sizeOfStack, maximumStackSize, attributeList);
                }
            }
        }

        struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            NTSTATUS NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            NTSTATUS NtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress, IntPtr buffer, UInt32 Length, ref UInt32 bytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate
            NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);
        };
    }
}
