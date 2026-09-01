using System.Runtime.InteropServices;

namespace Injector;

internal static partial class Interop
{
    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    public const uint MEM_COMMIT   = 0x1000;
    public const uint MEM_RESERVE  = 0x2000;
    public const uint MEM_RELEASE  = 0x8000;
    public const uint PAGE_READWRITE          = 0x04;
    public const uint PAGE_EXECUTE_READWRITE  = 0x40;
    public const uint TH32CS_SNAPPROCESS      = 0x00000002;
    public const uint STD_OUTPUT_HANDLE       = unchecked((uint)-11);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint OpenProcess(uint dwDesiredAccess,
                                           [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
                                           uint dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint VirtualAllocEx(nint hProcess, nint lpAddress, nuint dwSize,
                                              uint flAllocationType, uint flProtect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool VirtualFreeEx(nint hProcess, nint lpAddress, nuint dwSize, uint dwFreeType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool VirtualProtectEx(nint hProcess, nint lpAddress, nuint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    public const uint GENERIC_READ  = 0x80000000;
    public const uint FILE_SHARE_READ_WRITE_DELETE = 0x1 | 0x2 | 0x4;
    public const uint OPEN_EXISTING = 3;

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16,
        EntryPoint = "CreateFileW")]
    public static partial nint CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        nint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes,
        nint hTemplateFile);

    // CFG (Control Flow Guard)
    public const nuint CFG_CALL_TARGET_VALID = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    public struct CFG_CALL_TARGET_INFO
    {
        public nuint Offset;
        public nuint Flags;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool SetProcessValidCallTargets(nint hProcess, nint VirtualAddress,
        nuint RegionSize, uint NumberOfOffsets, CFG_CALL_TARGET_INFO* OffsetInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool WriteProcessMemory(nint hProcess, nint lpBaseAddress,
        void* lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool ReadProcessMemory(nint hProcess, nint lpBaseAddress,
        void* lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes,
        nuint dwStackSize, nint lpStartAddress, nint lpParameter,
        uint dwCreationFlags, nint lpThreadId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial nint GetModuleHandleW(string lpModuleName);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint GetProcAddress(nint hModule, string lpProcName);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32FirstW(nint hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Process32NextW(nint hSnapshot, ref PROCESSENTRY32W lppe);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint GetStdHandle(uint nStdHandle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetConsoleTextAttribute(nint hConsoleOutput, ushort wAttributes);

    [LibraryImport("user32.dll")]
    public static partial short GetAsyncKeyState(int vKey);

    [LibraryImport("kernel32.dll")]
    public static partial void Sleep(uint dwMilliseconds);

    [LibraryImport("ntdll.dll")]
    public static partial int NtQueryInformationProcess(nint ProcessHandle, int ProcessInformationClass,
        ref PROCESS_BASIC_INFORMATION ProcessInformation, uint ProcessInformationLength,
        out uint ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public nint Reserved1;
        public nint PebBaseAddress;
        public nint Reserved2_0;
        public nint Reserved2_1;
        public nint UniqueProcessId;
        public nint Reserved3;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public nuint th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int  pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    // NT section APIs for SEC_IMAGE mapping
    public const uint SECTION_ALL_ACCESS = 0x000F001F;
    public const uint SEC_IMAGE          = 0x01000000;
    public const uint PAGE_EXECUTE       = 0x10;

    [LibraryImport("ntdll.dll")]
    public static partial int NtCreateSection(out nint SectionHandle, uint DesiredAccess,
        nint ObjectAttributes, nint MaximumSize, uint SectionPageProtection,
        uint AllocationAttributes, nint FileHandle);

    [LibraryImport("ntdll.dll")]
    public static unsafe partial int NtMapViewOfSection(nint SectionHandle, nint ProcessHandle,
        ref nint BaseAddress, nuint ZeroBits, nuint CommitSize,
        long* SectionOffset, ref nuint ViewSize,
        uint InheritDisposition, uint AllocationType, uint Win32Protect);

    [LibraryImport("ntdll.dll")]
    public static partial int NtClose(nint Handle);
}
