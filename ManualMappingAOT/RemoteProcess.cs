using System.Runtime.InteropServices;
using System.Text;
using static Injector.Interop;

namespace Injector;

// Thin wrapper around a target-process handle. All the read/write helpers
// throw on failure so the caller can stay linear.
internal sealed unsafe class RemoteProcess : IDisposable
{
    public nint Handle { get; }
    private readonly List<(nint addr, nuint size)> _allocs = new();

    public RemoteProcess(int pid)
    {
        Handle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid);
        if (Handle == 0) throw new("OpenProcess failed err=" + Marshal.GetLastPInvokeError());
    }

    public nint Alloc(nuint size, uint protect = PAGE_READWRITE)
    {
        var addr = VirtualAllocEx(Handle, 0, size, MEM_COMMIT | MEM_RESERVE, protect);
        if (addr == 0) throw new("VirtualAllocEx failed err=" + Marshal.GetLastPInvokeError());
        _allocs.Add((addr, size));
        return addr;
    }

    public void WriteBytes(nint remoteAddr, byte[] data)
    {
        fixed (byte* p = data)
            if (!WriteProcessMemory(Handle, remoteAddr, p, (nuint)data.Length, out _))
                throw new("WriteProcessMemory failed err=" + Marshal.GetLastPInvokeError());
    }
    public void WriteBytes(nint remoteAddr, void* data, nuint size)
    {
        if (!WriteProcessMemory(Handle, remoteAddr, data, size, out _))
            throw new("WriteProcessMemory failed err=" + Marshal.GetLastPInvokeError());
    }
    public void WriteI64(nint addr, long v)  => WriteBytes(addr, &v, 8);
    public void WriteU64(nint addr, ulong v) => WriteBytes(addr, &v, 8);
    public void WriteI32(nint addr, int v)   => WriteBytes(addr, &v, 4);
    public void WriteU32(nint addr, uint v)  => WriteBytes(addr, &v, 4);
    public void WriteU16(nint addr, ushort v)=> WriteBytes(addr, &v, 2);

    public void ReadBytes(nint remoteAddr, void* buf, nuint size)
    {
        if (!ReadProcessMemory(Handle, remoteAddr, buf, size, out _))
            throw new("ReadProcessMemory failed err=" + Marshal.GetLastPInvokeError());
    }
    public T Read<T>(nint remoteAddr) where T : unmanaged
    {
        T v = default;
        ReadBytes(remoteAddr, &v, (nuint)sizeof(T));
        return v;
    }
    public nint ReadPtr(nint remoteAddr) => Read<nint>(remoteAddr);
    public uint ReadU32(nint remoteAddr) => Read<uint>(remoteAddr);

    // Read PEB base for the target
    public nint GetPebBase()
    {
        var pbi = new PROCESS_BASIC_INFORMATION();
        int st = NtQueryInformationProcess(Handle, 0, ref pbi,
            (uint)sizeof(PROCESS_BASIC_INFORMATION), out _);
        if (st < 0 || pbi.PebBaseAddress == 0)
            throw new("NtQueryInformationProcess failed 0x" + st.ToString("X8"));
        return pbi.PebBaseAddress;
    }

    // Find a module in target's PEB Ldr list by base name (case-insensitive).
    // Returns (dllBase, sizeOfImage) or (0,0) if not found.
    public (nint Base, uint Size) FindModule(string baseName)
    {
        nint peb = GetPebBase();
        nint ldr = ReadPtr(peb + 0x18);
        if (ldr == 0) return (0, 0);
        nint listHead = ldr + 0x10;
        nint cur = ReadPtr(listHead);   // Flink

        Span<char> nameBuf = stackalloc char[260];
        while (cur != 0 && cur != listHead)
        {
            ushort len = Read<ushort>(cur + Ldr.OFFSET_BaseDllName);
            nint buf   = ReadPtr(cur + Ldr.OFFSET_BaseDllName + 8);
            if (len > 0 && buf != 0 && len / 2 < 260)
            {
                int chars = len / 2;
                fixed (char* p = nameBuf)
                    ReadBytes(buf, p, (nuint)len);
                var s = new string(nameBuf[..chars]);
                if (string.Equals(s, baseName, StringComparison.OrdinalIgnoreCase))
                {
                    nint dllBase = ReadPtr(cur + Ldr.OFFSET_DllBase);
                    uint size    = ReadU32(cur + Ldr.OFFSET_SizeOfImage);
                    return (dllBase, size);
                }
            }
            cur = ReadPtr(cur);   // Flink
        }
        return (0, 0);
    }

    public nint CreateThread(nint startAddr, nint parameter)
    {
        var h = CreateRemoteThread(Handle, 0, 0, startAddr, parameter, 0, 0);
        if (h == 0) throw new("CreateRemoteThread failed err=" + Marshal.GetLastPInvokeError());
        return h;
    }

    public void Dispose()
    {
        foreach (var (addr, _) in _allocs)
            VirtualFreeEx(Handle, addr, 0, MEM_RELEASE);
        if (Handle != 0) CloseHandle(Handle);
    }
}
