using System.Runtime.InteropServices;
using static Injector.Interop;

namespace Injector;

internal static unsafe class SecImageMapper
{
    const uint GENERIC_EXECUTE = 0x20000000;

    public static nint TryMap(nint hProcess, byte[] dllBytes, out nuint viewSize)
    {
        viewSize = 0;
        string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".dll");

        try { File.WriteAllBytes(tempPath, dllBytes); }
        catch (Exception ex)
        {
            Log.Warn($"[!] SEC_IMAGE: temp file write failed: {ex.Message}");
            return 0;
        }

        nint result = 0;
        try
        {
            nint hFile = CreateFileW(tempPath, GENERIC_READ | GENERIC_EXECUTE,
                FILE_SHARE_READ_WRITE_DELETE, 0, OPEN_EXISTING, 0, 0);
            if (hFile == -1 || hFile == 0)
            {
                Log.Warn($"[!] SEC_IMAGE: CreateFileW err={Marshal.GetLastPInvokeError()}");
                return 0;
            }

            int status = NtCreateSection(out nint hSection, SECTION_ALL_ACCESS,
                0, 0, PAGE_EXECUTE, SEC_IMAGE, hFile);
            CloseHandle(hFile);

            if (status < 0)
            {
                Log.Warn($"[!] SEC_IMAGE: NtCreateSection NTSTATUS=0x{status:X8}");
                return 0;
            }

            nint baseAddr = 0;
            nuint vSize = 0;
            status = NtMapViewOfSection(hSection, hProcess, ref baseAddr, 0, 0,
                null, ref vSize, 2 /* ViewUnmap */, 0, PAGE_EXECUTE_READWRITE);
            NtClose(hSection);

            if (status < 0)
            {
                Log.Warn($"[!] SEC_IMAGE: NtMapViewOfSection NTSTATUS=0x{status:X8}");
                return 0;
            }

            viewSize = vSize;
            result = baseAddr;
        }
        finally
        {
            try { File.Delete(tempPath); } catch { }
        }
        return result;
    }

    public static void MakeWritable(nint hProcess, nint remoteBase, byte[] dllBytes)
    {
        fixed (byte* raw = dllBytes)
        {
            var dos = (Pe.DosHeader*)raw;
            var nt = (Pe.NtHeaders64*)(raw + dos->e_lfanew);

            VirtualProtectEx(hProcess, remoteBase, (nuint)nt->Optional.SizeOfHeaders,
                PAGE_EXECUTE_READWRITE, out _);

            var sec = (Pe.SectionHeader*)((byte*)nt + sizeof(uint) +
                sizeof(Pe.FileHeader) + nt->File.SizeOfOptionalHeader);
            for (int i = 0; i < nt->File.NumberOfSections; i++)
            {
                if (sec[i].VirtualSize == 0) continue;
                VirtualProtectEx(hProcess, remoteBase + (nint)sec[i].VirtualAddress,
                    (nuint)Math.Max(sec[i].VirtualSize, sec[i].SizeOfRawData),
                    PAGE_EXECUTE_READWRITE, out _);
            }
        }
    }
}
