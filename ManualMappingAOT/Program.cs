using System.Reflection;
using System.Runtime.InteropServices;
using static Injector.Interop;

namespace Injector;

internal static class Program
{
    private const int VK_F1 = 0x70;

    private static int Main(string[] args)
    {
        Log.Init();
        Console.Title = "CS2 Injector (NativeAOT Manual Map)";
        Log.Banner("""

    ______________      _____   __    ________________________  ____
   / ____/ ___/__ \    /  _/ | / /   / / ____/ ____/_  __/ __ \/ __ \
  / /    \__ \__/ /    / //  |/ /_  / / __/ / /     / / / / / / /_/ /
 / /___ ___/ / __/   _/ // /|  / /_/ / /___/ /___  / / / /_/ / _, _/
 \____//____/____/  /___/_/ |_/\____/_____/\____/ /_/  \____/_/ |_|
    NativeAOT-aware manual mapper

""");

        string target = "cs2.exe";
        bool autoInject = false;
        foreach (var a in args)
        {
            if (a == "--auto") autoInject = true;
            else if (!string.IsNullOrEmpty(a)) target = a;
        }
        Log.Info($"[*] Target process: {target}" +
                 (autoInject ? "  (auto-inject)" : ""));

        byte[]? dllBytes = LoadEmbeddedDll();
        if (dllBytes != null)
            Log.Ok($"[+] DLL loaded from embedded resource ({dllBytes.Length} bytes)");
        else
        {
            dllBytes = LoadDiskDllAndDelete();
            if (dllBytes == null)
            {
                Log.Err("[!] No cheat.dll found (neither embedded nor on disk).");
                Console.Write("Press ENTER to exit..."); Console.ReadLine();
                return 1;
            }
            Log.Ok($"[+] DLL loaded from disk ({dllBytes.Length} bytes), file deleted");
        }

        string ldrDisplay = @"C:\Windows\System32\uxtheme.dll";
        Log.Info($"[*] LDR entry name: {ldrDisplay}");

        Log.Info("");
        Log.Info($"[*] Waiting for {target}...");
        int pid = 0;
        while ((pid = FindProcess(target)) == 0) Sleep(500);
        Log.Ok($"[+] {target} found (PID {pid})");

        if (autoInject)
        {
            Log.Info("");
            Log.Info("[*] --auto: injecting without keypress in 500 ms...");
            Sleep(500);
        }
        else
        {
            Log.Warn("");
            Log.Warn(">>> Press F1 to inject <<<");
            Log.Info("");
            while ((GetAsyncKeyState(VK_F1) & 0x8000) == 0) Sleep(50);
            Sleep(200);
        }

        Log.Info("[*] Injecting via Manual Map (NativeAOT-aware)...");

        try
        {
            using var proc = new RemoteProcess(pid);
            var ntdll = NtdllInfo.Discover();
            Log.Ok($"[+] ntdll.dll base            @ 0x{ntdll.NtdllBase:X}");
            Log.Ok($"[+] LdrpHandleTlsData        @ 0x{ntdll.LdrpHandleTlsData:X}");
            Log.Ok($"[+] LdrpModuleBaseAddressIndex@ 0x{ntdll.RbTreePtr:X}");
            Log.Ok($"[+] LdrpInvertedFunctionTable @ 0x{ntdll.InvertedTablePtr:X}");

            nint remoteBase = SecImageMapper.TryMap(proc.Handle, dllBytes, out nuint secViewSize);
            if (remoteBase != 0)
            {
                Log.Ok($"[+] SEC_IMAGE mapped @ 0x{remoteBase:X} (0x{secViewSize:X} bytes)");
                SecImageMapper.MakeWritable(proc.Handle, remoteBase, dllBytes);
            }
            else
            {
                uint sizeOfImage = ReadSizeOfImage(dllBytes);
                Log.Warn("[!] SEC_IMAGE failed, using VirtualAllocEx (MEM_PRIVATE)");
                remoteBase = proc.Alloc(sizeOfImage, PAGE_EXECUTE_READWRITE);
                Log.Ok($"[+] VirtualAllocEx @ 0x{remoteBase:X} (0x{sizeOfImage:X} bytes)");
            }

            var img = PeImage.Load(dllBytes, remoteBase);
            Log.Info($"[*] EntryPoint RVA: 0x{img.EntryPointRva:X}");
            var injection = new Injection(proc, img, ntdll);
            bool ok = injection.Run(remoteBase, ldrDisplay);

            if (ok)
            {
                Log.Ok("");
                Log.Ok("=== Injection successful! ===");
            }
            else
            {
                Log.Err("");
                Log.Err("=== Injection FAILED ===");
            }
        }
        catch (Exception ex)
        {
            Log.Err($"[!] {ex.GetType().Name}: {ex.Message}");
            Log.Err(ex.StackTrace ?? "");
        }

        Sleep(3000);
        return 0;
    }

    private static byte[]? LoadEmbeddedDll()
    {
        var asm = Assembly.GetExecutingAssembly();
        foreach (var name in asm.GetManifestResourceNames())
        {
            if (name.EndsWith("cheat.dll", StringComparison.OrdinalIgnoreCase))
            {
                using var s = asm.GetManifestResourceStream(name);
                if (s == null) continue;
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                return ms.ToArray();
            }
        }
        return null;
    }

    private static byte[]? LoadDiskDllAndDelete()
    {
        string exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                     ?? Environment.ProcessPath ?? "";
        string dir = Path.GetDirectoryName(exe) ?? ".";
        foreach (var candidate in new[] {
            Path.Combine(dir, "cheat.dll"),
            Path.Combine(dir, "Release", "cheat.dll")
        })
        {
            if (!File.Exists(candidate)) continue;
            try
            {
                byte[] bytes = File.ReadAllBytes(candidate);
                for (int i = 0; i < 5; i++)
                {
                    try { File.Delete(candidate); break; }
                    catch { Sleep(100); }
                }
                if (File.Exists(candidate))
                    Log.Warn($"[!] Could not delete {candidate}");
                else
                    Log.Ok($"[+] Disk copy deleted: {candidate}");
                return bytes;
            } catch { continue; }
        }
        return null;
    }

    private static int FindProcess(string exeName)
    {
        nint snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == 0 || snap == -1) return 0;
        try
        {
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref pe)) return 0;
            do
            {
                if (string.Equals(pe.szExeFile, exeName, StringComparison.OrdinalIgnoreCase))
                    return (int)pe.th32ProcessID;
            } while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }
        return 0;
    }

    private static unsafe uint ReadSizeOfImage(byte[] fileBytes)
    {
        fixed (byte* p = fileBytes)
        {
            var dos = (Pe.DosHeader*)p;
            var nt  = (Pe.NtHeaders64*)(p + dos->e_lfanew);
            return nt->Optional.SizeOfImage;
        }
    }
}
