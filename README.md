# MMInject (BETA)
Credits by Jan (Me).

# NativeAOT DLL Base:
```c#
    public class EntryPoint
    {
        private const int DLL_PROCESS_ATTACH = 1;

        public static Process? GameProc { get; set; }
        private static int AdaptiveDelayMs { get; set; } = 10;
        private static CancellationTokenSource _cts = new();
        private static Delegate _originalUpdateDelegate;

        [UnmanagedCallersOnly(EntryPoint = "DllMain")]
        public static bool DllMain(nint hModule, uint reason, nint reserved)
        {
            if (reason == DLL_PROCESS_ATTACH)
            {
                Start();
            }
            return true;
        }

        private static unsafe void Start()
        {
                File.Delete("debug.log");
                Logging.Alloc();
                CrashHandler.Initialize();

                uint threadId;
                IntPtr hThread = _beginthreadex(IntPtr.Zero, 0, &ThreadStart, IntPtr.Zero, 0, out threadId);
                if (hThread != IntPtr.Zero)
                    CloseHandle(hThread);
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static uint ThreadStart(nint param)
        {
            try
            {
                ModuleManager.LoadCoreModulesAsync().Wait();
                RunMainLoopAsync(_cts.Token).Wait();
            }
            catch (Exception ex)
            {
                Logging.Log($"ThreadStart Fehler: {ex}");
                Logging.LogToFile($"ThreadStart Fehler: {ex}");
            }
            return 0;
        }

        public static async Task RunMainLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var sw = Stopwatch.StartNew();

                try
                {
                    // await EventManager.UpdateAll().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Logging.Log($"EventManager.UpdateAll Fehler: {ex.Message}");
                }

                int elapsed = (int)sw.ElapsedMilliseconds;
                int delay = Math.Max(1, AdaptiveDelayMs - elapsed);
                await Task.Delay(delay, token).ConfigureAwait(false);
            }
        }

        public static void Unload()
        {
            _cts.Cancel();
        }

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static unsafe extern IntPtr _beginthreadex(
            IntPtr security,
            uint stackSize,
            delegate* unmanaged[Cdecl]<nint, uint> startAddress,
            IntPtr argList,
            uint initFlag,
            out uint threadId
        );

        [DllImport("kernel32")]
        private static extern bool CloseHandle(nint hObject);
    }
```
