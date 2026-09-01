using System.Runtime.InteropServices;
using System.Text;
using static Injector.Interop;

namespace Injector;

// The ShellCtx struct - MUST match the offsets encoded in Shellcode.Bytes.
[StructLayout(LayoutKind.Sequential, Size = 0x78)]
internal struct ShellCtx
{
    public nint  RbTree;                 // +0x00
    public nint  RbParent;               // +0x08
    public long  RbRight;                // +0x10  low bit = BOOLEAN
    public nint  RbNode;                 // +0x18
    public nint  FuncTable;              // +0x20  0 = skip RtlAddFunctionTable
    public uint  FuncCount;              // +0x28
    public uint  _pad0;                  // +0x2C
    public nint  ImageBase;              // +0x30
    public nint  LdrEntry;               // +0x38
    public nint  RtlRbInsertNodeEx;      // +0x40
    public nint  RtlAddFunctionTable;    // +0x48
    public nint  LdrpHandleTlsData;      // +0x50
    public nint  DllMain;                // +0x58
    public long  NtStatusTls;            // +0x60
    public uint  Success;                // +0x68
    public uint  Stage;                  // +0x6C  last completed stage
    public nint  Sleep;                  // +0x70  kernel32!Sleep — keep thread alive
}

internal sealed unsafe class Injection
{
    private readonly RemoteProcess _proc;
    private readonly PeImage       _img;
    private readonly NtdllInfo     _ntdll;

    public Injection(RemoteProcess proc, PeImage img, NtdllInfo ntdll)
        { _proc = proc; _img = img; _ntdll = ntdll; }

    public bool Run(nint remoteBase, string ldrDisplayName)
    {
        // 1. Write mapped image
        _proc.WriteBytes(remoteBase, _img.Mapped);
        Log.Ok($"[+] Image sections written @ 0x{remoteBase:X}");

        // 2. Allocate LDR entry, DDAG node, name buffers in target
        nint remoteLdr  = _proc.Alloc((nuint)Ldr.LDR_ENTRY_ALLOC_SIZE);
        nint remoteDdag = _proc.Alloc((nuint)Ldr.DDAG_NODE_ALLOC_SIZE);
        byte[] fullBytes = Encoding.Unicode.GetBytes(ldrDisplayName + "\0");
        byte[] baseNameBytes = Encoding.Unicode.GetBytes(
            System.IO.Path.GetFileName(ldrDisplayName) + "\0");
        nint remoteFull = _proc.Alloc((nuint)fullBytes.Length);
        nint remoteBase2 = _proc.Alloc((nuint)baseNameBytes.Length);
        _proc.WriteBytes(remoteFull, fullBytes);
        _proc.WriteBytes(remoteBase2, baseNameBytes);

        // 3. Build the LDR entry locally, then flush
        byte[] ldrLocal = new byte[Ldr.LDR_ENTRY_ALLOC_SIZE];
        BuildLdrEntry(ldrLocal, remoteBase, _img.SizeOfImage, _img.EntryPointRva,
            _img.OriginalImageBase, remoteDdag, remoteFull, remoteBase2,
            (ushort)(fullBytes.Length - 2), (ushort)(baseNameBytes.Length - 2));
        _proc.WriteBytes(remoteLdr, ldrLocal);

        // 4. Build DDAG node locally, then flush
        byte[] ddagLocal = new byte[Ldr.DDAG_NODE_ALLOC_SIZE];
        BuildDdagNode(ddagLocal, remoteLdr, remoteDdag);
        _proc.WriteBytes(remoteDdag, ddagLocal);

        // 5. Link into PEB Ldr lists (all done via RPM/WPM)
        LinkIntoPebLists(remoteLdr);
        Log.Ok("[+] LDR entry linked into PEB lists");

        // 6. Walk RB tree in target, find insert position for our node
        (nint rbParent, bool rbRight) = FindRbInsertPosition(remoteBase);

        // 7. Insert into LdrpInvertedFunctionTable via RPM/WPM
        InsertInvertedTable(remoteBase, _img.SizeOfImage,
            _img.ExceptionDirRva != 0 ? remoteBase + (nint)_img.ExceptionDirRva : 0,
            _img.ExceptionDirSize / 12);   // sizeof RUNTIME_FUNCTION = 12
        Log.Ok("[+] Inserted into LdrpInvertedFunctionTable");

        // 8. Register CFG valid call targets
        RegisterCfgTargets(remoteBase);

        // 8b. Patch ntdll image-base validation to prevent FAST_FAIL_INVALID_IMAGE_BASE (24)
        PatchImageBaseValidation();

        // 9. Prepare ShellCtx in target
        var ctx = new ShellCtx
        {
            RbTree              = _ntdll.RbTreePtr,
            RbParent            = rbParent,
            RbRight             = rbRight ? 1 : 0,
            RbNode              = remoteLdr + Ldr.OFFSET_BaseAddressIndexNode,
            FuncTable           = _img.ExceptionDirSize > 0
                                      ? remoteBase + (nint)_img.ExceptionDirRva
                                      : 0,
            FuncCount           = _img.ExceptionDirSize / 12,
            ImageBase           = remoteBase,
            LdrEntry            = remoteLdr,
            RtlRbInsertNodeEx   = _ntdll.RtlRbInsertNodeEx,
            RtlAddFunctionTable = _ntdll.RtlAddFunctionTable,
            LdrpHandleTlsData   = _ntdll.LdrpHandleTlsData,
            DllMain             = remoteBase + (nint)_img.EntryPointRva,
            Sleep               = GetProcAddress(GetModuleHandleW("kernel32.dll"), "Sleep"),
        };
        nint remoteCtx = _proc.Alloc((nuint)sizeof(ShellCtx));
        _proc.WriteBytes(remoteCtx, &ctx, (nuint)sizeof(ShellCtx));

        // 9. Write shellcode and spawn a thread
        nint remoteSc = _proc.Alloc((nuint)Shellcode.Bytes.Length, PAGE_EXECUTE_READWRITE);
        _proc.WriteBytes(remoteSc, Shellcode.Bytes);

        nint hThread = _proc.CreateThread(remoteSc, remoteCtx);
        uint waitRes = WaitForSingleObject(hThread, 30000);
        CloseHandle(hThread);

        var post = _proc.Read<ShellCtx>(remoteCtx);
        Log.Info($"[*] Shellcode: stage={post.Stage} wait=0x{waitRes:X} NtStatusTls=0x{post.NtStatusTls:X8} Success={post.Success}");
        string stageName = post.Stage switch {
            0 => "before RtlRbInsertNodeEx",
            1 => "after RB insert, before RtlAddFunctionTable",
            2 => "after AddFunctionTable, before LdrpHandleTlsData",
            3 => "after LdrpHandleTlsData, before DllMain",
            4 => "after DllMain",
            _ => "?"
        };
        Log.Info($"[*] Crash location: {stageName}");

        return post.Success == 1;
    }

    // -----------------------------------------------------------------------
    // LDR entry / DDAG node construction (local memory)
    // -----------------------------------------------------------------------
    private static void BuildLdrEntry(byte[] buf, nint dllBase, uint sizeOfImage,
                                      uint entryPointRva, ulong originalImageBase,
                                      nint ddagNode, nint fullNamePtr, nint baseNamePtr,
                                      ushort fullNameByteLen, ushort baseNameByteLen)
    {
        Span<byte> s = buf;
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_DllBase..],       (long)dllBase);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_EntryPoint..],    (long)(dllBase + (nint)entryPointRva));
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_SizeOfImage..],   sizeOfImage);

        // UNICODE_STRING FullDllName / BaseDllName
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_FullDllName..],    fullNameByteLen);
        BitConverter.TryWriteBytes(s[(Ldr.OFFSET_FullDllName+2)..],(ushort)(fullNameByteLen + 2));
        BitConverter.TryWriteBytes(s[(Ldr.OFFSET_FullDllName+8)..],(long)fullNamePtr);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_BaseDllName..],    baseNameByteLen);
        BitConverter.TryWriteBytes(s[(Ldr.OFFSET_BaseDllName+2)..],(ushort)(baseNameByteLen + 2));
        BitConverter.TryWriteBytes(s[(Ldr.OFFSET_BaseDllName+8)..],(long)baseNamePtr);

        BitConverter.TryWriteBytes(s[Ldr.OFFSET_Flags..],
            Ldr.LDRP_IMAGE_DLL | Ldr.LDRP_ENTRY_PROCESSED |
            Ldr.LDRP_PROCESS_ATTACH_CALLED | Ldr.LDRP_PROCESS_STATIC_IMPORT |
            Ldr.LDRP_DONT_CALL_FOR_THREADS);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_ObsoleteLoadCount..], (ushort)1);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_TlsIndex..],          (ushort)0);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_DdagNode..],          (long)ddagNode);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_OriginalBase..],      (long)originalImageBase);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_LoadReason..],        (uint)4); // Dynamic
    }

    private static void BuildDdagNode(byte[] buf, nint ldrEntry, nint ddagSelf)
    {
        Span<byte> s = buf;
        // Modules head: point Flink/Blink to the LDR entry's NodeModuleLink
        nint nodeModuleLink = ldrEntry + Ldr.OFFSET_NodeModuleLink;
        BitConverter.TryWriteBytes(s[0..],  (long)nodeModuleLink);   // Modules.Flink
        BitConverter.TryWriteBytes(s[8..],  (long)nodeModuleLink);   // Modules.Blink
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_DdagLoadCount..], (uint)1);
        BitConverter.TryWriteBytes(s[Ldr.OFFSET_DdagState..],
            (uint)Ldr.DdagState_LdrModulesReadyToRun);
    }

    // -----------------------------------------------------------------------
    // PEB list linking (remote, patch tail-insert)
    // -----------------------------------------------------------------------
    private void LinkIntoPebLists(nint remoteLdr)
    {
        nint peb = _proc.GetPebBase();
        nint ldr = _proc.ReadPtr(peb + 0x18);
        if (ldr == 0) throw new("target PEB.Ldr is null");

        int[] listHeadOffsets  = { 0x10, 0x20, 0x30 };
        int[] entryLinkOffsets = { Ldr.OFFSET_InLoadOrderLinks,
                                    Ldr.OFFSET_InMemoryOrderLinks,
                                    Ldr.OFFSET_InInitializationLinks };
        for (int i = 0; i < 3; i++)
        {
            nint head    = ldr + listHeadOffsets[i];
            nint entry   = remoteLdr + entryLinkOffsets[i];
            nint prev    = _proc.ReadPtr(head + 8);   // head.Blink
            // entry.Flink = head ; entry.Blink = prev
            _proc.WriteI64(entry, (long)head);
            _proc.WriteI64(entry + 8, (long)prev);
            // prev.Flink = entry ; head.Blink = entry
            _proc.WriteI64(prev,       (long)entry);
            _proc.WriteI64(head + 8,   (long)entry);
        }
        // HashLinks: self-loop (we're not in LdrpHashTable)
        nint hl = remoteLdr + Ldr.OFFSET_HashLinks;
        _proc.WriteI64(hl,     (long)hl);
        _proc.WriteI64(hl + 8, (long)hl);
    }

    // -----------------------------------------------------------------------
    // RB tree walk in target - find (parent, direction) for our node's pos
    // -----------------------------------------------------------------------
    private (nint parent, bool right) FindRbInsertPosition(nint ourBase)
    {
        nint root = _proc.ReadPtr(_ntdll.RbTreePtr);   // RTL_RB_TREE.Root
        nint cur = root;
        nint parent = 0;
        bool right = false;
        while (cur != 0)
        {
            parent = cur;
            nint otherEntry = cur - Ldr.OFFSET_BaseAddressIndexNode;
            nint otherBase  = _proc.ReadPtr(otherEntry + Ldr.OFFSET_DllBase);
            if ((ulong)ourBase < (ulong)otherBase) { cur = _proc.ReadPtr(cur); right = false; }
            else if ((ulong)ourBase > (ulong)otherBase) { cur = _proc.ReadPtr(cur + 8); right = true; }
            else break;
        }
        return (parent, right);
    }

    // -----------------------------------------------------------------------
    // LdrpInvertedFunctionTable manual insert in target
    // Header (16): Count(u32), MaxCount(u32), pad(u64)
    // Entry (24): FunctionTable(ptr), ImageBase(ptr), SizeOfImage(u32), Count(u32)
    // Located via NtdllInfo.InvertedTableRva (relative to target's ntdll base)
    // -----------------------------------------------------------------------
    private void InsertInvertedTable(nint imageBase, uint sizeOfImage,
                                     nint funcTable, uint funcCount)
    {
        var (targetNtdll, _) = _proc.FindModule("ntdll.dll");
        if (targetNtdll == 0) throw new("ntdll.dll not found in target");
        nint hdrAddr = targetNtdll + (nint)_ntdll.InvertedTableRva;

        uint count    = _proc.ReadU32(hdrAddr);
        uint maxCount = _proc.ReadU32(hdrAddr + 4);
        if (count >= maxCount)
        {
            Log.Warn($"[!] InvertedFunctionTable full ({count}/{maxCount}) - skipping insert");
            return;
        }

        // Make the whole table region writable in the target (COW may leave it
        // read-only for pages we haven't touched yet).
        nuint tableBytes = (nuint)(16 + maxCount * 24);
        VirtualProtectEx(_proc.Handle, hdrAddr, tableBytes, PAGE_READWRITE, out _);

        // Find sorted-insert position by ImageBase
        nint entries = hdrAddr + 16;
        int pos;
        for (pos = 0; pos < count; pos++)
        {
            nint slotAddr = entries + (nint)((long)pos * 24) + 8;
            nint pImageBase = _proc.ReadPtr(slotAddr);
            if ((ulong)imageBase < (ulong)pImageBase) break;
        }

        // Shift entries [pos .. count-1] up by one
        byte[] buf = new byte[24];
        for (int i = (int)count; i > pos; i--)
        {
            nint src = entries + (nint)((long)(i - 1) * 24);
            nint dst = entries + (nint)((long)i * 24);
            fixed (byte* p = buf)
            {
                _proc.ReadBytes(src, p, 24);
                _proc.WriteBytes(dst, p, 24);
            }
        }

        // Populate our slot
        nint mySlot = entries + (nint)((long)pos * 24);
        _proc.WriteI64(mySlot,      (long)funcTable);
        _proc.WriteI64(mySlot + 8,  (long)imageBase);
        _proc.WriteU32(mySlot + 16, sizeOfImage);
        _proc.WriteU32(mySlot + 20, funcCount);

        // Bump Count last
        _proc.WriteU32(hdrAddr, count + 1);
    }

    // -----------------------------------------------------------------------
    // CFG: register all valid call targets from the PE's GuardCFFunctionTable
    // so ntdll doesn't FAST_FAIL_INVALID_IMAGE_BASE (24) on indirect calls
    // into our manually-mapped image.
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Patch ALL ntdll fastfail(24) = FAST_FAIL_INVALID_IMAGE_BASE sites.
    // For each "mov ecx, 18h; int 29h" (B9 18 00 00 00 CD 29), finds the
    // nearest preceding conditional jump and converts it to unconditional.
    // Falls back to NOPing the int 29h + adding a jump to the success path
    // found via the conditional jump's target.
    // -----------------------------------------------------------------------
    private void PatchImageBaseValidation()
    {
        var (targetNtdll, _) = _proc.FindModule("ntdll.dll");
        if (targetNtdll == 0) return;

        byte* text;
        int textSize;
        nint localNtdll = _ntdll.NtdllBase;
        {
            byte* m = (byte*)localNtdll;
            var dos = (Pe.DosHeader*)m;
            var nt  = (Pe.NtHeaders64*)(m + dos->e_lfanew);
            var sec = (Pe.SectionHeader*)((byte*)nt + sizeof(uint) + sizeof(Pe.FileHeader) + nt->File.SizeOfOptionalHeader);
            text = null;
            textSize = 0;
            for (int s = 0; s < nt->File.NumberOfSections; s++)
            {
                if (sec[s].Name[0] == '.' && sec[s].Name[1] == 't' && sec[s].Name[2] == 'e' && sec[s].Name[3] == 'x' && sec[s].Name[4] == 't')
                {
                    text = m + sec[s].VirtualAddress;
                    textSize = (int)sec[s].VirtualSize;
                    break;
                }
            }
        }

        if (text == null || textSize == 0) return;

        int patchCount = 0;
        for (int i = 0; i + 7 <= textSize; i++)
        {
            if (text[i]   != 0xB9 || text[i+1] != 0x18 || text[i+2] != 0x00 ||
                text[i+3] != 0x00 || text[i+4] != 0x00 ||
                text[i+5] != 0xCD || text[i+6] != 0x29)
                continue;

            nint ffRva = (nint)(text + i) - localNtdll;

            // Dump context bytes for diagnostics
            int ctxStart = Math.Max(0, i - 30);
            var sb = new System.Text.StringBuilder();
            for (int k = ctxStart; k < i + 7; k++)
            {
                if (k == i) sb.Append('[');
                sb.Append($"{text[k]:X2}");
                if (k == i + 6) sb.Append(']');
                sb.Append(' ');
            }
            Log.Info($"[*] fastfail(24) @ ntdll+0x{ffRva:X}  bytes: {sb}");

            nint patchRva = 0;
            byte[]? patchBytes = null;

            // Strategy 1: near conditional jump (0F 8x) at i-6 (immediately preceding)
            if (i >= 6 && text[i-6] == 0x0F && text[i-5] >= 0x80 && text[i-5] <= 0x8F)
            {
                int j = i - 6;
                patchRva = (nint)(text + j) - localNtdll;
                int origDisp = *(int*)(text + j + 2);
                int newDisp = origDisp + 1;
                patchBytes = new byte[] {
                    0xE9,
                    (byte)newDisp, (byte)(newDisp >> 8),
                    (byte)(newDisp >> 16), (byte)(newDisp >> 24),
                    0x90
                };
            }

            // Strategy 2: short conditional jump (7x) at i-2 (immediately preceding)
            if (patchRva == 0 && i >= 2 && text[i-2] >= 0x70 && text[i-2] <= 0x7F)
            {
                int j = i - 2;
                patchRva = (nint)(text + j) - localNtdll;
                patchBytes = new byte[] { 0xEB, text[j+1] };
            }

            // Strategy 3: near conditional jump further back (scan i-7..i-30)
            if (patchRva == 0)
            {
                int scanStart = Math.Max(0, i - 30);
                for (int j = i - 7; j >= scanStart; j--)
                {
                    if (text[j] == 0x0F && text[j+1] >= 0x80 && text[j+1] <= 0x8F)
                    {
                        int disp = *(int*)(text + j + 2);
                        int jccEnd = j + 6;
                        int target = jccEnd + disp;
                        // Validate: target should be outside [j, i+7) range
                        if (target < j || target >= i + 7)
                        {
                            patchRva = (nint)(text + j) - localNtdll;
                            int newDisp = disp + 1;
                            patchBytes = new byte[] {
                                0xE9,
                                (byte)newDisp, (byte)(newDisp >> 8),
                                (byte)(newDisp >> 16), (byte)(newDisp >> 24),
                                0x90
                            };
                            break;
                        }
                    }
                }
            }

            if (patchRva == 0)
            {
                Log.Info($"[*]   → shared landing pad, scanning for caller jcc's...");
                int callerPatches = 0;
                for (int j = 0; j + 6 <= textSize; j++)
                {
                    // Near conditional: 0F 8x xx xx xx xx
                    if (text[j] == 0x0F && text[j+1] >= 0x80 && text[j+1] <= 0x8F)
                    {
                        int disp = *(int*)(text + j + 2);
                        int target = j + 6 + disp;
                        if (target == i)
                        {
                            nint callerRva = (nint)(text + j) - localNtdll;
                            nint callerAddr = targetNtdll + callerRva;
                            VirtualProtectEx(_proc.Handle, callerAddr, 6,
                                PAGE_EXECUTE_READWRITE, out uint op);
                            _proc.WriteBytes(callerAddr, new byte[]{ 0x90,0x90,0x90,0x90,0x90,0x90 });
                            VirtualProtectEx(_proc.Handle, callerAddr, 6, op, out _);
                            callerPatches++;
                            Log.Ok($"[+]   NOP'd near jcc caller @ ntdll+0x{callerRva:X}");
                        }
                    }
                    // Short conditional: 7x xx
                    if (text[j] >= 0x70 && text[j] <= 0x7F && j + 2 <= textSize)
                    {
                        int disp = (sbyte)text[j+1];
                        int target = j + 2 + disp;
                        if (target == i)
                        {
                            nint callerRva = (nint)(text + j) - localNtdll;
                            nint callerAddr = targetNtdll + callerRva;
                            VirtualProtectEx(_proc.Handle, callerAddr, 2,
                                PAGE_EXECUTE_READWRITE, out uint op);
                            _proc.WriteBytes(callerAddr, new byte[]{ 0x90, 0x90 });
                            VirtualProtectEx(_proc.Handle, callerAddr, 2, op, out _);
                            callerPatches++;
                            Log.Ok($"[+]   NOP'd short jcc caller @ ntdll+0x{callerRva:X}");
                        }
                    }
                }
                patchCount += callerPatches;
                if (callerPatches == 0)
                    Log.Warn($"[!]   No callers found for landing pad");
                continue;
            }

            nint patchAddr = targetNtdll + patchRva;
            VirtualProtectEx(_proc.Handle, patchAddr, (nuint)patchBytes!.Length,
                PAGE_EXECUTE_READWRITE, out uint oldProt);
            _proc.WriteBytes(patchAddr, patchBytes);
            VirtualProtectEx(_proc.Handle, patchAddr, (nuint)patchBytes.Length, oldProt, out _);
            patchCount++;
            Log.Ok($"[+] Patched fastfail(24) @ ntdll+0x{ffRva:X} (patch @ 0x{patchRva:X})");
        }

        if (patchCount > 0)
            Log.Ok($"[+] Bypassed {patchCount} image-base validation site(s)");
        else
            Log.Warn("[!] No fastfail(24) sites found in ntdll");
    }

    private void RegisterCfgTargets(nint remoteBase)
    {
        uint[] rvas = _img.GuardCfRvas;
        if (rvas.Length == 0)
        {
            Log.Info("[*] CFG: no guard function table in PE, skipping");
            return;
        }

        var targets = new Interop.CFG_CALL_TARGET_INFO[rvas.Length];
        for (int i = 0; i < rvas.Length; i++)
        {
            targets[i].Offset = (nuint)rvas[i];
            targets[i].Flags  = Interop.CFG_CALL_TARGET_VALID;
        }

        fixed (Interop.CFG_CALL_TARGET_INFO* p = targets)
        {
            bool ok = Interop.SetProcessValidCallTargets(
                _proc.Handle, remoteBase, (nuint)_img.SizeOfImage,
                (uint)targets.Length, p);
            if (ok)
                Log.Ok($"[+] CFG: registered {targets.Length} valid call targets");
            else
                Log.Warn($"[!] CFG: SetProcessValidCallTargets failed err={System.Runtime.InteropServices.Marshal.GetLastPInvokeError()}");
        }
    }
}
