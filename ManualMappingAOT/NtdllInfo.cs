using System.Runtime.InteropServices;

namespace Injector;

// Discovery of ntdll internals (in the injector's own process — ntdll is at
// the same VA in every process on the same boot, so addresses transfer to the
// target, and RVA-relative fallback recovers if it doesn't).
internal sealed unsafe partial class NtdllInfo
{
    public nint  NtdllBase           { get; init; }
    public nint  LdrpHandleTlsData   { get; init; }
    public nint  RtlRbInsertNodeEx   { get; init; }
    public nint  RtlAddFunctionTable { get; init; }
    public nint  RbTreePtr           { get; init; }    // &LdrpModuleBaseAddressIndex
    public nint  InvertedTablePtr    { get; init; }    // &LdrpInvertedFunctionTable
    public uint  InvertedTableRva    { get; init; }
    public uint  RbTreeRva           { get; init; }

    public static NtdllInfo Discover()
    {
        nint ntdll = Interop.GetModuleHandleW("ntdll.dll");
        if (ntdll == 0) throw new("ntdll.dll not loaded");

        nint handleTls = FindLdrpHandleTlsData(ntdll);
        if (handleTls == 0) throw new("LdrpHandleTlsData pattern not found");

        nint rbTree = FindLdrpModuleBaseAddressIndex(ntdll);
        if (rbTree == 0) throw new("LdrpModuleBaseAddressIndex not found");

        nint invTable = FindLdrpInvertedFunctionTable(ntdll);
        if (invTable == 0) throw new("LdrpInvertedFunctionTable not found");

        return new NtdllInfo
        {
            NtdllBase           = ntdll,
            LdrpHandleTlsData   = handleTls,
            RtlRbInsertNodeEx   = Interop.GetProcAddress(ntdll, "RtlRbInsertNodeEx"),
            RtlAddFunctionTable = Interop.GetProcAddress(ntdll, "RtlAddFunctionTable") != 0
                                    ? Interop.GetProcAddress(ntdll, "RtlAddFunctionTable")
                                    : Interop.GetProcAddress(Interop.GetModuleHandleW("kernel32.dll"), "RtlAddFunctionTable"),
            RbTreePtr           = rbTree,
            RbTreeRva           = (uint)((long)rbTree - (long)ntdll),
            InvertedTablePtr    = invTable,
            InvertedTableRva    = (uint)((long)invTable - (long)ntdll),
        };
    }

    // Text-section access
    private static bool GetTextSection(nint module, out byte* baseAddr, out int size)
    {
        baseAddr = null; size = 0;
        byte* m = (byte*)module;
        var dos = (Pe.DosHeader*)m;
        var nt  = (Pe.NtHeaders64*)(m + dos->e_lfanew);
        var sec = (Pe.SectionHeader*)((byte*)nt + sizeof(uint) + sizeof(Pe.FileHeader) + nt->File.SizeOfOptionalHeader);
        for (int i = 0; i < nt->File.NumberOfSections; ++i)
        {
            byte* nm = sec[i].Name;
            if (nm[0] == '.' && nm[1] == 't' && nm[2] == 'e' && nm[3] == 'x' && nm[4] == 't')
            {
                baseAddr = m + sec[i].VirtualAddress;
                size     = (int)sec[i].VirtualSize;
                return true;
            }
        }
        return false;
    }

    // Heuristic: the ONE function that stores a WORD to [reg + 0x6E]
    // (LDR_DATA_TABLE_ENTRY.TlsIndex) is LdrpHandleTlsData. Encoded:
    //   66 89 <modrm:mod=01, r/m=<reg>, reg=ax> 6E
    // Walk back to CC CC padding to reach the function prologue.
    private static nint FindLdrpHandleTlsData(nint ntdll)
    {
        if (!GetTextSection(ntdll, out byte* text, out int size)) return 0;
        for (int i = 0; i + 4 < size; ++i)
        {
            if (text[i] == 0x66 && text[i + 1] == 0x89 &&
                text[i + 3] == 0x6E && (text[i + 2] >> 6) == 0b01)
            {
                for (int j = i; j > 2; --j)
                {
                    if (text[j - 1] == 0xCC && text[j - 2] == 0xCC)
                        return (nint)(text + j);
                }
                return 0;
            }
        }
        return 0;
    }

    // Walk any real module's BaseAddressIndexNode up to the RB tree root,
    // then scan ntdll's writable data for a QWORD == root. That slot IS
    // RTL_RB_TREE::Root, i.e. &LdrpModuleBaseAddressIndex.
    private static nint FindLdrpModuleBaseAddressIndex(nint ntdll)
    {
        // Read PEB via NtQueryInformationProcess of self
        var pbi = new Interop.PROCESS_BASIC_INFORMATION();
        int st = Interop.NtQueryInformationProcess(GetCurrentProcess(), 0, ref pbi, (uint)sizeof(Interop.PROCESS_BASIC_INFORMATION), out _);
        if (st < 0 || pbi.PebBaseAddress == 0) return 0;

        // PEB.Ldr is at offset 0x18
        nint ldr = *(nint*)((byte*)pbi.PebBaseAddress + 0x18);
        if (ldr == 0) return 0;

        // InLoadOrderModuleList head is at offset 0x10 inside PEB_LDR_DATA
        nint listHead = ldr + 0x10;
        nint cur = *(nint*)listHead;    // Flink

        while (cur != 0 && cur != listHead)
        {
            byte* entry = (byte*)cur; // InLoadOrderLinks at offset 0 → cur points to entry
            nint* nodePtr = (nint*)(entry + Ldr.OFFSET_BaseAddressIndexNode);

            // Walk up: parent = node.ParentValue & ~3
            nint node = (nint)nodePtr;
            nint root = WalkToRoot(node);
            if (root != 0)
            {
                // Scan writable sections of ntdll for QWORD == root
                byte* m = (byte*)ntdll;
                var dos = (Pe.DosHeader*)m;
                var nt  = (Pe.NtHeaders64*)(m + dos->e_lfanew);
                var sec = (Pe.SectionHeader*)((byte*)nt + sizeof(uint) + sizeof(Pe.FileHeader) + nt->File.SizeOfOptionalHeader);
                for (int i = 0; i < nt->File.NumberOfSections; ++i)
                {
                    const uint IMAGE_SCN_MEM_WRITE = 0x80000000u;
                    if ((sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) == 0) continue;
                    byte* b = m + sec[i].VirtualAddress;
                    int sz = (int)sec[i].VirtualSize;
                    for (int off = 0; off + 8 <= sz; off += 8)
                    {
                        if (*(nint*)(b + off) == root)
                            return (nint)(b + off);
                    }
                }
            }
            cur = *(nint*)cur;   // Flink of this entry
        }
        return 0;
    }

    private static nint WalkToRoot(nint node)
    {
        while (node != 0)
        {
            nint parentValue = *(nint*)((byte*)node + 16);
            nint parent = (nint)((long)parentValue & ~3L);
            if (parent == 0) return node;
            node = parent;
        }
        return 0;
    }

    // Scan ntdll .data for an entry whose ImageBase == ntdll and SizeOfImage
    // matches, then walk back in 24-byte strides until Count/MaxCount look
    // valid — the resulting address is the LdrpInvertedFunctionTable header.
    private static nint FindLdrpInvertedFunctionTable(nint ntdll)
    {
        byte* m = (byte*)ntdll;
        var dos = (Pe.DosHeader*)m;
        var nt  = (Pe.NtHeaders64*)(m + dos->e_lfanew);
        uint ntdllSize = nt->Optional.SizeOfImage;
        var sec = (Pe.SectionHeader*)((byte*)nt + sizeof(uint) + sizeof(Pe.FileHeader) + nt->File.SizeOfOptionalHeader);

        for (int i = 0; i < nt->File.NumberOfSections; ++i)
        {
            const uint IMAGE_SCN_MEM_WRITE = 0x80000000u;
            if ((sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) == 0) continue;
            byte* b = m + sec[i].VirtualAddress;
            int sz = (int)sec[i].VirtualSize;

            for (int off = 0; off + 24 <= sz; off += 8)
            {
                // Entry layout: FunctionTable(8) ImageBase(8) SizeOfImage(4) EntryCount(4)
                nint imageBase = *(nint*)(b + off + 8);
                uint sizeImg   = *(uint*)(b + off + 16);
                if (imageBase != ntdll || sizeImg != ntdllSize) continue;

                byte* e = b + off;
                for (int back = 0; back < 512; ++back)
                {
                    byte* hdr = e - back * 24 - 16;
                    if ((nint)hdr < (nint)b) break;
                    uint count = *(uint*)hdr;
                    uint maxCount = *(uint*)(hdr + 4);
                    if (count > 0 && count <= maxCount && maxCount >= 32 && maxCount <= 4096)
                    {
                        // Sanity: entries[count-1] must have valid ImageBase/SizeOfImage
                        byte* last = hdr + 16 + (int)(count - 1) * 24;
                        nint  lastBase = *(nint*)(last + 8);
                        uint  lastSize = *(uint*)(last + 16);
                        if (lastBase != 0 && lastSize != 0)
                            return (nint)hdr;
                    }
                }
            }
        }
        return 0;
    }

    [System.Runtime.InteropServices.LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();
}
