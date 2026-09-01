using System.Runtime.InteropServices;

namespace Injector;

// Mirrors the tiny subset of PE structures we need. All layouts are the
// canonical x64 sizes.
internal static class Pe
{
    public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
    public const uint   IMAGE_NT_SIGNATURE  = 0x00004550;
    public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;

    public const int IMAGE_DIRECTORY_ENTRY_EXPORT   = 0;
    public const int IMAGE_DIRECTORY_ENTRY_IMPORT   = 1;
    public const int IMAGE_DIRECTORY_ENTRY_EXCEPTION= 3;
    public const int IMAGE_DIRECTORY_ENTRY_BASERELOC= 5;
    public const int IMAGE_DIRECTORY_ENTRY_TLS      = 9;
    public const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;

    public const ushort IMAGE_REL_BASED_HIGHLOW = 3;
    public const ushort IMAGE_REL_BASED_DIR64   = 10;

    [StructLayout(LayoutKind.Sequential)]
    public struct DosHeader { public ushort e_magic; public unsafe fixed byte pad[58]; public int e_lfanew; }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileHeader
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DataDir { public uint Rva; public uint Size; }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct OptionalHeader64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public fixed byte DataDirectoriesRaw[16 * 8];
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NtHeaders64
    {
        public uint Signature;
        public FileHeader File;
        public OptionalHeader64 Optional;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SectionHeader
    {
        public fixed byte Name[8];
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BaseRelocation { public uint VirtualAddress; public uint SizeOfBlock; }

    [StructLayout(LayoutKind.Sequential)]
    public struct ImportDescriptor
    {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }
}

// Loads a PE image from disk bytes, applies relocations to the target base,
// resolves imports. The mapped bytes can then be WriteProcessMemory'd whole.
internal sealed unsafe partial class PeImage
{
    public byte[] Mapped { get; private set; } = null!;
    public uint SizeOfImage { get; private set; }
    public uint EntryPointRva { get; private set; }
    public ulong OriginalImageBase { get; private set; }
    public uint ExceptionDirRva { get; private set; }
    public uint ExceptionDirSize { get; private set; }
    public uint LoadConfigRva { get; private set; }
    public uint LoadConfigSize { get; private set; }
    public uint[] GuardCfRvas { get; private set; } = Array.Empty<uint>();

    public static PeImage Load(byte[] fileBytes, nint targetBase)
    {
        fixed (byte* raw = fileBytes)
        {
            var dos = (Pe.DosHeader*)raw;
            if (dos->e_magic != Pe.IMAGE_DOS_SIGNATURE) throw new("bad DOS sig");

            var nt = (Pe.NtHeaders64*)(raw + dos->e_lfanew);
            if (nt->Signature != Pe.IMAGE_NT_SIGNATURE) throw new("bad NT sig");
            if (nt->File.Machine != Pe.IMAGE_FILE_MACHINE_AMD64) throw new("not x64");

            var opt = &nt->Optional;

            var img = new PeImage
            {
                SizeOfImage       = opt->SizeOfImage,
                EntryPointRva     = opt->AddressOfEntryPoint,
                OriginalImageBase = opt->ImageBase,
                Mapped            = new byte[opt->SizeOfImage],
            };

            // Read DataDirectory entries
            {
                Pe.DataDir* dd = (Pe.DataDir*)opt->DataDirectoriesRaw;
                img.ExceptionDirRva  = dd[Pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].Rva;
                img.ExceptionDirSize = dd[Pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
                if (opt->NumberOfRvaAndSizes > Pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
                {
                    img.LoadConfigRva  = dd[Pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Rva;
                    img.LoadConfigSize = dd[Pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
                }
            }

            // Copy headers + sections into `Mapped`
            fixed (byte* dst = img.Mapped)
            {
                Buffer.MemoryCopy(raw, dst, img.Mapped.Length, opt->SizeOfHeaders);

                var section = (Pe.SectionHeader*)((byte*)nt + sizeof(uint) + sizeof(Pe.FileHeader) + nt->File.SizeOfOptionalHeader);
                for (int i = 0; i < nt->File.NumberOfSections; i++)
                {
                    var s = &section[i];
                    if (s->SizeOfRawData == 0) continue;
                    Buffer.MemoryCopy(raw + s->PointerToRawData,
                                      dst + s->VirtualAddress,
                                      img.Mapped.Length - (int)s->VirtualAddress,
                                      s->SizeOfRawData);
                }
            }

            img.ApplyRelocations(targetBase);
            img.ResolveImports();
            img.PatchHeaders(targetBase);
            img.PatchSecurityCookie();
            img.PatchCfgPointers();
            img.ReadGuardCfTable(targetBase);

            return img;
        }
    }

    private void ApplyRelocations(nint targetBase)
    {
        long delta = (long)targetBase - (long)OriginalImageBase;
        if (delta == 0) return;

        fixed (byte* mapped = Mapped)
        {
            var dos = (Pe.DosHeader*)mapped;
            var nt  = (Pe.NtHeaders64*)(mapped + dos->e_lfanew);
            var opt = &nt->Optional;
            Pe.DataDir* dd = (Pe.DataDir*)opt->DataDirectoriesRaw;
            uint relocRva = dd[Pe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Rva;
            uint relocSize = dd[Pe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            if (relocRva == 0 || relocSize == 0) return;

            byte* block = mapped + relocRva;
            byte* end   = block + relocSize;
            while (block < end)
            {
                var hdr = (Pe.BaseRelocation*)block;
                if (hdr->SizeOfBlock == 0) break;
                int count = (int)((hdr->SizeOfBlock - sizeof(Pe.BaseRelocation)) / sizeof(ushort));
                ushort* entries = (ushort*)(block + sizeof(Pe.BaseRelocation));
                for (int i = 0; i < count; i++)
                {
                    ushort type = (ushort)(entries[i] >> 12);
                    ushort off  = (ushort)(entries[i] & 0xFFF);
                    byte* patchAddr = mapped + hdr->VirtualAddress + off;
                    if (type == Pe.IMAGE_REL_BASED_DIR64)
                    {
                        *(long*)patchAddr += delta;
                    }
                    else if (type == Pe.IMAGE_REL_BASED_HIGHLOW)
                    {
                        *(int*)patchAddr += (int)delta;
                    }
                }
                block += hdr->SizeOfBlock;
            }
        }
    }

    private void ResolveImports()
    {
        fixed (byte* mapped = Mapped)
        {
            var dos = (Pe.DosHeader*)mapped;
            var nt  = (Pe.NtHeaders64*)(mapped + dos->e_lfanew);
            var opt = &nt->Optional;
            Pe.DataDir* dd = (Pe.DataDir*)opt->DataDirectoriesRaw;
            uint impRva = dd[Pe.IMAGE_DIRECTORY_ENTRY_IMPORT].Rva;
            uint impSize = dd[Pe.IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            if (impRva == 0 || impSize == 0) return;

            var desc = (Pe.ImportDescriptor*)(mapped + impRva);
            while (desc->Name != 0)
            {
                string modName = Marshal.PtrToStringAnsi((nint)(mapped + desc->Name)) ?? "";
                nint hMod = Interop.GetModuleHandleW(modName);
                if (hMod == 0) hMod = LoadLibrary(modName);

                if (hMod != 0)
                {
                    ulong* origThunk = (ulong*)(mapped + (desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk : desc->FirstThunk));
                    ulong* thunk     = (ulong*)(mapped + desc->FirstThunk);
                    while (*origThunk != 0)
                    {
                        ulong entry = *origThunk;
                        nint proc;
                        if ((entry & 0x8000_0000_0000_0000UL) != 0)
                        {
                            // Ordinal
                            ushort ord = (ushort)(entry & 0xFFFF);
                            proc = Interop.GetProcAddress(hMod, "#" + ord.ToString());
                            if (proc == 0)
                            {
                                // Real ordinal lookup — GetProcAddress with (LPCSTR)ordinal
                                proc = GetProcAddressByOrdinal(hMod, ord);
                            }
                        }
                        else
                        {
                            // Import by name — name is at mapped + entry + 2 (skip hint)
                            string func = Marshal.PtrToStringAnsi((nint)(mapped + entry + 2)) ?? "";
                            proc = Interop.GetProcAddress(hMod, func);
                        }
                        *thunk = (ulong)proc;
                        origThunk++;
                        thunk++;
                    }
                }
                desc++;
            }
        }
    }

    private void PatchHeaders(nint targetBase)
    {
        fixed (byte* m = Mapped)
        {
            var dos = (Pe.DosHeader*)m;
            var nt  = (Pe.NtHeaders64*)(m + dos->e_lfanew);
            nt->Optional.ImageBase = (ulong)targetBase;
        }
    }

    private void PatchSecurityCookie()
    {
        if (LoadConfigRva == 0 || LoadConfigSize < 0x60) return;
        fixed (byte* m = Mapped)
        {
            // LOAD_CONFIG_DIRECTORY64.SecurityCookie at offset 0x58 is a VA
            ulong cookieVa = *(ulong*)(m + LoadConfigRva + 0x58);
            if (cookieVa == 0) return;
            ulong* cookie = (ulong*)(m + LoadConfigRva);
            // cookieVa was relocated, convert back to RVA
            var dos = (Pe.DosHeader*)m;
            var nt  = (Pe.NtHeaders64*)(m + dos->e_lfanew);
            ulong imageBase = nt->Optional.ImageBase;
            ulong cookieRva = cookieVa - imageBase;
            if (cookieRva < (ulong)Mapped.Length)
            {
                ulong* slot = (ulong*)(m + cookieRva);
                ulong val = (ulong)Environment.TickCount64;
                val ^= 0x00002B992DDFA232UL;
                if (val == 0x00002B992DDFA232UL) val++;
                *slot = val;
            }
        }
    }

    private void PatchCfgPointers()
    {
        if (LoadConfigRva == 0 || LoadConfigSize < 0x80) return;
        fixed (byte* m = Mapped)
        {
            var dos = (Pe.DosHeader*)m;
            var nt  = (Pe.NtHeaders64*)(m + dos->e_lfanew);
            ulong imageBase = nt->Optional.ImageBase;

            // GuardCFCheckFunctionPointer at LOAD_CONFIG+0x70
            // GuardCFDispatchFunctionPointer at LOAD_CONFIG+0x78
            // Both are relocated VAs pointing to slots in the image
            // We write a RET (0xC3) gadget address into those slots
            // to make CFG checks a no-op
            ulong checkVa   = *(ulong*)(m + LoadConfigRva + 0x70);
            ulong dispatchVa = *(ulong*)(m + LoadConfigRva + 0x78);

            // Place a single RET at end of headers (safe area before first section)
            uint retRva = nt->Optional.SizeOfHeaders - 1;
            m[retRva] = 0xC3;
            ulong retVa = imageBase + retRva;

            if (checkVa != 0)
            {
                ulong checkRva = checkVa - imageBase;
                if (checkRva < (ulong)Mapped.Length)
                    *(ulong*)(m + checkRva) = retVa;
            }
            if (dispatchVa != 0)
            {
                ulong dispRva = dispatchVa - imageBase;
                if (dispRva < (ulong)Mapped.Length)
                    *(ulong*)(m + dispRva) = retVa;
            }
        }
    }

    private void ReadGuardCfTable(nint targetBase)
    {
        if (LoadConfigRva == 0 || LoadConfigSize < 0x94) return;
        fixed (byte* m = Mapped)
        {
            ulong imageBase = (ulong)targetBase;
            // LOAD_CONFIG+0x80: GuardCFFunctionTable (VA, relocated)
            // LOAD_CONFIG+0x88: GuardCFFunctionCount (ulong)
            // LOAD_CONFIG+0x90: GuardFlags (uint)
            ulong tableVa  = *(ulong*)(m + LoadConfigRva + 0x80);
            ulong count    = *(ulong*)(m + LoadConfigRva + 0x88);
            uint  flags    = *(uint*) (m + LoadConfigRva + 0x90);

            if (tableVa == 0 || count == 0) return;

            uint extraSize = (flags >> 28) & 0xF;
            uint stride = 4 + extraSize;

            ulong tableRva = tableVa - imageBase;
            if (tableRva >= (ulong)Mapped.Length) return;

            var rvas = new uint[count];
            byte* table = m + tableRva;
            for (ulong i = 0; i < count; i++)
                rvas[i] = *(uint*)(table + i * stride);
            GuardCfRvas = rvas;
        }
    }

    [System.Runtime.InteropServices.LibraryImport("kernel32.dll", StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf8)]
    private static partial nint LoadLibraryA(string lpLibFileName);
    private static nint LoadLibrary(string name) => LoadLibraryA(name);

    [System.Runtime.InteropServices.LibraryImport("kernel32.dll", EntryPoint = "GetProcAddress")]
    private static partial nint GetProcAddressOrd(nint hModule, nint ordinal);
    private static nint GetProcAddressByOrdinal(nint hModule, ushort ord) => GetProcAddressOrd(hModule, (nint)ord);
}
