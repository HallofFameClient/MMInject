namespace Injector;

// Layout constants for the "full" LDR_DATA_TABLE_ENTRY on Win10 1809+/Win11 x64.
internal static class Ldr
{
    // LDR_DATA_TABLE_ENTRY field offsets
    public const int OFFSET_InLoadOrderLinks         = 0x000;   // 16
    public const int OFFSET_InMemoryOrderLinks       = 0x010;   // 16
    public const int OFFSET_InInitializationLinks    = 0x020;   // 16
    public const int OFFSET_DllBase                  = 0x030;
    public const int OFFSET_EntryPoint               = 0x038;
    public const int OFFSET_SizeOfImage              = 0x040;
    public const int OFFSET_FullDllName              = 0x048;   // UNICODE_STRING (16)
    public const int OFFSET_BaseDllName              = 0x058;   // UNICODE_STRING (16)
    public const int OFFSET_Flags                    = 0x068;
    public const int OFFSET_ObsoleteLoadCount        = 0x06C;
    public const int OFFSET_TlsIndex                 = 0x06E;
    public const int OFFSET_HashLinks                = 0x070;   // LIST_ENTRY (16)
    public const int OFFSET_DdagNode                 = 0x098;
    public const int OFFSET_NodeModuleLink           = 0x0A0;   // LIST_ENTRY (16)
    public const int OFFSET_BaseAddressIndexNode     = 0x0C8;   // RTL_BALANCED_NODE (24)
    public const int OFFSET_OriginalBase             = 0x0F8;
    public const int OFFSET_LoadTime                 = 0x100;
    public const int OFFSET_LoadReason               = 0x10C;
    public const int LDR_ENTRY_ALLOC_SIZE            = 0x200;

    // DDAG node
    public const int OFFSET_DdagModules    = 0x00;     // LIST_ENTRY head
    public const int OFFSET_DdagLoadCount  = 0x18;
    public const int OFFSET_DdagState      = 0x38;
    public const int DDAG_NODE_ALLOC_SIZE  = 0x50;
    public const int DdagState_LdrModulesReadyToRun = 9;

    // Flags
    public const uint LDRP_IMAGE_DLL              = 0x00000004;
    public const uint LDRP_ENTRY_PROCESSED        = 0x00004000;
    public const uint LDRP_PROCESS_ATTACH_CALLED  = 0x00080000;
    public const uint LDRP_PROCESS_STATIC_IMPORT  = 0x00000020;
    public const uint LDRP_DONT_CALL_FOR_THREADS  = 0x00040000;
}
