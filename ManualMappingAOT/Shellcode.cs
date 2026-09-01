namespace Injector;

// Small x64 shellcode. Runs inside the target on a fresh thread. Receives a
// pointer to ShellCtx in RCX. Calls, in order:
//   1. RtlRbInsertNodeEx(Tree, Parent, Right, Node)         Stage=1 after
//   2. RtlAddFunctionTable(FT, Count, Base) or skip         Stage=2 after
//   3. LdrpHandleTlsData(LdrEntry)                          Stage=3 after
//   4. DllMain(ImageBase, DLL_PROCESS_ATTACH, NULL)         Stage=4 after
// Then sets Success=1 and calls Sleep(INFINITE) to keep the thread alive
// (exiting would corrupt TLS state and prevent new thread creation).
internal static class Shellcode
{
    // ShellCtx layout mirrored by Injection.cs ShellCtx struct
    //   +0x00  RbTree              +0x08  RbParent           +0x10  RbRight
    //   +0x18  RbNode              +0x20  FuncTable          +0x28  FuncCount
    //   +0x30  ImageBase           +0x38  LdrEntry
    //   +0x40  pRtlRbInsertNodeEx  +0x48  pRtlAddFunctionTable
    //   +0x50  pLdrpHandleTlsData  +0x58  pDllMain
    //   +0x60  NtStatusTls (i64)   +0x68  Success (u32)      +0x6C  Stage (u32)
    //   +0x70  pSleep

    public static readonly byte[] Bytes = new byte[]
    {
        0x53,                                // push rbx
        0x48, 0x89, 0xCB,                    // mov rbx, rcx

        // -- Call 1: RtlRbInsertNodeEx(Tree, Parent, Right, Node) --
        0x48, 0x8B, 0x0B,                    // mov rcx, [rbx]
        0x48, 0x8B, 0x53, 0x08,              // mov rdx, [rbx+8]
        0x4C, 0x8B, 0x43, 0x10,              // mov r8, [rbx+16]
        0x4C, 0x8B, 0x4B, 0x18,              // mov r9, [rbx+24]
        0x48, 0x83, 0xEC, 0x20,              // sub rsp, 0x20
        0x48, 0x8B, 0x43, 0x40,              // mov rax, [rbx+64]
        0xFF, 0xD0,                          // call rax
        0x48, 0x83, 0xC4, 0x20,              // add rsp, 0x20
        0xC7, 0x43, 0x6C, 0x01, 0x00, 0x00, 0x00,  // mov dword [rbx+108], 1

        // -- Call 2 (optional): RtlAddFunctionTable(FT, Count, Base) --
        0x48, 0x8B, 0x43, 0x20,              // mov rax, [rbx+32]
        0x48, 0x85, 0xC0,                    // test rax, rax
        0x74, 0x18,                          // jz +24
        0x48, 0x89, 0xC1,                    // mov rcx, rax
        0x8B, 0x53, 0x28,                    // mov edx, [rbx+40]
        0x4C, 0x8B, 0x43, 0x30,              // mov r8, [rbx+48]
        0x48, 0x83, 0xEC, 0x20,              // sub rsp, 0x20
        0x48, 0x8B, 0x43, 0x48,              // mov rax, [rbx+72]
        0xFF, 0xD0,                          // call rax
        0x48, 0x83, 0xC4, 0x20,              // add rsp, 0x20
        0xC7, 0x43, 0x6C, 0x02, 0x00, 0x00, 0x00,  // mov dword [rbx+108], 2

        // -- Call 3: LdrpHandleTlsData(LdrEntry) --
        0x48, 0x8B, 0x4B, 0x38,              // mov rcx, [rbx+56]
        0x48, 0x83, 0xEC, 0x20,              // sub rsp, 0x20
        0x48, 0x8B, 0x43, 0x50,              // mov rax, [rbx+80]
        0xFF, 0xD0,                          // call rax
        0x48, 0x83, 0xC4, 0x20,              // add rsp, 0x20
        0x48, 0x89, 0x43, 0x60,              // mov [rbx+96], rax   (NtStatusTls)
        0xC7, 0x43, 0x6C, 0x03, 0x00, 0x00, 0x00,  // stage=3

        // -- Call 4: DllMain(ImageBase, 1, 0) --
        0x48, 0x8B, 0x4B, 0x30,              // mov rcx, [rbx+48]
        0xBA, 0x01, 0x00, 0x00, 0x00,        // mov edx, 1
        0x4D, 0x31, 0xC0,                    // xor r8, r8
        0x48, 0x83, 0xEC, 0x20,              // sub rsp, 0x20
        0x48, 0x8B, 0x43, 0x58,              // mov rax, [rbx+88]
        0xFF, 0xD0,                          // call rax
        0x48, 0x83, 0xC4, 0x20,              // add rsp, 0x20
        0xC7, 0x43, 0x6C, 0x04, 0x00, 0x00, 0x00,  // stage=4

        // Success = 1
        0xC7, 0x43, 0x68, 0x01, 0x00, 0x00, 0x00,  // mov dword [rbx+104], 1

        // -- Sleep(INFINITE) to keep thread alive --
        // Exiting would free TLS for this thread, corrupting ntdll's
        // internal TLS tracking and deadlocking all future thread creation.
        0xB9, 0xFF, 0xFF, 0xFF, 0xFF,        // mov ecx, 0xFFFFFFFF  (INFINITE)
        0x48, 0x83, 0xEC, 0x20,              // sub rsp, 0x20
        0x48, 0x8B, 0x43, 0x70,              // mov rax, [rbx+0x70]  (pSleep)
        0xFF, 0xD0,                          // call rax
        0x48, 0x83, 0xC4, 0x20,              // add rsp, 0x20

        // unreachable — Sleep(INFINITE) never returns
        0x31, 0xC0,                                // xor eax, eax
        0x5B, 0xC3,                                // pop rbx ; ret
    };
}
