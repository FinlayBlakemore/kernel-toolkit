#include "Injector.hpp"

#include "Syscall.hpp"
#include "Memory.hpp"
#include "File.hpp"

#include <ntstatus.h>

#define WRITE_TO_OFFSET(Allocation, Offset, Address) *(std::uint64_t*)((std::uint64_t)(Allocation) + Offset) = Address
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks("", off)
#pragma optimize("", off)
uint32_t __stdcall Kernel::Injector::Shellcode(ModuleArgument* Argument)
{
    // Defining our image base and optional header
    IMAGE_OPTIONAL_HEADER* OptionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(Argument->TargetBuffer + reinterpret_cast<IMAGE_DOS_HEADER*>(Argument->TargetBuffer)->e_lfanew)->OptionalHeader;
    BYTE* ImageBase = Argument->TargetBuffer;

    // Defining all our imports
    auto _LoadLibraryA = Argument->LoadLibraryA;
    auto _GetProcAddress = Argument->GetProcAddress;
    auto _RtlAddFunctionTable = Argument->RtlAddFunctionTable;

    // Calculating the location delta of the new image
    BYTE* LocationDelta = ImageBase - OptionalHeader->ImageBase;

    // Checking if we need to perform any relocations
    if (LocationDelta && OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        // Getting the relocation start and end
        IMAGE_BASE_RELOCATION* RelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ImageBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        IMAGE_BASE_RELOCATION* RelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(RelocData) + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        // Looping through all of the relocation data and fixing the location
        while (RelocData < RelocEnd && RelocData->SizeOfBlock)
        {
            // Getting the number of entries for this block and the info related to the block
            UINT AmountOfEntries = (RelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* RelativeInfo = reinterpret_cast<WORD*>(RelocData + 1);

            for (UINT i = 0; i != AmountOfEntries; ++i, ++RelativeInfo)
            {
                // Checking if the flag is correct
                if (!RELOC_FLAG(*RelativeInfo)) {
                    continue;
                }

                // Updating the location delta for this current info block
                *reinterpret_cast<uint64_t*>(ImageBase + RelocData->VirtualAddress + ((*RelativeInfo) & 0xFFF)) += reinterpret_cast<uint64_t>(LocationDelta);
            }

            // Going to the next info block
            RelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocData) + RelocData->SizeOfBlock);
        }
    }

    // Checking if we need to fix any imports for the mapped module
    if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        // Getting the import descriptor thats first in the list
        IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(ImageBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        // Looping through all import descriptors
        while (ImportDescriptor->Name)
        {
            // Getting the imagename of the current image
            char* ImageName = reinterpret_cast<char*>(ImageBase + ImportDescriptor->Name);

            // Loading the dll into the current process
            HINSTANCE Dll = _LoadLibraryA(ImageName);

            // Validating the current dll
            if (!Dll) {
                ImportDescriptor++;
            }

            // Getting the Thunk and Func references from the import descriptor
            uint64_t* ThunkRef = reinterpret_cast<uint64_t*>(ImageBase + ImportDescriptor->OriginalFirstThunk);
            uint64_t* FuncRef = reinterpret_cast<uint64_t*>(ImageBase + ImportDescriptor->FirstThunk);

            // Fixing the thunk ref if needed
            if (!ThunkRef) {
                ThunkRef = FuncRef;
            }

            // Looping through all the functions inside of this import descriptor
            for (; *ThunkRef; ++ThunkRef, ++FuncRef)
            {
                // Defining the function name
                char* FunctionName = nullptr;

                // Getting the function name by ordinal
                if (IMAGE_SNAP_BY_ORDINAL(*ThunkRef)) {
                    FunctionName = reinterpret_cast<char*>(*ThunkRef & 0xFFFF);
                }

                // Getting the function name by IMAGE_IMPORT_BY_NAME
                else {
                    FunctionName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(ImageBase + (*ThunkRef))->Name;
                }

                // Fixing the import in the import address table
                *FuncRef = (uint64_t)_GetProcAddress(Dll, FunctionName);
            }

            // Going to the next import descriptor
            ImportDescriptor++;
        }
    }

    // Validating if there is any TLS callback to perform
    if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        // Getting the TlsDirectory
        IMAGE_TLS_DIRECTORY* TlsDirectory = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(ImageBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

        // Getting the Callback array to get all the callbacks to call
        PIMAGE_TLS_CALLBACK* CallbackArray = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(TlsDirectory->AddressOfCallBacks);

        // Calling all the callbacks in the array with the correct params
        for (; CallbackArray && *CallbackArray; ++CallbackArray) {
            (*CallbackArray)(ImageBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    // Validating if there is any exception handlers to install
    if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size)
    {
        // Installing all exception handlers needed
        _RtlAddFunctionTable(
            reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(ImageBase + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
            OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (uint64_t)ImageBase
        );
    }

    Argument->Status = 1;
    while (Argument->Status == 1) {
        Argument->Sleep(15);
    }

    return reinterpret_cast<EntryPoint_t>(ImageBase + OptionalHeader->AddressOfEntryPoint)(ImageBase, DLL_PROCESS_ATTACH, Argument->Parameter);
}
#pragma runtime_checks("", on)
#pragma optimize("", on)


THREADENTRY32 Kernel::Injector::GetThread(uint32_t ThreadId)
{
    THREADENTRY32 ThreadEntry = { 0 };
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, m_ProcessId);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return ThreadEntry;

    if (Thread32First(hSnapshot, &ThreadEntry))
    {
        do
        {
            if (ThreadEntry.th32ThreadID == ThreadId || ThreadId == NULL)
            {
                CloseHandle(hSnapshot);
                return ThreadEntry;
            }
        } while (Thread32Next(hSnapshot, &ThreadEntry));
    }

    CloseHandle(hSnapshot);
    return ThreadEntry;
}

MODULEENTRY32 Kernel::Injector::GetModule(uint64_t Hash)
{
    MODULEENTRY32 ModuleEntry = { 0 };
    ModuleEntry.dwSize = sizeof(MODULEENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_ProcessId);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return ModuleEntry;

    if (Module32First(hSnapshot, &ModuleEntry))
    {
        do
        {
            if (Hash == 0 || HashString(ModuleEntry.szModule) == Hash)
            {
                CloseHandle(hSnapshot);
                return ModuleEntry;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry));
    }

    CloseHandle(hSnapshot);
    return ModuleEntry;
}

uint64_t Kernel::Injector::LoadRwxDll(std::vector<uint8_t> VunerableDll)
{
    auto ModuleEntry = GetModule(HashString_("x2game.dll"));
    if (ModuleEntry.modBaseSize == NULL) {
        return reinterpret_cast<uint64_t>(ModuleEntry.modBaseAddr);
    }

    char SystemDirectory[MAX_PATH];
    GetSystemDirectoryA(SystemDirectory, MAX_PATH);
    std::string Filepath = std::string(SystemDirectory) + "\\x2game.dll";

    if (Kernel::File::Write(VunerableDll, Filepath) == false) {
        return NULL;
    }

    BYTE LoadLibraryExA_Shellcode[] //LoadLibraryExA(FilePath, 0, DONT_RESOLVE_DLL_REFERENCES);
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x28, 0x33, 0xD2, 0x44, 0x8D, 0x42, 0x01, 0x48, 0xB9, 0x01, 0x10, 0x87, 0x9C, 0x07, 0x6B, 0x12, 0x00,
        0x48, 0xB8, 0x05, 0x10, 0x87, 0x9C, 0x07, 0x6B, 0x12, 0x00, 0xFF, 0xD0, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3
    };

    strcpy((char*)LoadLibraryExA_Shellcode, Filepath.c_str());

    // Allocate Shellcode into remote process
    void* ShellcodeBuffer = nullptr;
    if (Kernel::SystemCall->NtAllocateVirtualMemory(
        m_Handle,
        &ShellcodeBuffer,
        sizeof(LoadLibraryExA_Shellcode),
        PAGE_EXECUTE_READWRITE) == false) {
        return false;
    }

    WRITE_TO_OFFSET(LoadLibraryExA_Shellcode, MAX_PATH + 0xC, (uint64_t)ShellcodeBuffer);
    WRITE_TO_OFFSET(LoadLibraryExA_Shellcode, MAX_PATH + 0x16, (uint64_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExA"));

    // Writing the shellcode
    Kernel::SystemCall->NtWriteVirtualMemory(
        m_Handle,
        ShellcodeBuffer,
        LoadLibraryExA_Shellcode,
        sizeof(LoadLibraryExA_Shellcode)
    );

    // Executing the shellcode that loads our vunerable dll
    HANDLE Thread = NULL;
    bool CreateThreadStatus = Kernel::SystemCall->NtCreateThreadEx(
        m_Handle, 
        &Thread, 
        reinterpret_cast<void*>(reinterpret_cast<uint64_t>(ShellcodeBuffer) + MAX_PATH),
        ShellcodeBuffer,
        reinterpret_cast<uint64_t>(GetModule(HashString_("win32u.dll")).modBaseAddr + 0x2000)
    );

    if (CreateThreadStatus == false) {
        return NULL;
    }

    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);

    // Free Shellcode
    //

    return reinterpret_cast<uint64_t>(GetModule(HashString_("x2game.dll")).modBaseAddr);
}

Kernel::Injector::Injector(std::shared_ptr<Kernel::FunctionCaller>& Function) : m_Function(Function)
{

}

bool Kernel::Injector::ManualMap(std::vector<uint8_t> VunerableDll, std::vector<uint8_t> TargetDll, uint64_t Parameter)
{
    // Loading the rwx dll into the process to then hyjack
    uint64_t RwxDllBuffer = LoadRwxDll(VunerableDll) + 0x100;

    if (RwxDllBuffer == NULL) {
        return false;
    }

    // Getting a pointer to the base address of the target dll
    uint8_t* BaseAddress = TargetDll.data();

    // Getting Headers
    IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(BaseAddress);
    IMAGE_NT_HEADERS* NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(BaseAddress + DosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER* OptionalHeader = &NtHeaders->OptionalHeader;
    IMAGE_FILE_HEADER* FileHeader = &NtHeaders->FileHeader;

    Kernel::SystemCall->NtWriteVirtualMemory(
        m_Handle,
        reinterpret_cast<void*>(RwxDllBuffer),
        BaseAddress,
        OptionalHeader->SizeOfHeaders
    );

    // Write Sections data
    IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    for (int i = 0; i < FileHeader->NumberOfSections; i++, SectionHeader++)
    {
        Kernel::SystemCall->NtWriteVirtualMemory(
            m_Handle,
            reinterpret_cast<void*>(RwxDllBuffer + SectionHeader->VirtualAddress),
            BaseAddress + SectionHeader->PointerToRawData,
            SectionHeader->SizeOfRawData
        );
    }

    // Allocate Argument
    void* ArgumentBuffer = nullptr;
    if (Kernel::SystemCall->NtAllocateVirtualMemory(
        m_Handle,
        &ArgumentBuffer,
        sizeof(Kernel::ModuleArgument),
        PAGE_READWRITE
    ) == false) {
        return false;
    }

    // Writing Argument
    Kernel::ModuleArgument Argument = { 
        (RtlAddFunctionTable_t)RtlAddFunctionTable, 
        GetProcAddress, 
        LoadLibraryA, 
        Sleep, 
        Parameter,
        (BYTE*)RwxDllBuffer,
        0
    };

    m_Status = reinterpret_cast<int*>(((uint64_t)ArgumentBuffer) + offsetof(Kernel::ModuleArgument, Status));

    Kernel::SystemCall->NtWriteVirtualMemory(
        m_Handle,
        ArgumentBuffer,
        &Argument,
        sizeof(Kernel::ModuleArgument)
    );

    // Allocate Shellcode
    void* ShellcodeBuffer = nullptr;
    if (Kernel::SystemCall->NtAllocateVirtualMemory(
        m_Handle,
        &ShellcodeBuffer,
        0x1000,
        PAGE_EXECUTE_READWRITE
    ) == false) {
        return false;
    }

    // Write Shellcode
    Kernel::SystemCall->NtWriteVirtualMemory(
        m_Handle,
        ShellcodeBuffer,
        &Shellcode,
        0x1000
    );

    // Call Shellcode
    HANDLE Thread = NULL;
    Kernel::SystemCall->NtCreateThreadEx(
        m_Handle,
        &Thread,
        ShellcodeBuffer,
        ArgumentBuffer,
        RwxDllBuffer
    );

    int Status = 0;
    while (Status == 0)
    {
        Kernel::SystemCall->NtReadVirtualMemory(
            m_Handle,
            m_Status,
            &Status,
            sizeof(int)
        );
    }

    // Clear Sections
    //SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    //for (int i = 0; i < FileHeader->NumberOfSections; i++, SectionHeader++)
    //{
    //    char* SectionName = reinterpret_cast<char*>(SectionHeader->Name);
    //
    //    if (strcmp(SectionName, ".reloc") != 0) {
    //        continue;
    //    }
    //
    //    void* ZeroBuffer = malloc(SectionHeader->SizeOfRawData);
    //    memset(ZeroBuffer, NULL, SectionHeader->SizeOfRawData);
    //
    //    Kernel::SystemCall->NtWriteVirtualMemory(
    //        m_Handle,
    //        reinterpret_cast<void*>(RwxDllBuffer + SectionHeader->VirtualAddress),
    //        ZeroBuffer,
    //        SectionHeader->SizeOfRawData
    //    );
    //
    //    free(ZeroBuffer);
    //}

    return true;
}

bool Kernel::Injector::AttachToProcess(uint64_t Context, uint32_t ProcessId)
{
    printf("Context -> 0x%llx\nProcess Id -> %i\n", Context, ProcessId);

    // Opening a handle to our target process
    m_Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

    if (m_Handle == NULL) {
        return false;
    }

    m_ProcessId = ProcessId;
    m_Context = Context;

    return true;
}

uint32_t Kernel::Injector::GetProcess(const uint64_t Hash)
{
    PROCESSENTRY32 Entry;
    Entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!Process32First(Snapshot, &Entry)) {
        return 0x00;
    }

    while (Process32Next(Snapshot, &Entry))
    {
        if (HashString(Entry.szExeFile) == Hash)
        {
            return Entry.th32ProcessID;
        }
    }

    CloseHandle(Snapshot);
    return NULL;
}

bool Kernel::Injector::CreateThread()
{
    int Status = 2;
    Kernel::SystemCall->NtWriteVirtualMemory(
        m_Handle,
        m_Status,
        &Status,
        sizeof(int)
    );

    return true;
}
