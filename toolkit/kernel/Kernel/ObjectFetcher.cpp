#include "ObjectFetcher.hpp"

#include "StringHash.hpp"
#include "DebugLogger.hpp"
#include "File.hpp"

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <string>

typedef struct _RTL_PROCESS_MODULE_INFORMATION { HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256]; } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES { ULONG NumberOfModules; RTL_PROCESS_MODULE_INFORMATION Modules[1]; } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
typedef struct _SYSTEM_HANDLE { PVOID Object; HANDLE UniqueProcessId; HANDLE HandleValue; ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex; ULONG HandleAttributes; ULONG Reserved; } SYSTEM_HANDLE, * PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX { ULONG_PTR HandleCount; ULONG_PTR Reserved; SYSTEM_HANDLE Handles[1]; } SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

Kernel::Struct& Kernel::ObjectFetcher::FetchModuleStruct(uint64_t ModuleHash, uint64_t StructHash)
{
	return Kernel::PdbFetcher::Fetch(ModuleHash)->GetStruct(StructHash);
}

uint64_t Kernel::ObjectFetcher::FetchModuleData(uint64_t ModuleHash, uint64_t ExportHash)
{
	Kernel::ObjectFetcher::ModuleInformation ModuleInfo = Kernel::ObjectFetcher::FetchModule(ModuleHash);

	if (ModuleInfo.BaseAddress == NULL) {
		return NULL;
	}

	uint64_t DataOffset = Kernel::PdbFetcher::Fetch(ModuleHash)->GetData(ExportHash);

	if (DataOffset == NULL) {
		return NULL;
	}

	return ModuleInfo.BaseAddress + DataOffset;
}

Kernel::ObjectFetcher::ModuleInformation Kernel::ObjectFetcher::FetchModule(uint64_t ModuleHash)
{
	Kernel::ObjectFetcher::ModuleInformation Module = { };
	memset(&Module, NULL, sizeof(Kernel::ObjectFetcher::ModuleInformation));

	// Intilizing Variables
	void* Buffer = nullptr;
	DWORD Length = NULL;

	// Getting Size Of List
	NTSTATUS Status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)(11),
		Buffer,
		Length,
		&Length
	);

	// Attempting To Fix List
	while (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Freeing Old Buffer And Allocating New Buffer
		VirtualFree(Buffer, NULL, MEM_RELEASE);
		Buffer = VirtualAlloc(nullptr, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		// Setting List Into New Buffer
		Status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)(11),
			Buffer,
			Length,
			&Length
		);
	}

	// Checking If It Failed To Assign List
	if (!NT_SUCCESS(Status))
	{
		if (Buffer != nullptr) {
			VirtualFree(Buffer, NULL, MEM_RELEASE);
		}
		return Module;
	}

	// Reinterpreting The Buffer Into The List Struct
	const RTL_PROCESS_MODULES* ImageList = (RTL_PROCESS_MODULES*)(Buffer);

	// Walking Module List
	for (unsigned long Index = 0; Index < ImageList->NumberOfModules; ++Index)
	{
		// Getting The Current Module Name
		std::string ImageName = std::string((char*)(ImageList->Modules[Index].FullPathName) + ImageList->Modules[Index].OffsetToFileName);

		for (std::size_t i = 0; i < ImageName.size(); i++) {
			ImageName[i] = tolower(ImageName[i]);
		}

		if (HashString(ImageName.c_str()) != ModuleHash) {
			continue;
		}

		Module.BaseAddress = (uint64_t)ImageList->Modules[Index].ImageBase;
		Module.Length = (size_t)ImageList->Modules[Index].ImageSize;
		break;
	}

	if (Buffer != nullptr) {
		VirtualFree(Buffer, NULL, MEM_RELEASE);
	}

	return Module;
}

uint64_t Kernel::ObjectFetcher::FetchModulePattern(uint64_t ModuleHash, BYTE* Pattern, const char* Mask)
{
	Kernel::ObjectFetcher::ModuleInformation ModuleInfo = Kernel::ObjectFetcher::FetchModule(ModuleHash);

	if (ModuleInfo.BaseAddress == NULL)
	{
		DebugErrorLog();
		return NULL;
	}

	uint64_t Offset = Kernel::File::PatternScan(ModuleHash, Pattern, Mask);

	if (Offset == NULL)
	{
		DebugErrorLog();
		return NULL;
	}

	return ModuleInfo.BaseAddress + Offset;
}

uint64_t Kernel::ObjectFetcher::FetchPointerAddress(uint64_t ModuleHash, uint64_t FunctionHash)
{
	uint64_t FunctionAddress = Kernel::ObjectFetcher::FetchModuleData(ModuleHash, FunctionHash);

	if (FunctionAddress == NULL) 
	{
		DebugErrorLog();
		return NULL;
	}

	uint64_t FunctionContext = FetchContextByHash(HashString_("explorer.exe"));

	if (FunctionContext == NULL)
	{
		DebugErrorLog();
		return false;
	}

	uint64_t PreviousContext = Kernel::Memory::SetContext(FunctionContext);
	unsigned char InstructionBuffer[0x1000];
	if (Kernel::Memory::ReadVirtual(
		FunctionAddress,
		InstructionBuffer,
		sizeof(InstructionBuffer)) == false)
	{
		DebugErrorLog();
		return false;
	}

	int InstructionOffset = NULL;

	// Setting up Instruction Offset
	for (int Index = 0; Index < sizeof(InstructionBuffer) - 1; Index++)
	{
		// mov rax, qword
		if (InstructionBuffer[Index] == 0x48 && InstructionBuffer[Index + 1] == 0x83)
		{
			InstructionOffset = Index + 4;
			break;
		}

		// mov r10, qword
		if (InstructionBuffer[Index] == 0x4C && InstructionBuffer[Index + 1] == 0x8B)
		{
			InstructionOffset = Index + 4;
			break;
		}
	}

	if (InstructionOffset == NULL)
	{
		Kernel::Memory::SetContext(PreviousContext);
		DebugErrorLog();
		return false;
	}

	// Calculating the address of the instruction
	uint64_t CalculatedAddress = FunctionAddress + InstructionOffset;

	// Getting the relative offset
	int RelativeOffset = NULL;
	if (!Kernel::Memory::ReadVirtual(CalculatedAddress + 3, &RelativeOffset, sizeof(int)))
	{
		Kernel::Memory::SetContext(PreviousContext);
		DebugErrorLog();
		return false;
	}

	// Calculating the result
	std::uint64_t PointerAddress = CalculatedAddress + RelativeOffset + 7;

	// Restoring the context
	Kernel::Memory::SetContext(PreviousContext);

	return PointerAddress;
}

uint64_t Kernel::ObjectFetcher::FetchProcess(uint64_t InitialProcess, uint64_t ProcessHash)
{
	auto ProcessCacheEntry = m_ProcessCache.find(ProcessHash);

	if (ProcessCacheEntry != m_ProcessCache.end()) {
		return ProcessCacheEntry->second;
	}

	// Fetching EPROCESS Offset Data from the symbol
	Struct& EProcessStruct = PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_EPROCESS"));

	// Getting the ProcessLinkHead
	uint64_t ProcessLinkHead = NULL;
	Kernel::Memory::ReadVirtual(
		InitialProcess + EProcessStruct.GetProperty(HashString_("ActiveProcessLinks")),
		&ProcessLinkHead,
		sizeof(uint64_t)
	);

	// Setting up our current process link
	uint64_t ProcessLink = ProcessLinkHead;

	do
	{
		// Calculating our current process address
		uint64_t Process = ProcessLink - EProcessStruct.GetProperty(HashString_("ActiveProcessLinks"));

		// Getting the next process link
		if (Kernel::Memory::ReadVirtual(
			Process + EProcessStruct.GetProperty(HashString_("ActiveProcessLinks")),
			&ProcessLink,
			sizeof(uint64_t)
		) == false) {
			break;
		}

		// Getting the virtual size
		uint64_t VirtualSize = NULL;
		if (Kernel::Memory::ReadVirtual(
			Process + EProcessStruct.GetProperty(HashString_("VirtualSize")),
			&VirtualSize,
			sizeof(uint64_t)
		) == false) {
			continue;
		}

		if (VirtualSize == NULL) {
			continue; // Invalid process so we skip
		}

		// Getting the process name
		char ImageFileName[15] = { '\0' };
		if (Kernel::Memory::ReadVirtual(
			Process + EProcessStruct.GetProperty(HashString_("ImageFileName")),
			ImageFileName,
			sizeof(ImageFileName)
		) == false) {
			continue;
		}

		if (HashString(ImageFileName) == ProcessHash)
		{
			// Adding process to the cache
			m_ProcessCache.emplace(ProcessHash, Process);
			return Process; // Process found return result
		}

	} while (ProcessLink != ProcessLinkHead);

	return NULL;
}

uint64_t Kernel::ObjectFetcher::FetchProcessByHash(uint64_t ProcessHash)
{
	return FetchProcess(m_PsInitialSystemProcess, ProcessHash);
}

uint64_t Kernel::ObjectFetcher::FetchProcessByContext(uint64_t Context)
{
	return m_MmPfnDatabase->FetchProcess(Context);
}

uint64_t Kernel::ObjectFetcher::FetchDriverObject(HANDLE Handle)
{
	// Intilizing Variables
	void* Buffer = nullptr;
	DWORD Length = NULL;

	// Getting Size Of List
	NTSTATUS Status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)(0x40),
		Buffer,
		Length,
		&Length
	);

	// Attempting To Fix List
	while (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Freeing Old Buffer And Allocating New Buffer
		VirtualFree(Buffer, NULL, MEM_RELEASE);
		Buffer = VirtualAlloc(nullptr, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		// Setting List Into New Buffer
		Status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)(0x40),
			Buffer,
			Length,
			&Length
		);
	}

	// Checking If It Failed To Assign List
	if (!NT_SUCCESS(Status))
	{
		if (Buffer != nullptr) {
			VirtualFree(Buffer, NULL, MEM_RELEASE);
		}
		return NULL;
	}

	// Reinterpreting our buffer into the HandleInformation structure
	SYSTEM_HANDLE_INFORMATION_EX* HandleInformation = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(Buffer);

	uint64_t DriverObject = NULL;

	// Walking our handle table to find the handle of the system process
	for (std::uint32_t Index = 0; Index < HandleInformation->HandleCount; Index++)
	{
		// Validating the unique process id
		if (HandleInformation->Handles[Index].UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId()))) {
			continue;
		}

		if (HandleInformation->Handles[Index].HandleValue != Handle) {
			continue;
		}

		// Getting the result
		DriverObject = (std::uint64_t)(HandleInformation->Handles[Index].Object);
		break;
	}

	if (Buffer != nullptr) {
		VirtualFree(Buffer, NULL, MEM_RELEASE);
	}

	return DriverObject;
}

uint64_t Kernel::ObjectFetcher::FetchProcessByProcessId(uint32_t ProcessId)
{
	// Fetching EPROCESS Offset Data from the symbol
	Struct& EProcessStruct = PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_EPROCESS"));

	// Getting the ProcessLinkHead
	uint64_t ProcessLinkHead = NULL;
	Kernel::Memory::ReadVirtual(
		m_PsInitialSystemProcess + EProcessStruct.GetProperty(HashString_("ActiveProcessLinks")),
		&ProcessLinkHead,
		sizeof(uint64_t)
	);

	// Setting up our current process link
	uint64_t ProcessLink = ProcessLinkHead;

	do
	{
		// Calculating our current process address
		uint64_t Process = ProcessLink - EProcessStruct.GetProperty(HashString_("ActiveProcessLinks"));

		// Getting the next process link
		if (Kernel::Memory::ReadVirtual(
			Process + EProcessStruct.GetProperty(HashString_("ActiveProcessLinks")),
			&ProcessLink,
			sizeof(uint64_t)
		) == false) {
			break;
		}

		// Getting the virtual size
		uint64_t VirtualSize = NULL;
		if (Kernel::Memory::ReadVirtual(
			Process + EProcessStruct.GetProperty(HashString_("VirtualSize")),
			&VirtualSize,
			sizeof(uint64_t)
		) == false) {
			continue;
		}

		if (VirtualSize == NULL) {
			continue; // Invalid process so we skip
		}

		uint64_t EntryId = NULL;
		if (Kernel::Memory::ReadVirtual(
			Process + EProcessStruct.GetProperty(HashString_("UniqueProcessId")),
			&EntryId,
			sizeof(uint64_t)
		) == false) {
			continue;
		}

		if (ProcessId == EntryId)
		{
			return Process; // Process found return result
		}

	} while (ProcessLink != ProcessLinkHead);

	return NULL;
}

uint64_t Kernel::ObjectFetcher::FetchSystemProcess()
{
	return m_PsInitialSystemProcess;
}

uint64_t Kernel::ObjectFetcher::FetchContextByHash(uint64_t ProcessHash)
{
	// Fetching EPROCESS Offset Data from the symbol
	Struct& KProcessStruct = Kernel::PdbFetcher::Fetch(HashString_("ntoskrnl.exe"))->GetStruct(HashString_("_KPROCESS"));

	// Fetching process from process list
	uint64_t Process = FetchProcessByHash(ProcessHash);

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

uint64_t Kernel::ObjectFetcher::FetchContextByObject(uint64_t Process)
{
	return m_MmPfnDatabase->FetchContext(Process);
}

Kernel::DatabaseData Kernel::ObjectFetcher::GetDatabaseData()
{
	return m_MmPfnDatabase->GetData();
}

bool Kernel::ObjectFetcher::Initilize()
{
	// Reading MmPfnDatabase Address from MmGetVirtualForPhysical
	uint64_t MmPfnDatabaseAddress = NULL;
	Kernel::Memory::ReadVirtual(
		FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("MmGetVirtualForPhysical")) + 0x10,
		&MmPfnDatabaseAddress,
		sizeof(uint64_t)
	);

	if (MmPfnDatabaseAddress <= 0) {
		return false;
	}

	MmPfnDatabaseAddress -= 8;

	// Creating our MmPfnDatabase Class
	m_MmPfnDatabase = std::make_unique<Kernel::MmPfnDatabase>(MmPfnDatabaseAddress);

	// Getting SystemProcess using the MmPfnDatabase and the System Context
	m_PsInitialSystemProcess = FetchProcessByContext(Kernel::Memory::GetContext());

	if (m_PsInitialSystemProcess == NULL) {
		return false;
	}

	return true;
}
