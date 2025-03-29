#include "Syscall.hpp"
#include <ntstatus.h>
#include <random>

Kernel::Syscall::Syscall() { }

bool Kernel::Syscall::NtDuplicateHandle(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, HANDLE* TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
	CallInfo Call = this->GetCallInfo(HashString("NtDuplicateHandle"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, HANDLE, HANDLE, HANDLE*, ACCESS_MASK, ULONG, ULONG))Call.Address)(
		SourceProcessHandle,
		SourceHandle,
		TargetProcessHandle,
		TargetHandle,
		DesiredAccess,
		HandleAttributes,
		Options
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength, NTSTATUS* Result)
{
	CallInfo Call = this->GetCallInfo(HashString("NtQuerySystemInformation"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, void*, ULONG, ULONG*))Call.Address)(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	if (Result) {
		*Result = Status;
	}

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtQueryInformationProcess(HANDLE Handle, PROCESSINFOCLASS ProcessInformationClass, void* ProcessInformation, ULONG ProcessInformationLength, ULONG* ReturnLength)
{
	CallInfo Call = this->GetCallInfo(HashString("NtQueryInformationProcess"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, PROCESSINFOCLASS, void*, ULONG, ULONG*))Call.Address)(
		Handle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtProtectVirtualMemory(HANDLE Handle, void* BaseAddress, std::size_t Length, std::size_t Protection, std::size_t* OldProtection)
{
	CallInfo Call = this->GetCallInfo(HashString("NtProtectVirtualMemory"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, PVOID*, std::size_t*, std::size_t, std::size_t*))Call.Address)(
		Handle,
		&BaseAddress,
		&Length,
		Protection,
		OldProtection
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtAllocateVirtualMemory(HANDLE Handle, void** Result, std::size_t RegionSize, ULONG Protect)
{
	CallInfo Call = this->GetCallInfo(HashString("NtAllocateVirtualMemory"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, void**, std::uint64_t, std::size_t*, ULONG, ULONG))Call.Address)(
		Handle,
		Result,
		NULL,
		&RegionSize,
		MEM_RESERVE | MEM_COMMIT,
		Protect
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtWriteVirtualMemory(HANDLE Handle, void* BaseAddress, void* Buffer, std::size_t Length)
{
	CallInfo Call = this->GetCallInfo(HashString("NtWriteVirtualMemory"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, void*, void*, std::size_t, std::size_t*))Call.Address)(
		Handle,
		BaseAddress,
		Buffer,
		Length,
		nullptr
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtReadVirtualMemory(HANDLE Handle, void* BaseAddress, void* Buffer, std::size_t Length)
{
	CallInfo Call = this->GetCallInfo(HashString("NtReadVirtualMemory"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, void*, void*, std::size_t, std::size_t*))Call.Address)(
		Handle,
		BaseAddress,
		Buffer,
		Length,
		nullptr
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtCreateThreadEx(HANDLE Handle, HANDLE* ThreadHandle, void* Address, void* Parameter, uint64_t StartAddress)
{
	CallInfo Call = this->GetCallInfo(HashString("NtCreateThreadEx"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE*, ACCESS_MASK, void*, HANDLE, uint64_t, void*, ULONG, std::size_t, std::size_t, std::size_t, void*))Call.Address)(
		ThreadHandle,
		THREAD_ALL_ACCESS,
		nullptr,
		Handle,
		StartAddress,
		Parameter,
		1,
		NULL,
		NULL,
		NULL,
		nullptr
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	// Getting thread context of our current thread
	CONTEXT Context;
	Context.ContextFlags = CONTEXT_ALL;
	this->NtGetContextThread(*ThreadHandle, &Context);

	// Setting the executing address to our thread location
	//Context.Rip = Address;
	Context.Rcx = (std::uint64_t)Address;

	// Setting thread context of our thread and resuming it
	this->NtSetContextThread(*ThreadHandle, &Context);
	this->NtResumeThread(*ThreadHandle);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtOpenProcess(HANDLE* Handle, HANDLE UniqueProcess, ACCESS_MASK DesiredAccess)
{
	CallInfo Call = this->GetCallInfo(HashString("NtOpenProcess"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	OBJECT_ATTRIBUTES ObjectAttributes;
	memset(&ObjectAttributes, 0, sizeof(OBJECT_ATTRIBUTES));
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	CLIENT_ID ClientId;
	memset(&ClientId, 0, sizeof(CLIENT_ID));
	ClientId.UniqueProcess = UniqueProcess;

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*))Call.Address)(
		Handle,
		DesiredAccess,
		&ObjectAttributes,
		&ClientId
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtGetContextThread(HANDLE ThreadHandle, CONTEXT* Context)
{
	CallInfo Call = this->GetCallInfo(HashString("NtGetContextThread"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, CONTEXT*))Call.Address)(
		ThreadHandle,
		Context
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtSetContextThread(HANDLE ThreadHandle, CONTEXT* Context)
{
	CallInfo Call = this->GetCallInfo(HashString("NtSetContextThread"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, CONTEXT*))Call.Address)(
		ThreadHandle,
		Context
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtFreeVirtualMemory(HANDLE Handle, void* BaseAddress)
{
	CallInfo Call = this->GetCallInfo(HashString("NtFreeVirtualMemory"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	std::size_t RegionSize = NULL;
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, void**, std::size_t*, ULONG))Call.Address)(
		Handle,
		&BaseAddress,
		&RegionSize,
		MEM_RELEASE
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::NtResumeThread(HANDLE ThreadHandle)
{
	CallInfo Call = this->GetCallInfo(HashString("NtResumeThread"));

	if (!Call.Address) {
		return false;
	}

	// Decrypting our shellcode
	this->DecryptShellcode(Call.Address, Call.XorKey);

	// Calling the shellcode
	NTSTATUS Status = (*(NTSTATUS(*)(HANDLE, ULONG*))Call.Address)(
		ThreadHandle,
		nullptr
		);

	// Encrypting our shellcode
	this->EncryptShellcode(Call.Address, Call.XorKey);

	return NT_SUCCESS(Status);
}

bool Kernel::Syscall::Create()
{
	// Creating the list of hashes to create the calls from
	std::vector<std::uint64_t> CallList = {
		HashString("NtQueryInformationResourceManager"),
		HashString("NtQueryInformationProcess"),
		HashString("NtQuerySystemInformation"),
		HashString("NtAllocateVirtualMemory"),
		HashString("NtProtectVirtualMemory"),
		HashString("NtWriteVirtualMemory"),
		HashString("NtReadVirtualMemory"),
		HashString("NtFreeVirtualMemory"),
		HashString("NtGetContextThread"),
		HashString("NtSetContextThread"),
		HashString("NtDuplicateObject"),
		HashString("NtCreateThreadEx"),
		HashString("NtResumeThread"),
		HashString("NtOpenProcess"),
	};

	// Looping through all the calls in the list
	for (std::uint64_t Hash : CallList) {
		if (!this->CreateCallInfo(Hash)) {
			return false;
		}
	}

	CallList.clear();
	return true;
}

void Kernel::Syscall::EncryptShellcode(void* Address, std::uint32_t XorKey)
{
	for (std::size_t Offset = NULL; Offset < 11; Offset++)
	{
		*(unsigned char*)((std::uint64_t)Address + Offset) ^= XorKey;
	}

	unsigned char Last = *(unsigned char*)((std::uint64_t)Address + 10);
	unsigned char First = *(unsigned char*)(Address);

	*(unsigned char*)((std::uint64_t)Address + 10) = First;
	*(unsigned char*)(Address) = Last;
}

void Kernel::Syscall::DecryptShellcode(void* Address, std::uint32_t XorKey)
{
	unsigned char Last = *(unsigned char*)((std::uint64_t)Address + 10);
	unsigned char First = *(unsigned char*)(Address);

	*(unsigned char*)((std::uint64_t)Address + 10) = First;
	*(unsigned char*)(Address) = Last;

	for (std::size_t Offset = NULL; Offset < 11; Offset++)
	{
		*(unsigned char*)((std::uint64_t)Address + Offset) ^= XorKey;
	}
}

Kernel::CallInfo Kernel::Syscall::GetCallInfo(std::uint32_t MethodHash)
{
	auto Entry = this->HashToInfo.find(MethodHash);

	if (Entry == this->HashToInfo.end()) {
		return { NULL, NULL };
	}

	return Entry->second;
}

bool Kernel::Syscall::CreateCallInfo(std::uint32_t MethodHash)
{
	PEB* ProcessEnviromentBlock = ((PEB*)__readgsqword(0x60));

	if (!ProcessEnviromentBlock) {
		return false;
	}

	PEB_LDR_DATA* LoaderData = (PEB_LDR_DATA*)ProcessEnviromentBlock->Ldr;

	if (!LoaderData) {
		return false;
	}

	for (LIST_ENTRY* ListEntry = LoaderData->InMemoryOrderModuleList.Flink; ListEntry != &LoaderData->InMemoryOrderModuleList; ListEntry = ListEntry->Flink)
	{
		LDR_DATA_TABLE_ENTRY* Module = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (!Module || !Module->FullDllName.Buffer) {
			continue;
		}

		std::wstring WideFullPath = std::wstring(Module->FullDllName.Buffer);

		std::string FullPath = std::string(
			WideFullPath.begin(),
			WideFullPath.end()
		);

		std::size_t LastBackSlash = FullPath.find_last_of('\\');

		if (LastBackSlash != std::string::npos) {
			FullPath = FullPath.substr(LastBackSlash + 1);
		}

		std::transform(FullPath.begin(), FullPath.end(), FullPath.begin(), [](unsigned char c) {
			return std::tolower(c);
			});

		if (HashString(FullPath.c_str()) != HashString("ntdll.dll")) {
			continue;
		}

		const std::uint64_t ImageBase = (std::uint64_t)Module->DllBase;

		if (!ImageBase) {
			return false;
		}

		IMAGE_DOS_HEADER* DosHeader = ((IMAGE_DOS_HEADER*)ImageBase);

		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			return false;
		}

		IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)((std::uint64_t)DosHeader + (std::uint64_t)DosHeader->e_lfanew);

		if (!NtHeaders || NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}

		std::uint64_t ExportDirectoryVirtualAddress = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(ImageBase + ExportDirectoryVirtualAddress);

		if (!ExportDirectory || !ExportDirectoryVirtualAddress) {
			return false;
		}

		DWORD* FunctionOffsetArray = (DWORD*)(ImageBase + ExportDirectory->AddressOfFunctions);
		WORD* OrdinalArray = (WORD*)(ImageBase + ExportDirectory->AddressOfNameOrdinals);
		DWORD* NameOffsetArray = (DWORD*)(ImageBase + ExportDirectory->AddressOfNames);

		for (std::size_t Index = 0; Index < ExportDirectory->NumberOfNames; Index++)
		{
			const std::uint32_t CurrentHash = HashString(reinterpret_cast<const char*>(ImageBase + NameOffsetArray[Index]));

			if (CurrentHash != MethodHash) {
				continue;
			}

			unsigned char InvokeSystemCall[11]
			{
				0x4C, 0x8B, 0xD1,			  // mov r10,rcx
				0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall_index
				0x0F, 0x05,					  // syscall
				0xC3					      // ret
			};

			const std::uint64_t MethodAddress = ImageBase + DWORD(FunctionOffsetArray[OrdinalArray[Index]]);;
			const std::uint32_t MethodID = *(std::uint32_t*)(MethodAddress + 0x4);

			void* Allocation = (VirtualAlloc)(
				nullptr,
				sizeof(InvokeSystemCall),
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE
				);

			if (!Allocation) {
				return false;
			}

			__movsb(
				&InvokeSystemCall[4],
				(BYTE*)&MethodID,
				sizeof(MethodID)
			);

			__movsb(
				(BYTE*)Allocation,
				InvokeSystemCall,
				sizeof(InvokeSystemCall)
			);

			// Initialize random number generator with a seed based on current time
			std::random_device RandomDevice;
			std::mt19937 Generator(RandomDevice());

			// Define the distribution for the random number (here, integers between 1 and 100)
			std::uniform_int_distribution<uint32_t> Distribution(5, 1000);

			std::uint32_t XorKey = Distribution(Generator);

			this->EncryptShellcode(Allocation, XorKey);

			this->HashToInfo.insert({
				CurrentHash,
				{ XorKey, Allocation}
				});

			return true;
		}
	}

	return false;
}
