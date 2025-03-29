#include "Communication.hpp"

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <chrono>

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))

uint64_t Kernel::Communication::CallKernelFunction(uint64_t Address, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, uint64_t Arg4, uint64_t Arg5)
{
	// Defining our function call struct
	struct FunctionCallStruct {
		uint64_t FunctionList[2];
		uint64_t Arg4;
		uint64_t Arg5;
	};

	// Setting up our function buffer
	char FunctionBuffer[0xBE8 + 8];
	memset(&FunctionBuffer, NULL, 0xBE8 + 8);

	// Writing the address of the function buffer at the start
	// It does a double dereference
	// mov rax, [rcx]
	// mov rax, [rax + 0xBE8]
	*(void**)(FunctionBuffer) = FunctionBuffer;

	// Writing our function to the offset
	*(uint64_t*)(FunctionBuffer + 0xBE8) = m_Data.Function.Handler;

	// Setting up our FunctionCallStruct
	FunctionCallStruct CallInfo;
	memset(&CallInfo, NULL, sizeof(FunctionCallStruct));

	// Setting up our function address to call
	CallInfo.FunctionList[0] = Address;
	CallInfo.FunctionList[1] = Address;

	// Setting up our other arguments
	CallInfo.Arg4 = Arg4;
	CallInfo.Arg5 = Arg5;

	// Calling our kernel function invoker
	return m_Data.Function.Invoker(FunctionBuffer, 1, Arg1, Arg2, Arg3, (void*)&CallInfo);
}

bool Kernel::Communication::WriteVirtualMemory(uint64_t PageDirectoryBase, uint64_t Address, void* Buffer, size_t Size)
{
	size_t Offset = NULL;
	size_t Value = Size;

	while (Value)
	{
		const uint64_t Physical = VirtualToPhysical(PageDirectoryBase, Address + Offset);

		if (Physical == NULL) {
			return false;
		}

		const uint64_t NumberOfBytes = min(PAGE_SIZE - (Physical & 0xFFF), Value);
		WritePhysicalMemory(Physical, (void*)((uint64_t)Buffer + Offset), NumberOfBytes);

		Offset += NumberOfBytes;
		Value -= NumberOfBytes;
	}

	return true;
}

bool Kernel::Communication::ReadVirtualMemory(uint64_t PageDirectoryBase, uint64_t Address, void* Buffer, size_t Size)
{
	memset(Buffer, NULL, Size);

	size_t Offset = NULL;
	size_t Value = Size;

	while (Value)
	{
		const uint64_t Physical = VirtualToPhysical(PageDirectoryBase, Address + Offset);

		if (Physical == NULL) {
			return false;
		}

		const uint64_t NumberOfBytes = min(PAGE_SIZE - (Physical & 0xFFF), Value);
		ReadPhysicalMemory(Physical, (void*)((uint64_t)Buffer + Offset), NumberOfBytes);

		Offset += NumberOfBytes;
		Value -= NumberOfBytes;
	}

	return true;
}

uint64_t Kernel::Communication::VirtualToPhysical(uint64_t PageDirectoryBase, uint64_t VirtualAddress)
{
	const bool UseCache = m_Data.Target.Context == PageDirectoryBase;
	constexpr uint64_t Mask = (~0xfull << 8) & 0xfffffffffull;

	uint64_t Pml4Index = ((VirtualAddress >> 39) & (0x1ffll));
	uint64_t Pml4e = NULL;
	if (UseCache == false) {
		ReadPageTable(PageDirectoryBase + Pml4Index * 8, &Pml4e, sizeof(uint64_t));
	}
	else {
		m_Mutex.lock_shared();
		Pml4e = m_Pml4Cache[Pml4Index];
		m_Mutex.unlock_shared();
	}

	if (~Pml4e & 1 || Pml4e == NULL) {
		return NULL;
	}

	uint64_t PdptIndex = ((VirtualAddress >> 30) & (0x1ffll));
	uint64_t Pdpte = NULL;
	if (UseCache == false) {
		ReadPageTable((Pml4e & Mask) + PdptIndex * 8, &Pdpte, sizeof(uint64_t));
	}
	else {
		m_Mutex.lock_shared();
		Pdpte = m_PdptCache[Pml4Index][PdptIndex];
		m_Mutex.unlock_shared();
	}

	if (~Pdpte & 1 || Pdpte == NULL) {
		return NULL;
	}
	else if (Pdpte & 0x80) {
		return (Pdpte & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));
	}

	uint64_t PdIndex = ((VirtualAddress >> 21) & (0x1ffll));
	uint64_t Pde = NULL;
	ReadPageTable((Pdpte & Mask) + PdIndex * 8, &Pde, sizeof(uint64_t));

	if (~Pde & 1 || Pde == NULL) {
		return NULL;
	}
	else if (Pde & 0x80) {
		return (Pde & Mask) + (VirtualAddress & ~(~0ull << 21));
	}

	uint64_t PtIndex = ((VirtualAddress >> 12) & (0x1ffll));
	uint64_t Pte = NULL;
	ReadPageTable((Pde & Mask) + PtIndex * 8, &Pte, sizeof(uint64_t));

	if (Pte == NULL) {
		return NULL;
	}

	return (Pte & Mask) + (VirtualAddress & ~(~0ul << 12));
}

bool Kernel::Communication::WritePhysicalMemory(uint64_t Address, void* Buffer, size_t Length)
{
	// Allocating a new page
	uint64_t VirtualAddress = CallKernelFunction(m_Data.Function.MmMapIoSpaceEx, Address, Length, PAGE_READWRITE);

	if (!VirtualAddress) {
		return false;
	}

	// Copying the memory from our page into our buffer
	CallKernelFunction(m_Data.Function.memcpy,
		VirtualAddress,
		reinterpret_cast<uint64_t>(Buffer),
		Length
	);

	// Freeing the page we allocated
	CallKernelFunction(m_Data.Function.MmUnmapIoSpace, VirtualAddress, Length);

	return true;
}

bool Kernel::Communication::ReadPhysicalMemory(uint64_t Address, void* Buffer, size_t Length)
{
	// Allocating a new page
	uint64_t VirtualAddress = CallKernelFunction(m_Data.Function.MmMapIoSpaceEx, Address, Length, PAGE_READWRITE);

	if (!VirtualAddress) {
		return false;
	}

	// Copying the memory from our page into our buffer
	CallKernelFunction(m_Data.Function.memcpy, 
		reinterpret_cast<uint64_t>(Buffer),
		VirtualAddress, 
		Length
	);

	// Freeing the page we allocated
	CallKernelFunction(m_Data.Function.MmUnmapIoSpace, VirtualAddress, Length);

	return true;
}

bool Kernel::Communication::ReadKernelMemory(uint64_t Address, void* Buffer, size_t Length)
{
	memset(Buffer, NULL, Length);
	CallKernelFunction(m_Data.Function.memcpy,
		reinterpret_cast<uint64_t>(Buffer),
		Address,
		Length
	);
	return true;
}

bool Kernel::Communication::ReadPageTable(uint64_t Address, void* Buffer, size_t Length)
{
	if (!Address || !Buffer || !Length) {
		return false;
	}

	std::size_t NumberOfBytes = NULL;
	NTSTATUS Status = static_cast<NTSTATUS>(CallKernelFunction(m_Data.Function.MmCopyMemory,
		reinterpret_cast<uint64_t>(Buffer),
		Address,
		Length,
		0x01,
		reinterpret_cast<uint64_t>(&NumberOfBytes)
	));

	return Status == STATUS_SUCCESS;
}

void Kernel::Communication::CachePageTables(uint64_t Context, uint64_t* Pml4Cache, uint64_t* PdptCache)
{
	// Caching the PML4 and PDPT
	for (uint16_t Pml4Index = 0; Pml4Index < 512; ++Pml4Index)
	{
		// Reading the Pml4E
		uint64_t Pml4 = NULL;
		ReadPageTable(Context + 8 * Pml4Index, &Pml4, sizeof(uint64_t));

		// Storing it inside the cache
		Pml4Cache[Pml4Index] = Pml4;

		for (uint16_t PdptIndex = 0; PdptIndex < 512; ++PdptIndex)
		{
			uint64_t Pdpt = NULL;
			ReadPageTable((Pml4Cache[Pml4Index] & 0xFFFFFFFFFF000) + 8 * PdptIndex, &Pdpt, sizeof(uint64_t));

			PdptCache[Pml4Index * 512 + PdptIndex] = Pdpt;
		}
	}

	m_Mutex.lock();
	for (std::size_t Pml4Index = 0; Pml4Index < 512; ++Pml4Index)
	{
		m_Pml4Cache[Pml4Index] = Pml4Cache[Pml4Index];

		for (std::uint16_t PdptIndex = 0; PdptIndex < 512; PdptIndex++) {
			m_PdptCache[Pml4Index][PdptIndex] = PdptCache[Pml4Index * 512 + PdptIndex];
		}
	}
	m_Mutex.unlock();
}

uint64_t Kernel::Communication::FetchContext(uint64_t Object)
{
	// Defining our result
	uint64_t Result = NULL;

	// Define chunk size (in pages)
	constexpr uint32_t ChunkSize = 256; // Increased chunk size for better performance

	// Calculate total chunks
	uint32_t TotalChunks = (m_Data.Database.NumberOfPages + ChunkSize - 1) / ChunkSize;

	// Calculate buffer size for each chunk
	const uint32_t ChunkBufferSize = ChunkSize * sizeof(_MMPFN);

	// Allocate buffer for chunk reading
	uint8_t* ChunkBuffer = new uint8_t[ChunkBufferSize];

	// Looping through chunks
	for (uint32_t ChunkIndex = 0; ChunkIndex < TotalChunks && Result == NULL; ++ChunkIndex)
	{
		// Calculate entries in current chunk
		uint32_t CurrentChunkSize = (ChunkIndex == TotalChunks - 1)
			? (m_Data.Database.NumberOfPages % ChunkSize)
			: ChunkSize;

		if (CurrentChunkSize == 0) CurrentChunkSize = ChunkSize;

		// Calculate offset for this chunk
		uint64_t ChunkOffset = ChunkIndex * ChunkBufferSize;

		// Read only this chunk from kernel memory
		ReadKernelMemory(
			m_Data.Database.Address + ChunkOffset,
			ChunkBuffer,
			CurrentChunkSize * sizeof(_MMPFN)
		);

		// Getting base PFN for this chunk
		uint64_t BasePageFrameNumber = ChunkIndex * ChunkSize;

		// Process current chunk
		_MMPFN* Pages = reinterpret_cast<_MMPFN*>(ChunkBuffer);
		for (uint32_t EntryIndex = 0; EntryIndex < CurrentChunkSize; ++EntryIndex)
		{
			// Getting current MmPfn
			_MMPFN& Page = Pages[EntryIndex];

			// Checking if the MmPfn is a EProcess
			if (!Page.Flag || Page.Flag == 1) {
				continue;
			}

			uint64_t EProcess = ((Page.Flag | 0xF000000000000000) >> 13) | 0xFFFF000000000000;
			if (EProcess == Object)
			{
				Result = (BasePageFrameNumber + EntryIndex) << 12;
				break;
			}
		}
	}

	// Cleanup
	delete[] ChunkBuffer;
	return Result;
}

uint64_t Kernel::Communication::FetchProcess(uint64_t Hash)
{
	if (!m_Data.Explorer.Object || !Hash) {
		return NULL;
	}

	// Setting up our values
	uint64_t LinkStart = m_Data.Explorer.Object + m_Data.Process.ActiveProcessLinks;
	uint64_t Flink = LinkStart;

	while (Flink)
	{
		// Reading the forward link to the next process
		ReadVirtualMemory(m_Data.System.Context, Flink, &Flink, sizeof(uint64_t));

		// Calculating the process by removing the process link offset
		uint64_t EProcess = Flink - m_Data.Process.ActiveProcessLinks;

		// Reading the size of the process
		uint64_t VirtualSize = NULL;
		ReadVirtualMemory(m_Data.System.Context, EProcess + m_Data.Process.VirtualSize, &VirtualSize, sizeof(uint64_t));

		// Validating the size of the process
		if (!VirtualSize) {
			continue;
		}

		// Reading the ImageFileName of the Process
		char ImageFileName[16] = { };
		ReadVirtualMemory(m_Data.System.Context, EProcess + m_Data.Process.ImageFileName, &ImageFileName, sizeof(ImageFileName));

		if (DriverHashString(ImageFileName) == Hash) {
			return EProcess;
		}
	}

	return NULL;
}

void Kernel::Communication::ContextCache()
{
	uint64_t* PdptCache = (uint64_t*)VirtualAlloc(nullptr, sizeof(uint64_t[512][512]), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	uint64_t* Pml4Cache = (uint64_t*)VirtualAlloc(nullptr, sizeof(uint64_t[512]), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	CachePageTables(m_Data.Target.Context, Pml4Cache, PdptCache);

	// Getting start time of search
	std::chrono::seconds StartTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());

	while (true)
	{
		Sleep(25);

		uint64_t CurrentContext = FetchContext(m_Data.Target.Object);

		if (CurrentContext < 0x1000) {
			continue;
		}

		std::chrono::seconds ElapsedTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()) - StartTime;

		if (CurrentContext != m_Data.Target.Context || ElapsedTime.count() > 20)
		{
			StartTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
			CachePageTables(CurrentContext, Pml4Cache, PdptCache);
		}

		m_Data.Target.Context = CurrentContext;
	}
}

Kernel::Communication::Communication()
{
	memset(&m_Data, NULL, sizeof(Kernel::Data));
}

bool Kernel::Communication::Startup(uint64_t ProcessHash, uint64_t* DataArray, uint64_t* HashArray, size_t Length)
{
	LoadLibraryA("user32.dll");

	// Setting up the data map
	std::map<uint64_t, uint64_t> DataMap;
	for (size_t i = 0; i < Length; i++) {
		DataMap.insert({ HashArray[i], DataArray[i] });
	}

	// Converting the map into struct data
	*(FARPROC*)&m_Data.Function.Invoker = GetProcAddress(LoadLibraryA("win32u.dll"), "NtGdiEngBitBlt");
	m_Data.Function.PsGetCurrentThread = DataMap.find(DRIVER_HASH_STRING("Function::PsGetCurrentThread"))->second;
	m_Data.Function.Handler = DataMap.find(DRIVER_HASH_STRING("Function::Handler"))->second;
	m_Data.Function.MmUnmapIoSpace = DataMap.find(DRIVER_HASH_STRING("Function::MmUnmapIoSpace"))->second;
	m_Data.Function.MmMapIoSpaceEx = DataMap.find(DRIVER_HASH_STRING("Function::MmMapIoSpaceEx"))->second;
	m_Data.Function.MmCopyMemory = DataMap.find(DRIVER_HASH_STRING("Function::MmCopyMemory"))->second;
	m_Data.Function.memcpy = DataMap.find(DRIVER_HASH_STRING("Function::memcpy"))->second;

	m_Data.Explorer.Context = DataMap.find(DRIVER_HASH_STRING("ExplorerProcess::Context"))->second;
	m_Data.Explorer.Object = DataMap.find(DRIVER_HASH_STRING("ExplorerProcess::Object"))->second;
	m_Data.System.Context = DataMap.find(DRIVER_HASH_STRING("SystemProcess::Context"))->second;
	m_Data.System.Object = DataMap.find(DRIVER_HASH_STRING("SystemProcess::Object"))->second;
	m_Data.Target.Context = NULL;
	m_Data.Target.Object = NULL;

	m_Data.Database.Address = DataMap.find(DRIVER_HASH_STRING("Database::Address"))->second;
	m_Data.Database.Length = DataMap.find(DRIVER_HASH_STRING("Database::Length"))->second;
	m_Data.Database.NumberOfPages = DataMap.find(DRIVER_HASH_STRING("Database::NumberOfPages"))->second;
	m_Data.Database.Buffer = (Kernel::_MMPFN*)VirtualAlloc(nullptr, m_Data.Database.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	m_Data.Process.ActiveProcessLinks = DataMap.find(DRIVER_HASH_STRING("ProcessOffset::ActiveProcessLinks"))->second;
	m_Data.Process.ImageFileName = DataMap.find(DRIVER_HASH_STRING("ProcessOffset::ImageFileName"))->second;
	m_Data.Process.VirtualSize = DataMap.find(DRIVER_HASH_STRING("ProcessOffset::VirtualSize"))->second;
	m_Data.Process.PebAddress = DataMap.find(DRIVER_HASH_STRING("ProcessOffset::PebAddress"))->second;

	m_Data.Thread.MiscFlags = DataMap.find(DRIVER_HASH_STRING("ThreadOffset::MiscFlags"))->second;

	// Clearing the Data map
	DataMap.clear();

	// Attempting to fetch the target process object
	m_Data.Target.Object = FetchProcess(ProcessHash);

	// Getting start time of search
	std::chrono::seconds StartTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
	
	while (!m_Data.Target.Object)
	{
		// Calculating the elapsed time in seconds of the search
		std::chrono::seconds ElapsedTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()) - StartTime;

		// Elapsed time exceeds 120 secs then return false
		if (ElapsedTime.count() > 120) {
			return false;
		}

		// Attempting to fetch the target process object
		m_Data.Target.Object = FetchProcess(ProcessHash);

		// Waiting 100 miliseconds
		Sleep(100);
	}

	m_Data.Target.Context = FetchContext(m_Data.Target.Object);

	// Getting start time of search
	StartTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());

	while (!m_Data.Target.Context)
	{
		// Calculating the elapsed time in seconds of the search
		std::chrono::seconds ElapsedTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()) - StartTime;

		// Elapsed time exceeds 10 secs then return false
		if (ElapsedTime.count() > 10) {
			return false;
		}

		// Attempting to fetch the target process context
		m_Data.Target.Context = FetchContext(m_Data.Target.Object);

		// Waiting 100 miliseconds
		Sleep(100);
	}

	// Starting up context caching thread
	std::thread([&] { ContextCache(); }).detach();

	// Waiting for page tables to cache
	Sleep(250);

	return true;
}

bool Kernel::Communication::Write(uint64_t Address, void* Buffer, size_t Length)
{
	return WriteVirtualMemory(m_Data.Target.Context, Address, Buffer, Length);
}

bool Kernel::Communication::Read(uint64_t Address, void* Buffer, size_t Length)
{
	return ReadVirtualMemory(m_Data.Target.Context, Address, Buffer, Length);
}

uint64_t Kernel::Communication::GetImageAddress(uint64_t Hash)
{
	typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks; PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName; } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
	typedef struct _PEB_LDR_DATA { ULONG Length; UCHAR Initialized; PVOID SsHandle; LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList; LIST_ENTRY InInitializationOrderModuleList; PVOID EntryInProgress; } PEB_LDR_DATA, * PPEB_LDR_DATA;
	typedef struct _PEB { BYTE Reserved1[2]; BYTE BeingDebugged; BYTE Reserved2[21]; PPEB_LDR_DATA LoaderData; PRTL_USER_PROCESS_PARAMETERS ProcessParameters; BYTE Reserved3[520]; PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine; BYTE Reserved4[136]; ULONG SessionId; } PEB;

	uint64_t PebAddress = NULL;
	ReadKernelMemory(
		m_Data.Target.Object + m_Data.Process.PebAddress, 
		&PebAddress, 
		sizeof(uint64_t)
	);

	PEB ProcessEnviromentBlock = { };
	Read(
		PebAddress, 
		&ProcessEnviromentBlock, 
		sizeof(PEB)
	);

	if (!ProcessEnviromentBlock.LoaderData) {
		return NULL;
	}
	
	PEB_LDR_DATA LoaderData = { };
	Read(
		(uint64_t)ProcessEnviromentBlock.LoaderData, 
		&LoaderData, 
		sizeof(PEB_LDR_DATA)
	);

	LIST_ENTRY* ListHead = (LIST_ENTRY*)LoaderData.InLoadOrderModuleList.Flink;
	LIST_ENTRY* CurrentNode = LoaderData.InLoadOrderModuleList.Flink;

	do
	{
		// Getting Table Entry From Current Node
		LDR_DATA_TABLE_ENTRY Entry = { };
		Read(
			((uint64_t)CurrentNode), 
			&Entry, 
			sizeof(LDR_DATA_TABLE_ENTRY)
		);

		// Updating Current Node
		CurrentNode = Entry.InLoadOrderLinks.Flink;

		// Validating Dll Name
		if (Entry.BaseDllName.Length <= 0x00) {
			continue;
		}

		// Getting Module Name
		std::wstring WideString = std::wstring(Entry.BaseDllName.Length, 0);
		Read(
			(uint64_t)(Entry.BaseDllName.Buffer),
			(void*)WideString.data(),
			Entry.BaseDllName.Length
		);

		std::string UnicodeString = std::string(
			WideString.begin(),
			WideString.end()
		);


		if (DriverHashString(UnicodeString.c_str()) != Hash) {
			continue;
		}

		return (std::uint64_t)Entry.DllBase;

	} while (ListHead != CurrentNode);

	return NULL;
}

bool Kernel::Communication::IsProcessOpen()
{
	uint64_t VirtualSize = NULL;
	ReadVirtualMemory(
		m_Data.System.Context, 
		m_Data.Target.Object + m_Data.Process.VirtualSize,
		&VirtualSize, 
		8
	);
	return VirtualSize > 0;
}
