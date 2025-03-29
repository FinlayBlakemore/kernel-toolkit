#include "Memory.hpp"

#pragma comment(lib, "ntdll.lib")

#include "DebugLogger.hpp"
#include <ntstatus.h>

#define PAGE_SHIFT      12
#ifdef __ASSEMBLY__
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#else
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define PAGE_OFFSET_SIZE 12

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

typedef union _VIRTUAL_MEMORY_ADDRESS { struct { UINT64 PageIndex : 12, PtIndex : 9, PdIndex : 9, PdptIndex : 9, Pml4Index : 9, Unused : 16; } Bits; UINT64 All; } VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;
typedef union _DIRECTORY_TABLE_BASE { struct { UINT64 Ignored0 : 3, PageWriteThrough : 1, PageCacheDisable : 1, _Ignored1 : 7, PhysicalAddress : 36, _Reserved0 : 16; } Bits; UINT64 All; } CR3, DIR_TABLE_BASE;
typedef union _PML4_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, _Ignored0 : 1, _Reserved0 : 1, _Ignored1 : 4, PhysicalAddress : 40, _Ignored2 : 11, ExecuteDisable : 1; } Bits; UINT64 All; } PML4E;
typedef union _PDPT_ENTRY_LARGE { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, Dirty : 1, PageSize : 1, Global : 1, _Ignored0 : 3, PageAttributeTable : 1, _Reserved0 : 17, PhysicalAddress : 22, _Ignored1 : 7, ProtectionKey : 4, ExecuteDisable : 1; } Bits; UINT64 All; } PDPTE_LARGE;
typedef union _PDPT_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, _Ignored0 : 1, PageSize : 1, _Ignored1 : 4, PhysicalAddress : 40, _Ignored2 : 11, ExecuteDisable : 1; } Bits; UINT64 All; } PDPTE;
typedef union _PD_ENTRY_LARGE { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, Dirty : 1, PageSize : 1, Global : 1, _Ignored0 : 3, PageAttributeTalbe : 1, _Reserved0 : 8, PhysicalAddress : 29, _Reserved1 : 2, _Ignored1 : 7, ProtectionKey : 4, ExecuteDisable : 1; } Bits; UINT64 All; } PDE_LARGE;
typedef union _PD_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, _Ignored0 : 1, PageSize : 1, _Ignored1 : 4, PhysicalAddress : 38, _Reserved0 : 2, _Ignored2 : 11, ExecuteDisable : 1; } Bits; UINT64 All; } PDE;
typedef union _PT_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, Dirty : 1, PageAttributeTable : 1, Global : 1, _Ignored0 : 3, PhysicalAddress : 38, _Reserved0 : 2, _Ignored1 : 7, ProtectionKey : 4, ExecuteDisable : 1; } Bits; UINT64 All; } PTE;
typedef union _MMPTE_HARDWARE { struct { UINT64 Valid : 1, Dirty1 : 1, Owner : 1, WriteThrough : 1, CacheDisable : 1, Accessed : 1, Dirty : 1, LargePage : 1, Global : 1, CopyOnWrite : 1, Unused : 1, Write : 1, PageFrameNumber : 36, ReservedForHardware : 4, ReservedForSoftware : 4, WsleAge : 4, WsleProtection : 3, NoExecute : 1; } Bits; UINT64 All; } MMPTE_HARDWARE;

inline HANDLE Kernel::Memory::s_Handle = NULL;
inline uint64_t Kernel::Memory::s_Context = NULL;

uint64_t Kernel::Memory::ResolveRelativeAddress(uint64_t Address, uint32_t Offset, uint32_t Length)
{
	int RelativeOffset = 0;
	if (Kernel::Memory::ReadVirtual(Address + Offset, &RelativeOffset, sizeof(int)) == false) {
		return NULL;
	}

	return Address + Length + RelativeOffset;
}

bool Kernel::Memory::WritePhysical(uint64_t Address, void* Buffer, size_t Length)
{
	DriverPacket Packet;
	Packet.PhysicalAddress = Address;
	Packet.Size = Length;

	if (!MapPhysicalMemory(&Packet)) {
		return false;
	}

	// Writing the data from the virtual address
	__movsb((BYTE*)Packet.BaseAddress, (BYTE*)Buffer, Length);

	if (!UnmapPhysicalMemory(&Packet)) {
		return false;
	}

	return true;
}

bool Kernel::Memory::ReadPhysical(uint64_t Address, void* Buffer, size_t Length)
{
	DriverPacket Packet;
	Packet.PhysicalAddress = Address;
	Packet.Size = Length;

	if (!MapPhysicalMemory(&Packet)) {
		return false;
	}

	// Reading the data from the virtual address
	__movsb((BYTE*)Buffer, (BYTE*)Packet.BaseAddress, Length);

	if (!UnmapPhysicalMemory(&Packet)) {
		return false;
	}

	return true;
}

bool Kernel::Memory::WriteVirtual(uint64_t Address, void* Buffer, size_t Length)
{
	if (!Address || !Buffer || !Length) {
		return false;
	}

	std::size_t Offset = 0x00;
	std::size_t Value = Length;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = VirtualToPhysical(Address + Offset);

		if (!PhysicalAddress) {
			return false;
		}

		const std::uint64_t MemoryLength = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

		WritePhysical(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), MemoryLength);

		Offset += MemoryLength;
		Value -= MemoryLength;
	}

	return true;
}

bool Kernel::Memory::ReadVirtual(uint64_t Address, void* Buffer, size_t Length)
{
	if (!Address || !Buffer || !Length) {
		return false;
	}

	std::size_t Offset = 0x00;
	std::size_t Value = Length;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = VirtualToPhysical(Address + Offset);

		if (!PhysicalAddress) {
			return false;
		}

		const std::uint64_t MemoryLength = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

		ReadPhysical(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), MemoryLength);

		Offset += MemoryLength;
		Value -= MemoryLength;
	}

	return true;
}

uint64_t Kernel::Memory::VirtualToPhysical(uint64_t Address)
{
	VIRTUAL_ADDRESS virtAddr = { 0 };

	DIR_TABLE_BASE  dirTableBase = { 0 };
	PML4E           pml4e = { 0 };
	PDPTE           pdpte = { 0 };
	PDPTE_LARGE     pdpteLarge = { 0 };
	PDE             pde = { 0 };
	PDE_LARGE       pdeLarge = { 0 };
	PTE             pte = { 0 };


	virtAddr.All = Address;
	dirTableBase.All = s_Context;

	if (ReadPhysical(
		/* This calculation results in the PML4E address */
		(dirTableBase.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.Pml4Index * 8),
		&pml4e,
		sizeof(PML4E)) == FALSE)
	{
		return 0;
	}

	/*
	 * Always ensure we can proceed with our translation process. It may
	 *  also be wise to check the read result of our MmCopyMemory wrapper.
	 */

	if (pml4e.Bits.Present == 0)
	{
		return 0;
	}


	if (ReadPhysical(
		/* This calculation results in the PDPTE address */
		(pml4e.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdptIndex * 8),
		&pdpte,
		sizeof(PDPTE)) == FALSE)
	{
		return 0;
	}

	if (pdpte.Bits.Present == 0)
	{
		return 0;
	}


	if (IS_LARGE_PAGE(pdpte.All) == TRUE)
	{
		pdpteLarge.All = pdpte.All;

		return (pdpteLarge.Bits.PhysicalAddress << PAGE_1GB_SHIFT)
			+ PAGE_1GB_OFFSET(Address);
	}

	if (ReadPhysical(
		/* This calculation results in the PDE address */
		(pdpte.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdIndex * 8),
		&pde,
		sizeof(PDE)) == FALSE)
	{
		return 0;
	}

	if (pde.Bits.Present == 0)
	{
		return 0;
	}


	if (IS_LARGE_PAGE(pde.All) == TRUE)
	{
		pdeLarge.All = pde.All;

		return (pdeLarge.Bits.PhysicalAddress << PAGE_2MB_SHIFT)
			+ PAGE_2MB_OFFSET(Address);
	}

	if (ReadPhysical(
		/* This calculation results in the PTE address */
		(pde.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PtIndex * 8),
		&pte,
		sizeof(PTE)) == FALSE)
	{
		return 0;
	}

	if (pte.Bits.Present == 0)
	{
		return 0;
	}

	return (pte.Bits.PhysicalAddress << PAGE_4KB_SHIFT)
		+ virtAddr.Bits.PageIndex;
}

uint64_t Kernel::Memory::SetContext(uint64_t Context)
{
	uint64_t PreviousContext = s_Context;
	s_Context = Context;

	DebugLog("s_Context (0x%llx:0x%llx)\n", PreviousContext, s_Context);
	return PreviousContext;
}

uint64_t Kernel::Memory::GetContext()
{
	return s_Context;
}

bool Kernel::Memory::UnmapPhysicalMemory(DriverPacket* Packet)
{
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();
	return NT_SUCCESS(NtDeviceIoControlFile(
		s_Handle,
		(HANDLE)NULL,
		(PIO_APC_ROUTINE)nullptr,
		(PVOID)nullptr,
		(PIO_STATUS_BLOCK)&StatusBlock,
		(ULONG)0x80102044,
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket),
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket)
	));
}

bool Kernel::Memory::MapPhysicalMemory(DriverPacket* Packet)
{
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();
	return NT_SUCCESS(NtDeviceIoControlFile(
		s_Handle,
		(HANDLE)NULL,
		(PIO_APC_ROUTINE)nullptr,
		(PVOID)nullptr,
		(PIO_STATUS_BLOCK)&StatusBlock,
		(ULONG)0x80102040,
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket),
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket)
	));
}

uint64_t Kernel::Memory::GetSystemContext()
{
	// Our result
	uint64_t Result = NULL;

	for (int Index = 0; Index < 10; Index++)
	{
		// Mapping a buffer of kernel pages to our process
		DriverPacket Packet;
		Packet.PhysicalAddress = Index * 0x10000;
		Packet.Size = 0x10000;
		if (!MapPhysicalMemory(&Packet)) {
			continue;
		}

		// Validating the buffer address
		if (!Packet.BaseAddress) {
			continue;
		}

		// Storing our buffer
		uint64_t Buffer = (std::uint64_t)Packet.BaseAddress;

		// Looping the buffer for the system cr3
		for (int Offset = 0; Offset < 0x10000; Offset += 0x1000)
		{
			if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(Buffer + Offset)))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0x70)))
				continue;
			if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0xa0))
				continue;

			Result = *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0xa0);
			break;
		}

		// Unmapping buffer
		UnmapPhysicalMemory(&Packet);

		if (Result > 0) {
			break;
		}
	}

	return Result;
}

NTSTATUS Kernel::Memory::CreateHandle()
{
	// Creating unicode string to open a device to our driver
	UNICODE_STRING UnicodeString;
	RtlInitUnicodeString(&UnicodeString, L"\\DosDevices\\WinIo");

	// Initilizing Classes To Pass To "NtCreateFile"
	OBJECT_ATTRIBUTES Attributes = OBJECT_ATTRIBUTES();
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();

	// Creating Handle To The File
	Attributes.Length = sizeof(OBJECT_ATTRIBUTES);
	Attributes.ObjectName = &UnicodeString;

	NTSTATUS Status = NtCreateFile(
		&s_Handle,
		GENERIC_READ | GENERIC_WRITE | WRITE_DAC | SYNCHRONIZE,
		&Attributes,
		&StatusBlock,
		nullptr,
		NULL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr,
		NULL
	);

	if (Status != STATUS_SUCCESS) {
		return Status;
	}

	s_Context = GetSystemContext();

	if (s_Context <= NULL) {
		return 0xC0000719; // STATUS_CONTEXT_MISMATCH
	}

	return Status;
}

void Kernel::Memory::DestoryHandle()
{
	CloseHandle(s_Handle);
}

HANDLE& Kernel::Memory::GetHandle()
{
	return s_Handle;
}
