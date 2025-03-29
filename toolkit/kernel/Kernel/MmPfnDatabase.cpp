#include "MmPfnDatabase.hpp"

#include <Windows.h>

Kernel::MmPfnDatabase::MmPfnDatabase(uint64_t Address)
{
	MEMORYSTATUSEX MemoryStatus;
	MemoryStatus.dwLength = sizeof(MEMORYSTATUSEX);

	// Getting the status which contains the physical memory length
	GlobalMemoryStatusEx(&MemoryStatus);

	// Calculating the size of the MmPfnDatabase
	m_NumberOfPages = MemoryStatus.ullTotalPhys / 0x1000;
	m_BufferLength = m_NumberOfPages * sizeof(_MMPFN);

	// Allocating a buffer with this length
	m_Buffer = reinterpret_cast<_MMPFN*>(VirtualAlloc(nullptr, m_BufferLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	m_Address = Address;
}

Kernel::MmPfnDatabase::~MmPfnDatabase()
{
	VirtualFree(m_Buffer, NULL, MEM_RELEASE);
}

uint64_t Kernel::MmPfnDatabase::FetchContext(uint64_t Process)
{
	// Reading the entire pfn database
	if (Kernel::Memory::ReadVirtual(
		m_Address,
		m_Buffer,
		m_BufferLength) == false) {
		return NULL;
	}

	for (std::uint64_t PageFrameNumber = 0; PageFrameNumber < m_NumberOfPages; ++PageFrameNumber)
	{
		// Getting current MmPfn
		_MMPFN& Page = m_Buffer[PageFrameNumber];

		// Checking if the MmPfn is a EProcess
		if (!Page.Flag || Page.Flag == 1) {
			continue;
		}

		std::uint64_t EProcess = ((Page.Flag | 0xF000000000000000) >> 13) | 0xFFFF000000000000;

		if (EProcess == Process) {
			return PageFrameNumber << 12;
		}
	}

	return 0;
}

uint64_t Kernel::MmPfnDatabase::FetchProcess(uint64_t Context)
{
	// Getting the PageFrameNumber of the context
	uint64_t PageFrameNumber = Context >> 12;

	// Reading the entry inside of the PfnDatabase for the PageFrameNumber
	if (Kernel::Memory::ReadVirtual(
		m_Address + (PageFrameNumber * sizeof(_MMPFN)),
		&m_Buffer[PageFrameNumber],
		sizeof(_MMPFN)) == false) {
		return NULL;
	}

	_MMPFN& Entry = m_Buffer[PageFrameNumber];

	return ((Entry.Flag | 0xF000000000000000) >> 13) | 0xFFFF000000000000;
}

Kernel::DatabaseData Kernel::MmPfnDatabase::GetData()
{
	Kernel::DatabaseData Data;
	memset(&Data, NULL, sizeof(Kernel::DatabaseData));

	Data.Address = m_Address;
	Data.Length = m_BufferLength;
	Data.NumberOfPages = m_NumberOfPages;

	return Data;
}
