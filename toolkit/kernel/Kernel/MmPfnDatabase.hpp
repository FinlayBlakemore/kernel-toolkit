#pragma once

#include "Memory.hpp"

#include <memory>
#include <cstdint>

struct _MMPFN {
	uint64_t Flag;
	uint64_t PteAddress;
	uint64_t Unused_2;
	uint64_t Unused_3;
	uint64_t Unused_4;
	uint64_t Unused_5;
};

namespace Kernel
{
	struct DatabaseData {
		size_t NumberOfPages;
		uint64_t Address;
		size_t Length;
	};

	class MmPfnDatabase {
	private:
		size_t m_NumberOfPages;
		size_t m_BufferLength;
		_MMPFN* m_Buffer;

		uint64_t m_Address;
	public:
		MmPfnDatabase(uint64_t Address);
		~MmPfnDatabase();

		uint64_t FetchContext(uint64_t Process);
		uint64_t FetchProcess(uint64_t Context);
		Kernel::DatabaseData GetData();
	};
}