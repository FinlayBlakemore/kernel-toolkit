#pragma once

#include "HashString.hpp"
#include "Structs.hpp"

#include <shared_mutex>
#include <vector>
#include <map>

namespace Kernel
{
	class Communication {
	private:
		uint64_t CallKernelFunction(uint64_t Address, uint64_t Arg1 = NULL, uint64_t Arg2 = NULL, uint64_t Arg3 = NULL, uint64_t Arg4 = NULL, uint64_t Arg5 = NULL);

		bool WriteVirtualMemory(uint64_t PageDirectoryBase, uint64_t Address, void* Buffer, size_t Size);
		bool ReadVirtualMemory(uint64_t PageDirectoryBase, uint64_t Address, void* Buffer, size_t Size);

		uint64_t VirtualToPhysical(uint64_t PageDirectoryBase, uint64_t VirtualAddress);
		bool WritePhysicalMemory(uint64_t Address, void* Buffer, size_t Length);
		bool ReadPhysicalMemory(uint64_t Address, void* Buffer, size_t Length);
		bool ReadPageTable(uint64_t Address, void* Buffer, size_t Length);

		bool ReadKernelMemory(uint64_t Address, void* Buffer, size_t Length);
	
		void CachePageTables(uint64_t Context, uint64_t* Pml4Cache, uint64_t* PdptCache);
		uint64_t FetchContext(uint64_t Object);
		uint64_t FetchProcess(uint64_t Hash);
		void ContextCache();

		uint64_t m_PdptCache[512][512];
		uint64_t m_Pml4Cache[512];
		std::shared_mutex m_Mutex;
		Kernel::Data m_Data;
	public:
		Communication();
		~Communication() = default;

		bool Startup(uint64_t ProcessHash, uint64_t* DataArray, uint64_t* HashArray, size_t m_Length);

		template<typename Type>
		Type ReadChain(uint64_t Address, std::vector<uint64_t> OffsetList)
		{
			for (size_t Index = 0; Index < OffsetList.size() - 1; Index++)
			{
				if (Address == NULL) {
					return Type();
				}

				Address = Read<uint64_t>(Address + OffsetList[Index]);
			}

			return Read<Type>(Address + OffsetList[OffsetList.size() - 1]);
		}

		template<typename Type>
		Type Write(uint64_t Address, Type Buffer) {
			return Write(Address, &Buffer, sizeof(Type));
		}

		template<typename Type>
		Type Read(uint64_t Address)
		{
			Type Buffer;
			memset(&Buffer, 0, sizeof(Type));

			Read(Address, &Buffer, sizeof(Type));

			return Buffer;
		}

		bool Write(uint64_t Address, void* Buffer, size_t Length);
		bool Read(uint64_t Address, void* Buffer, size_t Length);
		uint64_t GetImageAddress(uint64_t Hash);
		bool IsProcessOpen();
	};
}

inline Kernel::Communication* Driver = new Kernel::Communication();