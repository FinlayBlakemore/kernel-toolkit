#pragma once

#include "StringHash.hpp"
#include <array>

namespace Kernel
{
	class HashArray {
	private:
		uint64_t* m_HashArray;
		uint64_t* m_DataArray;
		size_t m_Length;
		size_t m_Index;
	public:
		HashArray(size_t Length);
		~HashArray();

		void AddProperty(uint64_t Hash, uint64_t Data);
		uint64_t GetProperty(uint64_t Hash);
		void DebugPrint();

		std::array<uint64_t, 3> GetData();
	};
}