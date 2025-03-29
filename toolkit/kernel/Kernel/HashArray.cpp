#include "HashArray.hpp"

#include <Windows.h>
#include <cstdio>

Kernel::HashArray::HashArray(size_t Length)
{
	m_DataArray = reinterpret_cast<uint64_t*>(malloc(Length * sizeof(uint64_t)));
	m_HashArray = reinterpret_cast<uint64_t*>(malloc(Length * sizeof(uint64_t)));
	m_Length = Length;
	m_Index = 0;

	memset(m_DataArray, NULL, m_Length * sizeof(uint64_t));
	memset(m_HashArray, NULL, m_Length * sizeof(uint64_t));
}

Kernel::HashArray::~HashArray()
{
	free(m_DataArray);
	free(m_HashArray);
}

void Kernel::HashArray::AddProperty(uint64_t Hash, uint64_t Data)
{
	m_DataArray[m_Index] = Data;
	m_HashArray[m_Index] = Hash;
	m_Index++;
}

uint64_t Kernel::HashArray::GetProperty(uint64_t Hash)
{
	for (size_t i = 0; i < m_Length; i++) {
		if (m_HashArray[i] == Hash) {
			return m_DataArray[i];
		}
	}

	return NULL;
}

void Kernel::HashArray::DebugPrint()
{
	printf("uint64_t DataArray[] = { ");
	for (size_t i = 0; i < m_Length; i++) {
		printf("0x%llx", m_DataArray[i]);

		if (i + 1 < m_Length) {
			printf(", ");
		}
	}
	printf("}\n\n");

	printf("uint64_t HashArray[] = { ");
	for (size_t i = 0; i < m_Length; i++) {
		printf("0x%llx", m_HashArray[i]);

		if (i + 1 < m_Length) {
			printf(", ");
		}
	}
	printf("}\n");
}

std::array<uint64_t, 3> Kernel::HashArray::GetData()
{
	return { 
		reinterpret_cast<uint64_t>(m_DataArray),
		reinterpret_cast<uint64_t>(m_HashArray),
		m_Length 
	};
}
