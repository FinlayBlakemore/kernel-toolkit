#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace Kernel
{
	struct FileInfo {
		uint64_t BaseAddress;
		size_t Length;
	};

	class File {
	private:
		static uint64_t PatternScan(uint64_t Address, size_t Length, unsigned char* Pattern, const char* Mask);
		static BOOLEAN DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
		static bool WriteMemory(uint64_t Address, void* Buffer, size_t Length);
		static bool ReadMemory(uint64_t Address, void* Buffer, size_t Length);
	public:
		static uint64_t PatternScan(uint64_t Filehash, BYTE* Pattern, const char* Mask);
		static uint64_t ResolveRelativeAddress(uint64_t Address, uint8_t* BaseAddress);
		static bool Write(std::vector<uint8_t>& FileData, std::string Filepath);
		static uint64_t GetExport(uint64_t BaseAddress, uint64_t ExportHash);
		static Kernel::FileInfo ManualMap(std::vector<uint8_t>& FileData);
		static std::vector<uint8_t> Load(uint64_t Filehash);
		static bool ReleaseFile(Kernel::FileInfo& File);
		static std::string Find(uint64_t Filehash);
	};
}