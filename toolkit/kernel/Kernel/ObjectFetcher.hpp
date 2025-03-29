#pragma once

#include "MmPfnDatabase.hpp"
#include "PdbFetcher.hpp"
#include "Memory.hpp"

#include <memory>
#include <cstdint>

namespace Kernel
{
	class ObjectFetcher {
	public:
		struct ModuleInformation {
			uint64_t BaseAddress;
			size_t Length;
		};
	private:
		std::unique_ptr<Kernel::MmPfnDatabase> m_MmPfnDatabase;

		std::map<uint64_t, ModuleInformation> m_ModuleCache;
		std::map<uint64_t, uint64_t> m_ProcessCache;
		uint64_t m_PsInitialSystemProcess;
	public:
		ObjectFetcher() = default;
		~ObjectFetcher() = default;

		static Struct& FetchModuleStruct(uint64_t ModuleHash, uint64_t StructHash);
		static uint64_t FetchModuleData(uint64_t ModuleHash, uint64_t DataHash);
		static ObjectFetcher::ModuleInformation FetchModule(uint64_t ModuleHash);

		static uint64_t FetchModulePattern(uint64_t ModuleHash, BYTE* Pattern, const char* Mask);
		uint64_t FetchPointerAddress(uint64_t ModuleHash, uint64_t FunctionHash);
		uint64_t FetchProcess(uint64_t InitialProcess, uint64_t ProcessHash);
		static uint64_t FetchDriverObject(HANDLE Handle);
		uint64_t FetchProcessByProcessId(uint32_t Context);
		uint64_t FetchProcessByHash(uint64_t ProcessHash);
		uint64_t FetchProcessByContext(uint64_t Context);
		uint64_t FetchSystemProcess();

		uint64_t FetchContextByHash(uint64_t ProcessHash);
		uint64_t FetchContextByObject(uint64_t Process);
		Kernel::DatabaseData GetDatabaseData();

		bool Initilize();
	};
}