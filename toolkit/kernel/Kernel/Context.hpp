#pragma once

#include "DriverTraceClear.hpp"
#include "FunctionCaller.hpp"
#include "ObjectFetcher.hpp"
#include "DriverLoader.hpp"
#include "PdbFetcher.hpp"
#include "Memory.hpp"
#include "HashArray.hpp"
#include "Injector.hpp"

#include <memory>

namespace Kernel
{
	class Context {
	private:
		bool InitilizeFunctionCaller(uint64_t FunctionHash);

		std::unique_ptr<Kernel::DriverTraceClear> m_DriverTraceClear;
		std::unique_ptr<Kernel::ObjectFetcher> m_ObjectFetcher;
		std::unique_ptr<Kernel::DriverLoader> m_DriverLoader;
		std::shared_ptr<Kernel::FunctionCaller> m_Function;
		std::unique_ptr<Kernel::Injector> m_Injector;
	public:
		Context(const char* DriverName);
		~Context() = default;

		uint64_t FetchModulePattern(uint64_t ModuleHash, BYTE* Pattern, const char* Mask);
		Struct& FetchModuleStruct(uint64_t ModuleHash, uint64_t StructHash);
		uint64_t FetchModuleData(uint64_t ModuleHash, uint64_t DataHash);
		ObjectFetcher::ModuleInformation FetchModule(uint64_t ModuleHash);

		uint64_t FetchPointerAddress(uint64_t ModuleHash, uint64_t FunctionHash);
		uint64_t ResolvePointerAddress(uint64_t ModuleHash, uint64_t Address);
		uint64_t FetchProcess(uint64_t InitalProcess, uint64_t ProcessHash);
		bool InsideModule(uint64_t Address, uint64_t ModuleHash);
		uint64_t FetchSystemProcess();

		uint64_t FetchProcess(uint64_t Process, bool HashSearch);
		uint64_t FetchContext(uint64_t Process, bool HashSearch);
		uint64_t FetchContextById(uint32_t ProcessId);
		uint32_t FetchProcessId(uint64_t ProcessHash);
		void SetPreviousMode(uint8_t Mode);

		std::shared_ptr<Kernel::FunctionCaller>& GetFunction();
		std::unique_ptr<Kernel::Injector>& GetInjector();
		Kernel::HashArray GetCommunicationData();

		bool Initilize();
		bool Shutdown();
	};
}