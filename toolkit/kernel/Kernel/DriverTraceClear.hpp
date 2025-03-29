#pragma once

#include "FunctionCaller.hpp"
#include "Memory.hpp"
#include "Pdb.hpp"

#include <memory>

namespace Kernel
{
	class DriverTraceClear {
	private:
		bool MmUnloadedDrivers();
		bool KernelHashBucketList();
		bool PiDDBCacheTable();
		bool WdFilter();

		std::shared_ptr<Kernel::FunctionCaller>& m_Function;
		std::wstring m_DeviceName;
		std::string& m_DriverPath;
		uint64_t m_DriverObject;
	public:
		DriverTraceClear(uint64_t DriverObject, std::wstring DeviceName, std::string& DriverPath, std::shared_ptr<Kernel::FunctionCaller>& Function);
		~DriverTraceClear() = default;

		bool Verify();
		bool Clear();
	};
}