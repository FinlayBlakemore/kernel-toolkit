#pragma once

#include "ObjectFetcher.hpp"
#include "StringHash.hpp"
#include "DebugLogger.hpp"
#include "Memory.hpp"

#include <memory>

namespace Kernel
{
	class FunctionCaller {
	private:
		uint64_t m_Address;
		uint64_t m_Invoker;
		uint64_t m_Context;

		template<typename ReturnType, typename ...Arguments>
		ReturnType CallInternal(uint64_t Function, Arguments... Args)
		{
			if (Function == NULL) {
				return { };
			}

			// Getting our previous context and setting the new one
			uint64_t PreviousContext = Kernel::Memory::SetContext(m_Context);

			// Getting original value of pointer
			uint64_t PreviousFunction = NULL;
			Kernel::Memory::ReadVirtual(
				m_Address,
				&PreviousFunction,
				sizeof(uint64_t)
			);

			if (PreviousFunction == NULL) {
				return { };
			}

			// Change to function we want to call
			Kernel::Memory::WriteVirtual(
				m_Address,
				&Function,
				sizeof(uint64_t)
			);

			// Calling the function
			ReturnType(__stdcall * ExportToInvoke)(Arguments...);
			*(void**)&ExportToInvoke = (void*)m_Invoker;

			ReturnType Result = ExportToInvoke(Args...);

			// Change back to original
			Kernel::Memory::WriteVirtual(
				m_Address,
				&PreviousFunction,
				sizeof(uint64_t)
			);

			Kernel::Memory::SetContext(PreviousContext);

			return Result;
		}

	public:
		FunctionCaller(uint64_t Context, uint64_t Address, uint64_t Invoker) {
			m_Address = Address;
			m_Invoker = Invoker;
			m_Context = Context;
		}

		template<typename ReturnType, typename ...Arguments>
		ReturnType CallByModule(uint64_t ModuleHash, uint64_t FunctionHash, Arguments... Args)
		{
			uint64_t Function = Kernel::ObjectFetcher::FetchModuleData(ModuleHash, FunctionHash);

			if (Function == NULL) {
				return { };
			}

			return CallInternal<ReturnType, Arguments...>(Function, Args...);
		}

		template<typename ReturnType, typename ...Arguments>
		ReturnType Call(uint64_t FunctionHash, Arguments... Args)
		{
			uint64_t Function = Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), FunctionHash);

			if (Function == NULL) {
				return { };
			}

			return CallInternal<ReturnType, Arguments...>(Function, Args...);
		}
	};
}