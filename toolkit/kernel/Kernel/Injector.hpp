#pragma once

#include "FunctionCaller.hpp"
#include <TlHelp32.h>
#include <memory>

namespace Kernel
{
	using RtlAddFunctionTable_t = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
	using EntryPoint_t = BOOL(WINAPI*)(BYTE* BaseAddress, DWORD Reason, uint64_t Parameter);
	using GetProcAddress_t = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
	using LoadLibraryA_t = HINSTANCE(WINAPI*)(const char* lpLibFilename);
	using Sleep_t = void(WINAPI*)(DWORD Miliseconds);

	struct ModuleArgument
	{
		RtlAddFunctionTable_t RtlAddFunctionTable;
		GetProcAddress_t GetProcAddress;
		LoadLibraryA_t LoadLibraryA;
		Sleep_t Sleep;

		uint64_t Parameter;
		BYTE* TargetBuffer;
		int Status;
	};

	class Injector {
	private:
		static uint32_t __stdcall Shellcode(ModuleArgument* Argument);
		uint64_t LoadRwxDll(std::vector<uint8_t> VunerableDll);
		THREADENTRY32 GetThread(uint32_t ThreadId);
		MODULEENTRY32 GetModule(uint64_t Hash);

		std::shared_ptr<Kernel::FunctionCaller>& m_Function;
		uint64_t m_Context;
		uint32_t m_ProcessId;
		int* m_Status;
		HANDLE m_Handle;
	public:
		Injector(std::shared_ptr<Kernel::FunctionCaller>& Function);
		~Injector() = default;

		bool ManualMap(std::vector<uint8_t> VunerableDll, std::vector<uint8_t> TargetDll, uint64_t Parameter);
		bool AttachToProcess(uint64_t Context, uint32_t ProcessId);
		uint32_t GetProcess(const uint64_t Hash);
		bool CreateThread();
	};
}