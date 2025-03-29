#pragma once

#include "StringHash.hpp"

#include <Windows.h>
#include <algorithm>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <map>

#define NtCurrentProcess (HANDLE)(-1)

namespace Kernel
{
	struct CallInfo {
		std::uint32_t XorKey;
		void* Address;
	};

	class Syscall {
	public:
		Syscall();

		bool NtDuplicateHandle(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, HANDLE* TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
		bool NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, void* SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength, NTSTATUS* Status);
		bool NtQueryInformationProcess(HANDLE Handle, PROCESSINFOCLASS ProcessInformationClass, void* ProcessInformation, ULONG ProcessInformationLength, ULONG* ReturnLength);
		bool NtProtectVirtualMemory(HANDLE Handle, void* BaseAddress, std::size_t Length, std::size_t Protection, std::size_t* OldProtection);
		bool NtAllocateVirtualMemory(HANDLE Handle, void** BaseAddress, std::size_t RegionSize, ULONG Protect);
		bool NtWriteVirtualMemory(HANDLE Handle, void* BaseAddress, void* Buffer, std::size_t Length);
		bool NtReadVirtualMemory(HANDLE Handle, void* BaseAddress, void* Buffer, std::size_t Length);
		bool NtCreateThreadEx(HANDLE Handle, HANDLE* ThreadHandle, void* Address, void* Parameter, uint64_t StartAddress);
		bool NtOpenProcess(HANDLE* Handle, HANDLE UniqueProcess, ACCESS_MASK DesiredAccess);
		bool NtGetContextThread(HANDLE ThreadHandle, CONTEXT* Context);
		bool NtSetContextThread(HANDLE ThreadHandle, CONTEXT* Context);
		bool NtFreeVirtualMemory(HANDLE Handle, void* BaseAddress);
		bool NtResumeThread(HANDLE ThreadHandle);

		bool Create();
	private:
		void EncryptShellcode(void* Address, std::uint32_t XorKey);
		void DecryptShellcode(void* Address, std::uint32_t XorKey);
		CallInfo GetCallInfo(std::uint32_t MethodHash);
		bool CreateCallInfo(std::uint32_t MethodHash);

		std::map<std::uint32_t, CallInfo> HashToInfo;
	};

	inline Kernel::Syscall* SystemCall = new Kernel::Syscall();
}