#pragma once

#include <Windows.h>
#include <winternl.h>
#include <string>

namespace Kernel
{
	class Memory {
	private:
		typedef struct DriverPacket
		{
			DWORD_PTR Size;
			DWORD_PTR PhysicalAddress;
			HANDLE SectionHandle;
			LPVOID BaseAddress;
			LPVOID ReferenceObject;
		};

		static bool UnmapPhysicalMemory(DriverPacket* Packet);
		static bool MapPhysicalMemory(DriverPacket* Packet);
		static uint64_t GetSystemContext();

		static uint64_t s_Context;
		static HANDLE s_Handle;
	public:
		static uint64_t ResolveRelativeAddress(uint64_t Address, uint32_t Offset, uint32_t Length);
		static bool WritePhysical(uint64_t Address, void* Buffer, size_t Length);
		static bool ReadPhysical(uint64_t Address, void* Buffer, size_t Length);
		static bool WriteVirtual(uint64_t Address, void* Buffer, size_t Length);
		static bool ReadVirtual(uint64_t Address, void* Buffer, size_t Length);
		static uint64_t VirtualToPhysical(uint64_t Address);
 
		static uint64_t SetContext(uint64_t Context);
		static uint64_t GetContext();

		static NTSTATUS CreateHandle();
		static void DestoryHandle();
		static HANDLE& GetHandle();
	};
}