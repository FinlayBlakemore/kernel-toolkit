#pragma once

#include <cstdint>

namespace Kernel
{
	struct _MMPFN {
		uint64_t Flag;
		uint64_t PteAddress;
		uint64_t Unused_2;
		uint64_t Unused_3;
		uint64_t Unused_4;
		uint64_t Unused_5;
	};

	struct ProcessData {
		uint64_t Object;
		uint64_t Context;
	};

	struct DatabaseData {
		_MMPFN* Buffer;
		size_t NumberOfPages;
		uint64_t Address;
		size_t Length;
	};

	struct ProcessOffset {
		uint64_t ActiveProcessLinks;
		uint64_t ImageFileName;
		uint64_t VirtualSize;
		uint64_t PebAddress;
	};

	struct ThreadOffset {
		uint64_t MiscFlags;
	};

	struct FunctionData {
		uint64_t(__stdcall* Invoker)(char*, unsigned int, uint64_t, uint64_t, uint64_t, void*);
		uint64_t PsGetCurrentThread;
		uint64_t Handler;
		uint64_t MmMapIoSpaceEx;
		uint64_t MmUnmapIoSpace;
		uint64_t MmCopyMemory;
		uint64_t memcpy;
	};

	struct Data {
		ProcessData Explorer;
		ProcessData System;
		ProcessData Target;

		DatabaseData Database;
		
		ProcessOffset Process;
		ThreadOffset Thread;

		FunctionData Function;
	};
}