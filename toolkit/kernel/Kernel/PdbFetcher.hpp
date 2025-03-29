#pragma once

#include "Pdb.hpp"

#include <Windows.h>
#include <vector>
#include <memory>

struct DebugInformation {
	std::string Name;
	char Guid[37];
};

namespace Kernel
{
	class PdbFetcher {
	private:
		static bool GetDebugInformation(uint64_t BaseAddress, DebugInformation& DebugInfo);
		static bool DownloadToFile(DebugInformation& DebugInfo, std::string* Path);

		static std::map<uint64_t, std::shared_ptr<Kernel::Pdb>> s_PdbCache;
	public:
		static std::shared_ptr<Kernel::Pdb> Fetch(uint64_t Name);
	};
}