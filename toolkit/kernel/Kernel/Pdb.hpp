#pragma once

#include "Struct.hpp"

#include <string>
#include <vector>

namespace Kernel
{
	class Pdb {
	private:
		bool ParseStructTable();
		bool ParseDataTable();

		void UnloadSymbol();
		bool LoadSymbol();

		std::map<uint64_t, uint64_t> DataTable;
		std::map<uint64_t, Struct> StructTable;
		uint64_t BaseAddress;
		std::string& Path;
	public:
		Pdb(std::string& Path);
		~Pdb() = default;

		Struct& GetStruct(uint64_t Hash);
		uint64_t GetData(uint64_t Name);
		bool Parse();
	};
}