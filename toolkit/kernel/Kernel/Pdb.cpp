#include "Pdb.hpp"

#pragma comment(lib, "dbghelp.lib")

#include "StringHash.hpp"

#include <Windows.h>
#include <dbghelp.h>

#define NtCurrentProcess (HANDLE)(-1)

bool Kernel::Pdb::ParseStructTable()
{
	auto Callback = [](SYMBOL_INFO* SymbolInformation, ULONG SymbolSize, void* UserContext)
		{
			std::map<uint64_t, Struct>* StructTable = reinterpret_cast<std::map<uint64_t, Struct>*>(UserContext);

			TI_FINDCHILDREN_PARAMS TempChildrenParams = { 0 };
			if (!SymGetTypeInfo(NtCurrentProcess, 0x1000, SymbolInformation->TypeIndex, TI_GET_CHILDRENCOUNT, &TempChildrenParams)) {
				return TRUE;
			}

			ULONG ChildParamsSize = sizeof(TI_FINDCHILDREN_PARAMS) + TempChildrenParams.Count * sizeof(ULONG);
			TI_FINDCHILDREN_PARAMS* ChildParams = (TI_FINDCHILDREN_PARAMS*)malloc(ChildParamsSize);
			ZeroMemory(ChildParams, ChildParamsSize);

			memcpy(ChildParams, &TempChildrenParams, sizeof(TI_FINDCHILDREN_PARAMS));

			if (!SymGetTypeInfo(NtCurrentProcess, 0x1000, SymbolInformation->TypeIndex, TI_FINDCHILDREN, ChildParams)) {
				return TRUE;
			}

			Struct Type;

			for (ULONG i = ChildParams->Start; i < ChildParams->Count; i++)
			{
				WCHAR* PropertyName = nullptr;
				if (!SymGetTypeInfo(NtCurrentProcess, 0x1000, ChildParams->ChildId[i], TI_GET_SYMNAME, &PropertyName)) {
					return TRUE;
				}

				if (PropertyName == nullptr) {
					continue;
				}

				std::wstring WideString = std::wstring(PropertyName);
				std::string UnicodeString = std::string(
					WideString.begin(),
					WideString.end()
				);

				ULONG Offset = 0;
				if (!SymGetTypeInfo(NtCurrentProcess, 0x1000, ChildParams->ChildId[i], TI_GET_OFFSET, &Offset)) {
					return TRUE;
				}

				// DATA
				Type.AddProperty(HashString(UnicodeString.c_str()), Offset);
			}

			StructTable->insert({ HashString(SymbolInformation->Name), Type });

			return TRUE; // Continue enumeration
		};

	// Enumerating all types using our callback
	if (!SymEnumTypes(NtCurrentProcess, this->BaseAddress, Callback, &this->StructTable)) {
		return false;
	}

	return true;
}

bool Kernel::Pdb::ParseDataTable()
{
	auto Callback = [](SYMBOL_INFO* SymbolInformation, ULONG SymbolSize, void* Context)
		{
			if (!SymbolInformation->Name || !SymbolInformation->Address) {
				return TRUE;
			}

			// Pushing back name and offset of function
			reinterpret_cast<std::map<uint64_t, uint64_t>*>(Context)->emplace(HashString(SymbolInformation->Name), SymbolInformation->Address - SymbolInformation->ModBase);

			// Continuing execution
			return TRUE;
		};

	if (!SymEnumSymbols(NtCurrentProcess, this->BaseAddress, "*", Callback, &this->DataTable)) {
		return false;
	}

	return true;
}

void Kernel::Pdb::UnloadSymbol()
{
	// Loading symbol from memory
	SymUnloadModule64(NtCurrentProcess, this->BaseAddress);

	// Destroying traces of symbol
	remove(this->Path.c_str());
	this->Path.clear();
}

bool Kernel::Pdb::LoadSymbol()
{
	// Getting file attributes
	WIN32_FILE_ATTRIBUTE_DATA FileAttributeData{ 0 };
	if (!GetFileAttributesExA(this->Path.c_str(), GetFileExInfoStandard, &FileAttributeData)) {
		return false;
	}

	// Initilizing the symbol parser
	if (SymInitialize(NtCurrentProcess, this->Path.c_str(), FALSE) == false) {
		return false;
	}

	// doing some options
	SymSetOptions(
		SYMOPT_UNDNAME |
		SYMOPT_DEFERRED_LOADS |
		SYMOPT_AUTO_PUBLICS |
		SYMOPT_DEBUG |
		SYMOPT_LOAD_ANYTHING
	);

	// Loading symbol into memory
	this->BaseAddress = SymLoadModuleEx(
		NtCurrentProcess,
		nullptr,
		this->Path.c_str(),
		this->Path.c_str(),
		BaseAddress,
		FileAttributeData.nFileSizeLow, // PdbLength
		NULL,
		NULL
	);

	return this->BaseAddress;
}

Kernel::Pdb::Pdb(std::string& Path) : Path(Path)
{
	this->BaseAddress = 0x1000;
}

Kernel::Struct& Kernel::Pdb::GetStruct(uint64_t Hash)
{
	auto StructEntry = this->StructTable.find(Hash);

	if (StructEntry == this->StructTable.end())
	{
		static Struct Empty = Struct();
		return Empty;
	}

	return StructEntry->second;
}

uint64_t Kernel::Pdb::GetData(uint64_t Hash)
{
	auto DataEntry = this->DataTable.find(Hash);

	if (DataEntry == this->DataTable.end()) {
		return NULL;
	}

	return DataEntry->second;
}

bool Kernel::Pdb::Parse()
{
	// Loading symbol into memory
	if (this->LoadSymbol() == false) {
		return false;
	}

	// Parsing all struct information
	if (this->ParseStructTable() == false) {
		return false;
	}

	// Parsing all data information
	if (this->ParseDataTable() == false) {
		return false;
	}

	// Unloading symbol from memory
	this->UnloadSymbol();

	return true;
}
