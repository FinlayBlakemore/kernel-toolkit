#include "File.hpp"

#include "StringHash.hpp"

#include <fstream>
#include <filesystem>

uint64_t Kernel::File::PatternScan(uint64_t Address, size_t Length, unsigned char* Pattern, const char* Mask)
{
    size_t MaxLength = Length - strlen(Mask);
    for (uint64_t Offset = 0; Offset < MaxLength; Offset++)
    {
        if (DataCompare((BYTE*)(Address + Offset), Pattern, Mask)) {
            return Offset;
        }
    }
    return 0;
}

BOOLEAN Kernel::File::DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return 0;
    return (*szMask) == 0;
}

bool Kernel::File::WriteMemory(uint64_t Address, void* Buffer, size_t Length)
{
    return WriteProcessMemory((HANDLE)(-1), (void*)(Address), Buffer, Length, nullptr);
}

bool Kernel::File::ReadMemory(uint64_t Address, void* Buffer, size_t Length)
{
    return ReadProcessMemory((HANDLE)(-1), (void*)(Address), Buffer, Length, nullptr);
}

uint64_t Kernel::File::PatternScan(uint64_t Filehash, BYTE* Pattern, const char* Mask)
{
    std::vector<uint8_t> FileData = Load(Filehash);

    if (FileData.empty() == true) {
        return NULL;
    }

    Kernel::FileInfo File = ManualMap(FileData);

    uint64_t Offset = PatternScan(File.BaseAddress, File.Length, Pattern, Mask);

    ReleaseFile(File);

    return Offset;
}

uint64_t Kernel::File::ResolveRelativeAddress(uint64_t Address, uint8_t* BaseAddress)
{
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)(BaseAddress);
    IMAGE_NT_HEADERS* NtHeaders = (IMAGE_NT_HEADERS*)(BaseAddress + DosHeader->e_lfanew);

    IMAGE_SECTION_HEADER* FirstSection = IMAGE_FIRST_SECTION(NtHeaders);
    for (IMAGE_SECTION_HEADER* Section = FirstSection; Section < FirstSection + NtHeaders->FileHeader.NumberOfSections; Section++) {
        if (Address >= Section->VirtualAddress && Address < Section->VirtualAddress + Section->Misc.VirtualSize) {
            return (uint64_t)BaseAddress + Section->PointerToRawData + (Address - Section->VirtualAddress);
        }
    }
    return NULL;
}

bool Kernel::File::Write(std::vector<uint8_t>& FileData, std::string Filepath)
{
    try
    {
        std::ofstream OutFile(Filepath, std::ios::binary);

        if (!OutFile.is_open())
        {
            return false;
        }

        OutFile.write(reinterpret_cast<const char*>(FileData.data()), FileData.size());

        if (OutFile.fail())
        {
            OutFile.close();
            return false;
        }

        OutFile.close();
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

uint64_t Kernel::File::GetExport(uint64_t BaseAddress, uint64_t ExportHash)
{
    // Get DOS header
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    // Get NT headers
    PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(BaseAddress + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    // Get export directory
    IMAGE_DATA_DIRECTORY ExportDirectory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ExportDirectory.VirtualAddress || !ExportDirectory.Size)
        return 0;

    // Get export directory details
    PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(BaseAddress + ExportDirectory.VirtualAddress);
    uint32_t* AddressOfFunctions = (uint32_t*)(BaseAddress + ExportTable->AddressOfFunctions);
    uint32_t* AddressOfNames = (uint32_t*)(BaseAddress + ExportTable->AddressOfNames);
    uint16_t* AddressOfNameOrdinals = (uint16_t*)(BaseAddress + ExportTable->AddressOfNameOrdinals);

    // Walk through exported functions
    for (uint32_t i = 0; i < ExportTable->NumberOfNames; i++)
    {
        // Get function name
        const char* FunctionName = (const char*)(BaseAddress + AddressOfNames[i]);

        // Check if hash matches
        if (HashString(FunctionName) == ExportHash)
        {
            uint16_t Ordinal = AddressOfNameOrdinals[i];
            uint32_t FunctionRVA = AddressOfFunctions[Ordinal];

            // Check if this is a forwarded export
            if (FunctionRVA >= ExportDirectory.VirtualAddress &&
                FunctionRVA < (ExportDirectory.VirtualAddress + ExportDirectory.Size))
            {
                // Handle forwarded exports if needed
                return 0;
            }

            return BaseAddress + FunctionRVA;
        }
    }

    return 0;
}

Kernel::FileInfo Kernel::File::ManualMap(std::vector<uint8_t>& FileData)
{
    uint8_t* BaseAddress = FileData.data();

    if (BaseAddress == nullptr) {
        return Kernel::FileInfo();
    }

    IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(BaseAddress);
    IMAGE_NT_HEADERS* NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(BaseAddress + DosHeader->e_lfanew);

    Kernel::FileInfo File;
    File.Length = NtHeaders->OptionalHeader.SizeOfImage;
    File.BaseAddress = (uint64_t)VirtualAlloc(nullptr, File.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    memcpy((void*)File.BaseAddress, BaseAddress, NtHeaders->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    for (std::size_t Index = 0; Index < NtHeaders->FileHeader.NumberOfSections; Index++, ++SectionHeader)
    {
        memcpy(
            (void*)(File.BaseAddress + SectionHeader->VirtualAddress),
            BaseAddress + SectionHeader->PointerToRawData,
            SectionHeader->SizeOfRawData
        );
    }

    FileData.clear();
    return File;
}

std::vector<uint8_t> Kernel::File::Load(uint64_t Filehash)
{
    // Opening a handle to our file
    std::ifstream File(Find(Filehash), std::ios::binary | std::ios::ate);

    if (!File.is_open()) {
        return { };
    }

    // Get the size of the file
    std::streamsize FileLength = File.tellg();

    // Create a vector with the appropriate size
    std::vector<uint8_t> FileData = std::vector<uint8_t>();

    FileData.resize(FileLength);

    // Go back to the beginning of the file
    File.seekg(0, std::ios::beg);

    // Read the file into the vector
    File.read((char*)FileData.data(), FileLength);

    // Close the handle to the file
    File.close();

    return FileData;
}

bool Kernel::File::ReleaseFile(Kernel::FileInfo& File)
{
    return VirtualFree((void*)File.BaseAddress, NULL, MEM_RELEASE);
}

std::string Kernel::File::Find(uint64_t Filehash)
{
    // Getting the system directory
    char SystemDirectory[MAX_PATH];
    GetSystemDirectoryA(SystemDirectory, MAX_PATH);

    // Defining the directories to scan for the file
    std::vector<std::string> DirectoryList = {
        SystemDirectory + std::string("\\drivers\\"),
        SystemDirectory + std::string("\\"),
    };

    // Defining our file directory
    std::string FileDirectory = "";

    // Scanning for the file in the directories provided.
    for (int i = 0; i < DirectoryList.size() && FileDirectory.empty(); i++)
    {
        for (const auto& Directory : std::filesystem::directory_iterator(DirectoryList[i]))
        {
            std::string Name = Directory.path().filename().string();

            for (std::size_t i = 0; i < Name.size(); i++) {
                Name[i] = tolower(Name[i]);
            }

            if (!Directory.is_regular_file() || HashString(Name.c_str()) != Filehash) {
                continue;
            }

            FileDirectory = Directory.path().string();
            break;
        }
    }

    return FileDirectory;
}
