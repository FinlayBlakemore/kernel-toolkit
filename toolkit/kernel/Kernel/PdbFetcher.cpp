#include "PdbFetcher.hpp"

#pragma comment(lib, "URLMon.lib")

#include <filesystem>
#include <Windows.h>
#include <fstream>
#include <sstream>

#include "DebugLogger.hpp"
#include "File.hpp"

inline std::map<uint64_t, std::shared_ptr<Kernel::Pdb>> Kernel::PdbFetcher::s_PdbCache;

typedef struct _CV_INFO_PDB70 {
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    BYTE PdbFileName[1];
} CV_INFO_PDB70, * PCV_INFO_PDB70;

bool Kernel::PdbFetcher::GetDebugInformation(uint64_t BaseAddress, DebugInformation& DebugInfo)
{
    IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(BaseAddress);
    IMAGE_NT_HEADERS* NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(BaseAddress + DosHeader->e_lfanew);

    uint32_t DebugDirectoryOffset = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;

    if (DebugDirectoryOffset == NULL)
    {
        DebugErrorLog();
        return false;
    }

    IMAGE_DEBUG_DIRECTORY* DebugDirectory = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(BaseAddress + DebugDirectoryOffset);

    if (DebugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
    {
        DebugErrorLog();
        return false;
    }

    PCV_INFO_PDB70 PdbInfo = reinterpret_cast<PCV_INFO_PDB70>(BaseAddress + DebugDirectory->AddressOfRawData);

    if (PdbInfo->CvSignature != 0x53445352) // 'RSDS'
    {
        DebugErrorLog();
        return false;
    }

    // Formatting the guid with the age
    sprintf_s(DebugInfo.Guid, sizeof(DebugInfo.Guid),
        ("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x"),
        PdbInfo->Signature.Data1,
        PdbInfo->Signature.Data2,
        PdbInfo->Signature.Data3,
        PdbInfo->Signature.Data4[0],
        PdbInfo->Signature.Data4[1],
        PdbInfo->Signature.Data4[2],
        PdbInfo->Signature.Data4[3],
        PdbInfo->Signature.Data4[4],
        PdbInfo->Signature.Data4[5],
        PdbInfo->Signature.Data4[6],
        PdbInfo->Signature.Data4[7],
        PdbInfo->Age
    );

    // Getting the name
    DebugInfo.Name = std::string((char*)PdbInfo->PdbFileName);
    DebugInfo.Name.resize(DebugInfo.Name.size() - 4);

    DebugLog("DebugInformation (%s.pdb, %s)\n", DebugInfo.Name, DebugInfo.Guid);

    return true;
}

bool Kernel::PdbFetcher::DownloadToFile(DebugInformation& DebugInfo, std::string* Path)
{
    // Getting the system temp path
    char TempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, TempPath);

    // Getting the download path ready
    *Path = TempPath + DebugInfo.Name + ".pdb";

    // Creating the stream ready to add our url to
    std::stringstream URL;

    // Pushing the base of the url (symbol server and image name .pbd)
    URL << "http://msdl.microsoft.com/download/symbols/" << DebugInfo.Name << ".pdb/";

    URL << DebugInfo.Guid;
    URL << "/" << DebugInfo.Name << ".pdb";

    bool Result = !URLDownloadToFileA(NULL, URL.str().c_str(), Path->c_str(), 0, 0);

    // Cleaning up strings
    DebugInfo.Name.clear();

    // Cleaning up debug information
    memset(&DebugInfo, NULL, sizeof(DebugInformation));

    return Result;
}

std::shared_ptr<Kernel::Pdb> Kernel::PdbFetcher::Fetch(uint64_t Hash)
{
    auto PdbEntry = s_PdbCache.find(Hash);

    if (PdbEntry != s_PdbCache.end()) {
        return PdbEntry->second;
    }

    // Loading the library into memory
    std::vector<uint8_t> FileData = Kernel::File::Load(Hash);

    if (FileData.empty()) 
    {
        DebugErrorLog();
        return nullptr;
    }

    // Mapping the file into memory
    Kernel::FileInfo File = Kernel::File::ManualMap(FileData);

    if (File.BaseAddress == NULL) 
    {
        DebugErrorLog();
        return nullptr;
    }

    // Getting debug information from the library
    DebugInformation DebugInfo;
    memset(&DebugInfo, NULL, sizeof(DebugInformation));
    bool HasDebugInfo = GetDebugInformation(File.BaseAddress, DebugInfo);

    // Freeing the file from memory
    Kernel::File::ReleaseFile(File);

    if (HasDebugInfo == false) 
    {
        DebugErrorLog();
        return nullptr;
    }

    // Downloading the pdb to disk
    std::string Path = "";
    if (DownloadToFile(DebugInfo, &Path) == false) {
        return nullptr;
    }

    // Creating a symbol instance
    std::shared_ptr<Pdb> Symbol = std::make_shared<Pdb>(Path);

    // Parsing the symbol information
    if (Symbol->Parse() == false) {
        return nullptr;
    }

    // Adding the pdb to the cache
    s_PdbCache.emplace(Hash, Symbol);

    // Returning the parsed symbol
    return Symbol;
}