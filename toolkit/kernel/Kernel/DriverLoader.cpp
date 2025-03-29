#include "DriverLoader.hpp"

#include "DebugLogger.hpp"
#include "Memory.hpp"

#include <Windows.h>
#include <winternl.h>
#include <random>
#include <fstream>
#include <ntstatus.h>

typedef NTSTATUS(*NtLoadDriver_t)(UNICODE_STRING* DriverServiceName);
typedef NTSTATUS(*NtUnloadDriver_t)(UNICODE_STRING* DriverServiceName);

bool Kernel::DriverLoader::SetPrivilege(const char* PrivilegeName, bool Toggle)
{
    // Open the process token
    HANDLE TokenHandle;
    if (!OpenProcessToken((HANDLE)(-1), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) {
        DebugErrorLog();
        return false;
    }

    // Get the LUID for the debug privilege
    TOKEN_PRIVILEGES TokenPrivileges;
    if (!LookupPrivilegeValueA(NULL, ("SeLoadDriverPrivilege"), &TokenPrivileges.Privileges[0].Luid))
    {
        CloseHandle(TokenHandle);
        DebugErrorLog();
        return false;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = Toggle ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

    // Enable the debug privilege
    if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        CloseHandle(TokenHandle);
        DebugErrorLog();
        return false;
    }

    CloseHandle(TokenHandle);
    return true;
}

bool Kernel::DriverLoader::CreateRegistryService()
{
    // Creating our registry key
    HKEY ServiceKey;
    LSTATUS Status = RegCreateKeyA(HKEY_LOCAL_MACHINE, m_ServicePath.c_str(), &ServiceKey); //Returns Ok if already exists

    if (Status != ERROR_SUCCESS)
    {
        RegDeleteTreeA(HKEY_LOCAL_MACHINE, m_ServicePath.c_str());
        Status = RegCreateKeyA(HKEY_LOCAL_MACHINE, m_ServicePath.c_str(), &ServiceKey); //Returns Ok if already exists

        if (Status != ERROR_SUCCESS)
        {
            DebugErrorLog();
            return false;
        }
    }

    // Setting up our RegistryDriverPath and setting that in registry
    std::string RegistryDriverPath = "\\??\\" + m_DriverPath;
    Status = RegSetKeyValueA(ServiceKey, nullptr, ("ImagePath"), REG_EXPAND_SZ, RegistryDriverPath.c_str(), (DWORD)RegistryDriverPath.size() * sizeof(char));

    if (Status != ERROR_SUCCESS)
    {
        DebugErrorLog();
        return false;
    }

    // Defining our ServiceType and setting that in registry
    const DWORD ServiceType = SERVICE_KERNEL_DRIVER;
    Status = RegSetKeyValueA(ServiceKey, nullptr, "Type", REG_DWORD, &ServiceType, sizeof(DWORD));

    if (Status != ERROR_SUCCESS) 
    {
        DebugErrorLog();
        return false;
    }

    RegCloseKey(ServiceKey);
    return true;
}

bool Kernel::DriverLoader::DeleteRegistryService()
{
    HKEY ServiceKey;
    LSTATUS Status = RegOpenKeyA(HKEY_LOCAL_MACHINE, m_ServicePath.c_str(), &ServiceKey);

    if (Status != ERROR_SUCCESS)
    {
        if (Status == ERROR_FILE_NOT_FOUND) {
            return true;
        }

        DebugErrorLog();
        return false;
    }

    RegCloseKey(ServiceKey);

    Status = RegDeleteTreeA(HKEY_LOCAL_MACHINE, m_ServicePath.c_str());

    if (Status != ERROR_SUCCESS)
    {
        DebugErrorLog();
        return false;
    }

    return true;
}

bool Kernel::DriverLoader::CreateDisk(char* DriverBuffer, size_t DriverLength)
{
    // Opening a file handle to our DriverPath
    std::ofstream DriverFile = std::ofstream(m_DriverPath, std::ios::binary);

    if (DriverFile.is_open() == false)
    {
        DriverFile.close();
        return true;
    }

    // Writing the driver buffer to disk
    DriverFile.write(DriverBuffer, DriverLength);

    // Closing our file handle to our DriverPath
    DriverFile.close();

    m_FileLength = DriverLength;

    return true;
}

bool Kernel::DriverLoader::DeleteDisk()
{
    // Opening a file handle to our DriverPath
    std::ofstream DriverFile = std::ofstream(m_DriverPath, std::ios::binary);

    if (DriverFile.is_open() == false) 
    {
        DebugErrorLog();
        return false;
    }

    // Create random number generator
    std::random_device RandomDevice;
    std::mt19937 Generator(RandomDevice());
    std::uniform_int_distribution<> Distribution(0, 255);

    // Generate random data for our file
    std::vector<char> RandomData;
    RandomData.reserve(1000);
    for (size_t i = 0; i < RandomData.size(); ++i) {
        RandomData.push_back(static_cast<char>(Distribution(Generator)));
    }

    // Writing our random bytes to the file on disk
    DriverFile.write(RandomData.data(), RandomData.size());

    // Closing our file handle to our DriverPath
    DriverFile.close();

    // Deleting the file from disk
    remove(m_DriverPath.c_str());

    return true;
}

Kernel::DriverLoader::DriverLoader(const char* DriverName)
{
    // Setting up the DriverName
    m_DriverName = std::string(DriverName);

    // Setting up the DriverPath
    char SystemDirectory[MAX_PATH];
    GetSystemDirectoryA(SystemDirectory, MAX_PATH);
    m_DriverPath = std::string(SystemDirectory) + "\\drivers\\" + m_DriverName;

    // Setting up the ServicePath
    m_RegistryPath = m_DriverName;
    m_RegistryPath.resize(m_RegistryPath.size() - 4);
    m_ServicePath = "SYSTEM\\CurrentControlSet\\Services\\" + m_RegistryPath;
    m_RegistryPath = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + m_RegistryPath;
}

std::wstring Kernel::DriverLoader::GetDriverName()
{
    return std::wstring(m_DriverName.begin(), m_DriverName.end());
}

std::string& Kernel::DriverLoader::GetDriverPath()
{
    return m_DriverPath;
}

bool Kernel::DriverLoader::Load(char* DriverBuffer, size_t DriverLength)
{
    // Enabling Driver Loading for our process
    if (SetPrivilege("SeLoadDriverPrivilege", true) == false) 
    {
        DebugErrorLog();
        return false;
    }

    // Writing the vunerable driver to disk and getting timestamp
    if (CreateDisk(DriverBuffer, DriverLength) == false) 
    {
        DebugErrorLog();
        return false;
    }

    // Creating a registry service of the vunerable driver
    if (CreateRegistryService() == false) 
    {
        DebugErrorLog();
        return false;
    }

    // Getting the function address of NtLoadDriver from ntdll.dll
    NtLoadDriver_t NtLoadDriver = (NtLoadDriver_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");

    if (NtLoadDriver == nullptr)
    {
        DebugErrorLog();
        return false;
    }

    // Converting the std::string to a std::wstring
    std::wstring ServicePathW = std::wstring(
        m_RegistryPath.begin(),
        m_RegistryPath.end()
    );

    // Loading our driver into memory
    UNICODE_STRING ServiceString;
    RtlInitUnicodeString(&ServiceString, ServicePathW.c_str());

    // Loading the driver into memory
    NTSTATUS Status = NtLoadDriver(&ServiceString);

    DebugLog("%s Loaded\n", m_DriverName.c_str());

    return Status == STATUS_IMAGE_ALREADY_LOADED || Status == STATUS_OBJECT_NAME_COLLISION || Status == STATUS_SUCCESS;
}

bool Kernel::DriverLoader::Unload()
{
    // Getting the function address of NtLoadDriver from ntdll.dll
    NtUnloadDriver_t NtUnloadDriver = (NtUnloadDriver_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnloadDriver");

    if (NtUnloadDriver == nullptr)
    {
        DebugErrorLog();
        return false;
    }

    // Converting the std::string to a std::wstring
    std::wstring ServicePathW = std::wstring(
        m_RegistryPath.begin(),
        m_RegistryPath.end()
    );

    // Loading our driver into memory
    UNICODE_STRING ServiceString;
    RtlInitUnicodeString(&ServiceString, ServicePathW.c_str());

    Kernel::Memory::DestoryHandle();

    // Unloading our driver from memory
    NTSTATUS Status = NtUnloadDriver(&ServiceString);
    if (Status != STATUS_SUCCESS)
    {
        DebugLog("NtUnloadDriver -> 0x%llx\n", Status);
        return false;
    }

    // Deleting the registry service of the vunerable driver
    if (DeleteRegistryService() == false) 
    {
        DebugErrorLog();
        return false;
    }

    // Deleting the vunerable driver from disk
    if (DeleteDisk() == false)
    {
        DebugErrorLog();
        return false;
    }

    return true;
}
