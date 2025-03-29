#pragma once

#include <string>

namespace Kernel
{
	class DriverLoader {
	private:
		bool SetPrivilege(const char* PrivilegeName, bool Toggle);
		bool CreateRegistryService();
		bool DeleteRegistryService();

		bool CreateDisk(char* DriverBuffer, size_t DriverLength);
		bool DeleteDisk();

		std::string m_RegistryPath;
		std::string m_ServicePath;
		std::string m_DriverName;
		std::string m_DriverPath;
		size_t m_FileLength;
	public:
		DriverLoader(const char* DriverName);
		~DriverLoader() = default;

		std::wstring GetDriverName();
		std::string& GetDriverPath();

		bool Load(char* DriverBuffer, size_t DriverLength);
		bool Unload();
	};
}