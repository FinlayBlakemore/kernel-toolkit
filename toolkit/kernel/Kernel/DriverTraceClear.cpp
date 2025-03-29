#include "DriverTraceClear.hpp"

#include "StringHash.hpp"
#include "ObjectFetcher.hpp"
#include "DebugLogger.hpp"

typedef struct _HashBucketEntry
{
	struct _HashBucketEntry* Next;
	UNICODE_STRING DriverName;
	ULONG CertHash[5];
} HashBucketEntry, * PHashBucketEntry;

typedef struct _PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
} PiDDBCacheEntry, * NPiDDBCacheEntry;

bool Kernel::DriverTraceClear::MmUnloadedDrivers()
{
	// Reading the real device object pointer
	uint64_t DeviceObject = NULL;
	if (Kernel::Memory::ReadVirtual(
		m_DriverObject + 0x8, 
		&DeviceObject,
		sizeof(uint64_t)) == false) {
		DebugErrorLog();
		return false;
	}

	if (DeviceObject == NULL)
	{
		DebugErrorLog();
		return false;
	}

	if (Kernel::Memory::ReadVirtual(
		DeviceObject + 0x8,
		&DeviceObject,
		sizeof(uint64_t)) == false) {
		DebugErrorLog();
		return false;
	}

	if (DeviceObject == NULL) 
	{
		DebugErrorLog();
		return false;
	}

	// Reading the device section pointer
	uint64_t DeviceSection = NULL;
	if (Kernel::Memory::ReadVirtual(
		DeviceObject + 0x28, 
		&DeviceSection, 
		sizeof(uint64_t)) == false) {
		DebugErrorLog();
		return false;
	}

	if (DeviceSection == NULL) 
	{
		DebugErrorLog();
		return false;
	}

	// Reading DeviceName UNICODE_STRING structure
	UNICODE_STRING DeviceName;
	if (Kernel::Memory::ReadVirtual(
		DeviceSection + 0x58,
		&DeviceName,
		sizeof(UNICODE_STRING)) == false) {
		DebugErrorLog();
		return false;
	}

	if (DeviceName.Length == NULL)
	{
		DebugErrorLog();
		return false;
	}

	m_DeviceName = std::wstring(DeviceName.Length / 2 + 1, L'\0');

	if (m_DeviceName.data() == nullptr)
	{
		DebugErrorLog();
		return false;
	}

	// Reading the device name buffer and length into our local buffer
	if (Kernel::Memory::ReadVirtual(
		(uint64_t)DeviceName.Buffer,
		m_DeviceName.data(),
		DeviceName.Length) == false)
	{
		DebugErrorLog();
		return false;
	}

	DebugLog("m_DeviceName -> %ws!\n", m_DeviceName.c_str());

	// Nulling DeviceName Length and Buffer
	DeviceName.Length = NULL;
	DeviceName.Buffer = nullptr;

	if (Kernel::Memory::WriteVirtual(
		DeviceSection + 0x58,
		&DeviceName,
		sizeof(UNICODE_STRING)) == false) {
		return false;
	}

	DebugLog("Cleared MmUnloadedDrivers\n");
	return true;
}

bool Kernel::DriverTraceClear::KernelHashBucketList()
{
	uint64_t g_KernelHashBucketList = Kernel::ObjectFetcher::FetchModuleData(HashString_("ci.dll"), HashString_("g_KernelHashBucketList"));

	if (g_KernelHashBucketList == NULL) 
	{
		DebugErrorLog();
		return false;
	}

	uint64_t g_HashCacheLock = Kernel::ObjectFetcher::FetchModuleData(HashString_("ci.dll"), HashString_("g_HashCacheLock"));

	if (g_HashCacheLock == NULL)
	{
		DebugErrorLog();
		return false;
	}

	// Attempting to acquire the KernelHashBucketList
	if (m_Function->Call<bool>(HashString_("ExAcquireResourceExclusiveLite"), g_HashCacheLock, true) == false)
	{
		DebugErrorLog();
		return false;
	}

	uint64_t BucketListPrev = g_KernelHashBucketList;
	uint64_t BucketListCurr = NULL;

	do
	{
		// Reading the current entry
		if (Kernel::Memory::ReadVirtual(
			BucketListPrev,
			&BucketListCurr,
			sizeof(uint64_t)) == false) {
			break;
		}

		if (BucketListCurr == NULL) {
			break;
		}

		// Setting the previous entry as the current
		uint64_t PreviousEntry = BucketListPrev;
		BucketListPrev = BucketListCurr;

		// Reading the current entries DriverName length
		USHORT DriverNameLength = NULL;
		if (Kernel::Memory::ReadVirtual(
			BucketListCurr + offsetof(HashBucketEntry, DriverName.Length),
			&DriverNameLength,
			sizeof(USHORT)) == false) {
			DebugErrorLog();
			continue;
		}

		if (DriverNameLength == NULL) 
		{
			DebugErrorLog();
			continue;
		}

		// Reading the current entries DriverName buffer
		wchar_t* DriverNameBuffer = nullptr;
		if (Kernel::Memory::ReadVirtual(
			BucketListCurr + offsetof(HashBucketEntry, DriverName.Buffer),
			&DriverNameBuffer,
			sizeof(wchar_t*)) == false) {
			DebugErrorLog();
			continue;
		}

		if (DriverNameBuffer == nullptr)
		{
			DebugErrorLog();
			continue;
		}

		std::unique_ptr<wchar_t[]> _DriverPathW = std::make_unique<wchar_t[]>(DriverNameLength / 2ULL + 1ULL);
		if (Kernel::Memory::ReadVirtual(
			reinterpret_cast<uint64_t>(DriverNameBuffer),
			_DriverPathW.get(),
			DriverNameLength) == false) {
			DebugErrorLog();
			continue;
		}

		DebugLog("BucketListCurr -> %ws!\n", _DriverPathW.get());

		// Converting the strings
		std::wstring DriverPathW = std::wstring(_DriverPathW.get(), DriverNameLength);

		if (DriverPathW.find(m_DeviceName) != std::string::npos)
		{
			DebugLog("BucketListTarget -> %ws!\n", _DriverPathW.get());

			// Restoring previous entry
			BucketListPrev = PreviousEntry;
			break;
		}

	} while (BucketListCurr);

	// Reading the next entry from our current entry
	uint64_t BucketListNext = NULL;
	Kernel::Memory::ReadVirtual(
		BucketListCurr,
		&BucketListNext,
		sizeof(uint64_t)
	);
	
	// Writing the previous entries next link to the one after our entry
	Kernel::Memory::WriteVirtual(
		BucketListPrev,
		&BucketListNext,
		sizeof(uint64_t)
	);
	
	if (BucketListCurr != NULL) 
	{
		// Freeing our current entry out of memory
		m_Function->Call<bool>(HashString_("ExFreePool"), BucketListCurr);
	}

	// Releasing the HashCacheLock resource
	m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), g_HashCacheLock);

	DebugLog("Cleared KernelHashBucketList!\n");

	return true;
}

bool Kernel::DriverTraceClear::PiDDBCacheTable()
{
	// Getting the RTL_AVL_TABLE
	Struct& RTL_AVL_TABLE = Kernel::ObjectFetcher::FetchModuleStruct(HashString_("ntoskrnl.exe"), HashString_("_RTL_AVL_TABLE"));

	// Getting the PiDDBCacheTable
	uint64_t PiDDBCacheTable = Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("PiDDBCacheTable"));

	if (PiDDBCacheTable == NULL)
	{
		DebugErrorLog();
		return false;
	}

	// Getting the PiDDBCacheTable Lock
	uint64_t PiDDBLock = Kernel::ObjectFetcher::FetchModuleData(HashString_("ntoskrnl.exe"), HashString_("PiDDBLock"));

	if (PiDDBLock == NULL)
	{
		DebugErrorLog();
		return false;
	}

	// Constructing the DriverCacheEntry 
	PiDDBCacheEntry DriverCacheEntry = { };
	DriverCacheEntry.DriverName.Buffer = (PWSTR)m_DeviceName.c_str();
	DriverCacheEntry.DriverName.Length = (USHORT)(wcslen(m_DeviceName.c_str()) * 2);
	DriverCacheEntry.DriverName.MaximumLength = DriverCacheEntry.DriverName.Length + 2;
	DriverCacheEntry.TimeDateStamp = 0x5B4EE51D;

	// Locking the PiDDBCacheTable
	if (m_Function->Call<bool>(HashString_("ExAcquireResourceExclusiveLite"), PiDDBLock, true) == false)
	{
		DebugErrorLog();
		return false;
	}

	// Getting our driver entry inside of the PiDDBCacheTable
	uint64_t PiDDBCacheTableCurr = m_Function->Call<uint64_t>(HashString_("RtlLookupElementGenericTableAvl"), PiDDBCacheTable, &DriverCacheEntry);

	DebugLog("PiDDBCacheTableCurr -> 0x%llx\n", PiDDBCacheTableCurr);

	if (PiDDBCacheTableCurr == NULL)
	{
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		return true;
	}

	// Getting the previous entry in the PiDDBCacheTable
	uint64_t PiDDBCacheTablePrev = NULL;
	if (Kernel::Memory::ReadVirtual(
		PiDDBCacheTableCurr + offsetof(struct _PiDDBCacheEntry, List.Blink),
		&PiDDBCacheTablePrev,
		sizeof(uint64_t)) == false) 
	{
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}

	DebugLog("PiDDBCacheTablePrev -> 0x%llx\n", PiDDBCacheTablePrev);

	if (PiDDBCacheTablePrev == NULL)
	{
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}

	// Getting the next entry in the PiDDBCacheTable
	uint64_t PiDDBCacheTableNext = NULL;
	if (Kernel::Memory::ReadVirtual(
		PiDDBCacheTableCurr + offsetof(struct _PiDDBCacheEntry, List.Flink),
		&PiDDBCacheTableNext,
		sizeof(uint64_t)) == false)
	{
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}

	DebugLog("PiDDBCacheTableNext -> 0x%llx\n", PiDDBCacheTableNext);

	if (PiDDBCacheTableNext == NULL)
	{
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}

	if (Kernel::Memory::WriteVirtual(
		PiDDBCacheTablePrev + offsetof(struct _PiDDBCacheEntry, List.Flink),
		&PiDDBCacheTableNext,
		sizeof(uint64_t)) == false) {
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}
	
	if (Kernel::Memory::WriteVirtual(
		PiDDBCacheTableNext + offsetof(struct _PiDDBCacheEntry, List.Blink),
		&PiDDBCacheTablePrev,
		sizeof(uint64_t)) == false) {
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}
	 
	if (m_Function->Call<bool>(HashString_("RtlDeleteElementGenericTableAvl"), PiDDBCacheTable, PiDDBCacheTableCurr) == false)
	{
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}
	
	ULONG DeleteCount = NULL;
	if (Kernel::Memory::ReadVirtual(
		PiDDBCacheTable + RTL_AVL_TABLE.GetProperty(HashString_("DeleteCount")),
		&DeleteCount,
		sizeof(ULONG)) == false)
	{
		m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
		DebugErrorLog();
		return false;
	}
	
	if (DeleteCount > 0)
	{
		DeleteCount--;
		if (Kernel::Memory::WriteVirtual(
			PiDDBCacheTable + RTL_AVL_TABLE.GetProperty(HashString_("DeleteCount")),
			&DeleteCount,
			sizeof(ULONG)) == false)
		{
			m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);
			DebugErrorLog();
			return false;
		}
	}

	m_Function->Call<bool>(HashString_("ExReleaseResourceLite"), PiDDBLock);

	DebugLog("Cleared PiDDBCacheTable!\n");
	return true;
}

bool Kernel::DriverTraceClear::WdFilter()
{
	//Kernel::ObjectFetcher::ModuleInformation WdFilter = Kernel::ObjectFetcher::FetchModule(HashString_("wdfilter.sys"));
	//
	//if (WdFilter.BaseAddress == NULL) {
	//	return true;
	//}
	//
	//uint64_t RuntimeDriversCountRef = Kernel::ObjectFetcher::FetchModulePattern(
	//	HashString_("wdfilter.sys"),
	//	(BYTE*)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", 
	//	"xx????xxx"
	//);
	//
	//if (RuntimeDriversCountRef == NULL) 
	//{
	//	DebugErrorLog();
	//	return false;
	//}
	//
	//uint64_t RuntimeDriversCount = Kernel::Memory::ResolveRelativeAddress(RuntimeDriversCountRef, 2, 6);
	//
	//if (RuntimeDriversCount == NULL) 
	//{
	//	DebugErrorLog();
	//	return false;
	//}
	//
	//DebugLog("RuntimeDriversCount -> 0x%llx\n", RuntimeDriversCount);
	//
	//uint64_t RuntimeDriversList = Kernel::ObjectFetcher::FetchModulePattern(
	//	HashString_("wdfilter.sys"),
	//	(BYTE*)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05",
	//	"xxx????xx"
	//);
	//
	//if (RuntimeDriversList == NULL)
	//{
	//	DebugErrorLog();
	//	return false;
	//}
	//
	//RuntimeDriversList = Kernel::Memory::ResolveRelativeAddress(RuntimeDriversList, 3, 7);
	//
	//if (RuntimeDriversList == NULL) 
	//{
	//	DebugErrorLog();
	//	return false;
	//}
	//
	//DebugLog("RuntimeDriversList -> 0x%llx\n", RuntimeDriversList - WdFilter.BaseAddress);
	//uint64_t RuntimeDriversListHead = RuntimeDriversList - 0x8;
	//
	//uint64_t RuntimeDriversEntry = NULL;
	//if (Kernel::Memory::ReadVirtual(RuntimeDriversListHead + offsetof(struct _LIST_ENTRY, Flink), &RuntimeDriversEntry, sizeof(uint64_t)) == false)
	//{
	//	DebugErrorLog();
	//	return false;
	//}
	//
	//for (RuntimeDriversEntry; RuntimeDriversEntry != RuntimeDriversListHead; Kernel::Memory::ReadVirtual(RuntimeDriversEntry + offsetof(struct _LIST_ENTRY, Flink), &RuntimeDriversEntry, sizeof(uint64_t)))
	//{
	//	UNICODE_STRING UnicodeString;
	//	if (Kernel::Memory::ReadVirtual(RuntimeDriversEntry + 0x10, &UnicodeString, sizeof(UNICODE_STRING)) == false) {
	//		continue;
	//	}
	//
	//	std::wstring DriverName = std::wstring(UnicodeString.Length / 2 + 1, L'\0');
	//	if (Kernel::Memory::ReadVirtual((uint64_t)UnicodeString.Buffer, DriverName.data(), UnicodeString.Length) == false) {
	//		continue;
	//	}
	//
	//	printf("%ws\n", DriverName.c_str());
	//}

	return true;
}

Kernel::DriverTraceClear::DriverTraceClear(uint64_t DriverObject, std::wstring DeviceName, std::string& DriverPath, std::shared_ptr<Kernel::FunctionCaller>& Function) : m_Function(Function), m_DriverPath(DriverPath)
{
	m_DriverObject = DriverObject;
	m_DeviceName = DeviceName;
}

bool Kernel::DriverTraceClear::Verify()
{
	// Clear Traces have been cleared
	//https://github.com/Deputation/hygieia/blob/master/hygieia/main.cc#L238
	return true;
}

bool Kernel::DriverTraceClear::Clear()
{
	if (this->PiDDBCacheTable() == false)
	{
		DebugErrorLog();
		return false;
	}

	if (this->KernelHashBucketList() == false)
	{
		DebugErrorLog();
		return false;
	}

	if (this->MmUnloadedDrivers() == false)
	{
		DebugErrorLog();
		return false;
	}
	
	//if (this->WdFilter() == false)
	//{
	//	DebugErrorLog();
	//	return false;
	//}

	return true;
}
