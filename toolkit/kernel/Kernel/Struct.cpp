#include "Struct.hpp"

Kernel::Struct::Struct()
{
	this->PropertyMap = std::map<uint64_t, uint64_t>();
}

void Kernel::Struct::AddProperty(uint64_t Hash, uint64_t Offset)
{
	// Attempting to find the property in the property map
	auto PropertyEntry = this->PropertyMap.find(Hash);

	if (PropertyEntry != this->PropertyMap.end()) {
		return;
	}

	// Adding the property to the property map
	this->PropertyMap.insert(std::pair<uint64_t, uint64_t>(Hash, Offset));
}

uint64_t Kernel::Struct::GetProperty(uint64_t Hash)
{
	// Attempting to find the property in the property map
	auto PropertyEntry = this->PropertyMap.find(Hash);

	if (PropertyEntry == this->PropertyMap.end()) {
		return NULL;
	}

	return PropertyEntry->second;
}
