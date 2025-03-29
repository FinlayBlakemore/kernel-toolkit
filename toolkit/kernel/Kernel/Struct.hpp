#pragma once

#include <string>
#include <map>

namespace Kernel
{
	class Struct {
	private:
		std::map<uint64_t, uint64_t> PropertyMap;
	public:
		Struct();
		~Struct() = default;

		void AddProperty(uint64_t Name, uint64_t Offset);
		uint64_t GetProperty(uint64_t Name);
	};
}