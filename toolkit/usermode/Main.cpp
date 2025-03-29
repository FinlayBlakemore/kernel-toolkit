#include "Communication/Communication.hpp"

#include <Windows.h>

int main()
{

	uint64_t DataArray[] = { 0xfffff8020e84a180, 0xfffff8020e942e78, 0xfffff8020e924d20, 0xfffff8020e925b60, 0xfffff8020e944120, 0xfffff8020ea14900, 0xffffaa8537e46080, 0x163dc9000, 0x1ae000, 0xffffaa8525c93140, 0xffffe98000000000, 0xbd69ea0, 0x3f234e, 0x448, 0x5a8, 0x498, 0x550, 0x74, 0x0, 0x0 };

	uint64_t HashArray[] = { 0x122e020af86abf85, 0xce5b28ec5500553f, 0xe8ae68abbb00cb9c, 0xfa6f221c685da152, 0x48129a9b6c7820a5, 0x927f07835cdb2d0, 0x68318820fdc71094, 0x177bcecb5195be5e, 0x960fe89229e49138, 0x51dabfe5d651ffce, 0xbd9ad97bb0ecf8f4, 0xc55f9e72a09358, 0xd5b122eb32617dc0, 0x4eee8f5c5fe49505, 0x87380a03c04181ff, 0x6b75fbcebd6301d, 0xd3d60f90277bc48c, 0x56cbbbfb30212a5, 0x0, 0x0 };

	if (Driver->Startup(DRIVER_HASH_STRING("RustClient.exe"), DataArray, HashArray, 18) == false) {
		return 1;
	}

	return 0;
}