#include "Kernel/Context.hpp"

int main()
{
	Kernel::Context Context = Kernel::Context("VunerableDriver.sys");

	if (Context.Initilize() == false) {
		return 1;
	}

	//
	//
	//

	if (Context.Shutdown() == false) {
		return 3;
	}

	return 0;
}