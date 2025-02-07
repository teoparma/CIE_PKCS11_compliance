#include "commons.h"

void error(CK_RV rv) {
	printf("  -------------------\n");
	//printf("  <e> Errore n. 0x%X\n", rv);
	std::cout << "  Return Val 0x" << rv << " : " << ErrorMap[rv] << std::endl;
	printf("  -------------------\n");
}