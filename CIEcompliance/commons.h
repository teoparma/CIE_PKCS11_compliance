#ifndef COMMONS_H
#define COMMONS_H

#include "cryptoki.h"
#include "error_map.h"
#include <iostream>

typedef CK_RV(*C_GETFUNCTIONLIST)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

void error(CK_RV rv);

#endif