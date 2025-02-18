#ifndef MISCELLANEOUS_H
#define MISCELLANOUSE_H

#include "cryptoki.h"
#include "UUCByteArray.h"
#include "functions.h"
#include "commons.h"
#include <string>
#include <iostream>

bool setPinTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki);

bool getAttributeValueTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki, CK_OBJECT_HANDLE hObject);

bool unsupportedFunctionsTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki);

bool initPinTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki);

#endif