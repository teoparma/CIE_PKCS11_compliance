#ifndef VERIFY_COMPLIANCE_H
#define VERIFY_COMPLIANCE_H

#include "cryptoki.h"
#include "UUCByteArray.h"
#include "functions.h"
#include "commons.h"
#include <string>
#include <iostream>

#include "softhsm.h"

#define RSA_KEY_MODULUS_LENGTH 256

bool verifyTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR pFunctionList, PKCS11* cryptoki);

#endif
