#ifndef DIGEST_COMPLIANCE_H
#define DIGEST_COMPLIANCE_H

#include "cryptoki.h"
#include "functions.h"
#include "commons.h"
#include <string>
#include <iostream>
#include <map>

#define MD5_DIGEST_LENGTH 16

bool digestTest(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki);

#endif
