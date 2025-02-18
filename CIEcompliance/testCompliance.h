#ifndef TEST_COMPLIANCE_H
#define TEST_COMPLIANCE_H

#include <iostream>
#include <string>

// directive for PKCS#11
#include "cryptoki.h"
#include <map>

#include "UUCByteArray.h"

#include "functions.h"
#include "error_map.h"
#include "commons.h"
#include "signCompliance.h"
#include "digestCompliance.h"
#include "verifyCompliance.h"
#include "miscellaneousCompliance.h"


typedef CK_RV(*C_GETFUNCTIONLIST)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

void error(CK_RV rv);

class Tester {
public:
	Tester(CK_FUNCTION_LIST_PTR_PTR pFunctionList, PKCS11* pkcs11);

	bool digestCompliance(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID);

	bool signCompliance(CK_SESSION_HANDLE hSession);

	bool verifyCompliance(CK_SESSION_HANDLE hSession);

	bool setPinCompliance(CK_SESSION_HANDLE hSession);

	bool getAttributeValueCompliance(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

	bool unsupportedFunctionsCompliance(CK_SESSION_HANDLE hSession);

	bool initPinCompliance(CK_SESSION_HANDLE hSession);

private:
	CK_FUNCTION_LIST_PTR g_pFuncList;
	//std::map<CK_MECHANISM_TYPE, std::string> mechanismMap;
	PKCS11* cryptoki;
};

#endif
