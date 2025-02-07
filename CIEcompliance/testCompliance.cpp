#include "testCompliance.h"

Tester::Tester(CK_FUNCTION_LIST_PTR_PTR pFunctionList, PKCS11* pkcs11) {
	this->g_pFuncList = *pFunctionList;
	//this->mechanismMap = mechMap;
	this->cryptoki = pkcs11;
}

bool Tester::digestCompliance(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID) {
	return digestTest(hSession, slotID, g_pFuncList, cryptoki);
}

bool Tester::signCompliance(CK_SESSION_HANDLE hSession) {
	return signTest(hSession, g_pFuncList, cryptoki);
}

bool Tester::verifyCompliance(CK_SESSION_HANDLE hSession) {
	return verifyTest(hSession, g_pFuncList, cryptoki);
}