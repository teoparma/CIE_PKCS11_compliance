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

bool Tester::setPinCompliance(CK_SESSION_HANDLE hSession) {
	return setPinTest(hSession, g_pFuncList, cryptoki);
}

bool Tester::getAttributeValueCompliance(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
	return getAttributeValueTest(hSession, g_pFuncList, cryptoki, hObject);
}

bool Tester::unsupportedFunctionsCompliance(CK_SESSION_HANDLE hSession) {
	return unsupportedFunctionsTest(hSession, g_pFuncList, cryptoki);
}

bool Tester::initPinCompliance(CK_SESSION_HANDLE hSession) {
	return initPinTest(hSession, g_pFuncList, cryptoki);
}

bool Tester::loginCompliance(CK_SESSION_HANDLE hSession) {
	return loginTest(hSession, g_pFuncList, cryptoki);
}