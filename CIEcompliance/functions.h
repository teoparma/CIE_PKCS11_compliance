#ifndef FUNCTIONS_H
#define FUNCTIONS_H


#include <iostream>
#include <string>

// directive for PKCS#11
#include "cryptoki.h"
#include <map>

#include "UUCByteArray.h"

#include "error_map.h"
#include "commons.h"

class PKCS11 {
public:
	PKCS11(CK_FUNCTION_LIST_PTR_PTR pFunctionList, std::map<CK_MECHANISM_TYPE, std::string> mechMap);
	
	void init(void);

	void close(void);

	bool getSlotInfo(CK_SLOT_ID slotid);

	CK_SLOT_ID_PTR getSlotList(bool bPresent, CK_ULONG* pulCount);

	void getTokenInfo(CK_SLOT_ID slotid);

	void mechanismList(CK_SLOT_ID slotid);

	CK_SESSION_HANDLE openSession(CK_SLOT_ID slotid);

	bool login_modificato(CK_SESSION_HANDLE hSession); //TODO

	bool login(CK_SESSION_HANDLE hSession);

	bool logout(CK_SESSION_HANDLE hSession);

	bool findObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pAttributes, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObjects, CK_ULONG_PTR pulObjCount);

	void closeSession(CK_SESSION_HANDLE hSession);

	void showAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

	void showCertAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

	bool signVerify(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanism);

	bool digest(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanism);
	
private:
	CK_FUNCTION_LIST_PTR g_pFuncList;
	std::map<CK_MECHANISM_TYPE, std::string> mechanismMap;
};

#endif // !FUNCTIONS_H
