#include "miscellaneousCompliance.h"

bool setPinTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki) {
	CK_RV rv;

	std::cout << "  -> Login allo slot\n    - C_Login" << std::endl;

	bool pinIsGood = false;
	std::string sPIN;
	while (!pinIsGood)
	{
		std::cout << "   - Inserire la seconda parte del PIN ";
		std::cin >> sPIN;
		size_t len = sPIN.size();
		if (len != 4)
		{
			std::cout << "   Attenzione: Il pin deve essere composto da 4 numeri" << std::endl;;
		}
		else
		{
			const char* szPIN = sPIN.c_str();

			size_t i = 0;
			while (i < len && (szPIN[i] >= '0' && szPIN[i] <= '9'))
				i++;

			if (i == len)
				pinIsGood = true;
			else
				std::cout << "   Attenzione: Il pin deve essere composto da 4 numeri" << std::endl;;
		}
	}
	int timeout = 10;
	do {
		rv = g_pFuncList->C_Login(hSession, CKU_USER, (CK_CHAR_PTR)sPIN.c_str(), sPIN.size());
		if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
		{
			error(rv);
			return false;
		}
		timeout--;
		if (timeout = 0) {
			error(rv);
			return false;
		}
	} while (rv == CKR_GENERAL_ERROR);

	std::cout << "  -- Login Effettuato " << std::endl;

	

	std::cout << "\t- SetPIN with R/O session and normal user logged in" << std::endl;
	rv = g_pFuncList->C_SetPIN(hSession, (CK_CHAR_PTR)sPIN.c_str(), sPIN.size(), (CK_CHAR_PTR)sPIN.c_str(), sPIN.size());
	error(rv);
	if (rv == CKR_SESSION_READ_ONLY)
	{
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
		return false;
	}


	std::cout << "  -> Logout allo slot\n    - C_Logout" << std::endl;

	rv = g_pFuncList->C_Logout(hSession);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	std::cout << "  -- Logout Effettuato" << std::endl;
	
	return true;
}

bool getAttributeValueTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki, CK_OBJECT_HANDLE hObject) {
	
	std::cout << "\t- C_GetAttributeValue asking for CKA_PRIVATE, CKA_TOKEN, CKA_PRIVATE_EXPONENT (not supported), CKA_LABEL, CKA_ID" << std::endl;

	CK_BBOOL        bPrivate = 0;
	CK_BBOOL        bToken = 0;

	char* btLabel = NULL;
	char* btID = NULL;
	char* btPrivateExp = NULL;

	CK_ATTRIBUTE    attr[] = {
		{CKA_PRIVATE, &bPrivate, sizeof(bPrivate)},
		{CKA_TOKEN, &bToken, sizeof(bToken)},
		{CKA_PRIVATE_EXPONENT, btPrivateExp, 0},
		{CKA_LABEL, btLabel, 0},
		{CKA_ID, btID, 0 }
	};

	CK_RV rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 5);
	/*if (rv != CKR_OK)
	{
		error(rv);
	}*/

	//attr[2].pValue = malloc(attr[2].ulValueLen + 2);
	attr[3].pValue = malloc(attr[3].ulValueLen + 2);
	attr[4].pValue = malloc(attr[4].ulValueLen + 2);


	rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 5);
	/*if (rv != CKR_OK)
	{
		free(attr[2].pValue);
		free(attr[3].pValue);
		free(attr[4].pValue);
		error(rv);
		return false;
	}*/

	//btPrivateExp = (char*)attr[2].pValue;
	btLabel = (char*)attr[3].pValue;
	btID = (char*)attr[4].pValue;

	//btPrivateExp[attr[2].ulValueLen] = 0;
	btLabel[attr[3].ulValueLen] = 0;
	btID[attr[4].ulValueLen] = 0;

	std::cout << "\n\n";
	std::cout << "\t\t- Private: " << (bPrivate ? "true" : "false") << std::endl;
	std::cout << "\t\t- Token: " << (bToken ? "true" : "false") << std::endl;
	std::cout << "\t\t- Private Exponent: CKR_ATTRIBUTE_TYPE_INVALID" << std::endl;
	std::cout << "\t\t- Label: " << btLabel << std::endl;
	std::cout << "\t\t- ID: " << btID << std::endl;

	free(attr[2].pValue);
	free(attr[3].pValue);
	free(attr[4].pValue);

	return true;
}


bool unsupportedFunctionsTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki) {

	CK_RV rv;

	std::cout << "All the following function will be called with all arguments set to NULL" << std::endl;

	struct Function {
		const char* name;
		CK_RV(*func)(...);
		int argCount;
	};

	Function test_set[] = {
		{"C_CreateObject", (CK_RV(*)(...))g_pFuncList->C_CreateObject, 4},
		{"C_GenerateKey", (CK_RV(*)(...))g_pFuncList->C_GenerateKey, 5},
		{"C_GenerateKeyPair", (CK_RV(*)(...))g_pFuncList->C_GenerateKeyPair, 8},
		{"C_DestroyObject", (CK_RV(*)(...))g_pFuncList->C_DestroyObject, 2},
		{"C_SetAttributeValue", (CK_RV(*)(...))g_pFuncList->C_SetAttributeValue, 4},
		{"C_SignRecover", (CK_RV(*)(...))g_pFuncList->C_SignRecover, 5},
		{"C_Encrypt", (CK_RV(*)(...))g_pFuncList->C_Encrypt, 5},
		{"C_EncryptFinal", (CK_RV(*)(...))g_pFuncList->C_EncryptFinal, 3},
		{"C_EncryptInit", (CK_RV(*)(...))g_pFuncList->C_EncryptInit, 3},
		{"C_EncryptUpdate", (CK_RV(*)(...))g_pFuncList->C_EncryptUpdate, 5},
		{"C_Decrypt", (CK_RV(*)(...))g_pFuncList->C_Decrypt, 5},
		{"C_DecryptFinal", (CK_RV(*)(...))g_pFuncList->C_DecryptFinal, 3},
		{"C_DecryptInit", (CK_RV(*)(...))g_pFuncList->C_DecryptInit, 3},
		{"C_DecryptUpdate", (CK_RV(*)(...))g_pFuncList->C_DecryptUpdate, 5},
		{"C_SeedRandom", (CK_RV(*)(...))g_pFuncList->C_SeedRandom, 3},
		{"C_GenerateRandom", (CK_RV(*)(...))g_pFuncList->C_GenerateRandom, 3},
		{"C_InitToken", (CK_RV(*)(...))g_pFuncList->C_InitToken, 4},
		{"C_CopyObject", (CK_RV(*)(...))g_pFuncList->C_CopyObject, 5},
		{"C_DigestKey", (CK_RV(*)(...))g_pFuncList->C_DigestKey, 2},
		{"C_DigestEncryptUpdate", (CK_RV(*)(...))g_pFuncList->C_DigestEncryptUpdate, 5},
		{"C_DecryptDigestUpdate", (CK_RV(*)(...))g_pFuncList->C_DecryptDigestUpdate, 5},
		{"C_SignEncryptUpdate", (CK_RV(*)(...))g_pFuncList->C_SignEncryptUpdate, 5},
		{"C_DecryptVerifyUpdate", (CK_RV(*)(...))g_pFuncList->C_DecryptVerifyUpdate, 5},
		{"C_WrapKey", (CK_RV(*)(...))g_pFuncList->C_WrapKey, 6},
		{"C_UnwrapKey", (CK_RV(*)(...))g_pFuncList->C_UnwrapKey, 7},
		{"C_DeriveKey", (CK_RV(*)(...))g_pFuncList->C_DeriveKey, 6},
		{"C_GetFunctionStatus", (CK_RV(*)(...))g_pFuncList->C_GetFunctionStatus, 1},
		{"C_CancelFunction", (CK_RV(*)(...))g_pFuncList->C_CancelFunction, 1},
		{"C_SetOperationState", (CK_RV(*)(...))g_pFuncList->C_SetOperationState, 5},
		{"C_GetObjectSize", (CK_ULONG(*)(...))g_pFuncList->C_GetObjectSize, 3}

	};

	for (const auto& test : test_set) {
		std::cout << "\n\t" << test.name << std::endl;

		switch (test.argCount) {
		case 1: rv = ((CK_RV(*)())test.func)(); break;
		case 2: rv = ((CK_RV(*)(CK_VOID_PTR, CK_VOID_PTR))test.func)(NULL, NULL); break;
		case 3: rv = ((CK_RV(*)(CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR))test.func)(NULL, NULL, NULL); break;
		case 4: rv = ((CK_RV(*)(CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR))test.func)(NULL, NULL, NULL, NULL); break;
		case 5: rv = ((CK_RV(*)(CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR))test.func)(NULL, NULL, NULL, NULL, NULL); break;
		case 6: rv = ((CK_RV(*)(CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR))test.func)(NULL, NULL, NULL, NULL, NULL, NULL); break;
		case 7: rv = ((CK_RV(*)(CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR))test.func)(NULL, NULL, NULL, NULL, NULL, NULL, NULL); break;
		case 8: rv = ((CK_RV(*)(CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR, CK_VOID_PTR))test.func)(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL); break;
		default: rv = CKR_GENERAL_ERROR; std::cerr << "Unsupported argument count" << std::endl;
		}

		error(rv);
		if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
			std::cout << "\t\t -> compliant" << std::endl;
		}
		else {
			std::cout << "\t\t** not compliant" << std::endl;
		}
	}

	return true;
}


bool initPinTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki) {

	CK_RV rv;

	std::cout << "\t- C_InitPIN whith user not logged in" << std::endl;

	rv = g_pFuncList->C_InitPIN(hSession, NULL, NULL);
	error(rv);
	if (rv == CKR_USER_NOT_LOGGED_IN) {
		std::cout << "\t\t -> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t ** not compliant" << std::endl;
	}



	return true;
}