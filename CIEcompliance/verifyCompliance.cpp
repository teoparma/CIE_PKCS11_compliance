#include "verifyCompliance.h"

bool verifyTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki)
{
	std::string MD5_RSA_NULL_SIGN = "03272599EC6C5BCD2C8BD4773126F91EA801FB52DC93CD9442A1C49D5C34EF77ABBBBE007881D15A4DB53AA573F51D937F72E269F3842CFBE1B0148692FA9400A7618E80D35DB798125E4682B7A517D8456934FB5CA7FBEBDBE51A3334956465BA3E574255027DF4B592222DA35D148E1D19BC2101992111375C3AEE0BE589090F6BCBDC9F75619910BEAF70C744B4D19D6062EB3C0AB49D8605C244F1BD700A63371D043C99A0494B0BDCEFB055CE9438B67D6738EE241A120025480C908B342EFEB89485300282454098AA6AED6084E75886EBA5498BB151FD8F9FF83CFAE35EEC77C699F2188295F704F41F61F8D25E54D15DDA2F122EC26F5215963072FE";
	std::string MD5_RSA_TEST_SIGN = "8EBED44E74D7129A0F85FD2F215C20392E3612DB06F88D75A8DF95D2BE2C144727206CCD2B1E1BA91B3AC5B36C3D4C0D992E9978BE6053956DC63AE9FE894C9AB868CD4AF605212939A28C581E36591195193A25DF68F8CAC65971E7B95287A4971349644564F0F9C3E31268004A892D815134D112E85C3CC9BB5EC5608BB17F3EA00C8386EC9D11B6F58005DEED69A48F7E4D4A3338CD76892CCB48DB4AC05D0061B06C638130A0E780A1170BB0CC9384A8E411BC4304C2D98C4954772615012EA61B4F6C2A2E8769D59B22B11920DA94347835660A93D2BC9BDD5B9AFB1D5C7148C9F9094081B3442A7553606ABF193C19C09C3BF06B8720A8B263D4244131";

	CK_MECHANISM_TYPE mechanism = CKM_MD5_RSA_PKCS;
	CK_MECHANISM pMechanism[] = { mechanism, NULL_PTR, 0 };

	CK_OBJECT_HANDLE hObjectPriKey;
	CK_OBJECT_HANDLE hObjectPubKey;
	CK_ULONG ulCount = 1;

	CK_OBJECT_CLASS ckClassPri = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS ckClassPub = CKO_PUBLIC_KEY;

	CK_ATTRIBUTE template_cko_keyPri[] = {
		{CKA_CLASS, &ckClassPri, sizeof(ckClassPri)},
	};
	CK_ATTRIBUTE template_cko_keyPub[] = {
	{CKA_CLASS, &ckClassPub, sizeof(ckClassPub)},
	};

	const char* szToSign = "some text to sign";
	UUCByteArray dataVal((BYTE*)szToSign, strlen(szToSign));

	BYTE* pOutput;
	CK_ULONG outputLen = 256;

	CK_RV rv;


	std::cout << "\n\t-Finding private key" << std::endl;
	if (!cryptoki->findObject(hSession, template_cko_keyPri, 1, &hObjectPriKey, &ulCount))
	{
		std::cout << "  -> Operazione fallita" << std::endl;
		return false;
	}

	if (ulCount < 1)
	{
		std::cout << "  -> Oggetto chiave privata non trovato" << std::endl;
		return false;
	}

	std::cout << "\n\t-Finding public key" << std::endl;
	if (!cryptoki->findObject(hSession, template_cko_keyPub, 1, &hObjectPubKey, &ulCount))
	{
		std::cout << "  -> Operazione fallita" << std::endl;
		return false;
	}

	if (ulCount < 1)
	{
		std::cout << "  -> Oggetto chiave publica non trovato" << std::endl;
		return false;
	}


	std::cout << "\n\tStarting Sign operation...";
	while(true){
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv == CKR_GENERAL_ERROR) { continue; }
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}

		/*rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL, &outputLen);
		if (rv == CKR_GENERAL_ERROR) { continue; }
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}*/

		pOutput = (BYTE*)malloc(outputLen);

		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
		if (rv == CKR_GENERAL_ERROR) { delete pOutput; continue; }
		if (rv != CKR_OK)
		{
			delete pOutput;
			error(rv);
			return false;
		}

		break;
	}
	std::cout << " Finished" << std::endl;

#ifndef SOFTHSM
	//sign operation to obtain the sign of a null input
	BYTE* pOutputNull;
	CK_ULONG outputLenNull = 256;
	while (true) {
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv == CKR_GENERAL_ERROR) { continue; }
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}
		/*rv = g_pFuncList->C_Sign(hSession, NULL_PTR, NULL, NULL, &outputLenNull);
		if (rv == CKR_GENERAL_ERROR) { continue; }
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}*/
		pOutputNull = (BYTE*)malloc(outputLenNull);

		rv = g_pFuncList->C_Sign(hSession, NULL_PTR, NULL, pOutputNull, &outputLenNull);
		if (rv == CKR_GENERAL_ERROR) { delete pOutputNull; continue; }
		if (rv != CKR_OK)
		{
			delete pOutputNull;
			error(rv);
			return false;
		}

		break;
	}
#else
	BYTE* pOutputNull;
	CK_ULONG outputLenNull = 256;
	pOutputNull = (BYTE*)malloc(outputLenNull);
#endif


	std::cout << "\n\n\n\n[TEST]	->	  C_VerifyInit (CKM_MD5_RSA_PKCS)" << std::endl;

	{
		CK_MECHANISM invalidMech[] = { CKM_MD5, NULL, 0 };
		std::cout << "\n\n\t1- Calling C_VerifyInit with an invalid Mechanism" << std::endl;
		rv = g_pFuncList->C_VerifyInit(hSession, invalidMech, hObjectPubKey);
		error(rv);
		if (rv == CKR_MECHANISM_INVALID) {
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
	}

	std::cout << "\n\n\t2- Calling C_VerifyInit with a NULL Mechanism";
#ifndef SOFTHSM
	std::cout << "   ->   **CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_VerifyInit(hSession, NULL_PTR, hObjectPubKey);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
#endif

	std::cout << "\n\n\t3- Calling C_VerifyInit with a NULL Session" << std::endl;
	rv = g_pFuncList->C_VerifyInit(NULL, pMechanism, hObjectPubKey);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	

	std::cout << "\n\n\t4- Calling C_VerifyInit with all arguments set to NULL" << std::endl;
	rv = g_pFuncList->C_VerifyInit(NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant: CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
	}
	else {
		std::cout << "\t** not compliant: CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
	}

	{
		std::cout << "\n\n\t5- Calling C_VerifyInit with invalid mechanism parameters" << std::endl;
		CK_RSA_PKCS_OAEP_PARAMS invalid_param = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
		CK_MECHANISM invalid_mech_param = { CKM_SHA_1, &invalid_param, sizeof(invalid_param) };
		rv = g_pFuncList->C_VerifyInit(hSession, &invalid_mech_param, hObjectPubKey);
		error(rv);
		if (rv == CKR_MECHANISM_PARAM_INVALID) {
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
	}

	//statefull test
	/*std::cout << "\n\n\t- Calling C_Verify without initialization" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLen);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	std::cout << "\n\n\t6- Calling C_VerifyInit with a NULL hKey" << std::endl;
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, NULL);
	error(rv);
	if (rv == CKR_KEY_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}


	std::cout << "\n\n\t7- Calling C_VerifyInit with the private Key" << std::endl;
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPriKey);
	error(rv);
	if (rv == CKR_KEY_FUNCTION_NOT_PERMITTED ) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}


	std::cout << "\n\n\t- Calling C_VerifyInit with valid arguments...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv != CKR_OK) {
		std::cout << std::endl;
		return false;
	}
	std::cout << "Ok\n";



	std::cout << "\n\n\n\n[TEST]	->	 C_Verify" << std::endl;


	std::cout << "\n\n\t1- Calling C_Verify with a NULL_PTR pData and NULL ulDataLen (with a signature of a NULL input)" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, NULL_PTR, NULL, pOutputNull, outputLenNull);
	error(rv);
	if (rv != CKR_OK) {
		std::cout << "\tsignature is not valid" << std::endl;
		std::cout << "\t** not compliant" << std::endl;
	}
	else {
		std::cout << "\tsignature is valid" << std::endl;
		std::cout << "\t-> compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}


	std::cout << "\n\n\t2- Calling C_Verify with a NULL_PTR pData and not-NULL ulDataLen";
#ifndef SOFTHSM
	std::cout << "	->	**CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_Verify(hSession, NULL_PTR, dataVal.getLength(), pOutput, outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv != CKR_OK) {
			error(rv);
			return false;
		}
	}
#endif

	std::cout << "\n\n\t3- Calling C_Verify with a not-NULL pData and NULL ulDataLen" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), NULL, pOutput, outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}

	/*std::cout << "\n\n\t4- Calling C_Verify with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() - 1, pOutput, outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD || rv == CKR_SIGNATURE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}


	std::cout << "\n\n\t5- Calling C_Verify with a not-NULL pData and a wrong not-NULL ulDataLen (> pData size)" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() + 1, pOutput, outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD || rv == CKR_SIGNATURE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}*/

	{
		CK_ULONG outputLenBig = outputLen + 1;
		CK_ULONG outputLenSmall = outputLen - 1;
		CK_ULONG outputLenSmaller = outputLenSmall - 1;
		BYTE* pOutputSmall = (BYTE*)malloc(outputLenSmall);


		std::cout << "\n\n\t4- Calling C_Verify with a buffer too small" << std::endl;
		rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, outputLenSmall);
		error(rv);
		if (rv == CKR_SIGNATURE_LEN_RANGE)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}


		/*std::cout << "\n\n\t-7 Calling C_Verify with a buffer too small and a wrong (it does not match with the accual buffer's size) outputLen Ok (with value >= RSA PKCS#1 Signature length (256))" << std::endl;
		rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, outputLen);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD || rv == CKR_SIGNATURE_INVALID)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
		if (rv != CKR_CRYPTOKI_NOT_INITIALIZED && rv != CKR_OPERATION_NOT_INITIALIZED && rv != CKR_SESSION_HANDLE_INVALID) {
			std::cout << "\t\t!!Read out of buffer's memory limit (Heap Corruption)!!" << std::endl;
		}
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}


		std::cout << "\n\n\t8- Calling C_Verify with a buffer too small and a wrong outputLen not Ok (with value < RSA PKCS#1 Signature length)" << std::endl;
		rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, outputLenSmaller);
		error(rv);
		if (rv == CKR_SIGNATURE_LEN_RANGE || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}


		std::cout << "\n\n\t9- Calling C_Verify with a buffer output Ok (size>= RSA PKCS#1 Sing length) and a wrong outputLen not Ok" << std::endl;
		rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLenSmall);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD || rv == CKR_SIGNATURE_LEN_RANGE)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}

		std::cout << "\n\n\t10- Calling C_Verify with a buffer Ok and a wrong outputLen Ok (with value > RSA PKCS#1 Signature length)" << std::endl;
		rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLenBig);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD || rv == CKR_SIGNATURE_LEN_RANGE)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}*/

		free(pOutputSmall);
	}


	std::cout << "\n\n\t5- Calling C_Verify with a NULL hSession" << std::endl;
	rv = g_pFuncList->C_Verify(NULL, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLen);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}


	std::cout << "\n\n\t6- Calling C_Verify with pulSignatureLen set to NULL" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, NULL_PTR);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}


	std::cout << "\n\n\t7- Calling C_Verify with pSignature set to NULL";
#ifndef SOFTHSM
	std::cout << "		->		**CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL_PTR, outputLen);
	error(rv);
	if (rv == CKR_SIGNATURE_INVALID || rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}
#endif


	std::cout << "\n\n\t8- Calling C_Verify with pSignature and pulSignatureLen set to NULL" << std::endl;
	do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey); }
		rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL_PTR, NULL_PTR);
	} while (rv == CKR_GENERAL_ERROR);
	error(rv);
	if (rv == CKR_SIGNATURE_LEN_RANGE) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Sign operation" << std::endl;
	}


	std::cout << "\n\n\t9- Calling C_Verify with all args NULL" << std::endl;
	rv = g_pFuncList->C_Verify(NULL, NULL_PTR, NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant: CKR_SESSION_HANDLE_INVALID >" << std::endl;
	}
	else {
		std::cout << "No	-> compliant: CKR_SESSION_HANDLE_INVALID >" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}


	std::cout << "\n\n\t-Calling C_Verify with valid arguments...";
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLen);
	if (rv != CKR_OK) {
		std::cout << std::endl;
		free(pOutput);
		error(rv);
		return false;
	}
	std::cout << "Ok\n";





	std::cout << "\n\n\n[TEST]	 ->	  C_VerifyUpdate" << std::endl;
	//statefull test
	/*std::cout << "\n\n\t0- Calling C_VerifyUpdate without initialization" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	std::cout << "\n\tcalling C_VerifyInit...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv != CKR_OK)
	{
		std::cout << std::endl;
		delete pOutput;
		error(rv);
		return false;
	}
	std::cout << "Ok\n";


	std::cout << "\n\n\t1- Calling C_VerifyUpdate with a NULL hSession" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(NULL, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	if (rv != CKR_OK) {
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}
	}

	std::cout << "\n\n\t2- Calling C_VerifyUpdate with pPart NULL_PTR and ulPartLen NULL" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_OK) {
		std::cout << "\t-> compliant" << std::endl;
		std::cout << "\t\tCalling C_VerifyFinal (with signature of a NULL input)...";
		rv = g_pFuncList->C_VerifyFinal(hSession, pOutputNull, outputLenNull);
		if (rv == CKR_OK) {
			std::cout << "Ok: Signature is valid" << std::endl;
		}
		else {
			error(rv);
			std::cout << "not Ok: Signature is not valid" << std::endl;
		}

		std::cout << "\t -Re-init the Verify operation" << std::endl;
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv != CKR_OK) {
			error(rv);
			delete pOutput;
			return false;
		}
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}
	}


	std::cout << "\n\n\t3- Calling C_VerifyUpdate with a NULL_PTR pData and not-NULL ulDataLen";
#ifndef SOFTHSM
	std::cout << "	   ->	  **CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, NULL_PTR, dataVal.getLength());
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
		std::cout << "\t\tCalling C_VerifyFinal with pDigest NULL" << std::endl;
		rv = g_pFuncList->C_VerifyFinal(hSession, NULL, outputLen);
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}
		pOutput = (BYTE*)malloc(outputLen);
		std::cout << "\t\tCalling C_VerifyFinal" << std::endl;
		do {
			rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLen);
			if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
			{
				error(rv);
				delete pOutput;
				return false;
			}
		} while (rv == CKR_GENERAL_ERROR);
		std::cout << "\t -Re-init the Verify operation" << std::endl;
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv != CKR_OK) {
			error(rv);
			delete pOutput;
			return false;
		}
		}
	}
#endif

	std::cout << "\n\n\t4- Calling C_VerifyUpdate with a not-NULL pData and NULL ulDataLen" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), NULL);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	if (rv == CKR_OK) {
		std::cout << "\t\tCalling C_VerifyFinal...";
		rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLen);
		error(rv);
		if (rv == CKR_OK) {
			std::cout << "Signature is valid" << std::endl;
		}
		else {
			std::cout << "Signature is not valid ";
			/*g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
			g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), NULL);
			rv = g_pFuncList->C_VerifyFinal(hSession, pOutputNull, outputLenNull);
			if (rv == CKR_OK) {
				std::cout << "(signature of a NULL input)";
			}
			std::cout << "\n";*/
		}
		std::cout << "\t -Re-init the Verify operation" << std::endl;
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv != CKR_OK) {
			error(rv);
			delete pOutput;
			return false;
		}
	}
	else {
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}
	}

	/*std::cout << "\n\n\t5- Calling C_VerifyUpdate with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() - 1);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_VerifyFinal with pSignature NULL" << std::endl;
			rv = g_pFuncList->C_VerifyFinal(hSession, NULL, outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_VerifyFinal" << std::endl;
			do {
				rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLen);
				error(rv);
				if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
				{
					error(rv);
					delete pOutput;
					return false;
				}
			} while (rv == CKR_GENERAL_ERROR);

			std::cout << "\t -Re-init the Verify operation" << std::endl;
			rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}

	std::cout << "\n\n\t6- Calling C_VerifyUpdate with a not-NULL pData and a wrong not-NULL ulDataLen (> pData size)" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() + 1);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_VerifyFinal...";
			rv = g_pFuncList->C_VerifyFinal(hSession, pOutputNull, outputLenNull);
			if (rv == CKR_OK) {
				std::cout << "Ok: Signature is valid" << std::endl;
			}
			else {
				error(rv);
				std::cout << "not Ok: Signature is not valid" << std::endl;
			}

			std::cout << "\t -Re-init the Verify operation" << std::endl;
			rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}*/

	std::cout << "\n\n\t5- Calling C_VerifyUpdate with all arguments set to NULL" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID >" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the Verify operation" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID >" << std::endl;
	}





	std::cout << "\n\n\n[TEST]	 ->	  C_VerifyFinal" << std::endl;


	std::cout << "\n\tCalling C_VerifyUpdate with valid arguments" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	if (rv != CKR_OK) {
		error(rv);
		delete pOutput;
		return false;
	}


	std::cout << "\n\n\t1- Calling C_VerifyFinal with pDigest NULL_PTR";
#ifndef SOFTHSM
	std::cout << "	  ->	**CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_VerifyFinal(hSession, NULL_PTR, outputLen);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
#endif

	/*{
		CK_ULONG outputLenBig = outputLen + 1;
		CK_ULONG outputLenSmall = outputLen - 1;
		BYTE* pOutputSmall = (BYTE*)malloc(outputLenSmall);


		std::cout << "\n\n\t2- Calling C_VerifyFinal with a buffer too small" << std::endl;
		rv = g_pFuncList->C_VerifyFinal(hSession, pOutputSmall, outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	** not compliant" << std::endl;
			}
			else {
				std::cout << "No	-> compliant" << std::endl;
				std::cout << "\t-Re-init the Verify operation" << std::endl;
				std::cout << "\t-Re-calling C_VerifyUpdate" << std::endl;
				rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t-3 Calling C_VerifyFinal with a buffer too small and a wrong (it does not match with the accual buffer's size) pulSignatureLen Ok (with value >= PKCS#1 RSA signature length (256))" << std::endl;
		do {
			if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey); }
			rv = g_pFuncList->C_VerifyFinal(hSession, pOutputSmall, outputLen);
			error(rv);
		} while (rv == CKR_GENERAL_ERROR);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t\t!!Write out of buffer's memory limit (Heap Corruption)!!" << std::endl;
				std::cout << "\t -Re-init the Verify operation" << std::endl;
				rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
				std::cout << "\t - Re-calling C_VerifyUpdate" << std::endl;
				rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t4- Calling C_VerifyFinal with a buffer too small and a wrong outputLen not Ok (with value < MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_VerifyFinal(hSession, pOutputSmall, outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	** not compliant" << std::endl;
			}
			else {
				std::cout << "No	-> compliant" << std::endl;
				std::cout << "\t- Re-initializing the operation" << std::endl;
				std::cout << "\t- Re-calling C_VerifyUpdate" << std::endl;
				rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t5- Calling C_VerifyFinal with a buffer output Ok (size>=PKCS#1 RSA signature length) and a wrong outputLen not Ok" << std::endl;
		rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLenSmall);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_BUFFER_TOO_SMALL) {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	-> compliant" << std::endl;
				}
				else {
					std::cout << "No	** not compliant" << std::endl;
				}
			}
			else {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	** not compliant" << std::endl;
				}
				else {
					std::cout << "No	-> compliant" << std::endl;
				}
			}
			std::cout << "\t -Re-init the Verify operation" << std::endl;
			std::cout << "\t - Re-calling C_VerifyUpdate" << std::endl;
			rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}

		std::cout << "\n\n\t6- Calling C_VerifyFinal with a buffer Ok and a wrong outputLen Ok (with value > MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLenBig);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {

				std::cout << "\t -Re-init the Verify operation" << std::endl;
				rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
				std::cout << "\t - Re-calling C_VerifyUpdate" << std::endl;
				rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}

			}
		}
	}*/

	std::cout << "\n\n\t2- Calling C_VerifyFinal with a NULL hSession" << std::endl;
	rv = g_pFuncList->C_VerifyFinal(NULL, pOutput, outputLen);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
	}

	
	std::cout << "\n\n\t3- Calling C_VerifyFinal with ulSignatureLen set to NULL" << std::endl;
	rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, NULL);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD || rv == CKR_SIGNATURE_LEN_RANGE) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}
	if (rv == CKR_OK) {
		std::cout << "\tSignature is valid" << std::endl;
	}
	else {
		std::cout << "\tSignature is not valid" << std::endl;
	}
	std::cout << "\tChecking if operation is still active...";
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "Yes	** not compliant" << std::endl;
	}
	else {
		std::cout << "No	-> compliant" << std::endl;
		std::cout << "\t -Re-init the Verify operation" << std::endl;
	}



	std::cout << "\n\n\t4- Calling C_VerifyFinal with all arguments set to NULL" << std::endl;
	rv = g_pFuncList->C_VerifyFinal(NULL, NULL_PTR, NULL_PTR);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID > " << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID > " << std::endl;
	}


	rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLen);
	if (rv != CKR_OK && rv != CKR_SIGNATURE_INVALID) {
		error(rv);
		delete pOutput;
		return false;
	}

	std::cout << "\n\n\n----statefull tests----" << std::endl;

	std::cout << "\n\t- Calling C_VerifytInit" << std::endl;
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	error(rv);
	std::cout << "\t1- [TEST]: Second call to C_VerifyInit (operation active)" << std::endl;
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	error(rv);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "\t\t-> complaint" << std::endl;
	}
	else {
		std::cout << "\t\t** not comlpliant" << std::endl;
	}

	std::cout << "\n\t- Calling C_VerifyUpdate" << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	std::cout << "\n\t2- [TEST]: Calling C_Verify after C_VerifyUpdate" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, NULL, NULL, pOutput, outputLen);
	error(rv);
	if (rv != CKR_OK) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "Correct signature verificaiton" << std::endl;
		}
		if (rv == CKR_SIGNATURE_LEN_RANGE || rv == CKR_SIGNATURE_INVALID) {
			std::cout << "Correct signature verificaiton" << std::endl;
		}
	}


	std::cout << "\n\t3- [TEST]: Call to C_VerifyFinal after invalid call to C_Verify";
#ifndef SOFTHSM
	std::cout << "	  ->     **CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLen);
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}
#endif

	std::cout << "\n\t- Calling C_VerifyInit" << std::endl;
	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	error(rv);
	std::cout << "\n\t- Call to C_Verify" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLen);
	error(rv);

	std::cout << "\n\t4- [TEST]: Second call to C_Verify (operation not initialized)" << std::endl;
	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLen);
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}

	std::cout << "\n\t5- [TEST]: Call to C_VerifyUpdate after C_Verify";
#ifndef SOFTHSM
	std::cout << "	   ->    **CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_VerifyUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}
#endif

	std::cout << "\n\t6- [TEST]: Call to C_VerifyFinal (operation not initialized)";
#ifndef SOFTHSM
	std::cout << "	   ->    **CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_VerifyFinal(hSession, pOutput, outputLen);
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}
#endif

	std::cout << "\n\n\n\n";

	delete pOutput;

	return true;
}