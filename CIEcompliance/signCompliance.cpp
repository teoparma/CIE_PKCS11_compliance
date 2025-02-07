#include "signCompliance.h"

bool signTest(CK_SESSION_HANDLE hSession, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki)
{
	CK_MECHANISM_TYPE mechanism = CKM_MD5_RSA_PKCS;
	CK_MECHANISM pMechanism[] = { mechanism, NULL_PTR, 0 };
	std::string MD5_RSA_NULL_SIGN = "03272599EC6C5BCD2C8BD4773126F91EA801FB52DC93CD9442A1C49D5C34EF77ABBBBE007881D15A4DB53AA573F51D937F72E269F3842CFBE1B0148692FA9400A7618E80D35DB798125E4682B7A517D8456934FB5CA7FBEBDBE51A3334956465BA3E574255027DF4B592222DA35D148E1D19BC2101992111375C3AEE0BE589090F6BCBDC9F75619910BEAF70C744B4D19D6062EB3C0AB49D8605C244F1BD700A63371D043C99A0494B0BDCEFB055CE9438B67D6738EE241A120025480C908B342EFEB89485300282454098AA6AED6084E75886EBA5498BB151FD8F9FF83CFAE35EEC77C699F2188295F704F41F61F8D25E54D15DDA2F122EC26F5215963072FE";
	std::string MD5_RSA_TEST_SIGN = "8EBED44E74D7129A0F85FD2F215C20392E3612DB06F88D75A8DF95D2BE2C144727206CCD2B1E1BA91B3AC5B36C3D4C0D992E9978BE6053956DC63AE9FE894C9AB868CD4AF605212939A28C581E36591195193A25DF68F8CAC65971E7B95287A4971349644564F0F9C3E31268004A892D815134D112E85C3CC9BB5EC5608BB17F3EA00C8386EC9D11B6F58005DEED69A48F7E4D4A3338CD76892CCB48DB4AC05D0061B06C638130A0E780A1170BB0CC9384A8E411BC4304C2D98C4954772615012EA61B4F6C2A2E8769D59B22B11920DA94347835660A93D2BC9BDD5B9AFB1D5C7148C9F9094081B3442A7553606ABF193C19C09C3BF06B8720A8B263D4244131";

	CK_OBJECT_HANDLE hObjectPriKey;
	CK_ULONG ulCount = 1;

	CK_OBJECT_CLASS ckClassPri = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE template_cko_keyPri[] = {
		{CKA_CLASS, &ckClassPri, sizeof(ckClassPri)},
	};

	const char* szToSign = "some text to sign";
	UUCByteArray dataVal((BYTE*)szToSign, strlen(szToSign));

	BYTE* pOutput;
	CK_ULONG outputLen = 256;

	CK_RV rv;


	std::cout << "\n\n\n\n[TEST]	->	  C_SignInit (CKM_MD5_RSA_PKCS)" << std::endl;

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

	{
		CK_MECHANISM invalidMech[] = { CKM_MD5, NULL, 0 };
		std::cout << "\n\n\t1- Calling C_SignInit with an invalid Mechanism" << std::endl;
		rv = g_pFuncList->C_SignInit(hSession, invalidMech, hObjectPriKey);
		error(rv);
		if (rv == CKR_MECHANISM_INVALID) {
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
	}

	std::cout << "\n\n\t2- Calling C_SignInit with a NULL Mechanism   ->   **CRASH**" << std::endl;
	/*rv = g_pFuncList->C_SignInit(hSession, NULL_PTR, hObjectPriKey);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	std::cout << "\n\n\t3- Calling C_SignInit with a NULL Session" << std::endl;
	rv = g_pFuncList->C_SignInit(NULL, pMechanism, hObjectPriKey);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	std::cout << "\n\n\t4- Calling C_SignInit with all arguments set to NULL" << std::endl;
	rv = g_pFuncList->C_SignInit(NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant: CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	{
		std::cout << "\n\n\t5- Calling C_SignInit with invalid mechanism parameters" << std::endl;
		CK_RSA_PKCS_OAEP_PARAMS invalid_param = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
		CK_MECHANISM invalid_mech_param = { CKM_SHA_1, &invalid_param, sizeof(invalid_param) };
		rv = g_pFuncList->C_SignInit(hSession, &invalid_mech_param, hObjectPriKey);
		error(rv);
		if (rv == CKR_MECHANISM_PARAM_INVALID) {
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}
	}

	//statefull test
	/*std::cout << "\n\n\t- Calling C_Sign without initialization" << std::endl;
	rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL_PTR, &outputLen);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	std::cout << "\n\n\t- Calling C_SignInit with valid arguments...";
	rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
	if (rv != CKR_OK) {
		std::cout << std::endl;
		return false;
	}
	std::cout << "Ok\n";



	std::cout << "\n\n\n\n[TEST]	->	 C_Sign" << std::endl;

	std::cout << "\n\t0- Calling C_Sign with pSignature NULL_PTR" << std::endl;
	rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL_PTR, &outputLen);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	std::cout << "\t[PKCS#1 RSA SIGNATURE]: " << outputLen << " bytes to hold the output" << std::endl;
	if (outputLen < RSA_KEY_MODULUS_LENGTH) {
		std::cout << "\t** not compliant : output length should be 256**" << std::endl;
	}
	else {
		std::cout << "\t-> compliant" << std::endl;
	}
	pOutput = (BYTE*)malloc(outputLen);

	std::cout << "\n\n\t1- Calling C_Sign with a NULL_PTR pData and NULL ulDataLen" << std::endl;
	do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
		rv = g_pFuncList->C_Sign(hSession, NULL_PTR, NULL, pOutput, &outputLen);
		error(rv);
	} while (rv == CKR_GENERAL_ERROR);
	if (rv != CKR_OK) {
		std::cout << "\t** not compliant" << std::endl;
	}
	else {
		std::cout << "\t-> compliant" << std::endl;
		UUCByteArray output(pOutput, outputLen);
		std::cout << "Signature: " << output.toHexString() << (output.toHexString() == MD5_RSA_NULL_SIGN ? "\n\n(signature of an empty input)\n" : "\n") << std::endl;
		if (output.toHexString() == MD5_RSA_NULL_SIGN)
			std::cout << "\t\Signature correct" << std::endl;
		else
			std::cout << "\t\Signature correct" << std::endl;
		std::cout << "\t -Re-init the Sign operation" << std::endl;
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv != CKR_OK) {
			error(rv);
			return false;
		}
	}

	//CRASH
	std::cout << "\n\n\t2- Calling C_Sign with a NULL_PTR pData and not-NULL ulDataLen	->	**CRASH**" << std::endl;
	/*rv = g_pFuncList->C_Sign(hSession, NULL_PTR, dataVal.getLength(), pOutput, &outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		UUCByteArray output(pOutput, outputLen);
		std::cout << "Signature: " << output.toHexString() << (output.toHexString() == MD5_RSA_NULL_SIGN ? "\n\n(signature of an empty input)" : "") << std::endl;
		if (output.toHexString() == MD5_RSA_NULL_SIGN)
			std::cout << "\t\tSignature correct" << std::endl;
		else
			std::cout << "\t\tSignature correct" << std::endl;
		std::cout << "\t -Re-init the Sign operation" << std::endl;
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv != CKR_OK) {
			error(rv);
			return false;
		}
	}*/

	std::cout << "\n\n\t3- Calling C_Sign with a not-NULL pData and NULL ulDataLen" << std::endl;
	do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), NULL, pOutput, &outputLen);
		error(rv);
	} while (rv == CKR_GENERAL_ERROR);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "Signature: " << output.toHexString() << (output.toHexString() == MD5_RSA_NULL_SIGN ? "\n\n(signature of an empty input)" : "") << std::endl;
			if (output.toHexString() != MD5_RSA_TEST_SIGN)
				std::cout << "\t\tSignature incorrect" << std::endl;
			else
				std::cout << "\t\tSignature correct" << std::endl;
			std::cout << "\t -Re-init the Sign operation" << std::endl;
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}

	std::cout << "\n\n\t4- Calling C_Sign with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)" << std::endl;
	do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() - 1, pOutput, &outputLen);
		error(rv);
	} while (rv == CKR_GENERAL_ERROR);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "Signature: " << output.toHexString() << std::endl;
			if (output.toHexString() != NULL)
				std::cout << "\t\tSignature incorrect : The pData is cutted by the wrong ulDataLen \n\t\t(in this case from \"some text to sign\" to \"some text to sig\") \n\t\tor it can do an out-of-bounds read" << std::endl;
			else
				std::cout << "\t\tSignature correct" << std::endl;
			std::cout << "\t -Re-init the Sign operation" << std::endl;
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}
	std::cout << "\n\n\t5- Calling C_Sign with a not-NULL pData and a wrong not-NULL ulDataLen (> pData size)" << std::endl;
	do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() + 1, pOutput, &outputLen);
		error(rv);
	} while (rv == CKR_GENERAL_ERROR);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "Signature: " << output.toHexString() << std::endl;
			if (output.toHexString() != MD5_RSA_TEST_SIGN)
				std::cout << "\t\tSignature incorrect" << std::endl;
			else
				std::cout << "\t\tSignature correct" << std::endl;
			std::cout << "\t\t!!Read out of pData's memory limit!!" << std::endl;
			std::cout << "\t -Re-init the Sign operation" << std::endl;
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}

	{
		CK_ULONG outputLenBig = outputLen + 1;
		CK_ULONG outputLenSmall = outputLen - 1;
		CK_ULONG outputLenSmaller = outputLenSmall - 1;
		BYTE* pOutputSmall = (BYTE*)malloc(outputLenSmall);

		std::cout << "\n\n\t6- Calling C_Sign with a buffer too small" << std::endl;
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv != CKR_OK) {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	-> compliant" << std::endl;
				}
				else {
					std::cout << "No	** not compliant" << std::endl;
				}
			}
		}


		//HEAP CORRUPTION DETECTED
		std::cout << "\n\n\t-7 Calling C_Sign with a buffer too small and a wrong (it does not match with the accual buffer's size) outputLen Ok (with value >= RSA PKCS#1 Signature length (256))" << std::endl;
		do {
			if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
			rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, &outputLen);
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
				std::cout << "\t -Re-init the Sign operation" << std::endl;
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
			}
		}

		std::cout << "\n\n\t8- Calling C_Sign with a buffer too small and a wrong outputLen not Ok (with value < RSA PKCS#1 Signature length)" << std::endl;
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, &outputLenSmaller);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv != CKR_OK) {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	-> compliant" << std::endl;
				}
				else {
					std::cout << "No	** not compliant" << std::endl;
				}
			}
		}

		std::cout << "\n\n\t9- Calling C_Sign with a buffer output Ok (size>= RSA PKCS#1 Sing length) and a wrong outputLen not Ok" << std::endl;
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLenSmall);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				UUCByteArray output(pOutput, outputLenBig);
				std::cout << "Signature: " << pOutput << std::endl;
				if (output.toHexString() != MD5_RSA_TEST_SIGN)
					std::cout << "\t\tSignature incorrect" << std::endl;
				else
					std::cout << "\t\tSignature correct" << std::endl;
			}
			else {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	-> compliant" << std::endl;
				}
				else {
					std::cout << "No	** not compliant" << std::endl;
				}
			}
		}

		std::cout << "\n\n\t10- Calling C_Sign with a buffer Ok and a wrong outputLen Ok (with value > RSA PKCS#1 Signature length)" << std::endl;
		do {
			if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
			rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLenBig);
			error(rv);
		} while (rv == CKR_GENERAL_ERROR);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				UUCByteArray output(pOutput, outputLenBig);
				std::cout << "Signature: " << output.toHexString() << std::endl;
				if (output.toHexString() != MD5_RSA_TEST_SIGN)
					std::cout << "\t\tSignature incorrect" << std::endl;
				else
					std::cout << "\t\tSignature correct" << std::endl;
				std::cout << "\t -Re-init the Sign operation" << std::endl;
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
			}
		}
		free(pOutputSmall);
	}


	//CRASH
	std::cout << "\n\n\t11- Calling C_Sign with a NULL hSession		->		**CRASH**" << std::endl;
	/*do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
		rv = g_pFuncList->C_Sign(NULL, NULL_PTR, NULL, NULL_PTR, NULL);
		error(rv);
	} while (rv == CKR_GENERAL_ERROR);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	//CRASH
	std::cout << "\n\n\t12- Calling C_Sign with pulSignatureLen set to NULL		->		**CRASH**" << std::endl;
	/*do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, NULL_PTR);
		error(rv);
	} while (rv == CKR_GENERAL_ERROR);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID > CKR_MECHANISM_INVALID" << std::endl;
	}
	else {
		std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
	}*/

	std::cout << "\n\n\t-Calling C_Sign with valid arguments...";
	do {
		if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
		rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() + 1, pOutput, &outputLen);
	} while (rv == CKR_GENERAL_ERROR);
	if (rv != CKR_OK) {
		std::cout << std::endl;
		free(pOutput);
		error(rv);
		return false;
	}
	std::cout << "Ok\n";

	UUCByteArray output(pOutput, outputLen);
	std::cout << "  -- Computed Signature : " << std::endl << "     " << output.toHexString() << std::endl;





	std::cout << "\n\n\n[TEST]	 ->	  C_SignUpdate" << std::endl;
	//statefull test
	/*std::cout << "\n\n\t1- Calling C_SignUpdate without initialization" << std::endl;
	rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	std::cout << "\n\tcalling C_SignInit...";
	rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
	if (rv != CKR_OK)
	{
		std::cout << std::endl;
		delete pOutput;
		error(rv);
		return false;
	}
	std::cout << "Ok\n";

	std::cout << "\n\n\t2- Calling C_SignUpdate with a NULL hSession" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(NULL, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	std::cout << "\n\n\t3- Calling C_SignUpdate with pPart NULL_PTR and ulPartLen NULL" << std::endl;
	rv = g_pFuncList->C_SignUpdate(hSession, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_OK) {
		std::cout << "\t-> compliant" << std::endl;
		std::cout << "\t\tCalling C_SignFinal with pSignature NULL" << std::endl;
		rv = g_pFuncList->C_SignFinal(hSession, NULL, &outputLen);
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}
		pOutput = (BYTE*)malloc(outputLen);
		std::cout << "\t\tCalling C_SignFinal" << std::endl;
		do {
			rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLen);
			error(rv);
			if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
			{
				error(rv);
				delete pOutput;
				return false;
			}
		} while (rv == CKR_GENERAL_ERROR);

		UUCByteArray output(pOutput, outputLen);
		std::cout << "Signature: " << output.toHexString() << (output.toHexString() == MD5_RSA_NULL_SIGN ? "\n\n(signature of an empty input)" : "") << std::endl;
		if (output.toHexString() == MD5_RSA_NULL_SIGN) {
			std::cout << "\t\tSignature correct" << std::endl;
		}
		else {
			std::cout << "\t\tSignature incorrect" << std::endl;
		}
		std::cout << "\t -Re-init the Sign operation" << std::endl;
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv != CKR_OK) {
			error(rv);
			delete pOutput;
			return false;
		}
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}


	std::cout << "\n\n\t4- Calling C_SignUpdate with a NULL_PTR pData and not-NULL ulDataLen	   ->	  **CRASH**" << std::endl;
	//CRASH	
	/*rv = g_pFuncList->C_SignUpdate(hSession, NULL_PTR, dataVal.getLength());
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
		std::cout << "\t\tCalling C_SignFinal with pDigest NULL" << std::endl;
		rv = g_pFuncList->C_SignFinal(hSession, NULL, &outputLen);
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}
		pOutput = (BYTE*)malloc(outputLen);
		std::cout << "\t\tCalling C_SignFinal" << std::endl;
		do {
			rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLen);
			if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
			{
				error(rv);
				delete pOutput;
				return false;
			}
		} while (rv == CKR_GENERAL_ERROR);
		UUCByteArray output(pOutput, outputLen);
		std::cout << "Signature: " << output.toHexString() << (output.toHexString() == MD5_RSA_NULL_SIGN ? "\n\n(signature of an empty input)" : "") << std::endl;
		if (output.toHexString() == MD5_RSA_NULL_SIGN) {
			std::cout << "\t\tSignature correct" << std::endl;
		}
		else {
			std::cout << "\t\tSignature incorrect" << std::endl;
		}
		std::cout << "\t -Re-init the Sign operation" << std::endl;
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv != CKR_OK) {
			error(rv);
			delete pOutput;
			return false;
		}
		}
	}*/

	std::cout << "\n\n\t5- Calling C_SignUpdate with a not-NULL pData and NULL ulDataLen" << std::endl;
	rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), NULL);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_SignFinal with pSignature NULL" << std::endl;
			rv = g_pFuncList->C_SignFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_SignFinal" << std::endl;
			do {
				rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLen);
				error(rv);
				if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
				{
					error(rv);
					delete pOutput;
					return false;
				}
			} while (rv == CKR_GENERAL_ERROR);
			UUCByteArray output(pOutput, outputLen);
			std::cout << "Signature: " << output.toHexString() << (output.toHexString() == MD5_RSA_NULL_SIGN ? "\n\n(signature of an empty input)" : "") << std::endl;
			if (output.toHexString() == MD5_RSA_NULL_SIGN)
				std::cout << "\t\tSignature correct" << std::endl;
			else
				std::cout << "\t\tSignature incorrect" << std::endl;
			std::cout << "\t -Re-init the Sign operation" << std::endl;
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}

	std::cout << "\n\n\t6- Calling C_SignUpdate with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)" << std::endl;
	rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() - 1);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_SignFinal with pSignature NULL" << std::endl;
			rv = g_pFuncList->C_SignFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_SignFinal" << std::endl;
			do {
				rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLen);
				error(rv);
				if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
				{
					error(rv);
					delete pOutput;
					return false;
				}
			} while (rv == CKR_GENERAL_ERROR);
			UUCByteArray output(pOutput, outputLen);
			std::cout << "Signature: " << output.toHexString() << std::endl;
			if (output.toHexString() != MD5_RSA_TEST_SIGN)
				std::cout << "\t\tSignature incorrect : The pData is cutted by the wrong ulDataLen \n\t\t(in this case from \"some text to sign\" to \"some text to sig\") \nor it can do an out-of-bounds read" << std::endl;
			else
				std::cout << "\t\tSignature correct" << std::endl;
			std::cout << "\t -Re-init the Sign operation" << std::endl;
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}

	std::cout << "\n\n\t7- Calling C_SignUpdate with a not-NULL pData and a wrong not-NULL ulDataLen (> pData size)" << std::endl;
	rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() + 1);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_SignFinal with pSignature NULL" << std::endl;
			rv = g_pFuncList->C_SignFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}

			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_SignFinal	->		**CRASH**" << std::endl;
			/*rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLen);
			do {
				rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLen);
				error(rv);
				if (rv != CKR_OK && rv != CKR_GENERAL_ERROR)
				{
					error(rv);
					delete pOutput;
					return false;
				}
			} while (rv == CKR_GENERAL_ERROR);
			UUCByteArray output(pOutput, outputLen);
			std::cout << "Signature: " << output.toHexString() << std::endl;
			if (output.toHexString() != MD5_RSA_TEST_SIGN)
				std::cout << "\t\tSignature incorrect" << std::endl;
			else
				std::cout << "\t\tSignature correct" << std::endl;
			std::cout << "\t\t!!Read out of pData's memory limit!!" << std::endl;
			std::cout << "\t -Re-init the Sign operation" << std::endl;
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}*/
		}
	}

	std::cout << "\n\n\t8- Calling C_SignUpdate with all arguments set to NULL" << std::endl;
	rv = g_pFuncList->C_SignUpdate(NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
	}






	std::cout << "\n\n\n[TEST]	 ->	  C_SignFinal" << std::endl;


	std::cout << "\n\tCalling C_SignUpdate with valid arguments" << std::endl;
	rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	if (rv != CKR_OK) {
		error(rv);
		delete pOutput;
		return false;
	}


	std::cout << "\n\n\t1- Calling C_SignFinal with pDigest NULL_PTR" << std::endl;
	rv = g_pFuncList->C_SignFinal(hSession, NULL_PTR, &outputLen);
	if (rv != CKR_OK) {
		error(rv);
		delete pOutput;
		return false;
	}

	std::cout << "\t[PKCS#1 RSA SIGNATURE]: " << outputLen << " bytes to hold the output" << std::endl;
	if (outputLen < RSA_KEY_MODULUS_LENGTH) {
		std::cout << "\t** not compliant : output length should be 256**" << std::endl;
	}
	else {
		std::cout << "\t-> compliant" << std::endl;
	}

	{
		CK_ULONG outputLenBig = outputLen + 1;
		CK_ULONG outputLenSmall = outputLen - 1;
		BYTE* pOutputSmall = (BYTE*)malloc(outputLenSmall);


		std::cout << "\n\n\t2- Calling C_SignFinal with a buffer too small" << std::endl;
		rv = g_pFuncList->C_SignFinal(hSession, pOutputSmall, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	** not compliant" << std::endl;
			}
			else {
				std::cout << "No	-> compliant" << std::endl;
				std::cout << "\t-Re-init the Sing operation" << std::endl;
				std::cout << "\t-Re-calling C_SignUpdate" << std::endl;
				rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t-3 Calling C_SignFinal with a buffer too small and a wrong (it does not match with the accual buffer's size) pulSignatureLen Ok (with value >= PKCS#1 RSA signature length (256))" << std::endl;
		do {
			if (rv == CKR_GENERAL_ERROR) { g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey); }
			rv = g_pFuncList->C_SignFinal(hSession, pOutputSmall, &outputLen);
			error(rv);
		} while (rv == CKR_GENERAL_ERROR);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				/*UUCByteArray output(pOutputSmall, outputLen);
				//UUCByteArray output(pOutputSmall, outputLenSmall);
				std::cout << "Signature: " << output.toHexString() << std::endl;
				if (output.toHexString() != MD5_RSA_TEST_SIGN)
					std::cout << "\t\tSignature incorrect" << std::endl;
				else
					std::cout << "\t\tSignature correct" << std::endl;*/
				std::cout << "\t\t!!Write out of buffer's memory limit (Heap Corruption)!!" << std::endl;
				std::cout << "\t -Re-init the Sign operation" << std::endl;
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
				std::cout << "\t - Re-calling C_SignUpdate" << std::endl;
				rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t4- Calling C_SignFinal with a buffer too small and a wrong outputLen not Ok (with value < MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_SignFinal(hSession, pOutputSmall, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	** not compliant" << std::endl;
			}
			else {
				std::cout << "No	-> compliant" << std::endl;
				std::cout << "\t- Re-initializing the operation" << std::endl;
				std::cout << "\t- Re-calling C_SignUpdate" << std::endl;
				rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t5- Calling C_SignFinal with a buffer output Ok (size>=PKCS#1 RSA signature length) and a wrong outputLen not Ok" << std::endl;
		rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLenSmall);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_BUFFER_TOO_SMALL) {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	-> compliant" << std::endl;
				}
				else {
					std::cout << "No	** not compliant" << std::endl;
				}
			}
			else {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	** not compliant" << std::endl;
				}
				else {
					std::cout << "No	-> compliant" << std::endl;
				}
			}
			std::cout << "\t -Re-init the Sign operation" << std::endl;
			std::cout << "\t - Re-calling C_SignUpdate" << std::endl;
			rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}

		std::cout << "\n\n\t6- Calling C_SignFinal with a buffer Ok and a wrong outputLen Ok (with value > MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_SignFinal(hSession, pOutput, &outputLenBig);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				UUCByteArray output(pOutput, outputLen);
				std::cout << "Signature: " << output.toHexString() << std::endl;
				if (output.toHexString() != MD5_RSA_TEST_SIGN)
					std::cout << "\t\tSignature incorrect" << std::endl;
				else
					std::cout << "\t\tSignature correct" << std::endl;

				std::cout << "\t -Re-init the Sign operation" << std::endl;
				rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
				std::cout << "\t - Re-calling C_SignUpdate" << std::endl;
				rv = g_pFuncList->C_SignUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}

			}
		}

		std::cout << "\n\n\t7- Calling C_SignFinal with all arguments set to NULL" << std::endl;
		rv = g_pFuncList->C_SignFinal(NULL, NULL_PTR, NULL_PTR);
		error(rv);
		if (rv == CKR_SESSION_HANDLE_INVALID) {
			std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	** not compliant" << std::endl;
			}
			else {
				std::cout << "No	-> compliant" << std::endl;
			}
		}
		else {
			std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
		}

	}

	std::cout << "\n\n\n\n";
}