#include "digestCompliance.h"


bool digestTest(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_FUNCTION_LIST_PTR g_pFuncList, PKCS11* cryptoki) 
{
	UUCByteArray dataValHashed;

	CK_ULONG ulCount = 1;

	CK_MECHANISM pMechanism[] = { CKM_MD5, NULL_PTR, 0 };
	BYTE* pOutput;
	CK_ULONG outputLen = 256;

	const char* szToHash = "some text to hash";
	UUCByteArray dataVal((BYTE*)szToHash, strlen(szToHash));

	std::string MD5_TEST_DIGEST = "F97AF9ACB61DCCBE5B660582BB2B0E39";
	std::string MD5_NULL_VALUE_DIGEST = "D41D8CD98F00B204E9800998ECF8427E";

	CK_RV rv;

	std::cout << "\n\n\n[TEST]	->	 C_DigestInit (MD5)" << std::endl;

	//statefull test
	/*std::cout << "\t- Remove the card" << std::endl;
	g_pFuncList->C_WaitForSlotEvent(0, &slotID, 0);

	std::cout << "\t- Calling C_DigestInit" << std::endl;
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	if (rv == CKR_TOKEN_NOT_PRESENT) {
		std::cout << "\t **not compliant : should return CKR_SESSION_HANDLE_INVALID**" << std::endl;
	}
	else if (rv == CKR_SESSION_HANDLE_INVALID) {
		error(rv);
		std::cout << "\t-> compliant: CKR_SESSION_HANDLE_INVALID > CKR_TOKEN_NOT_PRESENT" << std::endl;
	}
	else {
		std::cout << "\t-> Unexpected error" << std::endl;
		error(rv);
	}

	std::cout << "\n\n\t- Reinsert the card" << std::endl;
	g_pFuncList->C_WaitForSlotEvent(0, &slotID, 0);

	//std::cout << "\t- Closing session" << std::endl;
	//g_pFuncList->C_CloseSession(hSession);
	std::cout << "\t- Re-opening the session" << std::endl;
	rv = g_pFuncList->C_OpenSession(slotID, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if (rv != CKR_OK) {
		error(rv);
		return false;
	}*/

	{
		std::cout << "\n\n\t0- Calling C_DigestInit with an invalid Mechanism" << std::endl;
		CK_MECHANISM invalidMech[] = { CKM_SHA256_RSA_PKCS, NULL, 0 };
		rv = g_pFuncList->C_DigestInit(hSession, invalidMech);
		if (rv == CKR_MECHANISM_INVALID) {
			error(rv);
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			error(rv);
			std::cout << "\t**non-compliant" << std::endl;
		}
	}

	//CRASH
	std::cout << "\n\n\t1- Calling C_DigestInit with a NULL Mechanism	";
#ifndef SOFTHSM
	std::cout << "->  ** CRASH **" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_DigestInit(hSession, NULL_PTR);
	if (rv == CKR_MECHANISM_INVALID || rv == CKR_ARGUMENTS_BAD) {
		error(rv);
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		error(rv);
		std::cout << "\t**non-compliant" << std::endl;
	}
#endif

	std::cout << "\n\n\t2- Calling C_DigestInit with a NULL Session" << std::endl;
	rv = g_pFuncList->C_DigestInit(NULL, pMechanism);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		error(rv);
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		error(rv);
		std::cout << "\t** not compliant" << std::endl;
	}
	std::cout << "\n\n\t3- Calling C_DigestInit with both Session and Mechanism NULL" << std::endl;
	rv = g_pFuncList->C_DigestInit(NULL, NULL_PTR);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		error(rv);
		std::cout << "\t-> compliant: CKR_SESSION_HANDLE_INVALID >" << std::endl;
	}
	else {
		error(rv);
		std::cout << "\t** not compliant: CKR_SESSION_HANDLE_INVALID >" << std::endl;
	}

	{
		std::cout << "\n\n\t4- Calling C_DigestInit with invalid mechanism parameters" << std::endl;
		CK_RSA_PKCS_OAEP_PARAMS invalid_param = { CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0 };
		CK_MECHANISM invalid_mech_param = { CKM_SHA_1, &invalid_param, sizeof(invalid_param) };
		rv = g_pFuncList->C_DigestInit(hSession, &invalid_mech_param);
		if (rv == CKR_MECHANISM_PARAM_INVALID) {
			error(rv);
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			error(rv);
			std::cout << "\t** not compliant" << std::endl;
		}
	}
#ifndef SOFTHSM
	std::cout << "\n\n\t- Calling C_DigestInit with valid arguments...";
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	if (rv != CKR_OK) {
		std::cout << std::endl;
		return false;
	}
	std::cout << "Ok\n";
#endif

	//statefull test
	/*std::cout << "\n\n\t5- Re-calling C_DigestInit with a NULL session" << std::endl;
	rv = g_pFuncList->C_DigestInit(NULL, pMechanism);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		error(rv);
		std::cout << "\t-> compliant: CKR_SESSION_HANDLE_INVALID > CKR_OPERATION_ACTIVE" << std::endl;
	}
	else {
		error(rv);
		std::cout << "\t** not compliant" << std::endl;
	}*/

	std::cout << "\n\n\n\n[TEST]	->	 C_Digest" << std::endl;

	std::cout << "\n\t0- Calling C_Digest with pDigest NULL_PTR" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL_PTR, &outputLen);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	std::cout << "\t[MD_5]: " << outputLen << " bytes to hold the output" << std::endl;
	if (outputLen < MD5_DIGEST_LENGTH) {
		std::cout << "\t** not compliant : output length should be 16**" << std::endl;
	}
	else {
		std::cout << "\t-> compliant" << std::endl;
	}
	pOutput = (BYTE*)malloc(outputLen);

	std::cout << "\n\n\t1- Calling C_Digest with a NULL_PTR pData and NULL ulDataLen" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, NULL_PTR, NULL, pOutput, &outputLen);
	error(rv);
	if (rv != CKR_OK && rv != CKR_ARGUMENTS_BAD) {
		std::cout << "\t** not compliant" << std::endl;
	}
	else {
		std::cout << "\t-> compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() == MD5_NULL_VALUE_DIGEST)
				std::cout << "\t\tHash correct" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}

	std::cout << "\n\n\t2- Calling C_Digest with a NULL_PTR pData and not-NULL ulDataLen";
#ifndef SOFTHSM
	std::cout << "	->	**CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_Digest(hSession, NULL_PTR, dataVal.getLength(), pOutput, &outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		UUCByteArray output(pOutput, outputLen);
		std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
		if (output.toHexString() == MD5_NULL_VALUE_DIGEST)
			std::cout << "\t\tHash correct" << std::endl;
		else
			std::cout << "\t\tHash correct" << std::endl;
		std::cout << "\t -Re-init the digest operation" << std::endl;
		rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
		if (rv != CKR_OK) {
			error(rv);
			return false;
		}
	}
#endif


	std::cout << "\n\n\t3- Calling C_Digest with a not-NULL pData and NULL ulDataLen" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), NULL, pOutput, &outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}

	/*std::cout << "\n\n\t4- Calling C_Digest with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() - 1, pOutput, &outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect : The pData is cutted by the wrong ulDataLen \n\t\t(in this case from \"some text to hash\" to \"some text to has\") \nor it can do an out-of-bounds read" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}

	std::cout << "\n\n\t5- Calling C_Digest with a not-NULL pData and a wrong not-NULL ulDataLen (> pData size)" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() + 1, pOutput, &outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t\t!!Read out of pData's memory limit!!" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}*/

	{
		CK_ULONG outputLenBig = outputLen + 1;
		CK_ULONG outputLenSmall = outputLen - 1;
		CK_ULONG outputLenSmaller = outputLenSmall - 1;
		BYTE* pOutputSmall = (BYTE*)malloc(outputLenSmall);

		std::cout << "\n\n\t4- Calling C_Digest with a buffer too small" << std::endl;
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL)
		{
			std::cout << "\t-> compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	-> compliant" << std::endl;
			}
			else {
				std::cout << "No	** not compliant" << std::endl;
				std::cout << "\t -Re-init the digest operation" << std::endl;
			}
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					error(rv);
					return false;
				}
			}
		}
		/*
		//HEAP CORRUPTION DETECTED
		std::cout << "\n\n\t-7 Calling C_Digest with a buffer too small and a wrong (it does not match with the accual buffer's size) outputLen Ok (with value >= MD5 digest length (16))" << std::endl;
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, &outputLen);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t\t!!Write out of buffer's memory limit (Heap Corruption)!!" << std::endl;
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
			}
		}

		std::cout << "\n\n\t8- Calling C_Digest with a buffer too small and a wrong outputLen not Ok (with value < MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, &outputLenSmaller);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	-> compliant" << std::endl;
			}
			else {
				std::cout << "No	** not compliant" << std::endl;
			}
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
			}
		}

		std::cout << "\n\n\t9- Calling C_Digest with a buffer output Ok (size>=MD5 digest length) and a wrong outputLen not Ok" << std::endl;
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLenSmall);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t\tHash: " << pOutput << std::endl;
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
			}
			else {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	-> compliant" << std::endl;
				}
				else {
					std::cout << "No	** not compliant" << std::endl;
				}
			}
		}

		std::cout << "\n\n\t10- Calling C_Digest with a buffer Ok and a wrong outputLen Ok (with value > MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLenBig);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				UUCByteArray output(pOutput, outputLenBig);
				std::cout << "\t\tHash: " << output.toHexString() << std::endl;
				if (output.toHexString() != MD5_TEST_DIGEST)
					std::cout << "\t\tHash incorrect" << std::endl;
				else
					std::cout << "\t\tHash correct" << std::endl;
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
			}
		}*/
		free(pOutputSmall);
	}

	std::cout << "\n\n\t5- Calling C_Digest with a NULL pulDigestLen";
#ifndef SOFTHSM
	std::cout << "	  ->	**CRASH**" << std::endl;
#else
	std::cout << std::endl;
	delete pOutput;
	pOutput = (BYTE*)malloc(outputLen);
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, NULL_PTR);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}
#endif

	std::cout << "\n\n\t6- Calling C_Digest with all arguments set to null" << std::endl;
	rv = g_pFuncList->C_Digest(NULL, NULL_PTR, NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID >" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	**not compliant" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID >" << std::endl;
	}

	std::cout << "\n\n\t-Calling C_Digest with valid arguments...";
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	if (rv != CKR_OK) {
		std::cout << std::endl;
		free(pOutput);
		error(rv);
		return false;
	}
	std::cout << "Ok\n";

	UUCByteArray output(pOutput, outputLen);
	std::cout << "  -- Computed Hash : " << std::endl << "     " << output.toHexString() << std::endl;
	
	//statefull tests
	//**CRASH**
	/*std::cout << "\n\n\t11- Calling C_Digest not initialized" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	std::cout << "[TEST]	->	Calling C_DigestUpdate (not initialized)" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	if (rv != CKR_OK)
	{
		error(rv);
	}

	std::cout << "[TEST]	->	Calling C_DigestFinal (not initialized)" << std::endl;
	rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
	if (rv != CKR_OK)
	{
		error(rv);
	}*/

	std::cout << "\n\n\n[TEST]	 ->	  C_DigestUpdate" << std::endl;

	//statefull test
	/*std::cout << "\n\n\t- Calling C_DigestUpdate without initialization" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	std::cout << "\n\tcalling C_DigestInit...";
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	if (rv != CKR_OK)
	{
		std::cout << std::endl;
		delete pOutput;
		error(rv);
		return false;
	}
	std::cout << "Ok\n";

	std::cout << "\n\n\t1- Calling C_DigestUpdate with a NULL hSession" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(NULL, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
			std::cout << "\tCalling C_DigestFinal" << std::endl;
			g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);

			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	std::cout << "\n\n\t2- Calling C_DigestUpdate with pPart NULL_PTR and ulPartLen NULL" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_OK || rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_DigestFinal with pDigest NULL" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_DigestFinal" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() == MD5_NULL_VALUE_DIGEST) {
				std::cout << "\t\tHash correct" << std::endl;
			}
			else {
				std::cout << "\t\tHash incorrect" << std::endl;
			}
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}


	std::cout << "\n\n\t3- Calling C_DigestUpdate with a NULL_PTR pData and not-NULL ulDataLen";
#ifndef SOFTHSM
	std::cout << "	   ->	  **CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, NULL_PTR, dataVal.getLength());
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_DigestFinal with pDigest NULL" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_DigestFinal" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() == MD5_NULL_VALUE_DIGEST)
				std::cout << "\t\tHash correct" << std::endl;
			else
				std::cout << "\t\tHash incorrect" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}
#endif

	std::cout << "\n\n\t4- Calling C_DigestUpdate with a not-NULL pData and NULL ulDataLen" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), NULL);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_DigestFinal with pDigest NULL" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_DigestFinal" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() == MD5_TEST_DIGEST)
				std::cout << "\t\tHash correct" << std::endl;
			else
				std::cout << "\t\tHash incorrect" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}

	/*std::cout << "\n\n\t6- Calling C_DigestUpdate with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() - 1);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_DigestFinal with pDigest NULL" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_DigestFinal" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect : The pData is cutted by the wrong ulDataLen \n\t\t(in this case from \"some text to hash\" to \"some text to has\") \nor it can do an out-of-bounds read" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}

	std::cout << "\n\n\t7- Calling C_DigestUpdate with a not-NULL pData and a wrong not-NULL ulDataLen (> pData size)" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength() + 1);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			std::cout << "\t\tCalling C_DigestFinal with pDigest NULL" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, NULL, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			pOutput = (BYTE*)malloc(outputLen);
			std::cout << "\t\tCalling C_DigestFinal" << std::endl;
			rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
			if (rv != CKR_OK)
			{
				error(rv);
				delete pOutput;
				return false;
			}
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t\t!!Read out of pData's memory limit!!" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
		}
	}*/

	std::cout << "\n\n\t5- Calling C_DigestUpdate with all arguments set to NULL" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
			std::cout << "\tCalling C_DigestFinal" << std::endl;
			g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);

			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
	}

	/*
	const char* szToHashUpdate_1 = "some text";
	const char* szToHashUpdate_2 = " to hash";
	UUCByteArray dataValUpdate_1((BYTE*)szToHashUpdate_1, strlen(szToHashUpdate_1));
	UUCByteArray dataValUpdate_2((BYTE*)szToHashUpdate_2, strlen(szToHashUpdate_2));
	std::cout << "\t->C_DigestUpdate #1" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataValUpdate_1.getContent(), dataValUpdate_1.getLength());
	if (rv != CKR_OK){
		error(rv);
	}
	else {
		std::cout << "\t->C_DigestUpdate #2" << std::endl;
		rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataValUpdate_2.getContent(), dataValUpdate_2.getLength());
		if (rv != CKR_OK) {
			error(rv);
		}
	}
	std::cout << "\t->C_DigestFinal" << std::endl;
	rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
	if (rv != CKR_OK)
	{
		error(rv);
	}
	std::cout << "  -- Hash calcolato (Update): " << std::endl << "     " << output.toHexString() << std::endl;*/





	std::cout << "\n\n\n[TEST]	 ->	  C_DigestFinal" << std::endl;


	std::cout << "\n\tCalling C_DigestUpdate with valid arguments" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	if (rv != CKR_OK) {
		error(rv);
		delete pOutput;
		return false;
	}


	std::cout << "\n\n\t1- Calling C_DigestFinal with pDigest NULL_PTR" << std::endl;
	rv = g_pFuncList->C_DigestFinal(hSession, NULL_PTR, &outputLen);
	if (rv != CKR_OK) {
		error(rv);
		delete pOutput;
		return false;
	}

	std::cout << "\t[MD_5]: " << outputLen << " bytes to hold the output" << std::endl;
	if (outputLen < MD5_DIGEST_LENGTH) {
		std::cout << "\t** not compliant : output length should be 16**" << std::endl;
	}
	else {
		std::cout << "\t-> compliant" << std::endl;
	}

	{
		CK_ULONG outputLenBig = outputLen + 1;
		CK_ULONG outputLenSmall = outputLen - 1;
		BYTE* pOutputSmall = (BYTE*)malloc(outputLenSmall);

		std::cout << "\n\n\t2- Calling C_DigestFinal with a buffer too small" << std::endl;
		rv = g_pFuncList->C_DigestFinal(hSession, pOutputSmall, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL)
		{
			std::cout << "\t-> compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	-> compliant" << std::endl;
			}
			else {
				std::cout << "No	** not compliant" << std::endl;
				std::cout << "\t -Re-init the digest operation" << std::endl;
			}

		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}

		/*
		//HEAP CORRUPTION DETECTED
		std::cout << "\n\n\t-3 Calling C_DigestFinal with a buffer too small and a wrong (it does not match with the accual buffer's size) outputLen Ok (with value >= MD5 digest length (16))" << std::endl;
		rv = g_pFuncList->C_DigestFinal(hSession, pOutputSmall, &outputLen);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t\t!!Write out of buffer's memory limit (Heap Corruption)!!" << std::endl;
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
				std::cout << "\t - Re-calling C_DigestUpdate" << std::endl;
				rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t4- Calling C_DigestFinal with a buffer too small and a wrong outputLen not Ok (with value < MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv == CKR_OPERATION_ACTIVE) {
				std::cout << "Yes	-> compliant" << std::endl;
			}
			else {
				std::cout << "No	** not compliant" << std::endl;
			}
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
				std::cout << "\t - Re-calling C_DigestUpdate" << std::endl;
				rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
				if (rv != CKR_OK) {
					error(rv);
					delete pOutput;
					return false;
				}
			}
		}

		std::cout << "\n\n\t5- Calling C_DigestFinal with a buffer output Ok (size>=MD5 digest length) and a wrong outputLen not Ok" << std::endl;
		rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLenSmall);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_BUFFER_TOO_SMALL) {
				std::cout << "\tChecking if operation is still active...";
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv == CKR_OPERATION_ACTIVE) {
					std::cout << "Yes	-> compliant" << std::endl;
				}
				else {
					std::cout << "No	** not compliant" << std::endl;
					std::cout << "\t -Re-init the digest operation" << std::endl;
					std::cout << "\t - Re-calling C_DigestUpdate" << std::endl;
					rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
					if (rv != CKR_OK) {
						error(rv);
						delete pOutput;
						return false;
					}
				}
			}
		}

		std::cout << "\n\n\t6- Calling C_DigestFinal with a buffer Ok and a wrong outputLen Ok (with value > MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLenBig);
		error(rv);
		if (rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				UUCByteArray output(pOutput, outputLen);
				std::cout << "\t\tHash: " << output.toHexString() << std::endl;
				if (output.toHexString() != MD5_TEST_DIGEST)
					std::cout << "\t\tHash incorrect" << std::endl;
				else
					std::cout << "\t\tHash correct" << std::endl;
			}
		}

		std::cout << "\n\n\t7- Calling C_DigestFinal with all arguments set to NULL" << std::endl;
		rv = g_pFuncList->C_DigestFinal(NULL, NULL_PTR, NULL_PTR);
		error(rv);
		if (rv == CKR_SESSION_HANDLE_INVALID) {
			std::cout << "\t-> compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
			std::cout << "\tChecking if operation is still active...";
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
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

		std::cout << "\n\n\n\n";*/

		//statefull test
		/*std::cout << "\n\n\t7- Calling C_DigestFinal without initialization" << std::endl;
		rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
		error(rv);
		if (rv == CKR_OPERATION_NOT_INITIALIZED) {
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}*/

		free(pOutputSmall);
	}

	std::cout << "\n\n\t3- Calling C_DigestFinal with a NULL pulDigestLen";
#ifndef SOFTHSM
	std::cout << "	  ->	**CRASH**" << std::endl;
#else
	std::cout << std::endl;
	delete pOutput;
	pOutput = (BYTE*)malloc(outputLen);
	rv = g_pFuncList->C_DigestFinal(hSession, pOutput, NULL_PTR);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
			std::cout << "\t -Re-init the digest operation" << std::endl;
			rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
			if (rv != CKR_OK) {
				error(rv);
				return false;
			}
			std::cout << "\t -Re-calling C_DigestUpdate" << std::endl;
			rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
			if (rv != CKR_OK) {
				error(rv);
				delete pOutput;
				return false;
			}
		}
	}
#endif

	std::cout << "\n\n\t4- Calling C_DigestFinal with NULL hSession" << std::endl;
	rv = g_pFuncList->C_DigestFinal(NULL, pOutput, &outputLen);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
		std::cout << "\tChecking if operation is still active...";
		rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
		if (rv == CKR_OPERATION_ACTIVE) {
			std::cout << "Yes	** not compliant" << std::endl;
			g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
		}
		else {
			std::cout << "No	-> compliant" << std::endl;
		}
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	

	std::cout << "\n\n\n----statefull tests----" << std::endl;

	std::cout << "\n\t- Calling C_DigestInit" << std::endl;
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	error(rv);
	std::cout << "\t1- [TEST]: Second call to C_DigestInit (operation active)" << std::endl;
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	error(rv);
	if (rv == CKR_OPERATION_ACTIVE) {
		std::cout << "\t\t-> complaint" << std::endl;
	}
	else {
		std::cout << "\t\t** not comlpliant" << std::endl;
	}

	std::cout << "\n\t- Calling C_DigestUpdate" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	std::cout << "\n\t2- [TEST]: Calling C_Digest after C_DigestUpdate" << std::endl;
#ifndef SOFTHSM
	rv = g_pFuncList->C_Digest(hSession, NULL, NULL, pOutput, &outputLen);
	error(rv);
	if (rv != CKR_OK) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\tHash: " << output.toHexString() << (output.toHexString() == MD5_NULL_VALUE_DIGEST ? " (digest of an empty input)" : "") << std::endl;
			if (output.toHexString() != MD5_TEST_DIGEST)
				std::cout << "\t\tHash incorrect" << std::endl;
			else
				std::cout << "\t\tHash correct" << std::endl;
		}
	}
#else
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	error(rv);
	if (rv != CKR_OK) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}
#endif

	std::cout << "\n\t3- [TEST]: Call to C_DigestFinal after invalid call to C_Digest" << std::endl;
	rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}

	std::cout << "\n\t- Calling C_DigestInit" << std::endl;
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	error(rv);
	std::cout << "\n\t- Call to C_Digest" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	error(rv);


	std::cout << "\n\t4- [TEST]: Second call to C_Digest (operation not initialized)";
#ifndef SOFTHSM
	std::cout << "		->		**CRASH**" << std::endl;
#else
	std::cout << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}
#endif

	std::cout << "\n\t5- [TEST]: Call to C_DigestUpdate after C_Digest" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}

	std::cout << "\n\t6- [TEST]: Call to C_DigestFinal (operation not initialized)" << std::endl;
	rv = g_pFuncList->C_DigestFinal(hSession, pOutput, &outputLen);
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t\t** not compliant" << std::endl;
	}

	std::cout << "\n\n\n\n";

	delete pOutput;

	return true;
}