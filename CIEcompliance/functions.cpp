#include <iostream>
#include <string>

// directive for PKCS#11
#include "cryptoki.h"
#include <map>

#include "UUCByteArray.h"

#include "functions.h"
#include "error_map.h"

void error(CK_RV rv)
{
	printf("  -------------------\n");
	//printf("  <e> Errore n. 0x%X\n", rv);
	std::cout << "  Return Val 0x" << rv << " : " << ErrorMap[rv] << std::endl;
	printf("  -------------------\n");
}

PKCS11::PKCS11(CK_FUNCTION_LIST_PTR_PTR pFunctionList, std::map<CK_MECHANISM_TYPE, std::string> mechMap) {
	this->g_pFuncList = *pFunctionList;
	this->mechanismMap = mechMap;
}

void PKCS11::init()
{
	// Inizializza
	std::cout << "  -> Inizializza la libreria\n    - C_Initialize" << std::endl;

	CK_C_INITIALIZE_ARGS* pInitArgs = NULL_PTR;
	CK_RV rv = g_pFuncList->C_Initialize(pInitArgs);
	if (rv != CKR_OK)
	{
		error(rv);
		return;
	}

	std::cout << "  -- Inizializzazione completata " << std::endl;
}

void PKCS11::close()
{
	std::cout << "  -> Chiude la sessione con la libreria\n    - C_Finalize" << std::endl;

	CK_RV rv = g_pFuncList->C_Finalize(NULL_PTR);
	if (rv != CKR_OK)
	{
		error(rv);
		return;
	}
}

bool PKCS11::getSlotInfo(CK_SLOT_ID slotid)
{
	CK_SLOT_INFO slotInfo;
	CK_RV rv = g_pFuncList->C_GetSlotInfo(slotid, &slotInfo);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	std::cout << "    - " << slotInfo.slotDescription << std::endl;
	std::cout << "    - " << slotInfo.manufacturerID << std::endl;
	std::cout << "    - " << slotInfo.flags << std::endl;
	if (slotInfo.flags & CKF_TOKEN_PRESENT)
		std::cout << "    - Carta inserita" << std::endl;
	else
		std::cout << "    - Carta non inserita" << std::endl;

	return true;
}


CK_SLOT_ID_PTR PKCS11::getSlotList(bool bPresent, CK_ULONG* pulCount)
{
	// carica gli slot disponibili

	// legge la lista delle funzioni
	std::cout << "  -> Chiede la lista degli slot disponibili\n    - C_GetSlotList\n    - C_GetSlotInfo" << std::endl;

	CK_SLOT_ID_PTR pSlotList;

	// riceve la lista degli slot disponibili
	CK_RV rv = g_pFuncList->C_GetSlotList(bPresent, NULL_PTR, pulCount);
	if (rv != CKR_OK)
	{
		error(rv);
		return NULL_PTR;
	}

	if (*pulCount > 0)
	{
		std::cout << "  -> Slot disponibili: " << *pulCount << std::endl;

		pSlotList = (CK_SLOT_ID_PTR)malloc(*pulCount * sizeof(CK_SLOT_ID));
		rv = g_pFuncList->C_GetSlotList(bPresent, pSlotList, pulCount);
		if (rv != CKR_OK)
		{
			error(rv);
			free(pSlotList);
			return NULL_PTR;
		}

		for (unsigned int i = 0; i < *pulCount; i++)
		{
			getSlotInfo(pSlotList[i]);
		}

		std::cout << "  -- Richiesta completata " << std::endl;

		return pSlotList;
	}
	else
	{
		std::cout << "  -> Nessuno Slot disponibile " << std::endl;
		return NULL_PTR;
	}
}

void PKCS11::getTokenInfo(CK_SLOT_ID slotid)
{
	// Legge le info sul token inserito

	std::cout << "  -> Chiede le info sul token inserito\n    - C_GetTokenInfo" << std::endl;

	CK_TOKEN_INFO tkInfo;

	CK_RV rv = g_pFuncList->C_GetTokenInfo(slotid, &tkInfo);
	if (rv != CKR_OK)
	{
		error(rv);
		return;
	}

	std::cout << "  -> Token Info:" << std::endl;
	std::cout << "    - Label: " << tkInfo.label << std::endl;
	std::cout << "    - Model: " << tkInfo.model << std::endl;
	std::cout << "    - S/N: " << tkInfo.serialNumber << std::endl;

	std::cout << "  -- Richiesta completata " << std::endl;
}


void PKCS11::mechanismList(CK_SLOT_ID slotid)
{

	std::cout << "  -> Legge i maccanismi disponibili nello slot " << slotid << " - C_GetMechanismList" << std::endl;

	CK_MECHANISM_TYPE_PTR pMechanismType = NULL;
	CK_ULONG count = 0;
	CK_RV rv = g_pFuncList->C_GetMechanismList(slotid, pMechanismType, &count);
	if (rv != CKR_OK)
	{
		error(rv);
		return;
	}

	pMechanismType = new CK_MECHANISM_TYPE[count];

	rv = g_pFuncList->C_GetMechanismList(slotid, pMechanismType, &count);
	if (rv != CKR_OK)
	{
		error(rv);
		return;
	}

	for (CK_ULONG i = 0; i < count; i++)
	{
		std::cout << "  -- " << mechanismMap[pMechanismType[i]] << ": " << pMechanismType[i] << std::endl;
	}
}

CK_SESSION_HANDLE PKCS11::openSession(CK_SLOT_ID slotid)
{
	std::cout << "  -> Apre una sessione con lo slot " << slotid << " - C_OpenSession" << std::endl;

	CK_SESSION_HANDLE hSession;
	CK_RV rv = g_pFuncList->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if (rv != CKR_OK)
	{
		error(rv);
		return NULL_PTR;
	}

	std::cout << "  -- Sessione aperta: " << hSession << std::endl;

	return hSession;
}


bool PKCS11::login(CK_SESSION_HANDLE hSession)
{

	std::cout << "  -> Login allo slot\n    - C_Login" << std::endl;

	///////////////////////////////////////////////////////////////////////////////////////
	bool end;
	bool bSO;
	char resp;
	do {
		end = true;
		std::cout << "Autenticazione SO [s] o Nomarl User [n]? ";
		std::cin >> resp;
		if (resp == 's') { bSO = true; }
		else if (resp == 'n') { bSO = false; }
		else { std::cout << "Valore non valido\n"; end = false; }
	} while (!end);
	///////////////////////////////////////////////////////////////////////////////////////

	if (bSO) {
		bool pukIsGood = false;
		std::string sPUK;
		while (!pukIsGood) {
			std::cout << "  - Inserire il codice PUK per intero: ";
			std::cin >> sPUK;
			size_t PUKlen = sPUK.size();

			const char* szPUK = sPUK.c_str();
			size_t i = 0;
			while (i < PUKlen && (szPUK[i] >= '0' && szPUK[i] <= '9')) { i++; }
			if (i == PUKlen) { pukIsGood = true; }
			else { std::cout << "   Attenzione: Il pin deve essere composto da 4 numeri" << std::endl; }
		}

		CK_RV rv = g_pFuncList->C_Login(hSession, CKU_SO, (CK_CHAR_PTR)sPUK.c_str(), sPUK.size());
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}

		/*std::cout << "  -- SetPIN" << std::endl;
		CK_RV rvPUK = g_pFuncList->C_SetPIN(hSession, (CK_CHAR_PTR)sPUK.c_str(), sPUK.size(), (CK_CHAR_PTR)sPUK.c_str(), sPUK.size());
		if (rvPUK != CKR_OK)
		{
			error(rvPUK);
			return false;
		}
		std::cout << "  -- SetPIN effettuato (Security Officer)" << std::endl;*/
	}
	else {
		std::string sPIN;
		bool pinIsGood = false;
		while (!pinIsGood)
		{
			std::cout << "   - Inserire la seconda parte del PIN ";
			std::cin >> sPIN;
			//std::getline(std::cin, sPIN);
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

		CK_RV rv = g_pFuncList->C_Login(hSession, CKU_USER, (CK_CHAR_PTR)sPIN.c_str(), sPIN.size());
		if (rv != CKR_OK)
		{
			error(rv);
			return false;
		}
	}

	std::cout << "  -- Login Effettuato (" << (bSO ? "Security Officer" : "Normal User") << ")" << std::endl;

	//aggiunto
	/*std::cout << "  -- SetPIN" << std::endl;
	CK_RV rvPIN = g_pFuncList->C_SetPIN(hSession, (CK_CHAR_PTR)sPIN.c_str(), sPIN.size(), (CK_CHAR_PTR)sPIN.c_str(), sPIN.size());
	if (rvPIN != CKR_OK)
	{
		error(rvPIN);
		return false;
	}
	std::cout << "  -- SetPIN effettuato" << std::endl;*/

	return true;
}


bool PKCS11::logout(CK_SESSION_HANDLE hSession)
{
	std::cout << "  -> Logout allo slot\n    - C_Logout" << std::endl;

	CK_RV rv = g_pFuncList->C_Logout(hSession);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	std::cout << "  -- Logout Effettuato" << std::endl;
	return true;
}


bool PKCS11::findObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pAttributes, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR pObjects, CK_ULONG_PTR pulObjCount)
{
	std::cout << "  -> Ricerca di oggetti \n    - C_FindObjectsInit\n    - C_FindObjects\n    - C_FindObjectsFinal" << std::endl;

	CK_RV rv;

	rv = g_pFuncList->C_FindObjectsInit(hSession, pAttributes, ulCount);
	if (rv != CKR_OK)
	{
		std::cout << "  ->     - C_FindObjectsInit fails" << std::endl;
		error(rv);
		return false;
	}

	std::cout << "      - C_FindObjectsInit OK" << std::endl;

	/*std::cout << "Try to initialize again" << std::endl;
	rv = g_pFuncList->C_FindObjectsInit(hSession, pAttributes, ulCount);
	if (rv != CKR_OK)
	{
		std::cout << "  ->     - C_FindObjectsInit fails" << std::endl;
		error(rv);
		return false;
	}*/

	/*int counter = 0;
	while (*pulObjCount > 0) {
		counter++;
		*pulObjCount = 1;
		rv = g_pFuncList->C_FindObjects(hSession, pObjects, *pulObjCount, pulObjCount);
		if (rv != CKR_OK)
		{
			std::cout << "      - C_FindObjects n." << counter << " fails found" << *pulObjCount << std::endl;
			error(rv);
			g_pFuncList->C_FindObjectsFinal(hSession);
			return false;
		}

		if (g_nLogLevel > 2)
			std::cout << "      - C_FindObjects n." << counter << " OK. Objects found: " << *pulObjCount << std::endl;

		std::cout << "Try to finalize" << std::endl;
		rv = g_pFuncList->C_FindObjectsFinal(hSession);
		if (rv != CKR_OK)
		{
			std::cout << "      - C_FindObjectsFinal fails" << std::endl;
			error(rv);
			g_pFuncList->C_FindObjectsFinal(hSession);
			return false;
		}
	}*/

	rv = g_pFuncList->C_FindObjects(hSession, pObjects, *pulObjCount, pulObjCount);
	if (rv != CKR_OK)
	{
		std::cout << "      - C_FindObjects fails found" << *pulObjCount << std::endl;
		error(rv);
		g_pFuncList->C_FindObjectsFinal(hSession);
		return false;
	}

	std::cout << "      - C_FindObjects OK. Objects found: " << *pulObjCount << std::endl;

	rv = g_pFuncList->C_FindObjectsFinal(hSession);
	if (rv != CKR_OK)
	{
		std::cout << "      - C_FindObjectsFinal fails" << std::endl;
		error(rv);
		g_pFuncList->C_FindObjectsFinal(hSession);
		return false;
	}

	std::cout << "      - C_FindObjectsFinal OK" << std::endl;

	/*std::cout << "Try to Finalize again" << std::endl;

	rv = g_pFuncList->C_FindObjectsFinal(hSession);
	if (rv != CKR_OK)
	{
		std::cout << "      - C_FindObjectsFinal fails" << std::endl;
		error(rv);
		g_pFuncList->C_FindObjectsFinal(hSession);
		return false;
	}*/

	return true;

}


void PKCS11::closeSession(CK_SESSION_HANDLE hSession)
{
	std::cout << "  -> Chiude una sessione con lo slot\n    - C_CloseSession" << std::endl;

	CK_RV rv = g_pFuncList->C_CloseSession(hSession);
	if (rv != CKR_OK)
	{
		error(rv);
		return;
	}

	std::cout << "  -- Sessione chiusa: " << hSession << std::endl;
}

void PKCS11::showAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	std::cout << "  -> Legge gli attributi di un oggetto \n    - C_GetAttributeValue" << std::endl;

	CK_BBOOL        bPrivate = 0;
	CK_BBOOL        bToken = 0;

	char* btLabel = NULL;
	char* btID = NULL;

	CK_ATTRIBUTE    attr[] = {
		{CKA_PRIVATE, &bPrivate, sizeof(bPrivate)},
		{CKA_TOKEN, &bToken, sizeof(bToken)},
		{CKA_LABEL, btLabel, 0},
		{CKA_ID, btID, 0 }
	};

	CK_RV rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 4);
	if (rv != CKR_OK)
	{
		error(rv);
	}

	attr[2].pValue = malloc(attr[2].ulValueLen + 2);
	attr[3].pValue = malloc(attr[3].ulValueLen + 2);


	rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 4);
	if (rv != CKR_OK)
	{
		free(attr[2].pValue);
		free(attr[3].pValue);
		error(rv);
		return;
	}

	btLabel = (char*)attr[2].pValue;
	btID = (char*)attr[3].pValue;

	btLabel[attr[2].ulValueLen] = 0;
	btID[attr[3].ulValueLen] = 0;

	std::cout << "      - Label: " << btLabel << std::endl;
	std::cout << "      - Private: " << (bPrivate ? "true" : "false") << std::endl;
	std::cout << "      - Token: " << (bToken ? "true" : "false") << std::endl;
	std::cout << "      - ID: " << btID << std::endl;

	free(attr[2].pValue);
	free(attr[3].pValue);
}

void PKCS11::showCertAttributes(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	std::cout << "  -> Legge gli attributi di un oggetto \n    - C_GetAttributeValue" << std::endl;

	CK_BBOOL        bPrivate = 0;
	CK_BBOOL        bToken = 0;

	CK_ATTRIBUTE    attr[] = {
		{CKA_PRIVATE, &bPrivate, sizeof(bPrivate)},
		{CKA_TOKEN, &bToken, sizeof(bToken)},
		{CKA_LABEL, NULL, 256},
		{CKA_ISSUER, NULL, 256},
		{CKA_SERIAL_NUMBER, NULL, 256},
		{CKA_ID, NULL, 256},
		{CKA_SUBJECT, NULL, 256},
		{CKA_VALUE, NULL, 0},
		//{CKA_VALUE, szValue, 256}
	};

	CK_RV rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 8);
	if (rv != CKR_OK)
	{
		error(rv);
	}

	for (int i = 0; i < 8; i++)
	{
		attr[i].pValue = malloc(attr[i].ulValueLen + 1);
	}

	rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 8);
	if (rv != CKR_OK)
	{
		error(rv);
	}

	for (int i = 0; i < 8; i++)
	{
		((char*)attr[i].pValue)[attr[i].ulValueLen] = 0;
	}

	std::cout << "      - Label: " << (char*)attr[2].pValue << std::endl;
	std::cout << "      - Issuer: " << UUCByteArray((BYTE*)attr[3].pValue, attr[3].ulValueLen).toHexString() << std::endl;
	std::cout << "      - Subject: " << UUCByteArray((BYTE*)attr[6].pValue, attr[6].ulValueLen).toHexString() << std::endl;
	std::cout << "      - Value: " << UUCByteArray((BYTE*)attr[7].pValue, attr[7].ulValueLen).toHexString() << std::endl;
	std::cout << "      - Serial: " << (char*)attr[4].pValue << std::endl;
	std::cout << "      - ID: " << (char*)attr[5].pValue << std::endl;

	for (int i = 0; i < 8; i++)
	{
		free(attr[i].pValue);
	}
	/*
	////////////////////////////////////////////////////////////////////////////////////////////

	// crea l'oggetto di sistema del certificato
	PCCERT_CONTEXT cer = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (BYTE*)attr[7].pValue, attr[7].ulValueLen);

	// converte il Subject name in stringa e lo scrive sullo schermo
	int NameSize = CertNameToStr(X509_ASN_ENCODING, &cer->pCertInfo->Subject, CERT_X500_NAME_STR, NULL, 0);
	std::vector<char> Name(NameSize);
	CertNameToStr(X509_ASN_ENCODING, &cer->pCertInfo->Subject, CERT_X500_NAME_STR, Name.data(), NameSize);
	std::cout << "Titolare :" << Name.data() << "\n";

	CertFreeCertificateContext(cer);

	////////////////////////////////////////////////////////////////////////////////////////////
	*/
}


bool PKCS11::signVerify(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanism)
{
	std::cout << "  -> Firma e verifica con algo " << mechanismMap[mechanism] << "\n   - C_Sign\n    - C_Verify" << std::endl;

	UUCByteArray dataValHashed;

	CK_OBJECT_HANDLE hObjectPriKey;
	CK_OBJECT_HANDLE hObjectPubKey;
	CK_ULONG ulCount = 1;

	CK_OBJECT_CLASS ckClassPri = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS ckClassPub = CKO_PUBLIC_KEY;

	CK_ATTRIBUTE template_cko_keyPri[] = {
		{CKA_CLASS, &ckClassPri, sizeof(ckClassPri)},
	};

	if (!findObject(hSession, template_cko_keyPri, 1, &hObjectPriKey, &ulCount))
	{
		std::cout << "  -> Operazione fallita" << std::endl;
		return false;
	}

	if (ulCount < 1)
	{
		std::cout << "  -> Oggetto chiave privata non trovato" << std::endl;
		return false;
	}


	showAttributes(hSession, hObjectPriKey);

	CK_ATTRIBUTE template_cko_keyPub[] = {
		{CKA_CLASS, &ckClassPub, sizeof(ckClassPub)},
	};


	if (!findObject(hSession, template_cko_keyPub, 1, &hObjectPubKey, &ulCount))
	{
		std::cout << "  -> Operazione fallita" << std::endl;
		return false;
	}

	if (ulCount < 1)
	{
		std::cout << "  -> Oggetto chiave publica non trovato" << std::endl;
		return false;
	}

	showAttributes(hSession, hObjectPubKey);

	CK_MECHANISM pMechanism[] = { mechanism, NULL_PTR, 0 };
	BYTE* pOutput;
	CK_ULONG outputLen = 256;

	const char* szToSign = "some text to sign";
	UUCByteArray dataVal((BYTE*)szToSign, strlen(szToSign));

	std::cout << "  -> Appone la Firma digitale : " << std::endl;

	CK_RV rv = g_pFuncList->C_SignInit(hSession, pMechanism, hObjectPriKey);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL, &outputLen);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	pOutput = (BYTE*)malloc(outputLen);

	rv = g_pFuncList->C_Sign(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	if (rv != CKR_OK)
	{
		delete pOutput;
		error(rv);
		return false;
	}

	UUCByteArray output(pOutput, outputLen);

	std::cout << "  -- Firma digitale apposta: " << std::endl << "     " << output.toHexString() << std::endl;

	std::cout << "  -> Verifica la Firma digitale : " << std::endl;

	rv = g_pFuncList->C_VerifyInit(hSession, pMechanism, hObjectPubKey);
	if (rv != CKR_OK)
	{
		delete pOutput;
		error(rv);
		return false;
	}

	rv = g_pFuncList->C_Verify(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, outputLen);
	if (rv != CKR_OK)
	{
		delete pOutput;
		error(rv);
		return false;
	}

	std::cout << "  -- Verifica completata: " << std::endl << "     " << output.toHexString() << std::endl;

	delete pOutput;

	return true;
}

bool PKCS11::digest(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanism)
{
	std::cout << "  -> Hash con algo " << mechanismMap[mechanism] << std::endl;

	UUCByteArray dataValHashed;

	CK_ULONG ulCount = 1;

	CK_MECHANISM pMechanism[] = { mechanism, NULL_PTR, 0 };
	BYTE* pOutput;
	CK_ULONG outputLen = 256;

	const char* szToHash = "some text to hash";
	UUCByteArray dataVal((BYTE*)szToHash, strlen(szToHash));

	std::cout << "  -> Appone la Firma digitale : " << std::endl;

	CK_RV rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), NULL, &outputLen);
	if (rv != CKR_OK)
	{
		error(rv);
		return false;
	}

	pOutput = (BYTE*)malloc(outputLen);

	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	if (rv != CKR_OK)
	{
		delete pOutput;
		error(rv);
		return false;
	}

	UUCByteArray output(pOutput, outputLen);

	std::cout << "  -- Hash calcolato: " << std::endl << "     " << output.toHexString() << std::endl;

	delete pOutput;

	return true;
}

bool PKCS11::digestCompliance(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID) {
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

	//disabled during debugging
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

	//CRASH
	std::cout << "\t1- Calling C_DigestInit with a NULL Mechanism -> **CRASH**";
	/*rv = g_pFuncList->C_DigestInit(hSession, NULL_PTR);
	if (rv == CKR_MECHANISM_INVALID) {
		error(rv);
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		error(rv);
		std::cout << "\t**non-compliant" << std::endl;
	}*/
	
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
		std::cout << "\t-> compliant: CKR_SESSION_HANDLE_INVALID > CKR_MECHANISM_INVALID" << std::endl;
	}
	else {
		error(rv);
		std::cout << "\t** not compliant" << std::endl;
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
	std::cout << "\n\n\t- Calling C_DigestInit with valid arguments...";
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	if (rv != CKR_OK){
		return false;
	}
	std::cout << "Ok\n";

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
	if (rv != CKR_OK) {
		std::cout << "\t** not compliant" << std::endl;
	}
	else {
		std::cout << "\t-> compliant" << std::endl;
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

	//CRASH
	std::cout << "\n\n\t2- Calling C_Digest with a NULL_PTR pData and not-NULL ulDataLen	->	**CRASH**" << std::endl;
	/*rv = g_pFuncList->C_Digest(hSession, NULL_PTR, dataVal.getLength(), pOutput, &outputLen);
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
	}*/

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

	std::cout << "\n\n\t4- Calling C_Digest with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)"<< std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength()-1, pOutput, &outputLen);
	error(rv);
	if (rv == CKR_ARGUMENTS_BAD) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
		if (rv == CKR_OK) {
			UUCByteArray output(pOutput, outputLen);
			std::cout << "\t\t\"Hash\": " << output.toHexString() << std::endl;
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
			std::cout << "\t\t\"Hash\": " << output.toHexString() << std::endl;
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
	}
	
	{
		CK_ULONG outputLenBig = outputLen + 1;
		CK_ULONG outputLenSmall = outputLen - 1;
		BYTE* pOutputSmall = (BYTE*)malloc(outputLenSmall);

		std::cout << "\n\n\t6- Calling C_Digest with a buffer too small" << std::endl;
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutputSmall, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}

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
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLenSmall);
		error(rv);
		if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
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
		if ( rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				std::cout << "\t\t\"Hash\": " << pOutput << " -> garbage" << std::endl;
				std::cout << "\t -Re-init the digest operation" << std::endl;
				rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
				if (rv != CKR_OK) {
					free(pOutputSmall);
					error(rv);
					return false;
				}
			}
		}

		std::cout << "\n\n\t10- Calling C_Digest with a buffer Ok and a wrong outputLen Ok (with value > MD5 digest length)" << std::endl;
		rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLenBig);
		error(rv);
		if ( rv == CKR_ARGUMENTS_BAD)
		{
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
			if (rv == CKR_OK) {
				UUCByteArray output(pOutput, outputLenBig);
				std::cout << "\t\t\"Hash\": " << output.toHexString() << std::endl;
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
		}
		free(pOutputSmall);
	}

	std::cout << "\n\n\t11- Calling C_Digest with all arguments set to null" << std::endl;
	rv = g_pFuncList->C_Digest(NULL, NULL_PTR, NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
	}

	std::cout << "\n\n\t-Calling C_Digest with valid arguments...";
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	if (rv != CKR_OK) {
		free(pOutput);
		error(rv);
		return false;
	}
	std::cout << "Ok\n";
	
	UUCByteArray output(pOutput, outputLen);
	std::cout << "  -- Computed Hash : " << std::endl << "     " << output.toHexString() << std::endl;

	//statefull test **CRASH**
	/*std::cout << "\n\n\t11- Calling C_Digest not initialized" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}*/

	//statefull test
	/*std::cout << "[TEST]	->	Calling C_DigestUpdate (not initialized)" << std::endl;
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

	//CRASH
	/*std::cout << "Calling C_Digest (not initialized)" << std::endl;
	rv = g_pFuncList->C_Digest(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength(), pOutput, &outputLen);
	if (rv != CKR_OK)
	{
		delete pOutput;
		error(rv);
		return false;
	}*/
	std::cout << "\n\n\n[TEST]	 ->	  C_DigestUpdate" << std::endl;
	
	std::cout << "\n\n\t1- Calling C_DigestUpdate without initialization" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	std::cout << "\n\tcalling C_DigestInit...";
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);
	if (rv != CKR_OK)
	{
		delete pOutput;
		error(rv);
		return false;
	}
	std::cout << "Ok\n";

	std::cout << "\n\n\t2- Calling C_DigestUpdate with a NULL hSession" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(NULL, (BYTE*)dataVal.getContent(), dataVal.getLength());
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
	}
	else {
		std::cout << "\t** not compliant" << std::endl;
	}

	std::cout << "\n\n\t3- Calling C_DigestUpdate with pPart NULL_PTR and ulPartLen NULL" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(hSession, NULL_PTR, NULL);
	if (rv == CKR_OK) {
		std::cout << "\t-> compliant" << std::endl;
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
	else {
		std::cout << "\t** not compliant" << std::endl;
	}


	std::cout << "\n\n\t4- Calling C_DigestUpdate with a NULL_PTR pData and not-NULL ulDataLen	   ->	  **CRASH**" << std::endl;
	//CRASH	
	/*rv = g_pFuncList->C_DigestUpdate(hSession, NULL_PTR, dataVal.getLength());
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
	}*/

	std::cout << "\n\n\t5- Calling C_DigestUpdate with a not-NULL pData and NULL ulDataLen" << std::endl;
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

	std::cout << "\n\n\t6- Calling C_DigestUpdate with a not-NULL pData and a wrong (it does not match with the actual pData's size) not-NULL ulDataLen (< pData size)" << std::endl;
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
			std::cout << "\t\t\"Hash\": " << output.toHexString() << std::endl;
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
			std::cout << "\t\t\"Hash\": " << output.toHexString() << std::endl;
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
	}

	std::cout << "\n\n\t8- Calling C_DigestUpdate with all arguments set to NULL" << std::endl;
	rv = g_pFuncList->C_DigestUpdate(NULL, NULL_PTR, NULL);
	error(rv);
	if (rv == CKR_SESSION_HANDLE_INVALID) {
		std::cout << "\t-> compliant" << std::endl;
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

	//re-init digest operation
	rv = g_pFuncList->C_DigestInit(hSession, pMechanism);


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
		}
		else {
			std::cout << "\t** not compliant" << std::endl;
		}

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
			if (rv == CKR_OK) {
				std::cout << "\t\t\"Hash\": " << pOutput << " -> garbage" << std::endl;
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
				std::cout << "\t\t\"Hash\": " << output.toHexString() << std::endl;
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
			std::cout << "\t-> compliant" << std::endl;
		}
		else {
			std::cout << "\t** not compliant : CKR_SESSION_HANDLE_INVALID > CKR_ARGUMENTS_BAD" << std::endl;
		}

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

	delete pOutput;

	return true;

}