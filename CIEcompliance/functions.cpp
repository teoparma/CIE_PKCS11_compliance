#include "functions.h"

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


bool PKCS11::login_modificato(CK_SESSION_HANDLE hSession)
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

bool PKCS11::login(CK_SESSION_HANDLE hSession)
{
	std::cout << "  -> Login allo slot\n    - C_Login" << std::endl;

	CK_RV rv;
	bool pinIsGood = false;
	std::string sPIN;
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
	//modificato
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
	//std::cout << "  -> Ricerca di oggetti \n    - C_FindObjectsInit\n    - C_FindObjects\n    - C_FindObjectsFinal" << std::endl;

	CK_RV rv;

	rv = g_pFuncList->C_FindObjectsInit(hSession, pAttributes, ulCount);
	if (rv != CKR_OK)
	{
		std::cout << "  ->     - C_FindObjectsInit fails" << std::endl;
		error(rv);
		return false;
	}

	//std::cout << "      - C_FindObjectsInit OK" << std::endl;

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

	//std::cout << "      - C_FindObjects OK. Objects found: " << *pulObjCount << std::endl;

	rv = g_pFuncList->C_FindObjectsFinal(hSession);
	if (rv != CKR_OK)
	{
		std::cout << "      - C_FindObjectsFinal fails" << std::endl;
		error(rv);
		g_pFuncList->C_FindObjectsFinal(hSession);
		return false;
	}

	//std::cout << "      - C_FindObjectsFinal OK" << std::endl;

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
	CK_ULONG bModulusLen = 0;

	CK_ATTRIBUTE    attr[] = {
		{CKA_PRIVATE, &bPrivate, sizeof(bPrivate)},
		{CKA_TOKEN, &bToken, sizeof(bToken)},
		{CKA_LABEL, btLabel, 0},
		{CKA_ID, btID, 0 },
		{CKA_MODULUS_BITS, &bModulusLen, 0}
	};

	CK_RV rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 5);
	if (rv != CKR_OK)
	{
		error(rv);
	}

	attr[2].pValue = malloc(attr[2].ulValueLen + 2);
	attr[3].pValue = malloc(attr[3].ulValueLen + 2);


	rv = g_pFuncList->C_GetAttributeValue(hSession, hObject, attr, 5);
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
	std::cout << "		- Modulus len: " << bModulusLen << std::endl;	

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