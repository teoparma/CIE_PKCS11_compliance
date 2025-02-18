// TestCIE.cpp : Questo file contiene la funzione 'main', in cui inizia e termina l'esecuzione del programma.
//
/*
 *  Copyright (c) 2000-2018 by Ugo Chirico - http://www.ugochirico.com
 *  All Rights Reserved
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "pch.h"
#include <iostream>
#include <string>
 // directive for PKCS#11
#include "cryptoki.h"
#include <map>

#include "functions.h"
#include "testCompliance.h"

CK_FUNCTION_LIST_PTR g_pFuncList;
std::map<CK_MECHANISM_TYPE, std::string> mechanismMap;


int main(int argc, char* argv[])
{
	std::cout << "----------------------------------------------" << std::endl;
	std::cout << "- Console di test della libreria PKCS#11 della CIE" << std::endl;
	std::cout << "- Progrmma modificato a partire dal sorgente https://github.com/italia/cie-middleware/blob/master/TestCIE/TestCIE.cpp" << std::endl;
	std::cout << "- Copyright (c) 2006-2019 by Ugo Chirico\n- http://www.ugochirico.com\n- All right reserved" << std::endl;
	std::cout << "----------------------------------------------" << std::endl;

	mechanismMap[CKM_RSA_PKCS] = "CKM_RSA_PKCS";
	mechanismMap[CKM_SHA1_RSA_PKCS] = "CKM_SHA1_RSA_PKCS";
	mechanismMap[CKM_SHA256_RSA_PKCS] = "CKM_SHA256_RSA_PKCS";
	mechanismMap[CKM_MD5_RSA_PKCS] = "CKM_MD5_RSA_PKCS";
	mechanismMap[CKM_MD5] = "CKM_MD5";
	mechanismMap[CKM_SHA_1] = "CKM_SHA1";
	mechanismMap[CKM_SHA256] = "CKM_SHA256";


	LPCWSTR szCryptoki = L"ciepki.dll";
	//LPCWSTR szCryptoki = L"C:\\SoftHSM2\\lib\\softhsm2-x64.dll";
	//LPCWSTR szCryptoki = L"C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll";
	std::cout << "Load Module " << szCryptoki << std::endl;
	//HMODULE hModule = LoadLibrary(szCryptoki);
	HMODULE hModule = LoadLibrary("ciepki.dll");
	//HMODULE hModule = LoadLibrary("C:\\SoftHSM2\\lib\\softhsm2-x64.dll");
	if (!hModule)
	{
		std::cout << "  -> Modulo " << szCryptoki << " non trovato" << std::endl;
		exit(1);
	}

	C_GETFUNCTIONLIST pfnGetFunctionList = (C_GETFUNCTIONLIST)GetProcAddress(hModule, "C_GetFunctionList");

	if (!pfnGetFunctionList) {
		FreeLibrary(hModule);
		std::cout << "  -> Funzione C_GetFunctionList non trovata" << std::endl;
		exit(1);
	}

	// legge la lista delle funzioni
	std::cout << "  -> Chiede la lista delle funzioni esportate\n    - C_GetFunctionList" << std::endl;

	CK_RV rv = pfnGetFunctionList(&g_pFuncList);
	if (rv != CKR_OK)
	{
		FreeLibrary(hModule);
		std::cout << "  -> Funzione C_GetFunctionList ritorna errore " << rv << std::endl;
		exit(1);
	}

	PKCS11 cryptoki(&g_pFuncList, mechanismMap);
	Tester tester(&g_pFuncList, &cryptoki);

	std::cout << "  -- Richiesta completata " << std::endl;

	std::string sCommandLine;
	char* szCmd;
	bool bEnd = false;

	while (!bEnd)
	{
		if (argc > 1 && strlen(argv[1]) <= 2)
		{
			szCmd = argv[1];
			bEnd = true;
		}
		else
		{
			std::cout << "\nTest numbers:" << std::endl;
			std::cout << "1 Digest test" << std::endl;
			std::cout << "2 Sign test" << std::endl;
			std::cout << "3 Verify test" << std::endl;
			std::cout << "4 set PIN test" << std::endl;
			std::cout << "5 get attribute value test" << std::endl;
			std::cout << "6 unsupported functions test" << std::endl;
			std::cout << "7 init PIN test" << std::endl;
			std::cout << "20 Exit" << std::endl;
			std::cout << "Insert the test number:" << std::endl;
			std::cin >> sCommandLine;

			if (sCommandLine.length() <= 2)
				szCmd = (char*)sCommandLine.c_str();
			else
				szCmd = (char*)"";
		}

		std::cout << "---------------------------------------------------------" << std::endl;

		if (strcmp(szCmd, "?") == 0)
		{
			std::cout << "Uso:" << std::endl;
			std::cout << "testsimp11 <testnumber> " << std::endl;
			std::cout << "dove <testnumber> indica il numero del test come specificato nel documento di test" << std::endl;
			bEnd = true;
		}
		else if (strcmp(szCmd, "1") == 0) {
			CK_ULONG ulCount = 0;
			std::cout << "-> Test 1 - digest compliance" << std::endl;
			cryptoki.init();

			CK_SLOT_ID_PTR pSlotList = cryptoki.getSlotList(true, &ulCount);
			if (pSlotList == NULL_PTR)
			{
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			CK_SESSION_HANDLE hSession = cryptoki.openSession(pSlotList[0]);
			if (hSession == NULL_PTR)
			{
				free(pSlotList);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!tester.digestCompliance(hSession, pSlotList[0]))
			{
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			free(pSlotList);
			cryptoki.closeSession(hSession);

			cryptoki.close();
			std::cout << "-> Test 1 concluso" << std::endl;
		}
		else if (strcmp(szCmd, "2") == 0) {
			CK_ULONG ulCount = 0;
			std::cout << "-> Test 2 - sign compliance" << std::endl;
			cryptoki.init();

			CK_SLOT_ID_PTR pSlotList = cryptoki.getSlotList(true, &ulCount);
			if (pSlotList == NULL_PTR)
			{
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			CK_SESSION_HANDLE hSession = cryptoki.openSession(pSlotList[0]);
			if (hSession == NULL_PTR)
			{
				free(pSlotList);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.login(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!tester.signCompliance(hSession))
			{
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.logout(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			free(pSlotList);
			cryptoki.closeSession(hSession);

			cryptoki.close();
			std::cout << "-> Test 2 concluso" << std::endl;
		}
		else if (strcmp(szCmd, "3") == 0) {
			CK_ULONG ulCount = 0;
			std::cout << "-> Test 3 - verify compliance" << std::endl;
			cryptoki.init();

			CK_SLOT_ID_PTR pSlotList = cryptoki.getSlotList(true, &ulCount);
			if (pSlotList == NULL_PTR)
			{
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			CK_SESSION_HANDLE hSession = cryptoki.openSession(pSlotList[0]);
			if (hSession == NULL_PTR)
			{
				free(pSlotList);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.login(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!tester.verifyCompliance(hSession))
			{
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.logout(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			free(pSlotList);
			cryptoki.closeSession(hSession);

			cryptoki.close();
			std::cout << "-> Test 3 concluso" << std::endl;
		}
		else if (strcmp(szCmd, "4") == 0) {
			CK_ULONG ulCount = 0;
			std::cout << "-> Test 4 - set PIN compliance" << std::endl;
			cryptoki.init();

			CK_SLOT_ID_PTR pSlotList = cryptoki.getSlotList(true, &ulCount);
			if (pSlotList == NULL_PTR)
			{
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			CK_SESSION_HANDLE hSession = cryptoki.openSession_ReadOnly(pSlotList[0]);
			if (hSession == NULL_PTR)
			{
				free(pSlotList);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!tester.setPinCompliance(hSession))
			{
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			free(pSlotList);
			cryptoki.closeSession(hSession);
			cryptoki.close();
			std::cout << " -> Test 4 concluso" << std::endl;
		}
		else if (strcmp(szCmd, "5") == 0) {
			CK_ULONG ulCount = 0;
			std::cout << "-> Test 5 - get attribute value compliance" << std::endl;
			cryptoki.init();

			CK_SLOT_ID_PTR pSlotList = cryptoki.getSlotList(true, &ulCount);
			if (pSlotList == NULL_PTR)
			{
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			CK_SESSION_HANDLE hSession = cryptoki.openSession(pSlotList[0]);
			if (hSession == NULL_PTR)
			{
				free(pSlotList);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.login(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}


			CK_OBJECT_HANDLE phObject[200];
			CK_ULONG ulObjCount = 200;

			CK_OBJECT_CLASS ckClass = CKO_PRIVATE_KEY;

			CK_ATTRIBUTE template_ck[] = {
				{CKA_CLASS, &ckClass, sizeof(ckClass)} };

			//std::cout << "  - Chiavi private " << std::endl;

			cryptoki.findObject(hSession, template_ck, 1, phObject, &ulObjCount);

				/*for (CK_ULONG i = 0; i < ulObjCount; i++)
				{
					cryptoki.showAttributes(hSession, phObject[i]);
				}*/

			if (!tester.getAttributeValueCompliance(hSession, phObject[0]))
			{
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.logout(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			free(pSlotList);
			cryptoki.closeSession(hSession);
			cryptoki.close();
			std::cout << " -> Test 5 concluso" << std::endl;
		}
		else if (strcmp(szCmd, "6") == 0) {
			CK_ULONG ulCount = 0;
			std::cout << "-> Test 6 - unsupported functions compliance" << std::endl;
			cryptoki.init();

			CK_SLOT_ID_PTR pSlotList = cryptoki.getSlotList(true, &ulCount);
			if (pSlotList == NULL_PTR)
			{
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			CK_SESSION_HANDLE hSession = cryptoki.openSession(pSlotList[0]);
			if (hSession == NULL_PTR)
			{
				free(pSlotList);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.login(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!tester.unsupportedFunctionsCompliance(hSession))
			{
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (!cryptoki.logout(hSession)) {
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			free(pSlotList);
			cryptoki.closeSession(hSession);

			cryptoki.close();
			std::cout << "-> Test 6 concluso" << std::endl;
		}
		else if (strcmp(szCmd, "7") == 0) {
			CK_ULONG ulCount = 0;
			std::cout << "-> Test 7 - init PIN compliance" << std::endl;
			cryptoki.init();

			CK_SLOT_ID_PTR pSlotList = cryptoki.getSlotList(true, &ulCount);
			if (pSlotList == NULL_PTR)
			{
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			CK_SESSION_HANDLE hSession = cryptoki.openSession(pSlotList[0]);
			if (hSession == NULL_PTR)
			{
				free(pSlotList);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}

			if (! tester.initPinCompliance(hSession))
			{
				free(pSlotList);
				cryptoki.closeSession(hSession);
				cryptoki.close();
				std::cout << "-> Test non completato" << std::endl;
				continue;
			}


			free(pSlotList);
			cryptoki.closeSession(hSession);

			cryptoki.close();
			std::cout << "-> Test 6 concluso" << std::endl;
		}
		else if (strcmp(szCmd, "20") == 0)
		{
			bEnd = true;
		}

		std::cout << "*************************" << std::endl;
		std::cout << "*************************" << std::endl;
		std::cout << "---------------------------------------------------------" << std::endl;
	}

	FreeLibrary(hModule);

	return 0;
}
