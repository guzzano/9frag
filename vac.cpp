/*	
	Copyright (c) 9frag.ve - all rights reserved.	

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto Js� <v@9frag.net>
 */

#include "vac.h"


LONG WINAPI UnhandledException (LPEXCEPTION_POINTERS exceptionInfo)  
{
	/* Esta no era la verdadera funci�n de la exepci�n :( */
	MessageBoxA(NULL, "... *sorry, vAC is crashed* ;(", "9frag alert!", MB_OK);
	return EXCEPTION_EXECUTE_HANDLER;  
}  

void Init9fragAC ( ) {
	/*if ( !InitMD5Check( ) )
		EXIT_MSG("Sorry, you failed the directory safety test. Update client or delete suspicious files."); */

	SetUnhandledExceptionFilter(UnhandledException);

	while ( TRUE ) {
		g_Data.dwBaseEngine = (DWORD) GetModuleHandleA("hw.dll");
		g_Data.dwBaseClient = (DWORD) GetModuleHandleA("client.dll");

		if ( g_Data.dwBaseClient && g_Data.dwBaseEngine && ((DWORD *) (g_Data.dwBaseEngine + 0x0134260)) != NULL 
			&& ((DWORD *) (g_Data.dwBaseEngine + 0x0134260)) != NULL  ) break;
	}

	if ( !CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) StartAC, NULL, 0, NULL) )
		EXIT_MSG("Sorry, vAC thread cannot start. Please reboot computer.");
}


void StartAC ( ) {
	BOOL isDetected;
	DWORD dwRet;

	InitProtectedCalls();
		
	while ( TRUE ) {
		//CHECK_VHOOK( isDetected, CheckVirtualTableHook (g_dwEngine, (DWORD *) (g_Data.dwBaseEngine +  0x0134260), g_Data.dwBaseEngine, 131) );
		//CHECK_VHOOK( isDetected, CheckVirtualTableHook (g_dwClient, (DWORD *) (g_Data.dwBaseEngine +  0x122F540), g_Data.dwBaseClient,  43) );

		for ( DWORD dwIndex = 0; dwIndex < CHECK_ESP_FN_CURRENT; dwIndex++) {
			if ( g_protectedCallSt[dwIndex].isUnlock ) {
				/*dwRet = memcmp((void *) g_protectedCallSt[dwIndex].dwAddress, g_protectedCallSt[dwIndex].bBackup, sizeof (g_protectedCallSt[dwIndex].bBackup));
				
				if ( dwRet != 0 ) {
					MessageBoxA(NULL, "El mio...", "...", MB_OK);
				}*/

				ProtectedCalls_Check_Before(dwIndex);
			}
		}
			
		if ( DetectDebug() ) 
			EXIT_MSG("A debugger was detected.");

		/*if ( !isDetectedBadApp() ) 
			EXIT_MSG("A suspicious application was detected.");*/

		Sleep(100); /* test */ 
	}
}

BOOL DetectDebug ( ) {
	PPEB pPeb;

	__asm push eax
	__asm mov eax, fs:[0x30]
	__asm mov pPeb, eax
	__asm pop eax

	return (BOOL) pPeb->BeingDebugged;
}

BOOL isDetectedBadApp ( ) {
	PROCESSENTRY32 p32 = {0};
	HANDLE hProcess, hProc;
	char szBuff[512] = {0}, szMd5[33];
	DWORD dwRet, dwLen;
	
	if ( (hProcess = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0)) == INVALID_HANDLE_VALUE )
		return FALSE;

	p32.dwSize = sizeof (PROCESSENTRY32);
	Process32First(hProcess, &p32);	

	do {
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p32.th32ProcessID);

		if ( (dwRet = GetModuleFileNameExA(hProc, NULL, szBuff, sizeof szBuff)) > 0 ) {
			GetHashMD5File(szBuff, szMd5);
			
			if ( CompareArrayString(szMd5, g_szMd5BadApp, 7) ) 
				return FALSE;
		}

		CloseHandle(hProc);
	} while ( Process32NextW(hProcess, &p32) );

	CloseHandle(hProcess);

	return TRUE;
}

BOOL GetHashMD5File( const char *szFileName, char *pszMd5 ) {
	MD5_CTX mdContext = { 0 };
	FILE *fp = fopen(szFileName, "rb");
	char szData[1024] = { 0 };
	size_t nRead;
	unsigned char bMd5[MD5_DIGEST_LENGTH];
	unsigned int dwIndex;

	if ( !fp ) 
		return FALSE;

	MD5_Init(&mdContext);

	while ( (nRead = fread(szData, 1, sizeof (szData), fp)) )
		MD5_Update(&mdContext, szData, nRead);

	MD5_Final(bMd5, &mdContext);
	
	for ( dwIndex = 0; dwIndex < MD5_DIGEST_LENGTH; dwIndex++ )
		sprintf(&pszMd5[dwIndex * 2], "%02x", bMd5[dwIndex]);
	
	return TRUE;
}


BOOL CompareArrayString(const char *szText, const char *pArray[], DWORD dwSize ) {
	for ( DWORD dwIndex = 0; dwIndex < dwSize; dwIndex++ ) { 
		if ( strcmp(szText, pArray[dwIndex] ) == 0 ) return TRUE;
	}

	return FALSE;
}

BOOL CheckFolderFileMD5 ( const char *szRootPath, const char *szFolder, const char *szPathBackup, const char *szFiles[], 
							DWORD dwSizeFiles, const char *szMD5Check[], const DWORD dwSizeMD5, BOOL isRemove ) {
	WIN32_FIND_DATAA wFile = {0};
	HANDLE hFile = NULL;
	char szPathFile[MAX_PATH] = {0}, szPathPattern[MAX_PATH] = {0}, szPathFileBackup[MAX_PATH], szBuffMd5[32] = {0};

	_snprintf(szPathPattern, sizeof szPathPattern, "%s%s*", szRootPath, szFolder);
	hFile = FindFirstFileA(szPathPattern, &wFile);

	if ( hFile == INVALID_HANDLE_VALUE ) 
		return FALSE;

	do {
		if ( *(wFile.cFileName) == '.' || wFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) 
			continue;

		_snprintf(szPathFile, sizeof szPathFile, "%s\\%s", szRootPath, wFile.cFileName);

		if ( !CompareArrayString(wFile.cFileName, szFiles, dwSizeFiles) && isRemove ) {
			_snprintf(szPathFileBackup, sizeof szPathFileBackup, "%s\\%s", szPathBackup, wFile.cFileName);
			MoveFileExA(szPathFile, szPathFileBackup, MOVEFILE_REPLACE_EXISTING);
		} else {
			if ( !GetHashMD5File(szPathFile, szBuffMd5) ) 
				return FALSE;

			if ( !CompareArrayString(szBuffMd5, szMD5Check, dwSizeMD5) )
				return FALSE;
		}
	} while ( FindNextFileA(hFile, &wFile ) );

	FindClose(hFile);
	return TRUE;
}


BOOL CheckFileMD5 ( const char *szPathRoot, const char *szFile, const char *szMD5 ) {
	char szBuff[MAX_PATH], szMD5Actually[33];

	_snprintf(szBuff, MAX_PATH, "%s\\%s", szPathRoot, szFile);
	GetHashMD5File(szBuff, szMD5Actually);

	if ( strncmp(szMD5, szMD5Actually, sizeof szMD5Actually) != 0 ) {
		printf("%s\\%s", szPathRoot, szFile	);
		return FALSE;
	}

	return TRUE;
}


BOOL InitMD5Check( ) {
	char szPath[MAX_PATH], szPathBackup[MAX_PATH];

	GetCurrentDirectoryA(MAX_PATH, szPath);

	_snprintf(szPathBackup, MAX_PATH, "%s\\9folder", szPath);
	CreateDirectoryA(szPathBackup, NULL);

	/*CHECKFILE(CheckFolderFileMD5(szPath, "\\", szPathBackup, g_szFile, 28, g_szMd5, 28, TRUE));
	CHECKFILE(CheckFileMD5(szPath, "valve\\cl_dlls\\GameUI.dll", "4c8de6f302d592b6da05b386efe8afac"));
	CHECKFILE(CheckFileMD5(szPath, "valve\\cl_dlls\\particleman.dll", "f0ab4c734cbaf25b5bea698c054af768"));
	CHECKFILE(CheckFileMD5(szPath, "cstrike\\cl_dlls\\client.dll", "4e48070d709c6504dbbba3ade0ab7d9d"));
	CHECKFILE(CheckFileMD5(szPath, "cstrike\\dlls\\mp.dll", "92f5b664ffcb563389341597ed1c76c8"));
	CHECKFILE(CheckFileMD5(szPath, "..\\..\\..\\bin\\XInput1_3.dll", "da9506e800e13da0abba32bb0c105382"));*/
	/*CHECKFILE(CheckFileMD5(szPath, "..\\..\\..\\crashhandler.dll", "a73291b2a26fe6e2f8af35c5322a5a2f"));*/
	/*CHECKFILE(CheckFileMD5(szPath, "..\\..\\..\\gameoverlayrenderer.dll", "3daf150da1ed296c957795eb7e578804"));*/
	/*CHECKFILE(CheckFileMD5(szPath, "..\\..\\..\\steamclient.dll", "753773162d028d0de51a035a6e9a8ac6"));*/
	/*CHECKFILE(CheckFileMD5(szPath, "..\\..\\..\\tier0_s.dll", "10cd368f0f6ec2a692aadacd4c1dfbd3"));*/
	/*CHECKFILE(CheckFileMD5(szPath, "..\\..\\..\\vstdlib_s.dll", "6be502827581d17acd963a15f6ea1144"));*/
	/*CHECKFILE(CheckFileMD5(szPath, "cstrike\\sprites\\gas_puff_01.spr", "ac7c193ca297e483fb9839ed0db2a891"));*/

	return TRUE;
}

BOOL VirtualTableCheck( DWORD dwBase ) {
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *) dwBase;
	IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *) ((DWORD_PTR) pDosHeader + pDosHeader->e_lfanew);

	return FALSE;
}	

BOOL SignatureCheck ( ) {
	// 
	return FALSE;
}

void InitProtectedCalls ( ) {
	/* opengl */
	SetProtectedCalls(0, (DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glBegin"),		0);
	SetProtectedCalls(1, (DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glEnd"),			0);	
	SetProtectedCalls(2, (DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glVertex3fv"),	0);	
	SetProtectedCalls(3, (DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glClear"),		0);
	SetProtectedCalls(4, (DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glPopMatrix"),	0);

	/* motor */
	SetProtectedCalls(5, g_Data.dwBaseEngine + 0xc570,  0);  // GetLocalPlayer
	SetProtectedCalls(6, g_Data.dwBaseEngine + 0x3c730, 0);  // pfnFillRGBA
	SetProtectedCalls(7, g_Data.dwBaseEngine + 0x6d10,  0);  // pfnDrawLocalizedConsoleString
	SetProtectedCalls(8, g_Data.dwBaseEngine + 0xc980,  0);  // pfnSetScreenFade
	SetProtectedCalls(9, g_Data.dwBaseEngine + 0xc5b0,  0);  // GetEntityByIndex
}

void SetProtectedCalls ( DWORD dwIndex, DWORD dwToProtected, DWORD dwOriginalCall ) {
	UNREFERENCED_PARAMETER(dwOriginalCall); /* todav�a no est� la implementaci�n */

	DWORD dwCalc;
	BYTE bCode[52] = {	
		/* 0: pushad */ 0x60,
		/* 4: dword ptr [esp+20h]*/ 0xFF, 0x74, 0x24, 0x20,
		/* 9: push long */ 0x68, 0x00, 0x00, 0x00, 0x00, 
		/* 14: call protected_check */ 0xE8, 0xFC, 0xFF, 0xFF, 0xFF, 
		/* 17: esp, 0x8 */ 0x83, 0xC4, 0x08,
		/* 18: popad */ 0x61,
		/* 24: fn_original */ 0xE9, 0xFC, 0xFF, 0xFF, 0xFF,
		/* 25: ret */ 0xC3 
	};

	g_protectedCallSt[dwIndex].isUnlock = FALSE;
	g_protectedCallSt[dwIndex].dwAddress = dwToProtected;
	memcpy(g_protectedCallSt[dwIndex].bOp, bCode, sizeof (bCode));
	memcpy(&g_protectedCallSt[dwIndex].bOp[6],  &dwIndex, sizeof DWORD);
	dwCalc = ((DWORD) ProtectedCalls_Check - (DWORD) &g_protectedCallSt[dwIndex].bOp[11]) - 4;
	memcpy(&g_protectedCallSt[dwIndex].bOp[11], &dwCalc , sizeof DWORD);
	dwCalc = (dwToProtected - (DWORD) &g_protectedCallSt[dwIndex].bOp[20]) - 4;
	memcpy(&g_protectedCallSt[dwIndex].bOp[20], &dwCalc, sizeof DWORD);

	HookInMemory(0xE9, NULL, NULL, dwToProtected, (DWORD) &g_protectedCallSt[dwIndex].bOp[0], g_protectedCallSt[dwIndex].bBackup);
}

void ProtectedCalls_Check ( DWORD dwIndex, DWORD dwAddr ) {
	MEMORY_BASIC_INFORMATION mInfo;
	char szModule[MAX_PATH], szMd5[33];
	DWORD dwLen;

	VirtualQuery((void *) dwAddr, &mInfo, sizeof (MEMORY_BASIC_INFORMATION));
	dwLen = GetModuleFileNameA((HMODULE) mInfo.AllocationBase, szModule, sizeof (szModule));
	
	/* A�n falta por arreglar y diferenciar que �l m�dulo donde se llama sea legitimo.
	 * Con un dwLen <= 0 deber�a bastar, pero a�n no me convence... 
	 *
	 * if ( dwLen <= 0 || ...?? ) 
	 *    DetectedCheat(dwAddr);
	*/

	//GetMo
	//printf("%s\n", szModule);


	/*if ( dwLen ) {
		GetHashMD5File(szModule, szMd5);
	} else {
		DetectedCheat(dwAddr);
	}*/

	UnHookInMemory(NULL, NULL, g_protectedCallSt[dwIndex].dwAddress, g_protectedCallSt[dwIndex].bBackup);
	g_protectedCallSt[dwIndex].isUnlock = TRUE;
}

void ProtectedCalls_Check_Before ( DWORD dwIndex ) {
	HookInMemory(0xE9, NULL, NULL, g_protectedCallSt[dwIndex].dwAddress, (DWORD) &g_protectedCallSt[dwIndex].bOp[0], g_protectedCallSt[dwIndex].bBackup);
	g_protectedCallSt[dwIndex].isUnlock = FALSE;
}	

BOOL CheckVirtualTableHook ( DWORD *pAddrA, DWORD *pAddrB, DWORD dwBase, DWORD dwSize ) {
	DWORD dwIndex = 0;
	
	for ( ; dwIndex < dwSize; dwIndex++ ) {
		if ( pAddrA[dwIndex] + dwBase != *pAddrB ) return FALSE;
		pAddrB ++;
	}

	return TRUE;
}

void DetectedCheat ( DWORD dwAddr ) {
	DWORD * pInGame = (DWORD *) 0x10565C0 + g_Data.dwBaseClient;

	if ( *pInGame > 4 ) {
		// send data...
	}



	/*if ( dwAddr ) {
		VirtualQuery((LPVOID) dwAddr, &mInf, sizeof (PMEMORY_BASIC_INFORMATION));
		GetModuleFileNameA((HMODULE) mInf.AllocationBase, szFile, sizeof (szFile));

		GetHashMD5File(szFile, szMd5File);

		// Send file to analysis
	}*/

	while ( *pInGame != 4 )
		Sleep(200);

	// 
}