/*	
	Copyright (c) 9frag.ve - all rights reserved.	

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto Jsé <v@9frag.net>
 */

#include "vac.h"


/*LONG WINAPI UnhandledException (LPEXCEPTION_POINTERS exceptionInfo)  
{
	MessageBoxA(NULL, "... *sorry, vAC is crashed* ;(", "9frag alert!", MB_OK);
	return EXCEPTION_EXECUTE_HANDLER;  
}*/

void Init9fragAC ( ) {
	AllocConsole();

	while ( TRUE ) {
		g_Data.dwBaseEngine = (DWORD) GetModuleHandleA("hw.dll");
		g_Data.dwBaseClient = (DWORD) GetModuleHandleA("client.dll");

		if ( g_Data.dwBaseClient && g_Data.dwBaseEngine && ((DWORD *) (g_Data.dwBaseEngine + 0x0134260)) != NULL 
			&& ((DWORD *) (g_Data.dwBaseEngine + 0x0134260)) != NULL  ) break;
	}

	if ( !CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) StartAC, NULL, 0, NULL) )
		EXIT_MSG("Discúlpanos, vAC no se puedo iniciar, reinicia la computadora y intenta de nuevo.");
}

//void AnalysisMemoryAdd


BOOL isReaMemory( DWORD dwProtect ) {
	switch ( dwProtect ) {
		case PAGE_EXECUTE:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
		case PAGE_READONLY:
		case PAGE_WRITECOPY:
			return TRUE;
	}

	return FALSE;
}

BYTE *SearchBytePattern ( BYTE *pData, DWORD dwLenData, BYTE *pPattern, DWORD dwLenPattern ) {
	BYTE *pFound, *pTemp = pData;
	DWORD dwLen = dwLenData;

	while ( (pFound = (BYTE *) memchr(pTemp, pPattern[0], sizeof (BYTE))) != NULL ) {
		if ( memcmp(pFound, pPattern, dwLenPattern ) == 0 ) return pFound;
		pTemp = (BYTE *) pFound + dwLenPattern;

		if ( (DWORD) (pTemp - pData) > dwLenData) break; 
	}

	return NULL;
}

void AddBaseModules( DWORD dwBase ) {
	PagesModules *pAux = (PagesModules *) malloc(sizeof(PagesModules));
	if ( !pAux ) return;

	pAux->dwBase = dwBase;
	pAux->pNext = NULL;

	if ( !g_pFirts ) {
		g_pFirts = pAux;
		g_pLast = pAux;
	} else { 
		g_pLast->pNext = pAux;
		g_pLast = pAux;
	}
}

void RemoveBaseModules( DWORD dwBase ) {
	PagesModules *pAux = g_pFirts, *pPrev = NULL;
	if ( !pAux ) return;

	while ( pAux != NULL ) {
		if ( pAux->dwBase == dwBase ) {
			if ( pPrev ) pPrev->pNext = pAux->pNext;
			else if ( !pPrev ) g_pFirts = pAux->pNext;
		}

		pPrev = pAux;
		pAux = pAux->pNext;
	}
}

/* La idea principal era hacerlo funcionar mediante en analísis de la memoria y la comparación con 
 * los módulos en ldr del PEB, pero en esta versión no sé porque no hay margen correcto en la estructura
 * y me da datos en donde no debería.

	LDR_DATA_TABLE_ENTRY *pLdrDLL;

 	__asm push eax
	__asm mov eax, fs:[ 0x30 ]
	__asm mov eax, [ eax + 0xC ]
	__asm mov eax, [ eax + 0x14 ]
	__asm mov pLdrDLL, eax
	__asm pop eax 
*/

BOOL AnalysisMemoryPages( ) {
	BYTE MZHeader[4] = {0x4D, 0x5A, 0x90}, *pData = NULL, *pFound = NULL;
	MEMORY_BASIC_INFORMATION mInfo = {0};
	SYSTEM_INFO sInfo = {0};
	DWORD dwLast = 0, dwBase;
	HANDLE hSnap;
	MODULEENTRY32 m32 = {0};

	GetSystemInfo(&sInfo);

	for ( DWORD dwAddr = 0; dwAddr <= (DWORD) sInfo.lpMaximumApplicationAddress; ) {
		VirtualQuery((void *) dwAddr, &mInfo, sizeof (MEMORY_BASIC_INFORMATION));
		if ( mInfo.State == MEM_COMMIT && isReaMemory(mInfo.Protect) ) {	
			dwBase = ( dwLast == (DWORD) mInfo.AllocationBase ) ? (DWORD) mInfo.BaseAddress : (DWORD) mInfo.AllocationBase; 
			pData = (BYTE *) dwBase;

			if ( (pFound = SearchBytePattern(pData, (DWORD) mInfo.RegionSize, MZHeader, sizeof (MZHeader))) != NULL )
				AddBaseModules(dwBase);

			dwLast = (DWORD) mInfo.AllocationBase;
		}

		dwAddr += mInfo.RegionSize;
		memset(&mInfo, 0, sizeof (MEMORY_BASIC_INFORMATION));
	}

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE , 0);

	if ( hSnap == INVALID_HANDLE_VALUE ) 
		return FALSE;

	m32.dwSize = sizeof (MODULEENTRY32);
	Module32First(hSnap, &m32);

	do {
		RemoveBaseModules((DWORD) m32.modBaseAddr);
	} while ( Module32Next(hSnap, &m32) );


	return TRUE;
}



void StartAC ( ) {
	AnalysisMemoryPages();
	return;

	InitProtectedCalls();
	
	while ( TRUE ) {
		ProtectedCalls_Rehook();
		//AnalysisMemoryPages();

		//D_CHEAT( CheckVirtualTableHook (g_dwEngine, (DWORD *) (g_Data.dwBaseEngine +  0x0134260), g_Data.dwBaseEngine, 131) );
		//D_CHEAT( CheckVirtualTableHook (g_dwClient, (DWORD *) (g_Data.dwBaseEngine +  0x122F540), g_Data.dwBaseClient,  43) );
		
		//if ( DetectDebug() ) EXIT_MSG("Se detectó un depurador.");
		//if ( !isDetectedBadApp() ) EXIT_MSG("Se detectó una aplicación no permitida.");

		Sleep(100);
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
			if ( CompareArrayString(szMd5, g_szMd5BadApp, 1) ) return FALSE;
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

	if ( !fp ) 
		return FALSE;

	MD5_Init(&mdContext);

	while ( (nRead = fread(szData, 1, sizeof (szData), fp)) )
		MD5_Update(&mdContext, szData, nRead);

	MD5_Final(bMd5, &mdContext);
	
	for ( DWORD dwIndex = 0; dwIndex < MD5_DIGEST_LENGTH; dwIndex++ )
		sprintf(&pszMd5[dwIndex * 2], "%02x", bMd5[dwIndex]);
	
	return TRUE;
}


BOOL CompareArrayString(const char *szText, const char *pArray[], DWORD dwSize ) {
	for ( DWORD dwIndex = 0; dwIndex < dwSize; dwIndex++ ) { 
		if ( strcmp(szText, pArray[dwIndex] ) == 0 ) return TRUE;
	}

	return FALSE;
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
	SetProtectedCalls((DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glBegin"), 0);
	SetProtectedCalls((DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glEnd"),	0);	
	SetProtectedCalls((DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glVertex3fv"), 0);	
	SetProtectedCalls((DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glClear"), 0);
	SetProtectedCalls((DWORD) GetProcAddress(GetModuleHandleA("opengl32.dll"), "glPopMatrix"), 0);

	SetProtectedCalls(g_Data.dwBaseEngine + 0xc570, 0);  // GetLocalPlayer
	SetProtectedCalls(g_Data.dwBaseEngine + 0x3c730, 0);  // pfnFillRGBA
	SetProtectedCalls(g_Data.dwBaseEngine + 0x6d10, 0);  // pfnDrawLocalizedConsoleString
	SetProtectedCalls(g_Data.dwBaseEngine + 0xc980, 0);  // pfnSetScreenFade
	SetProtectedCalls(g_Data.dwBaseEngine + 0xc5b0, 0);  // GetEntityByIndex
}

void SetProtectedCalls ( DWORD dwToProtected, DWORD dwOriginalCall ) {
	UNREFERENCED_PARAMETER(dwOriginalCall); /* todavía no está la implementación */

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

	g_protectedCallSt[g_dwIndexProtectedCall].isUnlock = FALSE;
	g_protectedCallSt[g_dwIndexProtectedCall].dwAddress = dwToProtected;
	memcpy(g_protectedCallSt[g_dwIndexProtectedCall].bOp, bCode, sizeof (bCode));
	memcpy(&g_protectedCallSt[g_dwIndexProtectedCall].bOp[6],  &g_dwIndexProtectedCall, sizeof DWORD);
	dwCalc = ((DWORD) ProtectedCalls_Check - (DWORD) &g_protectedCallSt[g_dwIndexProtectedCall].bOp[11]) - 4;
	memcpy(&g_protectedCallSt[g_dwIndexProtectedCall].bOp[11], &dwCalc , sizeof DWORD);
	dwCalc = (dwToProtected - (DWORD) &g_protectedCallSt[g_dwIndexProtectedCall].bOp[20]) - 4;
	memcpy(&g_protectedCallSt[g_dwIndexProtectedCall].bOp[20], &dwCalc, sizeof DWORD);

	HookInMemory(0xE9, NULL, NULL, dwToProtected, (DWORD) &g_protectedCallSt[g_dwIndexProtectedCall].bOp[0], g_protectedCallSt[g_dwIndexProtectedCall].bBackup);

	g_dwIndexProtectedCall++;
}

void ProtectedCalls_Check ( DWORD dwIndex, DWORD dwAddr ) {
	MEMORY_BASIC_INFORMATION mInfo;
	char szModule[MAX_PATH], szMd5[33];
	DWORD dwRetVirtual, dwRetFileName;
	IMAGE_DOS_HEADER *pDosHeader;
	IMAGE_NT_HEADERS *pNtHeader;

	dwRetVirtual = VirtualQuery((void *) dwAddr, &mInfo, sizeof (MEMORY_BASIC_INFORMATION));

	pDosHeader = (IMAGE_DOS_HEADER *) mInfo.AllocationBase;
	pNtHeader = (IMAGE_NT_HEADERS *) ((DWORD_PTR) pDosHeader + pDosHeader->e_lfanew);

	dwRetFileName = GetModuleFileNameA((HMODULE) mInfo.AllocationBase, szModule, sizeof (szModule));

	if ( !dwRetFileName || !dwRetVirtual || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE )
		DetectedCheat(dwAddr); 

	UnHookInMemory(NULL, NULL, g_protectedCallSt[dwIndex].dwAddress, g_protectedCallSt[dwIndex].bBackup);
	g_protectedCallSt[dwIndex].isUnlock = TRUE;
}

void ProtectedCalls_Rehook ( ) {
	for ( DWORD dwIndex = 0; dwIndex < g_dwIndexProtectedCall; dwIndex++)
		if ( g_protectedCallSt[dwIndex].isUnlock ) {
			HookInMemory(0xE9, NULL, NULL, g_protectedCallSt[dwIndex].dwAddress, (DWORD) &g_protectedCallSt[dwIndex].bOp[0], NULL);
			g_protectedCallSt[dwIndex].isUnlock = FALSE;

			break;
		}
}	

BOOL CheckVirtualTableHook ( DWORD *pAddrA, DWORD *pAddrB, DWORD dwBase, DWORD dwSize ) {	
	for ( DWORD dwIndex = 0; dwIndex < dwSize; dwIndex++, pAddrB ++ ) {
		if ( pAddrA[dwIndex] + dwBase != *pAddrB ) return FALSE;
	}

	return TRUE;
}

void DetectedCheat ( DWORD dwAddr ) {
	MessageBox(NULL, L"Se detectó una llamada inusual.", L"debug", MB_OK);
	return;
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