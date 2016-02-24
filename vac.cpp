/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto Jsé <v@9frag.net>
 */

#include "vac.h"

/*
LONG WINAPI UnhandledException (LPEXCEPTION_POINTERS exceptionInfo)  
{
	if ( exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ) {
		//
			
	}


	return EXCEPTION_EXECUTE_HANDLER;  
}  
*/

void Init9fragAC ( ) {
	/*if ( !InitMD5Check( ) )
		EXIT_MSG("Sorry, you failed the directory safety test. Update client or delete suspicious files."); */

	//SetUnhandledExceptionFilter(UnhandledException);

	while ( TRUE ) {
		g_Data.dwBaseEngine = (DWORD) GetModuleHandleA("hw.dll");
		g_Data.dwBaseClient = (DWORD) GetModuleHandleA("client.dll");

		if ( g_Data.dwBaseClient && g_Data.dwBaseEngine && ((DWORD *) (g_Data.dwBaseEngine + 0x0134260)) != NULL 
			&& ((DWORD *) (g_Data.dwBaseEngine + 0x0134260)) != NULL  ) break;
	}

	if ( !CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) StartAC, NULL, 0, NULL) )
		EXIT_MSG("Sorry, vAC thread cannot start. Please reboot computer.");;
}	

/*void HideModule ( DWORD dwBase ) {
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *) dwBase;		
	IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *) ((DWORD_PTR) pDosHeader + pDosHeader->e_lfanew);
	DWORD dwOldProtect;		
	TEB *pTeb;
	PEB *pPeb;
	LIST_ENTRY *pList;

	_asm {
		mov eax, fs:[0x18]
		mov pTeb, eax
	}

	pPeb = pTeb->ProcessEnvironmentBlock;
	pList = pPeb->Ldr->InMemoryOrderModuleList.Flink;
	
	while ( (DWORD) ((LDR_DATA_TABLE_ENTRY *) pList)->Reserved2[0] != 0 ) {
		if ( (DWORD) ((LDR_DATA_TABLE_ENTRY *) pList)->Reserved2[0] == dwBase ) {
			VirtualProtect((void *) pList, sizeof LDR_DATA_TABLE_ENTRY, PAGE_EXECUTE_READWRITE, &dwOldProtect);

			memset(((LDR_DATA_TABLE_ENTRY *) pList)->FullDllName.Buffer, 0, ((LDR_DATA_TABLE_ENTRY *) pList)->FullDllName.Length);
			// FIXME: memset pList 0 

			pList->Flink->Blink = pList->Flink->Flink;
			pList->Blink->Flink = pList->Blink->Flink->Flink;

			VirtualProtect((void *) pList, sizeof LDR_DATA_TABLE_ENTRY, dwOldProtect, &dwOldProtect);
		}

		pList = pList->Flink;
	}	

	VirtualProtect((void*)pDosHeader, sizeof IMAGE_DOS_HEADER, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	VirtualProtect((void*)pNtHeader, sizeof IMAGE_NT_HEADERS, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	RtlZeroMemory((void*)pDosHeader, sizeof IMAGE_DOS_HEADER);
	RtlZeroMemory((void*)pNtHeader, sizeof IMAGE_DOS_HEADER);
}*/


void StartAC ( ) {
	BOOL isDetected;
	//InitProtectedMemory();
	//ProtectedMemory();
	// HideModule((DWORD) GetModuleHandleA("vDLL.dll"));
	// 
	//HookInMemory(0xE9, "kernel32.dll", "VirtualProtect", 0, (DWORD) VirtualProtect_Hook, NULL);
	//DWORD s;
	//VirtualProtect(0x0, 0x0, 0x0, &s);
	//MessageBoxA(NULL, "debug", "debug", MB_OK);

	
	//HookInMemory(0xE9, "kernel32.dll", "LoadLibraryA", 0, (DWORD) LoadLibraryA_hook, g_bVirtualQuery); 
	DWORD dwBs = ((DWORD) /*GetModuleHandleA("client.dll")) + 0x43a30;*/ GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
	InitProtectedCalls(0, dwBs);	

	//DWORD d;
	//VirtualProtect(0, 0x0, 0, &d);
	//VirtualProtect(0, 0x0, 0, &d);

	while ( TRUE ) {
		CHECK_VHOOK(isDetected, CheckVirtualTableHook (g_dwEngine, (DWORD *) (g_Data.dwBaseEngine +  0x0134260), g_Data.dwBaseEngine, 131));
		CHECK_VHOOK(isDetected, CheckVirtualTableHook (g_dwClient, (DWORD *) (g_Data.dwBaseEngine +  0x122F540), g_Data.dwBaseClient,  43));

		/* Solo para pruebas, se tomará en cuanta un hilo con eventos. */
		for ( DWORD dwIndex = 0; dwIndex < CHECK_ESP_FN_CURRENT; dwIndex++) {
			if ( g_protectedCallSt[dwIndex].isUnlock ) 
				ProtectedCalls_Check_Before(dwIndex);
		}
			
		/*if ( !DetectBadAppAndDebug() ) 
			ExitProcess(0x0);*/

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

void InitProtectedCalls ( DWORD dwIndex, DWORD dwToProtected ) {
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
	char szModule[MAX_PATH];

	VirtualQuery((void *) dwAddr, &mInfo, sizeof (MEMORY_BASIC_INFORMATION));
	GetModuleFileNameA((HMODULE) mInfo.AllocationBase, szModule, sizeof (szModule));
	
	printf("%s\n", szModule);

	UnHookInMemory(NULL, NULL, g_protectedCallSt[dwIndex].dwAddress, g_protectedCallSt[dwIndex].bBackup);
	g_protectedCallSt[dwIndex].isUnlock = TRUE;
}

void ProtectedCalls_Check_Before ( DWORD dwIndex ) {
	HookInMemory(0xE9, NULL, NULL, g_protectedCallSt[dwIndex].dwAddress, (DWORD) &g_protectedCallSt[dwIndex].bOp[0], NULL);
	g_protectedCallSt[dwIndex].isUnlock = FALSE;
}

BOOL CheckVirtualTableHook ( DWORD *pAddrA, DWORD *pAddrB, DWORD dwBase, DWORD dwSize ) {
	DWORD dwIndex = 0;
	
	for ( ; dwIndex < dwSize; dwIndex++ ) {
		if ( pAddrA[dwIndex] + dwBase != *pAddrB ) return FALSE;
		printf("%x - %x", pAddrA[dwIndex] + dwBase,  *pAddrB);
		pAddrB ++;
	}

	return TRUE;
}

void DetectedCheat( DWORD dwAddr ) {
	MessageBoxA(NULL, "Detected", "9frag", MB_OK);
	return; 

	DWORD * pInGame = (DWORD *) 0x10565C0 ; // + Base Module;
	MEMORY_BASIC_INFORMATION mInf = { 0 };
	char szFile[512], szMd5File[33];

	MessageBoxA(NULL, "Detected", "Detected", MB_OK);

	if ( dwAddr ) {
		VirtualQuery((LPVOID) dwAddr, &mInf, sizeof (PMEMORY_BASIC_INFORMATION));
		GetModuleFileNameA((HMODULE) mInf.AllocationBase, szFile, sizeof (szFile));

		GetHashMD5File(szFile, szMd5File);

		// Send file to analysis
	}

	while ( *pInGame != 4 )
		Sleep(200);

	// 
}