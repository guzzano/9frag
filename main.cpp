/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto Jsé <v@9frag.net>
 */

#include "main.h"

/*
	client.dll+124484 MONEY 
	hw.dll+1200FAC NAME



	 SCREENINFO
*/

BOOL APIENTRY DllMain( HMODULE hModule, DWORD dwReason, LPVOID lpReserved ) {
//	DWORD dwEngineBase, dwClientBase;
	/*if ( dwReason == DLL_PROCESS_ATTACH ) {
		//ProtectedLibrary();
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) vDllProtectedGameStart, NULL, 0, NULL);
	}*/

	//MessageBoxA(NULL, "Listo el mío.", "Cargado", MB_OK);

	if ( dwReason == DLL_PROCESS_ATTACH ) {
		AllocConsole();

		/*while ( TRUE ) {
			dwEngineBase = (DWORD) GetModuleHandleA("hw.dll");
			dwClientBase = (DWORD) GetModuleHandleA("client.dll");

			if ( ((DWORD *) dwEngineBase) != NULL || ((DWORD *) dwClientBase != NULL ))
				break;

			Sleep(100);
		}
		*/
		//VirtualTableCheck((DWORD) hModule) ;
		Init9fragAC ( );
		//DetectedCheat((DWORD) hModule);
		//DirectoryCheck();
		//VirtualTableCheck((DWORD) hModule);

		// LoadData("hw.dll",      DLL_ENGINE, 0x134260, 131, dwGEngine);
	//LoadData("client.dll",  DLL_CLIENT, 0x122F540, 43, dwGClient);

		//GetHLFn(((DWORD) GetModuleHandleA("hw.dll")) , ((DWORD) GetModuleHandleA("client.dll")));

	}

	return TRUE;
}

void vDllProtectedGameStart ( ) {

}

/*
void ProtectedLibrary() {
	/*CHAR szDirRoot[MAX_PATH] = { 0 };
	DWORD dwSizeRoot = GetCurrentDirectoryA(sizeof szDirRoot, szDirRoot);*/


	
	//HookInMemory("kernel32.dll", "LoadLibraryA", (DWORD) hLoadLibraryA, bLoadLibraryA);

	//SafeDirectory(szDirRoot, "*", dwSizeRoot, szFilesInHLBase, 28);
	//SafeDirectory(szDirRoot, "cstrikecl_dlls*", dwSizeRoot, szFilesInHLCLDLLS, 3);

/*}


/*
	Test signature
*/

/*
BOOL CheckSignature( DWORD dwAddrStart, DWORD dwAddrTo, const unsigned char *pSignature, DWORD dwSize ) {
	DWORD dwByte = dwAddrStart;
	unsigned char *pByte = (unsigned char *) dwAddrStart;

	while ( dwByte <= (dwAddrStart + dwSize) )
	{
		if ( *pSignature != *pByte ) return FALSE;
		pByte = (unsigned char *) dwByte++;
	}

	return TRUE;
}

*/
/*


*/
/*
void vDllProtectedGameStart() {
	const unsigned char sz[15] = "\x83\xC4\x04\x89\x44\x16\x08\x8D\x47\x01\x5F\x5E\x5D\xC";

	LoadData("hw.dll",      DLL_ENGINE, 0x134260, 131, dwGEngine);
	CheckSignature(g_Data[DLL_ENGINE].dwBase, g_Data[DLL_ENGINE].dwBase + 0x1258000, sz, 15);

	//LoadData("hw.dll",      DLL_ENGINE, 0x134260, 131, dwGEngine);
	//LoadData("client.dll",  DLL_CLIENT, 0x122F540, 43, dwGClient);
	//LoadDataDep(DLL_STUDIO, DLL_ENGINE, 0x1502F0,  43, dwGStudio);

	//LoadDataForDriverVideo();



	//TabGameHook();
	//GetHLFn();
	//GetTokenAES128("_volatile_", "123456test");
	
	while ( TRUE ) { 
		if( IsDebuggerPresent() ) {
			MessageBoxA(NULL, "Oh sorry... but nice try.", "9frag alert!", MB_OK);
			ExitProcess(0x0);
		}

		//CHEATDETECT(VTableCheck());

		Sleep(100);
	}
}


void LoadData( LPCSTR szModule, DWORD dwType, DWORD dwOffset, DWORD dwSizeShould, DWORD *lpShould ) {
	DWORD dwIndex;

	while ( TRUE ) {
		DWORD dwBase = (DWORD) GetModuleHandleA(szModule);

		if ( dwBase ) {
			g_Data[dwType].dwBase = dwBase;
			g_Data[dwType].lpAddr = (DWORD *) (g_Data[DLL_ENGINE].dwBase + dwOffset);

			for ( dwIndex = 0; dwIndex < dwSizeShould; dwIndex++ ) {
				if ( lpShould[dwIndex] != 0 ) {
					lpShould[dwIndex] += g_Data[dwType].dwBase;
				}
			}

			g_Data[dwType].dwSizeShould = dwSizeShould;
			g_Data[dwType].lpShould = lpShould;

			break;
		}

		Sleep(100);
	}
}

void LoadDataDep( DWORD dwType, DWORD dwDep, DWORD dwOffset, DWORD dwSizeShould, DWORD *lpShould ) {
	DWORD dwIndex;

	g_Data[dwType].dwBase = g_Data[dwDep].dwBase;
	g_Data[dwType].lpAddr = dwBaseOffset(dwOffset, dwDep);

	for ( dwIndex = 0; dwIndex < dwSizeShould; dwIndex++ ) {
		if ( lpShould[dwIndex] != 0 ) {
			lpShould[dwIndex] += g_Data[dwType].dwBase;
		}
	}

	g_Data[dwType].dwSizeShould = dwSizeShould;
	g_Data[dwType].lpShould = lpShould;
}

DWORD * dwBaseOffset( DWORD dwOffset, DWORD dwDll ) {
	return (DWORD *) (g_Data[dwDll].dwBase + dwOffset);
}

BOOL LoadDataForDriverVideo( ) {

	MEMORY_BASIC_INFORMATION mInfo;
	char szPathModule[MAX_PATH], *lpNameModule;
	DWORD *lpAddr = (DWORD *) (0xA8E664 + g_Data[DLL_ENGINE].dwBase); 


	VirtualQuery((LPVOID) *lpAddr, &mInfo, sizeof (MEMORY_BASIC_INFORMATION));
	GetModuleFileNameA((HMODULE) mInfo.AllocationBase, szPathModule, MAX_PATH);

	if ( !(lpNameModule = strrchr(szPathModule, '')) ) {
		return FALSE;
	}

	lpNameModule ++;
	

	DWORD lpAddr = (DWORD) (0xA8E664 + g_Data[DLL_ENGINE].dwBase); 
	char szPathModule[MAX_PATH], *lpName = NULL;
	GetModuleNameForAddress(szPathModule, lpName, MAX_PATH, lpAddr);

	//DebugLog(TRUE, "%s - %s", szPathModule, &lpName);

	return TRUE;
}

BOOL GetModuleNameForAddress( LPSTR lpFullPath, LPSTR lpModuleName, DWORD dwSize, DWORD dwAddr ) {
	MEMORY_BASIC_INFORMATION mInfo;
	SIZE_T nSize;

	nSize = VirtualQuery((LPVOID) dwAddr, &mInfo, sizeof (MEMORY_BASIC_INFORMATION));

	if ( !nSize ) 
		return FALSE;

	GetModuleFileNameA((HMODULE) mInfo.AllocationBase, lpFullPath, dwSize);

	return TRUE;
}


BOOL VTableCheck() {
	DWORD dwIndex, dwType = 0;
	DWORD *dwAddr;

	while ( dwType < VDLL_STRUCT_SIZE ) {
		dwAddr = g_Data[dwType].lpAddr;

		for ( dwIndex = 0; dwIndex < g_Data[dwType].dwSizeShould; dwIndex++, dwAddr++ ) {
			if ( *dwAddr != g_Data[dwType].lpShould[dwIndex] || !CheckMemory(*dwAddr, dwType) ) {
				return FALSE;
			}
		}

		dwType++;
	}

	return TRUE;
}

BOOL CheckMemory( DWORD dwAddr, DWORD dwType ) {
	BYTE bData[5]; 
	SIZE_T dwRead;
	DWORD dwAddrHook;

	if ( ReadProcessMemory(GetCurrentProcess(), (LPVOID) dwAddr, bData, sizeof bData, &dwRead) ) {

		if ( dwRead != sizeof bData) {
			return FALSE;
		}
		
		dwAddrHook = (bData[1] + (bData[2] << 8) + (bData[3] << 16) + (bData[4] << 24));
		dwAddrHook += dwAddr + 5;
	
		switch ( bData[0] ) {
			case 0xE9: // jump
			case 0xEB: // jump short
			case 0xE8: // call
			if ( !PathHotValve(dwAddrHook, dwType) ) {
				return FALSE;
			}
		}
	} else {
		return FALSE;
	}

	return TRUE;
}

BOOL PathHotValve( DWORD dwAddrHook, DWORD dwType ) {
	DWORD dwIndex;
	DWORD dwOffsetClient[7] = {0x58140, 0x2e610, 0x61d00, 0x61dd0, 0x5c660, 0xbd20, 0x588e0};

	if ( dwType == DLL_ENGINE ) {
		if ( dwAddrHook  == (0x27700 + g_Data[DLL_ENGINE].dwBase) )
			return TRUE; 
	} else if ( dwType == DLL_CLIENT ) {
		for ( dwIndex = 0; dwIndex < 7; dwIndex++ ) { 
			if ( (dwOffsetClient[dwIndex] + g_Data[DLL_CLIENT].dwBase == dwAddrHook) ) {
				return TRUE;
			}
		}
	} else if ( dwType == DLL_STUDIO ) {
		if ( dwAddrHook == (0x85060 + g_Data[DLL_ENGINE].dwBase) ) {
			return TRUE;
		}
	} else {
		return FALSE;
	}

	return FALSE;
}

void DetectInstruction() {
	PDWORD lpInGame = (PDWORD) 0x10565C0 + g_Data[DLL_ENGINE].dwBase; 

	while ( *lpInGame != 5 ) 
		Sleep(100);
	

	// SendData
	//MessageBoxA(NULL, "Detected", "debug", MB_OK);
	//TerminateProcess(GetCurrentProcess(), 0x0);
	//ConnectWith9frag(cHandle, "9frag.net/banned.php", szPostField, NULL)
}

#ifdef VDBUG
void DebugLog( BOOL isPrint, LPCSTR szText, ... ) {
	FILE *fp = fopen(VDLL_DEBUG_PATH, "a+");
	CHAR szBuff[512];
	va_list lpArg;

	va_start(lpArg, szText);
	vsnprintf(szBuff, sizeof szBuff, szText, lpArg);

	if ( isPrint ) {
		MessageBoxA(NULL, szBuff, "debug", MB_OK);
	} else 
	{
		if ( fp ) {
			fprintf(fp, szBuff);
			fclose(fp);
		}
	}
}
#endif
*/