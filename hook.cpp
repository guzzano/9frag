/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto Jsé <v@9frag.net>
 */

#include "hook.h"

DWORD HookInMemory( BYTE bType, LPCSTR szModule, LPCSTR szFnName, DWORD dwFn, DWORD dwTo, PBYTE lpBackup ) {
	DWORD dwPrevProtect, dwFrom, dwCalc;
	BYTE bData[5] = { /*0xE9*/ bType, 0x0, 0x0, 0x0, 0x0};

	dwFrom = ( !szFnName ) ? dwFn : (DWORD) GetProcAddress(GetModuleHandleA(szModule), szFnName);

	dwCalc = (dwTo - dwFrom - 5);
	memcpy(&bData[1], &dwCalc, 4);

	if ( lpBackup )
		ReadProcessMemory(GetCurrentProcess(), (LPVOID) dwFrom, lpBackup, sizeof bData, NULL);
	
	VirtualProtect((LPVOID) dwFrom, 5, PAGE_EXECUTE_READWRITE, &dwPrevProtect);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID) dwFrom, bData, 5, NULL);
	VirtualProtect((LPVOID) dwFrom, 5, dwPrevProtect, &dwPrevProtect);

	return dwFrom;
}

void UnHookInMemory( LPCSTR szModule, LPCSTR szFunName, DWORD dwFn, PBYTE lpBackup ) {
	DWORD dwPrevProtect;
	DWORD dwAddr = ( !szFunName ) ? dwFn : (DWORD) GetProcAddress(GetModuleHandleA(szModule), szFunName);

	VirtualProtect((LPVOID) dwAddr, 5, PAGE_EXECUTE_READWRITE, &dwPrevProtect);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID) dwAddr, lpBackup, 5, NULL);		
	VirtualProtect((LPVOID) dwAddr, 5, dwPrevProtect, &dwPrevProtect);
}