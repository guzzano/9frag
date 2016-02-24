/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto J. Guilarte <volatile@9frag.net>
 */

#pragma once
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


//#include "should.h"
#include "vac.h"
#include "game.h"

#define VDBUG
#define CHEATDETECT(x) if ( !x ) { DetectInstruction(); break; }

#ifdef VDBUG
	void DebugLog( BOOL isPrint, LPCSTR szText, ... );
	#define VDLL_DEBUG_PATH "C:\\Users\\jseg\\vPugDebug\\debug.txt"
#endif


/*

void ProtectedLibrary();

BOOL GetHashMD5File( LPCSTR szFileName, PSTR lpString );
void vDllProtectedGameStart();

void LoadData( LPCSTR szModule, DWORD dwType, DWORD dwOffset, DWORD dwSizeShould, DWORD *lpShould );
void LoadDataDep( DWORD dwType, DWORD dwDep, DWORD dwOffset, DWORD dwSizeShould, DWORD *lpShould );
DWORD *dwBaseOffset( DWORD dwOffset, DWORD dwDll );
BOOL LoadDataForDriverVideo( );
BOOL GetModuleNameForAddress( LPSTR lpFullPath, LPSTR lpName, DWORD dwSize, DWORD dwAddr );

BOOL VTableCheck();
BOOL CheckMemory( DWORD dwAddr, DWORD dwType );
BOOL PathHotValve( DWORD dwAddrHook, DWORD dwType );
void DetectInstruction();
void GetTokenAES128( LPCSTR szName, LPCSTR szPassword );

*/