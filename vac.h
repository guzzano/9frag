/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto Jsé <v@9frag.net>
 */

#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <openssl/md5.h>
#include <DbgHelp.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Pathcch.h>

#include "hook.h"

#define EXIT_MSG(x) { MessageBoxA(NULL, x, "9frag vAC", MB_OK); ExitProcess(0x0); }
#define D_CHEAT(y) if ( !y ) { DetectedCheat(0); }

/*
typedef struct _WIN32LDR
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;

     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };

     _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} WIN32LDR;
*/


typedef struct {
	DWORD dwBaseEngine;
	DWORD dwBaseClient;
} GameData;

typedef struct _ProtectedCalls_ {
	/* for protected calls */
	DWORD dwAddress;
	DWORD dwEsp;
	BYTE bOp[70];
	BYTE bBackup[5];
	BOOL isUnlock;
} pCall;

typedef struct _PagesModules_ {
	DWORD dwBase;
	DWORD dwSize;
	struct _PagesModules_ * pNext;
} PagesModules;

static DWORD g_dwClient[43] =
{
    0x436e0, 0x439a0, 0x43990, 0x43a30, 0x43a50, 0x43a70, 0x435f0,
    0x435d0, 0x435e0, 0x2d9a0, 0x2d9e0, 0x2dc40, 0x2e350, 0x2e1d0, 
	0x57970, 0x56b70, 0x56ba0, 0x56ce0, 0x56010, 0x6c580, 0x44eb0,
	0x452e0, 0x68ee0, 0x68ef0, 0x45300, 0x0ec30, 0x439b0, 0x44f60,
    0x44fb0, 0x45160, 0x44e30, 0x435c0, 0x435a0, 0x43a80, 0x56fe0,
    0x45450, 0x45dd0, 0x43aa0, 0x43b30, 0x497c0, 0x27f10, 0x43b50,
    0x43b70
}, g_dwEngine[131] = 
{
    0x011400, 0x0116a0, 0x011710, 0x0116d0, 0x011770, 0x011810,
    0x011890, 0x011910, 0x011a30, 0x011a70, 0x00c070, 0x03c730, 
	0x00a810, 0x011320, 0x00a880, 0x00a8d0, 0x00a910, 0x00a940,
    0x00aa50, 0x00a970, 0x00aa10, 0x00aa80, 0x00abe0, 0x00ae40,
    0x060ee0, 0x0b1760, 0x0b1860, 0x03b600, 0x03b540, 0x00afb0,
    0x00aff0, 0x00b010, 0x00c1e0, 0x00c1f0, 0x00c200, 0x00c240,
    0x00c270, 0x02dcd0, 0x0277b0, 0x0277c0, 0x02c080, 0x02c1a0,
    0x02c540, 0x02c5c0, 0x00c280, 0x00c2a0, 0x00c910, 0x06f8b0,
    0x05fe90, 0x00c2c0, 0x00c520, 0x00c570, 0x00c5a0, 0x00c5b0,
    0x00c5f0, 0x0bff50, 0x0c0150, 0x06a060, 0x06a0f0, 0x06ad70, 
	0x00c660, 0x00c6c0, 0x00c730, 0x00af00, 0x00c750, 0x00c7a0,
    0x00c8c0, 0x06ef40, 0x06ef70, 0x01ea70, 0x02c650, 0x00c920,
    0x02d7e0, 0x05fbd0, 0x00c930, 0x00c950, 0x00c980, 0x0bf1a0,
    0x0b51e0, 0x02ad70, 0x00bfa0, 0x02aed0, 0x150578, 0x14fe90,
	0x13e7e8, 0x1352d4, 0x14a7ac, 0x15ac84, 0x0203a0, 0x044e30,
    0x00ca10, 0x00ca40, 0x00cad0, 0x00cb50, 0x00cc00, 0x00cc70,
    0x00cc90, 0x00a9c0, 0x00c3e0, 0x00c500, 0x036c80, 0x00ccb0,
    0x00ccc0, 0x00ccd0, 0x00cce0, 0x00c610, 0x00c630, 0x00c640,
    0x0112a0, 0x0112c0, 0x011300, 0x089690, 0x011990, 0x088f50,
    0x006ca0, 0x006d10, 0x00cb30, 0x006a70, 0x006b20, 0x02b9d0,
    0x007880, 0x02dc90, 0x007860, 0x00ad70, 0x0091b0, 0x0a8610,
    0x007900, 0x007940, 0x007990, 0x00aca0, 0x03c8e0
};

static const char *g_szMd5BadApp[] = { 
	/* DCInjector.exe */ "d7a7966cc50771be6bd25bf494ee9673", /* sinJect.exe */"1de8afdce3d6c1c2e05b83c7ce77fd30", 
	/* Winject.exe */ "d17e73c68c23598558f5b3c23da04755", /*ollydbg v1 */ "bd3abb4ac01da6edb30006cc55953be8", 
	/* ollydbg v2 */ "a8d8531a3995494a1cfc62f7e7cc77ec", /* autoinjectordll */"1dbb21e7ef1732f3235227e2a9d84c23",
	/*extreme-injector */ "ecc00d4e4b2cbf7caefdce122f017c3d"
};

static pCall g_protectedCallSt[1024] = {0};
static BYTE g_bVirtualQuery[6]  = {0};
static GameData g_Data = {0};
static DWORD g_dwIndexProtectedCall = 0;
static PagesModules * g_pFirts = NULL, *g_pLast = NULL;

void Init9fragAC ( );
void StartAC ( );
BOOL isDetectedBadApp ( );
BOOL DetectDebug ( );
BOOL GetHashMD5File( const char *szFileName, char *pszMd5 );
BOOL CompareArrayString(const char *szText, const char *pArray[], DWORD dwSize );
BOOL VirtualTableCheck( DWORD dwBase );
BOOL SignatureCheck ( );
void InitProtectedCalls ( );
void SetProtectedCalls ( DWORD dwToProtected, DWORD dwOriginalCall );
void ProtectedCalls_Check ( DWORD dwAddr, DWORD dwIndex );
void ProtectedCalls_Rehook ( ) ;
BOOL CheckVirtualTableHook ( DWORD *pAddrA, DWORD *pAddrB, DWORD dwBase, DWORD dwSize );
void DetectedCheat( DWORD dwAddr );

