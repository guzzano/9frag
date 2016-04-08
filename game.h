/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto J. Guilarte <volatile@9frag.net>
 */

#pragma once
#include <windows.h>

#include "valve/parsemsg.h"
#include "hook.h"
#include "HLSDK/engine/wrect.h"
#include "HLSDK/engine/cl_dll.h"
#include "HLSDK/engine/cdll_int.h"

#include <gl\GL.h>
#include <gl\GLU.h>


#define MAX_PLAYERS 10

typedef struct {
	char *lpName;
	BYTE lpExp;
	short nRank;

	BOOL isReady;
	BOOL isInGame;
} gPlayer;

typedef struct {
	DWORD dwEngine;
	DWORD dwClient;

	// screen
	int nWidth;
	int nHeight;

	int sprData[2];	
	BOOL isFirtsFinish;
	BOOL isPugFinish;
	BOOL isPlayerWin;
	float fTimeFinish;

	BOOL isPugIsLive;
	BOOL IsTutorLive;
	
	/* */

	short int nLocalPlayer;
	gPlayer gpData[10];

} vPugData;

static vPugData	     g_vData    = {0};
static cl_enginefunc_t *g_pEngine  = NULL;

static int (*pfnHUD_Redraw)( float, int );
static int (*pfnKey_Event)(int, int, const char *);

void GetHLFn( DWORD dwEngine, DWORD dwClient );
int EventvPugUserReady ( const char *szName, int nSize, void *lpBuf );
int EventvPugFinishData ( const char *szName, int nSize, void *lpBuf );
int EventvPugConnectInit ( const char *szName, int nSize, void *lpBuf );
void TabGameHook( );
BOOL VerifyStatusPug ( DWORD dwIndex );
void vTest( );
int HUD_Redraw( float flTime, int intermission );
void DrawTextWColor( int nX, int nY, const char * szText, int nR, int nG, int nB );
void HUD_PugIsFinish_Add( DWORD dwIndex, DWORD nX, DWORD nY, const char *nRank, const char *szName, const char *szExp );
void HUD_PugIsFinish( float flTime );
int Key_Event ( int down, int keynum, const char *pszCurrentBinding );