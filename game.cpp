/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto J. Guilarte <volatile@9frag.net>
 */

#include "game.h"



void GetHLFn( DWORD dwEngine, DWORD dwClient ) {
	SCREENINFO sInfo;
	DWORD *dwReDraw;

	g_pEngine = (cl_enginefunc_t *) (dwEngine + 0x134260);

	g_vData.dwClient = dwClient;
	g_vData.dwEngine = dwEngine;

	pfnHUD_Redraw = (int (*)(float, int)) (g_vData.dwClient + 0x43a30);
	pfnKey_Event  = (int (*)(int, int, const char *)) (g_vData.dwClient + 0x56fe0);

	TabGameHook();

	/**/ HookInMemory(0xE8, NULL, NULL, 0x4B31A + g_vData.dwEngine, (DWORD) &HUD_Redraw, NULL);
	dwReDraw     = (DWORD *) (g_vData.dwEngine + 0x122F540);
	//dwReDraw[3]  = (DWORD) &HUD_Redraw;
	dwReDraw[34] = (DWORD) &Key_Event;

	printf("Key_Event: %x\n", dwReDraw[34]);

	g_pEngine->pfnRegisterVariable("_auth___vpug___token_",  "",  0);

	g_pEngine->pfnHookUserMsg("ReadyUser", EventvPugUserReady);
	g_pEngine->pfnHookUserMsg("vDataConnectInit", EventvPugConnectInit);
	g_pEngine->pfnHookUserMsg("vDataPugFinish", EventvPugFinishData);

	g_pEngine->pfnAddCommand("vtest", vTest);

	sInfo.iSize = sizeof (SCREENINFO);
	g_pEngine->pfnGetScreenInfo(&sInfo);

	g_vData.nHeight = sInfo.iHeight;
	g_vData.nWidth  = sInfo.iWidth;

	/* */
}


int EventvPugUserReady ( const char *szName, int nSize, void *lpBuf ) {
	short int nId;

	BEGIN_READ(lpBuf, nSize);

	if ( (nId = READ_SHORT()) > MAX_PLAYERS )
		return FALSE;
	
	g_vData.gpData[nId].isReady = TRUE;

	return TRUE;
}

int EventvPugFinishData ( const char *szName, int nSize, void *lpBuf ) {
	DWORD dwIndex;
	
	BEGIN_READ(lpBuf, nSize);

	for ( dwIndex = 0; dwIndex < MAX_PLAYERS; dwIndex++ ) {
		g_vData.gpData[dwIndex].lpExp = READ_BYTE();
		g_vData.gpData[dwIndex].nRank = READ_SHORT();
	}

	g_vData.isPugFinish = TRUE;

	return TRUE;
}

int EventvPugConnectInit ( const char *szName, int nSize, void *lpBuf ) {
	DWORD dwIndex;
	short int nId;

	BEGIN_READ(lpBuf, nSize);

	if ( (nId = READ_SHORT()) < MAX_PLAYERS )
		return FALSE;

	g_vData.nLocalPlayer = nId;

	for ( dwIndex = 0; dwIndex < MAX_PLAYERS; dwIndex++ ) {
		g_vData.gpData[dwIndex].isReady = READ_BYTE();

		g_vData.gpData[dwIndex].isInGame = READ_BYTE();
		g_vData.gpData[dwIndex].lpName = READ_STRING();
	}

	g_vData.isPugIsLive = READ_BYTE();
	g_vData.isPugFinish = READ_BYTE();
	g_vData.isPlayerWin = READ_BYTE();

	return TRUE;
}


void TabGameHook( ) {
	const static char *szReady = "ready", *szUnReady = "unready";
	DWORD dwPush = 0xE5360 + g_vData.dwClient, dwJmp = 0x2B8F7 + g_vData.dwClient;
	DWORD dwReady = (DWORD) &szReady[0], dwUnReady = (DWORD) &szUnReady[0], dwPugLive = (DWORD) &(g_vData.isPugIsLive);
	DWORD dwCalSetName, dwCalVerifyReady, dwSetClassA, dwSetClassB;

	static BYTE bPathTabulator[61] = { 
		/* 4 */  0x68, 0x0, 0x0, 0x0, 0x0, /* push name */
		/* 6 */  0x8B, 0xCE, /* mov ecx, esi */           
		/* 9 */  0xFF, 0x52, 0x44, /* call dword ptr ds:[edx + 44] */
		/* 16 */ 0x80, 0x3D, 0x0, 0x0, 0x0, 0x0, 0x0,  /* cmp byte ptr ds:[g_PugIsLive] */
		/* 22 */ 0x0F, 0x85, 0x0, 0x0, 0x0, 0x0, /* jne 2b8fc + client */ 
		/* 23 */ 0x55, /* push ebp */
		/* 28 */ 0xE8, 0x0, 0x0, 0x0, 0x0, /* call VerifyStatusPug */
		/* 31 */ 0x83, 0xC4, 0x04, /* add esp, 0x04 */
		/* 34 */ 0x83, 0xF8, 0x00, /* cmp eax, 0 */
		/* 40 */ 0x0F, 0x85, 0xA, 0x0, 0x0, 0x0, /* jne 0x00 */
	 	/* 45 */ 0x68, 0x0, 0x0, 0x0, 0x0, /* push szUnReady */
		/* 50 */ 0xE9, 0x0, 0x0, 0x0, 0x0,  /* jmp 2b99a + client */
				 // if jnz is taken
		/* 55 */ 0x68, 0x0, 0x0, 0x0, 0x0, /* push szReady */ 
		/* 60 */ 0xE9, 0x0, 0x0, 0x0, 0x0,  /* jmp 2b99a + client */
	};

	dwCalSetName = ((0x2B8FC + g_vData.dwClient) - ((DWORD) &bPathTabulator[18])) - 5;
	dwCalVerifyReady = (((DWORD) VerifyStatusPug) - ((DWORD) &bPathTabulator[24])) - 5;
	dwSetClassA = ((0x2B99A + g_vData.dwClient) - ((DWORD) &bPathTabulator[46])) - 5;
	dwSetClassB = ((0x2B99A + g_vData.dwClient) - ((DWORD) &bPathTabulator[56])) - 5;

	memcpy(&bPathTabulator[1],  &dwPush,	       4);
	memcpy(&bPathTabulator[12], &dwPugLive,        4);
	memcpy(&bPathTabulator[19],	&dwCalSetName,     4);
	memcpy(&bPathTabulator[25], &dwCalVerifyReady, 4);
	memcpy(&bPathTabulator[42], &dwUnReady,		   4);
	memcpy(&bPathTabulator[52], &dwReady,		   4);
	memcpy(&bPathTabulator[47], &dwSetClassA,	   4);
	memcpy(&bPathTabulator[57], &dwSetClassB,      4);
		
	HookInMemory(0xE9, NULL, NULL, 0x2B8F2 + g_vData.dwClient, (DWORD) &bPathTabulator, NULL);
}

BOOL VerifyStatusPug ( DWORD dwIndex ) {
	if ( dwIndex >= MAX_PLAYERS )
		return FALSE;

	return g_vData.gpData[dwIndex].isReady;
}

void DrawTextWColor( int nX, int nY, const char * szText, int nR, int nG, int nB ) {
	g_pEngine->pfnDrawSetTextColor((float) nR / 255.0f, (float) nG / 255.0f, (float) nB / 255.0f);
	g_pEngine->pfnDrawLocalizedConsoleString(nX, nY, szText);
}

void HUD_PugIsFinish_Add( DWORD dwIndex, DWORD nX, DWORD nY, const char *nRank, const char *szName, const char *szExp ) 
{
	DrawTextWColor(nX - 25,  nY + (dwIndex * 23), nRank,  255, 255, 255);
	DrawTextWColor(nX + 3,	 nY + (dwIndex * 23), szName, 255,  255, 44); 
	DrawTextWColor(nX + 264, nY + (dwIndex * 23), szExp,  118, 238, 94 );
}


void HUD_PugIsFinish( float flTime ) {
	DWORD dwSprX, dwSprY, dwR, dwG, dwB, dwXRank, dwYRank, dwIndex;
	const char *szScore[10] = {"01", "02", "03", "04", "05", "06", "07", "08", "09", "10"};
	int hSprite;

	if ( !g_vData.sprData[0] && !g_vData.sprData[1] ) { 
		g_vData.sprData[0] = g_pEngine->pfnSPR_Load("sprites/vpug_1.spr"); // Wins
		g_vData.sprData[1] = g_pEngine->pfnSPR_Load("sprites/vpug_2.spr"); // Lose
	}

	g_pEngine->pfnFillRGBA(0, 0, g_vData.nWidth, g_vData.nHeight, 0, 0, 0, 245);

	if ( g_vData.isPlayerWin ) {
		dwR = 84;
		dwG = 110;
		dwB = 215;

		hSprite = g_vData.sprData[0];
	} else {
		dwR = 249;
		dwG = 131;
		dwB = 98;

		hSprite = g_vData.sprData[1];
	}

	g_pEngine->pfnSPR_Set(hSprite, dwR, dwG, dwB);

	dwSprX = (g_vData.nWidth / 2) - 128;
	dwSprY = (g_vData.nHeight / 2) - 128 - 120;

	g_pEngine->pfnSPR_DrawAdditive(1, dwSprX , dwSprY, NULL);

	// divisors
	g_pEngine->pfnFillRGBA(dwSprX - 30, dwSprY + 276, 28,  4, 255, 255, 255, 255); // Num
	g_pEngine->pfnFillRGBA(dwSprX - 2, dwSprY + 276, 250, 4, dwR,  dwG, dwB, 255); // Name
	g_pEngine->pfnFillRGBA(dwSprX + 258, dwSprY + 276,  35, 4, 118, 238,  94, 255); // Exp

	dwXRank = dwSprX;
	dwYRank = dwSprY + 276 + 9;

	for ( dwIndex = 0 ; dwIndex < MAX_PLAYERS; dwIndex++ ) {
		if ( !g_vData.gpData[dwIndex].isInGame )
			continue;
		
		HUD_PugIsFinish_Add(dwIndex, dwXRank, dwYRank, szScore[g_vData.gpData[dwIndex].nRank], 
			g_vData.gpData[dwIndex].lpName, ".21");
	}
}

//void CreateWindowvGui() {
//	DWORD dwX, dwY, dwWidth, dwHeight;
//	
//	g_pEngine->pfnFillRGBA(dwY, dwY, dwWidth, 20, 99, 99, 99, 255); /* Title bar */
	//g_pEngine->pfnFillRGBA(dwY, dwY, 1, dwHeight, 99, 99, 99, 255); /* Title bar */
//}

/*typedef struct _ControllWindows {
	PaintWin *pW;
	DWORD dwLenWindows;
} ControllWindows;

typedef struct _PaintWindows {
	DWORD dwX, dwY, dwHeight, dwWidth;
	const char *szTitle[25];
	BOOL isVisible, isActive;
} PaintWin;*/

/*DWORD PaintWindows( PaintWin *pWindow ) {

}*/

#define VGUI_TYPE_BUTTON 0x1000
#define VGUI_MOUSENOAREA  0
#define VGUI_MOUSEFOCUS  100
#define VGUI_MOUSETOGGLE 101

typedef DWORD HVGUI;

typedef struct _vGUI_Container {
	int dwX, dwY, dwHeight, dwWidth, dwMaxLen, dwType;
	char szText[512];
	BOOL isVisible, isActive;
	HVGUI hVHandleRoot;
	void (* pfnCallBack)( void * );
	struct _vGUI_Container * pNext;
} vGUI_Container;

typedef struct _PaintWindows {
	DWORD dwX, dwY, dwHeight, dwWidth;
	char szTitle[25];
	BOOL isVisible, isActive;
	HVGUI hVgui;
	vGUI_Container *pFirts, *pLast;
} PaintWin;

typedef struct _PaintWindowsList {
	PaintWin *Paint;
	struct _PaintWindowsList *pNext;
} PaintWindowList;

static PaintWindowList *pFirts = NULL;
static PaintWindowList *pLast = NULL;

HVGUI vGUI_CreateWindow( const char *lpszTitle, DWORD dwX, DWORD dwY, DWORD dwHeight, DWORD dwWidth );

DWORD vGUI_GetTextEntry( HVGUI hVHandleWindow, HVGUI hVHandleItem, const char *lpszEntry ) {

}

HVGUI vGUI_CreateButton( HVGUI hVHandle, DWORD dwX, DWORD dwY, DWORD dwHeight, DWORD dwWidth, const char *szText, void *(pfnCallback)(void)) {
	PaintWin *Paint = (PaintWin *) hVHandle;
	vGUI_Container * Container = NULL;

	Container = (vGUI_Container *) malloc(sizeof (vGUI_Container));
	if ( !Container ) return 0;

	memset(Container, 0, sizeof (vGUI_Container));

	Container->dwX = dwX + Paint->dwX;
	Container->dwY = dwY + Paint->dwY;
	Container->dwHeight = dwHeight;
	Container->dwWidth = dwWidth;
	Container->isActive = Container->isActive = TRUE; /*test*/
	Container->dwType = VGUI_TYPE_BUTTON;
	Container->pfnCallBack = (void (*) (void *)) pfnCallback;
	Container->hVHandleRoot = hVHandle;
	Container->pNext = NULL;
	strncpy(Container->szText, szText, sizeof (Container->szText));

	if ( !Paint->pFirts ) Paint->pFirts = Paint->pLast = Container;
	else Paint->pLast = Paint->pLast->pNext = Container;

	return (DWORD) Container;
}

void vGUI_SetVisibleWindow( HVGUI hVHandle, BOOL isVisible ) {
	PaintWin *Paint = (PaintWin *) hVHandle;
	Paint->isVisible = isVisible;
}

//void vGUI_SetLinkedList( void 
void vGUI_CloseWindow( HVGUI hVHandle );

void vGUI_CloseWindow( HVGUI hVHandle ) {
	//vGUI_SetVisibleWindow(hVHandle, FALSE);
}

HVGUI vGUI_CreateWindow( const char *lpszTitle, DWORD dwX, DWORD dwY, DWORD dwHeight, DWORD dwWidth ) {
	PaintWin *PaintAux = NULL;
	PaintWindowList *PaintList = NULL;

	PaintAux = (PaintWin *) malloc(sizeof (PaintWin));
	PaintList = (PaintWindowList *) malloc(sizeof (PaintWindowList));
	vGUI_Container * ContainerClose = (vGUI_Container *) malloc(sizeof (vGUI_Container));

	if ( !PaintAux || !PaintList || !ContainerClose )
		return 0;

	memset(PaintAux, 0, sizeof (PaintWin));
	memset(PaintList, 0, sizeof (PaintWindowList));
	memset(ContainerClose, 0, sizeof (vGUI_Container));

	PaintAux->dwX = dwX;
	PaintAux->dwY = dwY;
	PaintAux->dwHeight = dwHeight;
	PaintAux->dwWidth = dwWidth;
	PaintAux->isActive = PaintAux->isVisible = FALSE;
	PaintAux->pFirts = PaintAux->pLast = NULL;
	PaintList->Paint = PaintAux;
	PaintList->pNext = NULL;
	strncpy(PaintAux->szTitle, lpszTitle, sizeof(PaintAux->szTitle));
	/* button closed */
	ContainerClose->dwX = (PaintAux->dwX + PaintAux->dwWidth ) - 60;
	ContainerClose->dwY = (PaintAux->dwY + PaintAux->dwHeight) - 60;
	ContainerClose->dwHeight = 30;
	ContainerClose->dwWidth = 30;
	ContainerClose->isVisible = FALSE;
	ContainerClose->pNext = NULL;
	ContainerClose->dwType = VGUI_TYPE_BUTTON;
	ContainerClose->hVHandleRoot = (HVGUI) PaintAux;
	strncpy(ContainerClose->szText, "X", sizeof (ContainerClose->szText));
	ContainerClose->pfnCallBack = (void (*) (void *)) vGUI_CloseWindow;

	if ( !pFirts ) pFirts = pLast = PaintList;
	else pLast = pLast->pNext = PaintList;
	if ( !PaintAux->pFirts ) PaintAux->pFirts = PaintAux->pLast = ContainerClose;
	else PaintAux->pLast = PaintAux->pLast->pNext = ContainerClose;

	return (DWORD) PaintAux;
}

typedef struct _BorderRGB {
	DWORD dwBgR, dwBgG, dwBgB; /* background box */
	DWORD dwLineTrR, dwLineTrG, dwLineTrB; /* righ and top */
	DWORD dwLineBlR, dwLineBlG, dwLineBlB; /* button and left */
} BorderRGB;

void vGUI_DrawBoxWithBorder( DWORD dwX, DWORD dwY, DWORD dwWidth, DWORD dwHeight, BorderRGB Border ) {
	g_pEngine->pfnTintRGBA(dwX, dwY, dwWidth, dwHeight, Border.dwBgR, Border.dwBgG, Border.dwBgB, 256); /* box, borders -> */
	g_pEngine->pfnTintRGBA(dwX, dwY, dwWidth, 1, Border.dwLineTrR, Border.dwLineTrG, Border.dwLineTrB, 256); /* up */ 
	g_pEngine->pfnTintRGBA(dwX, dwY, 1, dwHeight, Border.dwLineTrR, Border.dwLineTrG, Border.dwLineTrB, 256); /* left */
	g_pEngine->pfnTintRGBA(dwX, dwY+dwHeight, dwWidth, 1, Border.dwLineBlR, Border.dwLineBlG, Border.dwLineBlB, 256); /* down */
	g_pEngine->pfnTintRGBA(dwX+dwWidth, dwY, 1, dwHeight, Border.dwLineBlR, Border.dwLineBlG, Border.dwLineBlB, 256); /* right */
}

DWORD vGUI_MouseEventInContainer( DWORD dwX, DWORD dwY, DWORD dwWidth, DWORD dwHeight ) {
	int dwMY, dwMX;
	g_pEngine->GetMousePosition(&dwMX, &dwMY);

	if ( dwMX > dwX  && dwMX < dwX+dwWidth && dwMY > dwY && dwMY < dwY+dwHeight ) {
		if ( (GetKeyState(VK_LBUTTON) & 0x80) != 0 ) return VGUI_MOUSETOGGLE;
		return VGUI_MOUSEFOCUS;
	}

	return VGUI_MOUSENOAREA;
}

void vGUI_DrawButton( vGUI_Container *Container ) {
	BorderRGB Border = {0};

	Border.dwBgR = 76; Border.dwBgG = 88; Border.dwBgB = 68; /**/ Border.dwLineTrR = 136; Border.dwLineTrG = 145;
	Border.dwLineTrB = 128; /**/ Border.dwLineBlR = 40; Border.dwLineBlG = 46; Border.dwLineBlB = 34;
	vGUI_DrawBoxWithBorder(Container->dwX, Container->dwY, Container->dwWidth, Container->dwHeight, Border);

	g_pEngine->pfnDrawSetTextColor((float) 255 / 255.0f, (float) 255 / 255.0f, (float) 255 / 255.0f);
	g_pEngine->pfnDrawConsoleString(Container->dwX - (Container->dwWidth / 2),  Container->dwY + (Container->dwHeight / 2), Container->szText);


	if ( vGUI_MouseEventInContainer(Container->dwX, Container->dwY, Container->dwWidth, Container->dwHeight) == VGUI_MOUSETOGGLE ) {
		Border.dwBgR = 76; Border.dwBgG = 88; Border.dwBgB = 68; /**/ Border.dwLineTrR = 40; Border.dwLineTrG = 46;
		Border.dwLineTrB = 34; /**/ Border.dwLineBlR = 136; Border.dwLineBlG = 145; Border.dwLineBlB = 128;
		vGUI_DrawBoxWithBorder(Container->dwX, Container->dwY, Container->dwWidth, Container->dwHeight, Border);
	}
}

void vGUI_PaintWindow( ) {
	PaintWindowList *WinList = pFirts;
	vGUI_Container *Container;
	BorderRGB Border = {0};

	while ( WinList != NULL ) {
		if ( WinList->Paint->isVisible ) {
			Border.dwBgR = 76; Border.dwBgG = 88; Border.dwBgB = 68; /**/ Border.dwLineTrR = 136; Border.dwLineTrG = 145;
			Border.dwLineTrB = 128; /**/ Border.dwLineBlR = 40; Border.dwLineBlG = 46; Border.dwLineBlB = 34; 

			vGUI_DrawBoxWithBorder(WinList->Paint->dwX, WinList->Paint->dwY, WinList->Paint->dwWidth, WinList->Paint->dwHeight, Border);
			g_pEngine->pfnDrawSetTextColor((float) 255 / 255.0f, (float) 255 / 255.0f, (float) 255 / 255.0f);
			g_pEngine->pfnDrawConsoleString(WinList->Paint->dwX+13,  WinList->Paint->dwY+13, WinList->Paint->szTitle);

			for (  Container = WinList->Paint->pFirts; Container != NULL; Container = Container->pNext ) { 
				if ( Container->dwType ==  VGUI_TYPE_BUTTON ) vGUI_DrawButton( Container );
			}

			/**/
		}
		WinList = WinList->pNext;
	}
	// 
}

void vgGUI_PaintContainers( PaintWin * Paint ) {

}


void vTest( ) {
	DWORD dwIndex;
	
	//for (dwIndex = 0; dwIndex < MAX_PLAYERS; dwIndex++)
	//g_pEngine->Con_Printf("Se ejecuto");
	//vGUI_CreateWindow("test", 1, 1, 20, 20);
	static BOOL isc = FALSE;
	static HVGUI s, e;


		s = vGUI_CreateWindow("9frag account", 100, 100, 400, 600);
		vGUI_SetVisibleWindow(s, TRUE);
		vGUI_CreateButton(s, 10, 10, 50, 50, "ss", NULL);
	//vGUI_PaintWindow();
	//printf("Se ejecuto\n");

		
		//paneladmin->setSize(1000, 1000);
	//paneladmin->setVisible(TRUE);
	//paneladmin->hasFocus();
	//paneladmin->doExecCommand();
}

int HUD_Redraw( float flTime, int intermission ) {
	vGUI_PaintWindow();
	//g_pEngine->pfnFillRGBA(1, 2, 100, 100, 99, 99, 99, 0);

	//g_pEngine->pfnTintRGBA(0, 0, g_vData.nWidth, g_vData.nHeight, 0, 0, 0, 248);
	//g_pEngine->pfnTintRGBA(100, 100, 336, 331, 76, 88, 68, 256);

	//g_pEngine->pfnTintRGBA(100, 100, 336, 1, 136, 145, 128, 256); /* _ (up) */
	//g_pEngine->pfnTintRGBA(100, 100, 1, 331, 136, 145, 128, 256); /* | (left) */
	//g_pEngine->pfnTintRGBA(100, 100+331, 336, 1, 40, 46, 34, 256); /* _ (down) */
	//g_pEngine->pfnTintRGBA(100+336, 100, 1, 331, 40, 46, 34, 256); /* | (right) */

	//g_pEngine->pfnDrawSetTextColor((float) 61 / 255.0f, (float) 58 / 255.0f, (float) 58 / 255.0f);
	//g_pEngine->pfnDrawConsoleString(100+60,  100+60, "Please, press (p) for ready, you will kick in 30s.");
	//DrawTextWColor(100+60,  100+60, "Por favor, esto no debería ser así", 160, 160, 160);
   //glClear(GL_COLOR_BUFFER_BIT);

	//pfnHUD_Redraw(flTime, intermission);


    //glutSwapBuffers();

	/*if ( g_vData.isPugFinish ) {
		g_vData.isPugFinish = TRUE;
		
		if ( !g_vData.fTimeFinish ) {
			g_vData.fTimeFinish = flTime + 10; 
		} else if ( flTime >= g_vData.fTimeFinish ) {
			g_vData.fTimeFinish = 0;
			g_vData.isPugFinish = FALSE;
			g_vData.isFirtsFinish = TRUE;
		}	

		HUD_PugIsFinish(flTime);

		return 0;
	}

	if ( !g_vData.isPugIsLive && !g_vData.gpData[g_vData.nLocalPlayer].isReady ) {
		g_pEngine->pfnFillRGBA(g_vData.nWidth - 350, 0, 600, 20, 0, 0, 0, 210);
		g_pEngine->pfnDrawConsoleString(g_vData.nWidth - 350 + 10,  2, "Please, press (p) for ready, you will kick in 30s.");
	}*/
	
	return 0;
}

int Key_Event ( int down, int keynum, const char *pszCurrentBinding ) {
	/*if ( ((keynum == 239 || keynum == 240) && strcmp(pszCurrentBinding, "+duck")) == 0 )
		return 0;

	if ( g_vData.isPugFinish ) 
		return 0;

	if ( (!g_vData.isPugIsLive && !g_vData.gpData[g_vData.nLocalPlayer].isReady) && keynum == 112  ) {
		g_pEngine->pfnClientCmd("*_vPug_Im_Ready\n");
		g_vData.gpData[g_vData.nLocalPlayer].isReady = true;
	}*/

	printf("Hola ejecute\n");
	return pfnKey_Event(down, keynum, pszCurrentBinding);
}
