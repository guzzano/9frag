/*	
	Copyright (c) 9frag.ve - all rights reserved.

	Unauthorized copying of this file, via any medium is 
	strictly prohibited proprietary and confidential.

	Written by Alberto J. Guilarte <volatile@9frag.net>
 */

#pragma once
/*
DWORD dwGEngine[131] =
{
    0x011400,
    0x0116a0,
    0x011710,
    0x0116d0,
    0x011770,
    0x011810,
    0x011890,
    0x011910,
    0x011a30,
    0x011a70,
    0x00c070,
    0x03c730,
    0x00a810,
    0x011320,
    0x00a880,
    0x00a8d0,
    0x00a910,
    0x00a940,
    0x00aa50,
    0x00a970,
    0x00aa10,
    0x00aa80,
    0x00abe0,
    0x00ae40,
    0x060ee0,
    0x0b1760,
    0x0b1860,
    0x03b600,
    0x03b540,
    0x00afb0,
    0x00aff0,
    0x00b010,
    0x00c1e0,
    0x00c1f0,
    0x00c200,
    0x00c240,
    0x00c270,
    0x02dcd0,
    0x0277b0,
    0x0277c0,
    0x02c080,
    0x02c1a0,
    0x02c540,
    0x02c5c0,
    0x00c280,
    0x00c2a0,
    0x00c910,
    0x06f8b0,
    0x05fe90,
    0x00c2c0,
    0x00c520,
    0x00c570,
    0x00c5a0,
    0x00c5b0,
    0x00c5f0,
    0x0bff50,
    0x0c0150,
    0x06a060,
    0x06a0f0,
    0x06ad70,
    0x00c660,
    0x00c6c0,
    0x00c730,
    0x00af00,
    0x00c750,
    0x00c7a0,
    0x00c8c0,
    0x06ef40,
    0x06ef70,
    0x01ea70,
    0x02c650,
    0x00c920,
    0x02d7e0,
    0x05fbd0,
    0x00c930,
    0x00c950,
    0x00c980,
    0x0bf1a0,
    0x0b51e0,
    0x02ad70,
    0x00bfa0,
    0x02aed0,
    0x150578,
    0x14fe90,
    0x13e7e8,
    0x1352d4,
    0x14a7ac,
    0x15ac84,
    0x0203a0,
    0x044e30,
    0x00ca10,
    0x00ca40,
    0x00cad0,
    0x00cb50,
    0x00cc00,
    0x00cc70,
    0x00cc90,
    0x00a9c0,
    0x00c3e0,
    0x00c500,
    0x036c80,
    0x00ccb0,
    0x00ccc0,
    0x00ccd0,
    0x00cce0,
    0x00c610,
    0x00c630,
    0x00c640,
    0x0112a0,
    0x0112c0,
    0x011300,
    0x089690,
    0x011990,
    0x088f50,
    0x006ca0,
    0x006d10,
    0x00cb30,
    0x006a70,
    0x006b20,
    0x02b9d0,
    0x007880,
    0x02dc90,
    0x007860,
    0x00ad70,
    0x0091b0,
    0x0a8610,
    0x007900,
    0x007940,
    0x007990,
    0x00aca0,
    0x03c8e0
};

DWORD dwGClient[43] =
{
    0x436e0,
    0x439a0,
    0x43990,
    0x43a30,
    0x43a50,
    0x43a70,
    0x435f0,
    0x435d0,
    0x435e0,
    0x2d9a0,
    0x2d9e0,
    0x2dc40,
    0x2e350,
    0x2e1d0,
    0x57970,
    0x56b70,
    0x56ba0,
    0x56ce0,
    0x56010,
    0x6c580,
    0x44eb0,
    0x452e0,
    0x68ee0,
    0x68ef0,
    0x45300,
    0x0ec30,
    0x439b0,
    0x44f60,
    0x44fb0,
    0x45160,
    0x44e30,
    0x435c0,
    0x435a0,
    0x43a80,
    0x56fe0,
    0x45450,
    0x45dd0,
    0x43aa0,
    0x43b30,
    0x497c0,
    0x27f10,
    0x43b50,
    0x43b70
};

DWORD dwGStudio[43] = 
{
	0x61cf0,
	0xc6550,
	0x2b0c0,
	0x86c30,
	0x3ed70,
	0x863c0,
	0x863e0,
	0x863f0,
	0x86420,
	0x86470,
	0x86480,
	0x867f0,
	0x86770,
	0x86810,
	0x86820,
	0x86840,
	0x86730,
	0x86740,
	0x86750,
	0x86760,
	0x864c0,
	0x80500,
	0x83fe0,
	0x84790,
	0x83020,
	0x85c10,
	0x81a30,
	0x81c10,
	0x81dc0,
	0x82e20,
	0x86860,
	0x86650,
	0x84a90,
	0x868c0,
	0x868d0,
	0x868e0,
	0x868f0,
	0x86500,
	0x865c0,
	0x86620,
	0x86900,
	0x869f0,
	0x86910
};

*/
char *szFilesInHLBase[MAX_PATH] = {
	"a3dapi.dll",
	"avcodec-53.dll",
	"avformat-53.dll",
	"avutil-51.dll",
	"binkawin.asi",
	"chromehtml.dll",
	"Core.dll",
	"DemoPlayer.dll",
	"FileSystem_Stdio.dll",
	"hl.exe",
	"hlds.exe",
	"hltv.exe",
	"htmlcache",
	"hw.dll",
	"icudt.dll",
	"language.inf",
	"libcef.dll",
	"Mss32.dll",
	"mssmp3.asi",
	"mssvoice.asi",
	"proxy.dll",
	"SDL2.dll",
	"steam_api.dll",
	"sw.dll",
	"swds.dll",
	"tier0.dll",
	"vgui.dll",
	"vgui2.dll",
	"vstdlib.dll"
};

LPCSTR szFilesInHLCLDLLS[MAX_PATH] =  {
	"client.dll",
	"client.dylib",
	"client.so"
};

LPCSTR szMD5HLBase[32] = 
{
	// actually base
	"0b3f04a2757f5e43140ac81db1afdc42",
	"bba1fe328cea501fcce1e5df16276439",
	"c5ccb86cd745746b9908031a54315f90",
	"2a8b8a15a58edf3b443083ec29894e54",
	"f415f94065be11ed9a3b55a5d9baeae7",
	"43d2a3b6f8125842e6ea136897493af4",
	"0833126204df0583bd8b8004163f922a",
	"bdc5238414662c3b1fb0304a632e524c",
	"13b853b53a6e0512bd55e007e7992a9e",
	"8a8c398d4cb36461dc16c7dc0ec60437",
	"56cc24bba3b8c50cf3a679cabaec9207",
	"1f524f409dd7dce0e579d0d38c610b6d",
	"3b6460a5604317b1bfacdd6ab1a58f87",
	"045d0f4f41ca53d4cb22bdc814a22b64",
	"c754dc22669532620b48b3fe9d299d7c",
	"60be2cec0d95bb135d4452f39aac6805",
	"1f7c162a3e43bd6bbd65fa30b6659637",
	"ae0183c77404ac09270f44bb1a3e1204",
	"ac55930ed33d9c3a6af4d398af5a9c89",
	"cbf28ab5ffe69d369c21550292fa3497",
	"3b18fa46189823696366b2a9e2e05dbe",
	"cc3d1ca6401e2ab106733c7bd7489cad",
	"a35aa6087c18c9ef5ca3f46d63ca2671",
	"b542c04c06fed33812ac0a0ebd8ec88e",
	"fbfeb5dae01b4b2456cd1ebabbed4922",
	"4cbd03f4c6da4cb5c0a619579a16bc19",
	"86660114a3823dd4f2960fe1ab92123d",
	"866e49fc80c2b7500334a716b177afad",

	// beta (6x5x)

	// cl_dlls
	"4e48070d709c6504dbbba3ade0ab7d9d",
	"f6898b8f4e6dfc0566c2ebc5ce373ae4",
	"ea87f864a76b79bfe4dc7f27b4022625"
};

#define MS  "\x55\x8B\xEC\x56\x8D\x45\x08\x57\x50\xFF\x15"  \
		     "\x00\x00\x00\x00\x8B\x45\x08\x83\xC4\x04\x85" \
			\xC0\x0F\x84\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x85\xC0\x74\x7D\xA1\x00\x00\x00\x00\x85\xC0\x7E\x74\x33\xFF\x85\xC0\x7E\x5C\x33\xF6\x8B\x0D\x00\x00\x00\x00\x83\x3C\x0E\x00\x75\x27\x8B\x55\x08\x52\xE8\x00\x00\x00\x00\x40\x50\xE8\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\x89\x44\x0E\x04\x8B\x55\x08\x52\x50\xE8\x00\x00\x00\x00\x83\xC4\x10\xA1\x00\x00\x00\x00\x8B\x55\x08\x8B\x4C\x06\x04\x51\x52\xE8\x00\x00\x00\x00\x83\xC4\x08\x85\xC0\x74\x25\xA1\x00\x00\x00\x00\x47\x83\xC6\x0C\x3B\xF8\x7C\xA6\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x08\x5F\x33\xC0\x5E\x5D\xC3\x8B\x45\x08\x6A\x01\x6A\x00\x50\xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\x8D\x34\x7F\xC1\xE6\x02\x83\xC4\x0C\xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\x85\xC0\x89\x04\x0E\x74\xC3\x50\xE8\x00\x00\x00\x00\x8B\x15\x00\x00\x00\x00\x83\xC4\x04\x89\x44\x16\x08\x8D\x47\x01\x5F\x5E\x5D\xC3