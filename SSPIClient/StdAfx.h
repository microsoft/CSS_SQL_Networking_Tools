// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__7EF51904_68E9_4255_A068_283068C28FCC__INCLUDED_)
#define AFX_STDAFX_H__7EF51904_68E9_4255_A068_283068C28FCC__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define _WIN32_WINNT 0x0501 // changed from 0x0500 to 0x0601 on 8/12/2021

#include <afxwin.h>         // MFC core and standard components
#include <objbase.h>	// CoInitializeEx()
#include <afxext.h>         // MFC extensions

#include <sql.h>
#include <sqlext.h>

#include <dsgetdc.h>
#include <lmcons.h>
#include <lmapibuf.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntdsapi.h>
#include <activeds.h>
#include <objbase.h>
#include <winsock2.h>	// Winsock APIs.
#include <ws2tcpip.h>
#include <ntsecapi.h>

#define MAX_MSG_SIZE 256

struct SSPIClient_Status
{
	BOOL fLsaConnectUntrusted;
	BOOL fLsaLookupAuthenticationPackage;
	BOOL fLsaCallAuthenticationPackage;
	BOOL fLoadedDCDlls;
	BOOL fLoadedDCFunctions;
	BOOL fDsGetDcName;
	BOOL fDsBind;
	BOOL fGetUserName;
	BOOL fGetUserNameEx;
	BOOL fDsCrackNames;
	BOOL fLoadDetourDllsAndFunctions;
	BOOL fAllFunctionsDetoured;
	BOOL fGetHostByName;
	BOOL fGetHostByAddr;
	BOOL fODBCConnected;
	BOOL fSPNResolved;
	BOOL fSPNResolvedToTGT;
	BOOL fSPNResolvedToTGTNoCache;
	BOOL fLoadedADSI;
	BOOL fGetGCIADsContainer;
	BOOL fExecuteSearch;
	BOOL fSPNFoundInAD;
	BOOL fDuplicateSPNFound;
	BOOL fUsedKerberos;
	char g_szSavedFQDN[1024];
	char g_szSavedSQLServer[1024];
	char g_szSavedSQLServerHost[1024];
	char g_szSavedIP[1024];
	char g_szSavedSPN[1024];
	char g_szSavedSPNObject[1024];
	BOOL fSnac9Available;
	BOOL fSnac10Available;
	BOOL fSnac11Available;
	BOOL fodbc11Available;
	BOOL fodbc13Available;
	BOOL fodbc17Available;
	BOOL fodbc18Available;
};

extern SSPIClient_Status g_STATUS;

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__7EF51904_68E9_4255_A068_283068C28FCC__INCLUDED_)
