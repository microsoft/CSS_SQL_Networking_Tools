// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Written by the Microsoft CSS SQL Networking Team
//

#include "stdafx.h"
#include "DynamicDCInfo.h"
#include "DetourFunctions.h" 

WCHAR* GetGuidStringW( GUID & g )
{
	static WCHAR wszGUID[255];
	StringFromGUID2( g, wszGUID, sizeof(wszGUID) );
	return wszGUID;
}

#define BITFLAG_TEST(x) if ( dwFlags & x ) { if ( lstrlen(szFS) > 0 ) lstrcat( szFS,"|" ); lstrcat( szFS, #x ); }

char* GetDCFlagsString( DWORD dwFlags )
{
	static char szFS[1024];
	ZeroMemory( szFS, sizeof(szFS) );
	BITFLAG_TEST(DS_DNS_CONTROLLER_FLAG);
	BITFLAG_TEST(DS_DNS_DOMAIN_FLAG);
	BITFLAG_TEST(DS_DNS_FOREST_FLAG);
	BITFLAG_TEST(DS_DS_FLAG);
	BITFLAG_TEST(DS_GC_FLAG);
	BITFLAG_TEST(DS_KDC_FLAG);
	BITFLAG_TEST(DS_PDC_FLAG);
	BITFLAG_TEST(DS_TIMESERV_FLAG);
	BITFLAG_TEST(DS_WRITABLE_FLAG);
	return szFS;
}

#define CONST_CASE(x) case x: return #x

char* GetDsGetDcNameErrorString( DWORD dwError )
{
	switch( dwError )
	{
		CONST_CASE(ERROR_INVALID_DOMAINNAME);
		CONST_CASE(ERROR_INVALID_FLAGS);
		CONST_CASE(ERROR_NOT_ENOUGH_MEMORY);
		CONST_CASE(ERROR_NO_SUCH_DOMAIN);
	}
	return "";
}

#define SAFE_LOAD_FUNCTION( w, x, y, z )	\
	w = (x) GetProcAddress( y, z );			\
	if ( NULL == w )						\
	{										\
		o_printf( "*** ERROR: %s is NULL, cannot load advanced security APIs.", #w ); \
		goto CheckDomainInfoExit;	\
	}

void CheckDomainInfo()
{
	DWORD                       dwError;    
	HANDLE                      hDs;
	CHAR                     ** pspn = NULL;
	ULONG                       dwLen = 0;
	DWORD                       ulSpn = 1;
	PDS_NAME_RESULT             pRes;
	PDOMAIN_CONTROLLER_INFO     pDomainControllerInfo = NULL;
	char                        szUserName[MAX_PATH + 1];
	DWORD                       dwUserNameLen = MAX_PATH;
	LPSTR                       szTmp = szUserName;
	DsFunctionTable g_DsFunc;
	HMODULE hDsLib  = NULL;
	HMODULE hNetapi = NULL;
	HMODULE hSecur  = NULL;
	DWORD i;

	o_printf( "Checking user's logon name and domain information using advanced security APIs." );
	o_printf( "Note that these checks may fail on Windows Vista and older systems." );

	// Zero out function array.
	ZeroMemory( &g_DsFunc, sizeof(g_DsFunc) );

	// Initialize g_DsFunc if this is possible (only works on Windows 2000 or later OR NT4 SP6A with DCClient installed).
	hDsLib  = LoadLibrary( "ntdsapi.dll" );
	hNetapi = LoadLibrary( "netapi32.dll" );
	hSecur  = LoadLibrary( "secur32.dll" );

    if ( NULL == hDsLib )
    {
		o_printf( "*** ERROR: Failed to load ntdsapi.dll." );
        goto CheckDomainInfoExit;
    }
    if ( NULL == hNetapi )
    {
		o_printf( "*** ERROR: Failed to load netapi32.dll." );
        goto CheckDomainInfoExit;
    }
    if ( NULL == hSecur )
    {
		o_printf( "*** ERROR: Failed to load secur32.dll." );
        goto CheckDomainInfoExit;
    }

	g_STATUS.fLoadedDCDlls = TRUE;

	// Load needed functions.
	// If any of these fail, we exit with appropriate error message.
	SAFE_LOAD_FUNCTION( g_DsFunc.DsBind, DSBIND_FN, hDsLib, "DsBindA" );
	SAFE_LOAD_FUNCTION( g_DsFunc.DsCrackNames, DSCRACKNAMES_FN, hDsLib, "DsCrackNamesA" );
	SAFE_LOAD_FUNCTION( g_DsFunc.DsFreeNameResult, DSFREENAMERESULT_FN, hDsLib, "DsFreeNameResultA" );
	SAFE_LOAD_FUNCTION( g_DsFunc.DsUnBind, DSUNBIND_FN, hDsLib, "DsUnBindA" );
	SAFE_LOAD_FUNCTION( g_DsFunc.DsFreeSpnArray, DSFREESPNARRAY_FN, hDsLib, "DsFreeSpnArrayA" );

	SAFE_LOAD_FUNCTION( g_DsFunc.NetApiBufferFree, NETAPIBUFFERFREEFN, hNetapi, "NetApiBufferFree" );
	SAFE_LOAD_FUNCTION( g_DsFunc.DsGetDcName, DSGETDCNAME_FN, hNetapi, "DsGetDcNameA" );

	SAFE_LOAD_FUNCTION( g_DsFunc.GetComputerObjectName, GETCOMPUTEROBJECTFN, hSecur, "GetComputerObjectNameA" );
	SAFE_LOAD_FUNCTION( g_DsFunc.GetUserNameEx, GETUSERNAMEEXFN, hSecur, "GetUserNameExA" );

	g_STATUS.fLoadedDCFunctions = TRUE;

    // Start with a DsBind, The DS APIs need this.
    dwError = g_DsFunc.DsGetDcName( NULL,
									NULL,
									NULL,
									NULL,
									DS_RETURN_DNS_NAME,
									&pDomainControllerInfo );
    if ( NO_ERROR != dwError ) 
    {
        o_printf( "*** ERROR: DsGetDcName(DS_RETURN_DNS_NAME) failed with error %lu (%s).", 
				  dwError, GetDsGetDcNameErrorString( dwError ) );
		goto CheckDomainInfoExit;
    }

	g_STATUS.fDsGetDcName = TRUE;

	// Dump out pDomainControllerInfo
	o_printf( "DomainControllerName        = '%s'",			pDomainControllerInfo->DomainControllerName );
	o_printf( "DomainControllerAddress     = '%s'",			pDomainControllerInfo->DomainControllerAddress );
	o_printf( "DomainGuid                  = '%S'",			GetGuidStringW( pDomainControllerInfo->DomainGuid ) );
	o_printf( "DomainName                  = '%s'",			pDomainControllerInfo->DomainName );
	o_printf( "DnsForestName               = '%s'",			pDomainControllerInfo->DnsForestName );
	o_printf( "Flags                       = 0x%08x (%s)",	pDomainControllerInfo->Flags, GetDCFlagsString( pDomainControllerInfo->Flags ) );
	o_printf( "DcSiteName                  = '%s'",			pDomainControllerInfo->DcSiteName );
	o_printf( "ClientSiteName              = '%s'",			pDomainControllerInfo->ClientSiteName );

	o_printf( "Attempting to bind to DC." );

    dwError = g_DsFunc.DsBind( NULL, pDomainControllerInfo->DomainName, &hDs );
    if ( NO_ERROR != dwError ) 
    {
        o_printf( "*** ERROR: DsBind failed with error %lu.", dwError );
		goto CheckDomainInfoExit;
    }

	g_STATUS.fDsBind = TRUE;

	o_printf( "Successfully bound to DC, hDs=0x%08x.", hDs );

    // Free the buffer allocated by the system for DomainControllerInfo
	if ( NULL != pDomainControllerInfo )
	{
		g_DsFunc.NetApiBufferFree( pDomainControllerInfo );
		pDomainControllerInfo = NULL;
	}

    // Get the DN for the object whose SPN we will update: a user or computer
    //
    // If this service will run in a named account then get the DN for that account
    // and use that as the target object for the SPN, otherwise use the computer
    // object for the local system as the target for the SPN.  
    //
    if( !GetUserName( szUserName,
                      &dwUserNameLen) )
    {
		dwError = GetLastError();
        o_printf( "*** ERROR: GetUserName failed with error %lu.", dwError );
		goto CheckDomainInfoExit;
    }

	g_STATUS.fGetUserName = TRUE;

	o_printf( "GetUserName returned '%s'.", szUserName );

    dwUserNameLen = MAX_PATH;
    if( !g_DsFunc.GetUserNameEx( NameSamCompatible,
								 szUserName,
								 &dwUserNameLen ) )
    {
		dwError = GetLastError();
		o_printf( "*** ERROR: GetUserNameEx failed with error %lu.", dwError );
        goto CheckDomainInfoExit;
    }

	g_STATUS.fGetUserNameEx = TRUE;

	o_printf( "GetUserNameEx returned '%s'.", szUserName );

    dwError = g_DsFunc.DsCrackNames( hDs,
									 DS_NAME_NO_FLAGS,
									 DS_NT4_ACCOUNT_NAME,
									 DS_FQDN_1779_NAME,
									 1,
									 &szTmp,
									 &pRes );

    if ( NO_ERROR != dwError )
	{
		o_printf( "*** ERROR: DsCrackNames failed with error %lu.", dwError );
		goto CheckDomainInfoExit;
	}

	g_STATUS.fDsCrackNames = TRUE;

	if ( NULL != pRes )
	{
		o_printf( "DsCrackNames successful. Dumping items." );
		for( i=0; i<pRes->cItems; i++ )
		{
			o_printf( "rItems[%lu].status  = 0x%08x", i, pRes->rItems[i].status );
			o_printf( "rItems[%lu].pDomain = '%s'", i, ( NULL == pRes->rItems[i].pDomain ) ? "<NULL>" : pRes->rItems[i].pDomain );
			o_printf( "rItems[%lu].pName   = '%s'", i, ( NULL == pRes->rItems[i].pName ) ? "<NULL>" : pRes->rItems[i].pName );
		}
		g_DsFunc.DsFreeNameResult( pRes );
	}

CheckDomainInfoExit:

    // Unbind the DS in any case.
	if ( ( NULL != g_DsFunc.DsUnBind ) && ( NULL != hDs ) )  g_DsFunc.DsUnBind( &hDs );

    // Free the SPN array, we are done with it.
    if ( ( NULL != pspn ) && ( NULL != g_DsFunc.DsFreeSpnArray ) ) g_DsFunc.DsFreeSpnArray( ulSpn, pspn );

	if ( hDsLib )	FreeLibrary( hDsLib );
	if ( hNetapi )	FreeLibrary( hNetapi );
	if ( hSecur )	FreeLibrary( hSecur );

	o_printf( "" );

    return;

}


