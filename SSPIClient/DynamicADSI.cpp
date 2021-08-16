// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Written by the Microsoft CSS SQL Networking Team
//

#include "stdafx.h"
#include "DynamicADSI.h"

// Dynamically loading of AD stuff because I want to work on NT4 and Windows 95/98.
typedef HRESULT (WINAPI* ADsOpenObject_FN)( LPCWSTR lpszPathName, 
											LPCWSTR lpszUserName, 
											LPCWSTR lpszPassword,    
											DWORD  dwReserved,
											REFIID riid,
											void FAR * FAR * ppObject );
ADsOpenObject_FN pfnADsOpenObject = NULL;

// Returns TRUE if ADSI can be loaded.
BOOL LoadADSI()
{
	HMODULE hMod = NULL;
	if ( NULL != pfnADsOpenObject ) return TRUE;
	hMod = LoadLibrary( "activeds.dll" );
	if ( NULL == hMod ) return FALSE;
	pfnADsOpenObject = (ADsOpenObject_FN) GetProcAddress( hMod, "ADsOpenObject" );
	if ( NULL == pfnADsOpenObject ) return FALSE;
	return TRUE;
}

// Get GC container.
HRESULT GetGCIADsContainer( IADsContainer** ppContainer )
{
	HRESULT hr;
	IADsContainer *pContainer = NULL;

	if ( !LoadADSI() ) return NULL;

	//Bind to Global Catalog
    hr = pfnADsOpenObject( L"GC:",  // NT 4.0, Win9.x client must include the servername, e.g GC://myServer
						   NULL,
						   NULL,
						   ADS_SECURE_AUTHENTICATION, //Use Secure Authentication
						   __uuidof(guid_IID_IADsContainer),
						   (void**)&pContainer );

	*ppContainer = pContainer;
	return hr;
}