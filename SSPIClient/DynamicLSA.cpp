// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Written by the Microsoft CSS SQL Networking Team
//

#include "stdafx.h"
#include "SSPIClient.h"
#include "DynamicLSA.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/*
NTSTATUS
NTAPI
LsaLookupAuthenticationPackage (
    IN HANDLE LsaHandle,
    IN PLSA_STRING PackageName,
    OUT PULONG AuthenticationPackage
    );

// begin_ntifs

NTSTATUS
NTAPI
LsaFreeReturnBuffer (
    IN PVOID Buffer
    );

// end_ntifs

NTSTATUS
NTAPI
LsaCallAuthenticationPackage (
    IN HANDLE LsaHandle,
    IN ULONG AuthenticationPackage,
    IN PVOID ProtocolSubmitBuffer,
    IN ULONG SubmitBufferLength,
    OUT PVOID *ProtocolReturnBuffer,
    OUT PULONG ReturnBufferLength,
    OUT PNTSTATUS ProtocolStatus
    );


NTSTATUS
NTAPI
LsaDeregisterLogonProcess (
    IN HANDLE LsaHandle
    );

NTSTATUS
NTAPI
LsaConnectUntrusted (
    OUT PHANDLE LsaHandle
    );
*/

BOOL g_fKerberosLoaded = FALSE;

LsaLookupAuthenticationPackage_FN pfnLsaLookupAuthenticationPackage = NULL;
LsaFreeReturnBuffer_FN pfnLsaFreeReturnBuffer = NULL;
LsaCallAuthenticationPackage_FN pfnLsaCallAuthenticationPackage = NULL;
LsaDeregisterLogonProcess_FN pfnLsaDeregisterLogonProcess = NULL;
LsaConnectUntrusted_FN pfnLsaConnectUntrusted = NULL;

void LoadLSA()
{
	HMODULE hSecur32 = NULL;

	g_fKerberosLoaded = FALSE;

	hSecur32 = LoadLibraryA( "Secur32.dll" );
	if ( NULL == hSecur32 ) 
	{
		hSecur32 = LoadLibraryA( "ntdll.dll" );
	}

	pfnLsaLookupAuthenticationPackage = (LsaLookupAuthenticationPackage_FN) GetProcAddress( hSecur32, "LsaLookupAuthenticationPackage" );
	pfnLsaFreeReturnBuffer			  = (LsaFreeReturnBuffer_FN) GetProcAddress( hSecur32, "LsaFreeReturnBuffer" );
	pfnLsaCallAuthenticationPackage   = (LsaCallAuthenticationPackage_FN) GetProcAddress( hSecur32, "LsaCallAuthenticationPackage" );
	pfnLsaDeregisterLogonProcess	  = (LsaDeregisterLogonProcess_FN) GetProcAddress( hSecur32, "LsaDeregisterLogonProcess" );
	pfnLsaConnectUntrusted			  = (LsaConnectUntrusted_FN) GetProcAddress( hSecur32, "LsaConnectUntrusted" );

	if ( NULL == pfnLsaLookupAuthenticationPackage ) return;
	if ( NULL == pfnLsaFreeReturnBuffer )			 return;
	if ( NULL == pfnLsaCallAuthenticationPackage )	 return;
	if ( NULL == pfnLsaDeregisterLogonProcess )		 return;
	if ( NULL == pfnLsaConnectUntrusted )			 return;

	g_fKerberosLoaded = TRUE;

}