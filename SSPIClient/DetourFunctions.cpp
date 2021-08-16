// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Written by the Microsoft CSS SQL Networking Team
//
// DetourFunctions.cpp: implementation of the DetourFunctions class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "DetourFunctions.h"
#include "detours.h"	// Detours header
#include <schannel.h>
#include "dbnetlib.h"
#include "sspierrors.h"

BOOL g_fSupressOutput = FALSE;
int g_iStackDepth = 0;
BOOL g_fFunctionsDetoured = FALSE;
HANDLE g_hLogFile = NULL;
CRITICAL_SECTION* g_pLogFileLock = NULL;
PCCERT_CONTEXT g_pCertContext = NULL;
BOOL g_fCertSubjectCheckDone = FALSE;

#define ENTER_API_CS  { if ( g_pLogFileLock ) EnterCriticalSection( g_pLogFileLock ); }

#define LEAVE_API_CS  { if ( g_pLogFileLock ) LeaveCriticalSection( g_pLogFileLock ); }

HMODULE g_hModSecurity = NULL;
HMODULE g_hModDBNetlib = NULL;
HMODULE g_hModCrypt32  = NULL;

struct _DETOUR_FUNCTIONS
{
	// security.dll/secur32.dll functions
	ACQUIRE_CREDENTIALS_HANDLE_FN_A  pfnAcquireCredentialsHandleA;
	INITIALIZE_SECURITY_CONTEXT_FN_A pfnInitializeSecurityContextA;
	COMPLETE_AUTH_TOKEN_FN           pfnCompleteAuthToken;
	ACCEPT_SECURITY_CONTEXT_FN       pfnAcceptSecurityContext;
	QUERY_SECURITY_PACKAGE_INFO_FN_A pfnQuerySecurityPackageInfoA;

	/*
	FREE_CONTEXT_BUFFER_FN			 pfnFreeContextBuffer;
    DELETE_SECURITY_CONTEXT_FN		 pfnDeleteSecurityContext;
	*/

	QUERY_CONTEXT_ATTRIBUTES_FN_A	 pfnQueryContextAttributesA;

	// Crypt32.dll functions
	CertNameToStrW_FN pfnCertNameToStrW;
	CertGetCertificateChain_FN pfnCertGetCertificateChain;
	CertVerifyCertificateChainPolicy_FN pfnCertVerifyCertificateChainPolicy;
	CertFindChainInStore_FN pfnCertFindChainInStore;

	// dbnetlib.dll functions
	ConnectionOpenW_FN ConnectionOpenW;
	ConnectionGetSvrUser_FN ConnectionGetSvrUser;
	GenClientContext_FN GenClientContext;
	InitSSPIPackage_FN InitSSPIPackage;
	InitSession_FN InitSession;
	TermSSPIPackage_FN TermSSPIPackage;
	TermSession_FN TermSession;

} g_DFN;

BSTR AnsiToBSTR( char* s )
{
	LPWSTR pswzBuffer = NULL;
	int nNeededChars = 0;

	if ( NULL == s ) return NULL;
	if ( 0 == lstrlen( s ) ) return SysAllocString( L"" );

	nNeededChars = MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED, s, -1, pswzBuffer, 0 );
	pswzBuffer = (LPWSTR) new WCHAR[nNeededChars];
	if ( NULL == pswzBuffer ) return NULL;

	if ( 0 == MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED, s, -1, pswzBuffer, nNeededChars ) )
	{
		// Conversion failed. bail out.
		delete pswzBuffer;
		pswzBuffer = NULL;
		return NULL;
	}

	return SysAllocString( pswzBuffer );

}

void o_write( char* pszTTStamp, char* pszMessage )
{
	DWORD dwBytesWritten;
	if ( g_hLogFile )
	{
		ENTER_API_CS;
		WriteFile( g_hLogFile, pszTTStamp, lstrlen(pszTTStamp), &dwBytesWritten, NULL );
		WriteFile( g_hLogFile, pszMessage, lstrlen(pszMessage), &dwBytesWritten, NULL );
		LEAVE_API_CS;
	}
}

// Helper functions
void o_printf( char* lpszFormat, ... )
{
	char szMessage[2048];
	char szTTStamp[100];
	SYSTEMTIME LT;
	va_list args;

	// Exit now if we cannot log to file.
	if ( NULL == g_hLogFile ) return;
	if ( NULL == g_pLogFileLock ) return;

	// Format input string.
	va_start( args, lpszFormat );
	_vsnprintf_s( szMessage, sizeof(szMessage), sizeof(szMessage), lpszFormat, args );
	va_end(args);
	lstrcat( szMessage, "\r\n" );

	// Get timestamp, format.
	GetSystemTime( &LT );
	sprintf_s( szTTStamp, sizeof(szTTStamp),
			 "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
			 LT.wYear, LT.wMonth, LT.wDay, 
			 LT.wHour, LT.wMinute, LT.wSecond, LT.wMilliseconds );

	// Write data.
	o_write( szTTStamp, szMessage );

}

#define O_STRINGA(x) { o_printf( "%-25s = '%s'", #x, (NULL==x) ? (char*)"<NULL>" : (char*) x ); }
#define O_STRINGU(x) { o_printf( "%-25s = '%S'", #x, (NULL==x) ? (unsigned char*)L"<NULL>" : (unsigned char*)x ); }
#define O_DEC(x)     { o_printf( "%-25s = %lu", #x, x ); }
#define O_WORD(x)    { o_printf( "%-25s = %d", #x, x ); }
#define O_HEX(x)     { o_printf( "%-25s = 0x%08x", #x, x ); }
#define O_BOOL(x)    { o_printf( "%-25s = %s", #x, ( x ) ? "TRUE" : "FALSE" ); }

char* GetSecurityErrorString( DWORD dwError )
{
	switch( dwError )
	{
		case SEC_E_INSUFFICIENT_MEMORY:         return "SEC_E_INSUFFICIENT_MEMORY (Not enough memory is available to complete this request)";
		case SEC_E_INVALID_HANDLE:				return "SEC_E_INVALID_HANDLE (The handle specified is invalid)";
		case SEC_E_UNSUPPORTED_FUNCTION:        return "SEC_E_UNSUPPORTED_FUNCTION (The function requested is not supported)";
		case SEC_E_TARGET_UNKNOWN:				return "SEC_E_TARGET_UNKNOWN (The specified target is unknown or unreachable)";
		case SEC_E_INTERNAL_ERROR:				return "SEC_E_INTERNAL_ERROR (The Local Security Authority cannot be contacted)";
		case SEC_E_SECPKG_NOT_FOUND:			return "SEC_E_SECPKG_NOT_FOUND (The requested security package does not exist)";
		case SEC_E_NOT_OWNER:					return "SEC_E_NOT_OWNER (The caller is not the owner of the desired credentials)";
		case SEC_E_CANNOT_INSTALL:				return "SEC_E_CANNOT_INSTALL (The security package failed to initialize, and cannot be installed)";
		case SEC_E_INVALID_TOKEN:				return "SEC_E_INVALID_TOKEN (The token supplied to the function is invalid)";
		case SEC_E_CANNOT_PACK:					return "SEC_E_CANNOT_PACK (The security package is not able to marshall the logon buffer, so the logon attempt has failed)";
		case SEC_E_QOP_NOT_SUPPORTED:			return "SEC_E_QOP_NOT_SUPPORTED (The per-message Quality of Protection is not supported by the security package)";
		case SEC_E_NO_IMPERSONATION:			return "SEC_E_NO_IMPERSONATION (The security context does not allow impersonation of the client)";
		case SEC_E_LOGON_DENIED:				return "SEC_E_LOGON_DENIED (The logon attempt failed)";
		case SEC_E_UNKNOWN_CREDENTIALS:         return "SEC_E_UNKNOWN_CREDENTIALS (The credentials supplied to the package were not recognized)";
		case SEC_E_NO_CREDENTIALS:				return "SEC_E_NO_CREDENTIALS (No credentials are available in the security package)";
		case SEC_E_MESSAGE_ALTERED:				return "SEC_E_MESSAGE_ALTERED (The message or signature supplied for verification has been altered)";
		case SEC_E_OUT_OF_SEQUENCE:				return "SEC_E_OUT_OF_SEQUENCE (The message supplied for verification is out of sequence)";
		case SEC_E_NO_AUTHENTICATING_AUTHORITY: return "SEC_E_NO_AUTHENTICATING_AUTHORITY (No authority could be contacted for authentication)";
		case SEC_I_CONTINUE_NEEDED:				return "SEC_I_CONTINUE_NEEDED (The function completed successfully, but must be called again to complete the context)";
		case SEC_I_COMPLETE_NEEDED:				return "SEC_I_COMPLETE_NEEDED (The function completed successfully, but CompleteToken must be called)";
		case SEC_I_COMPLETE_AND_CONTINUE:       return "SEC_I_COMPLETE_AND_CONTINUE (The function completed successfully, but both CompleteToken and this function must be called to complete the context)";
		case SEC_I_LOCAL_LOGON:					return "SEC_I_LOCAL_LOGON (The logon was completed, but no network authority was available. The logon was made using locally known information)";
		case SEC_E_BAD_PKGID:					return "SEC_E_BAD_PKGID (The requested security package does not exist)";
		case SEC_E_CONTEXT_EXPIRED:				return "SEC_E_CONTEXT_EXPIRED (The context has expired and can no longer be used)";
		case SEC_I_CONTEXT_EXPIRED:				return "SEC_I_CONTEXT_EXPIRED (The context has expired and can no longer be used)";
		case SEC_E_INCOMPLETE_MESSAGE:			return "SEC_E_INCOMPLETE_MESSAGE (The supplied message is incomplete.  The signature was not verified)";
		case SEC_E_INCOMPLETE_CREDENTIALS:      return "SEC_E_INCOMPLETE_CREDENTIALS (The credentials supplied were not complete, and could not be verified. The context could not be initialized)";
		case SEC_E_BUFFER_TOO_SMALL:			return "SEC_E_BUFFER_TOO_SMALL (The buffers supplied to a function was too small)";
		case SEC_I_INCOMPLETE_CREDENTIALS:      return "SEC_I_INCOMPLETE_CREDENTIALS (The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context)";
		case SEC_I_RENEGOTIATE:					return "SEC_I_RENEGOTIATE (The context data must be renegotiated with the peer)";
		case SEC_E_WRONG_PRINCIPAL:				return "SEC_E_WRONG_PRINCIPAL (The target principal name is incorrect)";
		case SEC_I_NO_LSA_CONTEXT:				return "SEC_I_NO_LSA_CONTEXT (There is no LSA mode context associated with this context)";
		case SEC_E_TIME_SKEW:					return "SEC_E_TIME_SKEW (The clocks on the client and server machines are skewed)";
		case SEC_E_UNTRUSTED_ROOT:				return "SEC_E_UNTRUSTED_ROOT (The certificate chain was issued by an authority that is not trusted)";
		case SEC_E_ILLEGAL_MESSAGE:				return "SEC_E_ILLEGAL_MESSAGE (The message received was unexpected or badly formatted)";
		case SEC_E_CERT_UNKNOWN:				return "SEC_E_CERT_UNKNOWN (An unknown error occurred while processing the certificate)";
		case SEC_E_CERT_EXPIRED:				return "SEC_E_CERT_EXPIRED (The received certificate has expired)";
		case SEC_E_ENCRYPT_FAILURE:				return "SEC_E_ENCRYPT_FAILURE (The specified data could not be encrypted)";
		case SEC_E_DECRYPT_FAILURE:				return "SEC_E_DECRYPT_FAILURE (The specified data could not be decrypted)";
		case SEC_E_ALGORITHM_MISMATCH:			return "SEC_E_ALGORITHM_MISMATCH (The client and server cannot communicate, because they do not possess a common algorithm)";
		case SEC_E_SECURITY_QOS_FAILED:         return "SEC_E_SECURITY_QOS_FAILED (The security context could not be established due to a failure in the requested quality of service (e.g. mutual authentication or delegation))";
		case SEC_E_UNFINISHED_CONTEXT_DELETED:  return "SEC_E_UNFINISHED_CONTEXT_DELETED (A security context was deleted before the context was completed.  This is considered a logon failure)";
		case SEC_E_NO_TGT_REPLY:				return "SEC_E_NO_TGT_REPLY (The client is trying to negotiate a context and the server requires user-to-user but didn't send a TGT reply)";
		case SEC_E_NO_IP_ADDRESSES:				return "SEC_E_NO_IP_ADDRESSES (Unable to accomplish the requested task because the local machine does not have any IP addresses)";
		case SEC_E_WRONG_CREDENTIAL_HANDLE:     return "SEC_E_WRONG_CREDENTIAL_HANDLE (The supplied credential handle does not match the credential associated with the security context)";
		case SEC_E_CRYPTO_SYSTEM_INVALID:       return "SEC_E_CRYPTO_SYSTEM_INVALID (The crypto system or checksum function is invalid because a required function is unavailable)";
		case SEC_E_MAX_REFERRALS_EXCEEDED:      return "SEC_E_MAX_REFERRALS_EXCEEDED (The number of maximum ticket referrals has been exceeded)";
		case SEC_E_MUST_BE_KDC:					return "SEC_E_MUST_BE_KDC (The local machine must be a Kerberos KDC (domain controller) and it is not)";
		case SEC_E_STRONG_CRYPTO_NOT_SUPPORTED: return "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED (The other end of the security negotiation is requires strong crypto but it is not supported on the local machine)";
		case SEC_E_TOO_MANY_PRINCIPALS:         return "SEC_E_TOO_MANY_PRINCIPALS (The KDC reply contained more than one principal name)";
		case SEC_E_NO_PA_DATA:					return "SEC_E_NO_PA_DATA (Expected to find PA data for a hint of what etype to use, but it was not found)";
		case SEC_E_PKINIT_NAME_MISMATCH:        return "SEC_E_PKINIT_NAME_MISMATCH (The client cert name does not matches the user name or the KDC name is incorrect)";
		case SEC_E_SMARTCARD_LOGON_REQUIRED:    return "SEC_E_SMARTCARD_LOGON_REQUIRED (Smartcard logon is required and was not used)";
		case SEC_E_SHUTDOWN_IN_PROGRESS:        return "SEC_E_SHUTDOWN_IN_PROGRESS (A system shutdown is in progress)";
		case SEC_E_KDC_INVALID_REQUEST:         return "SEC_E_KDC_INVALID_REQUEST (An invalid request was sent to the KDC)";
		case SEC_E_KDC_UNABLE_TO_REFER:         return "SEC_E_KDC_UNABLE_TO_REFER (The KDC was unable to generate a referral for the service requested)";
		case SEC_E_KDC_UNKNOWN_ETYPE:			return "SEC_E_KDC_UNKNOWN_ETYPE (The encryption type requested is not supported by the KDC)";
		case SEC_E_UNSUPPORTED_PREAUTH:         return "SEC_E_UNSUPPORTED_PREAUTH (An unsupported preauthentication mechanism was presented to the kerberos package)";
		case SEC_E_DELEGATION_REQUIRED:         return "SEC_E_DELEGATION_REQUIRED (The requested operation requires delegation to be enabled on the machine)";
		case SEC_E_BAD_BINDINGS:				return "SEC_E_BAD_BINDINGS (Client's supplied SSPI channel bindings were incorrect)";
		case SEC_E_MULTIPLE_ACCOUNTS:			return "SEC_E_MULTIPLE_ACCOUNTS (The received certificate was mapped to multiple accounts)";
		case SEC_E_NO_KERB_KEY:					return "SEC_E_NO_KERB_KEY (SEC_E_NO_KERB_KEY)";
	}
	return "UNKNOWN_SEC_E_CODE";
}

#define CONST_CASE(x) case x: return #x

char* GetSecBufferTypeString( DWORD dwFlags )
{
	switch( dwFlags )
	{
		CONST_CASE(SECBUFFER_EMPTY);
		CONST_CASE(SECBUFFER_DATA);
		CONST_CASE(SECBUFFER_TOKEN);
		CONST_CASE(SECBUFFER_PKG_PARAMS);
		CONST_CASE(SECBUFFER_MISSING);
		CONST_CASE(SECBUFFER_EXTRA);
		CONST_CASE(SECBUFFER_STREAM_TRAILER);
		CONST_CASE(SECBUFFER_STREAM_HEADER);
		CONST_CASE(SECBUFFER_NEGOTIATION_INFO);
		CONST_CASE(SECBUFFER_PADDING);
		CONST_CASE(SECBUFFER_STREAM);
		CONST_CASE(SECBUFFER_MECHLIST);
		CONST_CASE(SECBUFFER_MECHLIST_SIGNATURE);
		CONST_CASE(SECBUFFER_TARGET);
		CONST_CASE(SECBUFFER_CHANNEL_BINDINGS);
	}
	return "UNKNOWN_SECBUFFER_FLAG_VALUE";
}

char* GetSecPkgContextAttrString( DWORD dwFlags )
{
	switch( dwFlags )
	{
		CONST_CASE(SECPKG_ATTR_SIZES);
		CONST_CASE(SECPKG_ATTR_NAMES);
		CONST_CASE(SECPKG_ATTR_LIFESPAN);
		CONST_CASE(SECPKG_ATTR_DCE_INFO);
		CONST_CASE(SECPKG_ATTR_STREAM_SIZES);
		CONST_CASE(SECPKG_ATTR_KEY_INFO);
		CONST_CASE(SECPKG_ATTR_AUTHORITY);
		CONST_CASE(SECPKG_ATTR_PROTO_INFO);
		CONST_CASE(SECPKG_ATTR_PASSWORD_EXPIRY);
		CONST_CASE(SECPKG_ATTR_SESSION_KEY);
		CONST_CASE(SECPKG_ATTR_PACKAGE_INFO);
		CONST_CASE(SECPKG_ATTR_USER_FLAGS);
		CONST_CASE(SECPKG_ATTR_NEGOTIATION_INFO);
		CONST_CASE(SECPKG_ATTR_NATIVE_NAMES);
		CONST_CASE(SECPKG_ATTR_FLAGS);
		CONST_CASE(SECPKG_ATTR_USE_VALIDATED);
		CONST_CASE(SECPKG_ATTR_CREDENTIAL_NAME);
		CONST_CASE(SECPKG_ATTR_TARGET_INFORMATION);
		CONST_CASE(SECPKG_ATTR_ACCESS_TOKEN);
	}
	return "UNKNOWN_SECPKG_ATTR_VALUE";
}

char* GetAuthType( DWORD dwFlags )
{
	switch (dwFlags)
	{
		CONST_CASE(AUTHTYPE_CLIENT);
		CONST_CASE(AUTHTYPE_SERVER);
	}
	return "UNKNOWN_AUTH_TYPE";
}

char* GetCertChainPolicyStatusCode( DWORD dwError)
{
	switch (dwError)
	{
		CONST_CASE(S_OK);
		CONST_CASE(TRUST_E_CERT_SIGNATURE);
		CONST_CASE(CERT_E_UNTRUSTEDROOT);
		CONST_CASE(CERT_E_UNTRUSTEDTESTROOT);
		CONST_CASE(CERT_E_CHAINING);
		CONST_CASE(CERT_E_WRONG_USAGE);
		CONST_CASE(CERT_E_EXPIRED);
		CONST_CASE(CERT_E_VALIDITYPERIODNESTING);
		CONST_CASE(CERT_E_PURPOSE);
		CONST_CASE(TRUST_E_BASIC_CONSTRAINTS);
		CONST_CASE(CERT_E_ROLE);
		CONST_CASE(CERT_E_CN_NO_MATCH);
		CONST_CASE(CRYPT_E_REVOKED);
		CONST_CASE(CRYPT_E_REVOCATION_OFFLINE);
		CONST_CASE(CERT_E_REVOKED);
		CONST_CASE(CERT_E_REVOCATION_FAILURE);
	}
	return "UNKNOWN_CERT_CHAIN_POLICY_STATUS";

}

#define BITFLAG_TEST(x) if ( dwFlags & x ) { if ( lstrlen(szFS) > 0 ) lstrcat( szFS,"|" ); lstrcat( szFS, #x ); }

char* Get_ISC_REQ_FlagsString( DWORD dwFlags )
{
	static char szFS[1024];
	ZeroMemory( szFS, sizeof(szFS) );
	BITFLAG_TEST(ISC_REQ_DELEGATE);
	BITFLAG_TEST(ISC_REQ_MUTUAL_AUTH);
	BITFLAG_TEST(ISC_REQ_REPLAY_DETECT);
	BITFLAG_TEST(ISC_REQ_SEQUENCE_DETECT);
	BITFLAG_TEST(ISC_REQ_CONFIDENTIALITY);
	BITFLAG_TEST(ISC_REQ_USE_SESSION_KEY);
	BITFLAG_TEST(ISC_REQ_PROMPT_FOR_CREDS);
	BITFLAG_TEST(ISC_REQ_USE_SUPPLIED_CREDS);
	BITFLAG_TEST(ISC_REQ_ALLOCATE_MEMORY);
	BITFLAG_TEST(ISC_REQ_USE_DCE_STYLE);
	BITFLAG_TEST(ISC_REQ_DATAGRAM);
	BITFLAG_TEST(ISC_REQ_CONNECTION);
	BITFLAG_TEST(ISC_REQ_CALL_LEVEL);
	BITFLAG_TEST(ISC_REQ_FRAGMENT_SUPPLIED);
	BITFLAG_TEST(ISC_REQ_EXTENDED_ERROR);
	BITFLAG_TEST(ISC_REQ_STREAM);
	BITFLAG_TEST(ISC_REQ_INTEGRITY);
	BITFLAG_TEST(ISC_REQ_IDENTIFY);
	BITFLAG_TEST(ISC_REQ_NULL_SESSION);
	BITFLAG_TEST(ISC_REQ_MANUAL_CRED_VALIDATION);
	BITFLAG_TEST(ISC_REQ_RESERVED1);
	BITFLAG_TEST(ISC_REQ_FRAGMENT_TO_FIT);
	return szFS;
}

char* Get_ISC_RET_FlagsString( DWORD dwFlags )
{
	static char szFS[1024];
	ZeroMemory( szFS, sizeof(szFS) );
	BITFLAG_TEST(ISC_RET_DELEGATE);
	BITFLAG_TEST(ISC_RET_MUTUAL_AUTH);
	BITFLAG_TEST(ISC_RET_REPLAY_DETECT);
	BITFLAG_TEST(ISC_RET_SEQUENCE_DETECT);
	BITFLAG_TEST(ISC_RET_CONFIDENTIALITY);
	BITFLAG_TEST(ISC_RET_USE_SESSION_KEY);
	BITFLAG_TEST(ISC_RET_USED_COLLECTED_CREDS);
	BITFLAG_TEST(ISC_RET_USED_SUPPLIED_CREDS);
	BITFLAG_TEST(ISC_RET_ALLOCATED_MEMORY);
	BITFLAG_TEST(ISC_RET_DATAGRAM);
	BITFLAG_TEST(ISC_RET_CONNECTION);
	BITFLAG_TEST(ISC_RET_INTERMEDIATE_RETURN);
	BITFLAG_TEST(ISC_RET_CALL_LEVEL);
	BITFLAG_TEST(ISC_RET_EXTENDED_ERROR);
	BITFLAG_TEST(ISC_RET_STREAM);
	BITFLAG_TEST(ISC_RET_INTEGRITY);
	BITFLAG_TEST(ISC_RET_IDENTIFY);
	BITFLAG_TEST(ISC_RET_NULL_SESSION);
	BITFLAG_TEST(ISC_RET_MANUAL_CRED_VALIDATION);
	BITFLAG_TEST(ISC_RET_RESERVED1);
	BITFLAG_TEST(ISC_RET_FRAGMENT_ONLY);
	return szFS;
}

char* Get_ASC_REQ_FlagsString( DWORD dwFlags )
{
	static char szFS[1024];
	ZeroMemory( szFS, sizeof(szFS) );
	BITFLAG_TEST(ASC_REQ_DELEGATE);
	BITFLAG_TEST(ASC_REQ_MUTUAL_AUTH);
	BITFLAG_TEST(ASC_REQ_REPLAY_DETECT);
	BITFLAG_TEST(ASC_REQ_SEQUENCE_DETECT);
	BITFLAG_TEST(ASC_REQ_CONFIDENTIALITY);
	BITFLAG_TEST(ASC_REQ_USE_SESSION_KEY);
	BITFLAG_TEST(ASC_REQ_ALLOCATE_MEMORY);
	BITFLAG_TEST(ASC_REQ_USE_DCE_STYLE);
	BITFLAG_TEST(ASC_REQ_DATAGRAM);
	BITFLAG_TEST(ASC_REQ_CONNECTION);
	BITFLAG_TEST(ASC_REQ_CALL_LEVEL);
	BITFLAG_TEST(ASC_REQ_EXTENDED_ERROR);
	BITFLAG_TEST(ASC_REQ_STREAM);
	BITFLAG_TEST(ASC_REQ_INTEGRITY);
	BITFLAG_TEST(ASC_REQ_LICENSING);
	BITFLAG_TEST(ASC_REQ_IDENTIFY);
	BITFLAG_TEST(ASC_REQ_ALLOW_NULL_SESSION);
	BITFLAG_TEST(ASC_REQ_ALLOW_NON_USER_LOGONS);
	BITFLAG_TEST(ASC_REQ_ALLOW_CONTEXT_REPLAY);
	BITFLAG_TEST(ASC_REQ_FRAGMENT_TO_FIT);
	BITFLAG_TEST(ASC_REQ_FRAGMENT_SUPPLIED);
	return szFS;
}

char* Get_ASC_RET_FlagsString( DWORD dwFlags )
{
	static char szFS[1024];
	ZeroMemory( szFS, sizeof(szFS) );
	BITFLAG_TEST(ASC_RET_DELEGATE);
	BITFLAG_TEST(ASC_RET_MUTUAL_AUTH);
	BITFLAG_TEST(ASC_RET_REPLAY_DETECT);
	BITFLAG_TEST(ASC_RET_SEQUENCE_DETECT);
	BITFLAG_TEST(ASC_RET_CONFIDENTIALITY);
	BITFLAG_TEST(ASC_RET_USE_SESSION_KEY);
	BITFLAG_TEST(ASC_RET_ALLOCATED_MEMORY);
	BITFLAG_TEST(ASC_RET_USED_DCE_STYLE);
	BITFLAG_TEST(ASC_RET_DATAGRAM);
	BITFLAG_TEST(ASC_RET_CONNECTION);
	BITFLAG_TEST(ASC_RET_CALL_LEVEL);
	BITFLAG_TEST(ASC_RET_THIRD_LEG_FAILED);
	BITFLAG_TEST(ASC_RET_EXTENDED_ERROR);
	BITFLAG_TEST(ASC_RET_STREAM);
	BITFLAG_TEST(ASC_RET_INTEGRITY);
	BITFLAG_TEST(ASC_RET_LICENSING);
	BITFLAG_TEST(ASC_RET_IDENTIFY);
	BITFLAG_TEST(ASC_RET_NULL_SESSION);
	BITFLAG_TEST(ASC_RET_ALLOW_NON_USER_LOGONS);
	BITFLAG_TEST(ASC_RET_ALLOW_CONTEXT_REPLAY);
	BITFLAG_TEST(ASC_RET_FRAGMENT_ONLY);
	return szFS;
}

void DumpSEC_WINNT_AUTH_IDENTITY( SEC_WINNT_AUTH_IDENTITY_A* pAuthData )
{
	if ( NULL == pAuthData ) return;
	
	if ( SEC_WINNT_AUTH_IDENTITY_ANSI == pAuthData->Flags )
	{
		O_STRINGA( pAuthData->User );
		O_DEC(pAuthData->UserLength );
		O_STRINGA( pAuthData->Domain );
		O_DEC(pAuthData->DomainLength );
		O_STRINGA( pAuthData->Password );
		O_DEC( pAuthData->PasswordLength );
		o_printf( "%-25s = SEC_WINNT_AUTH_IDENTITY_ANSI", "pAuthData->Flags" );
	}
	else
	{
		O_STRINGU( pAuthData->User );
		O_DEC(pAuthData->UserLength );
		O_STRINGU( pAuthData->Domain );
		O_DEC(pAuthData->DomainLength );
		O_STRINGU( pAuthData->Password );
		O_DEC( pAuthData->PasswordLength );
		o_printf( "%-25s = SEC_WINNT_AUTH_IDENTITY_UNICODE", "pAuthData->Flags" );
	}
}

void DumpSCHANNEL_CRED( PSCHANNEL_CRED pAuthData )
{
	if ( NULL == pAuthData ) return;
    O_DEC( pAuthData->dwVersion );     
    O_DEC( pAuthData->cCreds );
    O_HEX( pAuthData->paCred );
    O_HEX( pAuthData->hRootStore );
    O_DEC( pAuthData->cMappers );
    O_HEX( pAuthData->aphMappers );
    O_DEC( pAuthData->cSupportedAlgs );
    O_HEX( pAuthData->palgSupportedAlgs );
    O_HEX( pAuthData->grbitEnabledProtocols );
    O_DEC( pAuthData->dwMinimumCipherStrength );
    O_DEC( pAuthData->dwMaximumCipherStrength );
    O_DEC( pAuthData->dwSessionLifespan );
    O_HEX( pAuthData->dwFlags );
}

void DumpHex( void* pData, unsigned long length )
{
	unsigned long i, ulWritten;
	BYTE* pB = (BYTE*) pData;
	char szLookup[] = "0123456789abcdef";
	char szHex[100];
	char szDisplay[100];
	if ( ( NULL == pData ) || ( 0 == length ) ) return;

	ulWritten = 0;
	for( ;; )
	{
		ZeroMemory( szHex, sizeof(szHex) );
		ZeroMemory( szDisplay, sizeof(szDisplay) );
		for ( i=0; i<0x10; i++ )
		{
			if ( ulWritten >= length )
			{
				// Just write a blank.
				szDisplay[i]   = ' ';
				szHex[(i*3)]   = ' ';
				szHex[(i*3)+1] = ' ';
				szHex[(i*3)+2] = ' ';
			}
			else
			{
				szDisplay[i]   = (char) ( ( pB[i] > 31 ) && (pB[i] < 127 ) ) ? (char)pB[i] : '.';
				szHex[(i*3)]   = szLookup[ ((pB[i]/0x10)%0x10) ];
				szHex[(i*3)+1] = szLookup[ (pB[i]%0x10) ];
				szHex[(i*3)+2] = ' ';
			}
			ulWritten++;
		}
		o_printf( "%08x  %s  %s", pB, szHex, szDisplay );

		if ( ulWritten >= length ) break;

		pB += 0x10;

	}
}

void DumpSecBufferInputDesc( PSecBufferDesc pInput )
{
	unsigned long i;
	if ( NULL == pInput ) return;

	O_DEC( pInput->ulVersion );
	O_DEC( pInput->cBuffers );

	for( i=0; i<pInput->cBuffers; i++ )
	{
		o_printf( "pBuffers[%02lu].cbBuffer   = %lu",    i, pInput->pBuffers[i].cbBuffer );
		o_printf( "pBuffers[%02lu].BufferType = %lu %s", i, pInput->pBuffers[i].BufferType, GetSecBufferTypeString( pInput->pBuffers[i].BufferType) );
		o_printf( "pBuffers[%02lu].pvBuffer   = 0x%08x", i, pInput->pBuffers[i].pvBuffer );
		DumpHex( pInput->pBuffers[i].pvBuffer, pInput->pBuffers[i].cbBuffer );
	}
}

void DumpSecBufferOutputDesc( SECURITY_STATUS rv, PSecBufferDesc pOutput )
{
	unsigned long i;
	if ( NULL == pOutput ) return;

	O_DEC( pOutput->ulVersion );
	O_DEC( pOutput->cBuffers );

	for( i=0; i<pOutput->cBuffers; i++ )
	{
		o_printf( "pBuffers[%02lu].cbBuffer   = %lu",    i, pOutput->pBuffers[i].cbBuffer );
		o_printf( "pBuffers[%02lu].BufferType = %lu %s", i, pOutput->pBuffers[i].BufferType, GetSecBufferTypeString( pOutput->pBuffers[i].BufferType) );
		o_printf( "pBuffers[%02lu].pvBuffer   = 0x%08x", i, pOutput->pBuffers[i].pvBuffer );

		// Only dump output buffers if call was successful.
		if ( rv >= 0 )
		{
			DumpHex( pOutput->pBuffers[i].pvBuffer, pOutput->pBuffers[i].cbBuffer );
		}
	}
}

char* DumpTimeStamp( PTimeStamp ptsExpiry, char* pszTSBuffer, size_t cchTSBuffer )
{
	SYSTEMTIME stExpire;
	__int64 i64Now, i64Expire, i64Diff, i64Hours, i64Mins, i64Secs;
	BOOL fExpired = FALSE;
	
	if ( NULL == pszTSBuffer || cchTSBuffer < 2) return "NULL";
	__try
	{
		pszTSBuffer[0] = '\0';
		pszTSBuffer[1] = '\0';
		if ( ( 0x7FFFFFFF == ptsExpiry->HighPart ) && ( 0xFFFFFFFF == ptsExpiry->LowPart ) ) 
		{
			sprintf_s( pszTSBuffer, cchTSBuffer, "%08x:%08x Infinite",
				     ptsExpiry->HighPart,
				     ptsExpiry->LowPart );
			return pszTSBuffer;
		}

		if ( ptsExpiry->HighPart > 0x7FFF0000 )
		{
			sprintf_s( pszTSBuffer, cchTSBuffer, "%08x:%08x Infinite",
				     ptsExpiry->HighPart,
				     ptsExpiry->LowPart );
			return pszTSBuffer;
		}

		GetSystemTimeAsFileTime( (FILETIME*)&i64Now );
		i64Expire = *(__int64*)ptsExpiry;
		if ( i64Expire < i64Now )
		{
			fExpired = TRUE;
			i64Diff = i64Now - i64Expire;
		}
		else
		{
			fExpired = FALSE;
			i64Diff = i64Expire - i64Now;
		}

		// lDiffHours is in 100 nanoseconds units.
		// Convert this to seconds.
		i64Secs = i64Diff/10000000; 
		
		// Calculate hours, minutes, and seconds.
		i64Mins    = i64Secs/60;
		i64Secs    = i64Secs - (i64Mins*60);
		i64Hours   = i64Mins/60;
		i64Mins    = i64Mins - (i64Hours*60);

        if ( !FileTimeToSystemTime( (PFILETIME) ptsExpiry, &stExpire ) )
		{
			sprintf_s( pszTSBuffer, cchTSBuffer, "FTTST Fail %lu", GetLastError() );
			return pszTSBuffer;
		}

		sprintf_s( pszTSBuffer, cchTSBuffer, "%04d-%02d-%02d %02d:%02d:%02d %s (%02I64u:%02I64u:%02I64u diff)",
                 stExpire.wYear,
                 stExpire.wMonth,
                 stExpire.wDay,
                 stExpire.wHour,
                 stExpire.wMinute,
                 stExpire.wSecond,
				 ( fExpired ) ? "*** EXPIRED ***" : "STILL VALID", 
				 i64Hours, i64Mins, i64Secs );

	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};
	return pszTSBuffer;
}

#define CONST_CASE1(x)		case x: return #x
#define CONST_CASE2(x,msg)	case x: return msg

char* GetImpLevelString( DWORD dwImpLevel )
{
	switch ( dwImpLevel )
	{
		CONST_CASE2( 0, "SecurityAnonymous" );
		CONST_CASE2( 1, "SecurityIdentification" );
		CONST_CASE2( 2, "SecurityImpersonation" );
		CONST_CASE2( 3, "SecurityDelegation" );
		// I added this extra "state" myself for state where you can't read the value from the thread token.
		CONST_CASE2( 4, "SecurityNoImpersonation" ); 
	}
	return "UnknownImpLevel";
}

char* GetTokenTypeString( DWORD dwTokenType )
{
	switch ( dwTokenType )
	{
		CONST_CASE2( 1, "TokenPrimary" );
		CONST_CASE2( 2, "TokenImpersonation" );
	}
	return "UnknownTokenType";
}

char* GetThreadOrProcString( DWORD dwThreadOrProc )
{
	switch ( dwThreadOrProc )
	{
		CONST_CASE2( 0, "ProcessToken" );
		CONST_CASE2( 1, "ThreadToken" );
	}
	return "UnknownThreadOrProc";
}

// Returns THREAD_USER* filled out using current thread's token info.
THREAD_USER* GetThreadUser()
{
    PTOKEN_USER   pTU		   = NULL;
    PTOKEN_SOURCE pTS		   = NULL;
    HANDLE        hToken	   = NULL;
    DWORD         dwLen        = 0;
    DWORD         dwErr		   = 0;
    DWORD         cbName	   = 0;
    DWORD         cbDomainName = 0;
    SID_NAME_USE  Se;
    DWORD         dwProcessId  = 0;
    HANDLE        hProcess	   = NULL;
	PTHREAD_USER  pThreadUser  = NULL;
	DWORD i;
	BOOL fStatus			   = FALSE;

	// Get process id and process handle.
    dwProcessId = GetCurrentProcessId();
    hProcess	= GetCurrentProcess();
	if ( NULL == hProcess ) goto GetThreadUserExit;	

	pThreadUser = new THREAD_USER;
    if ( NULL == pThreadUser ) goto GetThreadUserExit;
	
	ZeroMemory( pThreadUser, sizeof(THREAD_USER) );

    pThreadUser->dwProcId = dwProcessId;

	// Try opening thread token, if this fails, then try to open process token.
    if ( !OpenThreadToken( GetCurrentThread(), TOKEN_QUERY|TOKEN_QUERY_SOURCE, TRUE, &hToken ) ) 
	{
        if( !OpenProcessToken( hProcess, TOKEN_QUERY|TOKEN_QUERY_SOURCE, &hToken ) ) return NULL;
		pThreadUser->dwThreadOrProc = 0; // Got process token.
    }
    else
	{
        pThreadUser->dwThreadOrProc = 1; // Got thread token.
	}

    //Get the Token source.
    dwLen = 0;
    if ( !GetTokenInformation( hToken, TokenSource, (LPVOID)pTS, 0, &dwLen ) ) 
	{
        if ( ERROR_INSUFFICIENT_BUFFER == GetLastError() ) 
		{
            SetLastError(0);
            pTS = (TOKEN_SOURCE *) new BYTE[ dwLen ];
            if ( pTS ) 
			{
				ZeroMemory( pTS, dwLen );
				ZeroMemory( pThreadUser->szTokenSource, sizeof(pThreadUser->szTokenSource) );
				if ( GetTokenInformation( hToken, TokenSource, (LPVOID)pTS, dwLen, &dwLen ) )
				{
					if ( pTS->SourceName )
					{
						if ( dwLen > sizeof(pThreadUser->szTokenSource) ) dwLen = sizeof(pThreadUser->szTokenSource);
						for ( i=0; i<dwLen; i++ )
						{
							pThreadUser->szTokenSource[i] = pTS->SourceName[i];
							if ( ( pThreadUser->szTokenSource[i] > '~'  ) ||
								 ( pThreadUser->szTokenSource[i] <= ' '  ) )
							{
									pThreadUser->szTokenSource[i] = '\0';
									break;
							}
						}
					}
				}
			}
        }
    }
    dwErr = GetLastError();

    // Get the users sid, and look up the name and domain.
    if ( !dwErr ) 
	{
        dwLen = 0;
        if ( !GetTokenInformation( hToken, TokenUser, (LPVOID)pTU, 0, &dwLen ) ) 
		{
            if ( ERROR_INSUFFICIENT_BUFFER == GetLastError() ) 
			{
                SetLastError(0);
                pTU = (TOKEN_USER *) new BYTE[ dwLen ];
                if ( pTU ) 
				{
                    if ( GetTokenInformation( hToken, TokenUser, (LPVOID)pTU, dwLen, &dwLen) ) 
					{
						cbName		 = sizeof(pThreadUser->szName);
						cbDomainName = sizeof(pThreadUser->szDomain);
						ZeroMemory( &Se, sizeof(Se) );
                        if ( LookupAccountSidA( NULL, 
                                                pTU->User.Sid, 
                                                pThreadUser->szName, 
                                                &cbName, 
                                                pThreadUser->szDomain, 
                                                &cbDomainName, 
                                                &Se ) ) 
						{
                            SetLastError(0);
                        }
                    }
                }
            }
        }
        dwErr = GetLastError();
    }

    if ( !dwErr ) 
	{
        dwLen = 0;
        if ( !GetTokenInformation( hToken, 
                                   TokenImpersonationLevel, 
                                   (LPVOID)&(pThreadUser->dwImpLevel), 
                                   sizeof(pThreadUser->dwImpLevel), 
                                   &dwLen ) ) 
		{
            pThreadUser->dwImpLevel = 4;
        }
    }

    if ( !dwErr ) 
	{
        dwLen = 0;
        if( !GetTokenInformation( hToken, 
                                  TokenType, 
                                  (LPVOID)&(pThreadUser->dwTokenType), 
                                  sizeof(pThreadUser->dwTokenType), 
                                  &dwLen ) ) 
		{
            dwErr = GetLastError();
        }
    }

	if ( 0 == dwErr ) fStatus = TRUE;

GetThreadUserExit:

	if ( hProcess ) CloseHandle( hProcess );
	hProcess = NULL;

	if ( hToken ) CloseHandle( hToken );
	hToken = NULL;

    // Clean up and leave.
    if ( pTU ) delete [] pTU;
    
    if ( pTS ) delete [] pTS;

    if( fStatus ) return pThreadUser;
    
	if ( pThreadUser ) delete pThreadUser;
	pThreadUser = NULL;

    return NULL;

}


void DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal)
{
    char szName[1000];
    PCCERT_CONTEXT pCurrentCert;
    PCCERT_CONTEXT pIssuerCert;
    DWORD dwVerificationFlags;
    char pszNameString[1024];

    // Display Subject
    if(CertGetNameString( pServerCert,
                                      CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                      0,
                                      NULL,
                                      pszNameString,
                                      1023))
    {
       o_printf("Certificate Subject (simple): %s", pszNameString);
    }
    else
    {
       o_printf("CertGetName failed. Error = %d", GetLastError());
       return;
    }

    // display leaf name
    if(!CertNameToStrA(pServerCert->dwCertEncodingType,
                      &pServerCert->pCertInfo->Subject,
                      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                      szName, sizeof(szName)))
    {
        o_printf("**** Error 0x%x building subject name", GetLastError());
    }
    
	o_printf("Certificate Subject: %s", szName);

    if(!CertNameToStrA(pServerCert->dwCertEncodingType,
                      &pServerCert->pCertInfo->Issuer,
                      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                      szName, sizeof(szName)))
    {
        o_printf("**** Error 0x%x building issuer name", GetLastError());
    }
    
    o_printf("Issuer: %s", szName);

    // display certificate chain
    pCurrentCert = pServerCert;
    while(pCurrentCert != NULL)
    {
        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(pServerCert->hCertStore,
                                                        pCurrentCert,
                                                        NULL,
                                                        &dwVerificationFlags);
        if(pIssuerCert == NULL)
        {
            if(pCurrentCert != pServerCert)
            {
                CertFreeCertificateContext(pCurrentCert);
            }
            break;
        }

        if(!CertNameToStrA(pIssuerCert->dwCertEncodingType,
                          &pIssuerCert->pCertInfo->Subject,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          szName, sizeof(szName)))
        {
            o_printf("**** Error 0x%x building subject name", GetLastError());
        }
        o_printf("CA subject: %s", szName);
        if(!CertNameToStrA(pIssuerCert->dwCertEncodingType,
                          &pIssuerCert->pCertInfo->Issuer,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          szName, sizeof(szName)))
        {
            o_printf("**** Error 0x%x building issuer name", GetLastError());
        }
        o_printf("CA issuer: %s", szName);

        if(pCurrentCert != pServerCert)
        {
            CertFreeCertificateContext(pCurrentCert);
        }
        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }
}


// Trampolines

#pragma warning(disable:4100) 

// No real function trampolines are needed, we're binding directly to the function addresses in g_DFN.

// Detour functions.

SECURITY_STATUS SEC_ENTRY Mine_AcquireCredentialsHandleA(
    SEC_CHAR SEC_FAR * pszPrincipal,    // Name of principal
    SEC_CHAR SEC_FAR * pszPackage,      // Name of package
    unsigned long fCredentialUse,       // Flags indicating use
    void SEC_FAR * pvLogonId,           // Pointer to logon ID
    void SEC_FAR * pAuthData,           // Package specific data
    SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    void SEC_FAR * pvGetKeyArgument,    // Value to pass to GetKey()
    PCredHandle phCredential,           // (out) Cred Handle
    PTimeStamp ptsExpiry                // (out) Lifetime (optional)
    )
{
	SECURITY_STATUS rv;
	char szTSBuffer[128];
	
    __try 
	{
		o_printf( "" );
		o_printf( "ENTER AcquireCredentialsHandleA" );
		O_STRINGA( pszPrincipal );
		O_STRINGA( pszPackage );
		O_DEC( fCredentialUse );
		O_HEX( pvLogonId );
		O_HEX( pAuthData );
		DumpSCHANNEL_CRED( (PSCHANNEL_CRED) pAuthData );
		O_HEX( pGetKeyFn );
		O_HEX( pvGetKeyArgument );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnAcquireCredentialsHandleA( pszPrincipal,
												 pszPackage,
												 fCredentialUse,
												 pvLogonId,
												 pAuthData,
												 pGetKeyFn,
												 pvGetKeyArgument,
												 phCredential,
												 ptsExpiry );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{

		if ( SEC_E_OK != rv )
		{
			o_printf( "EXIT  AcquireCredentialsHandleA returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
		else
		{
			O_HEX( phCredential );
			o_printf( "ptsExpiry=0x%08x -> %s", ptsExpiry, DumpTimeStamp( ptsExpiry, szTSBuffer, sizeof(szTSBuffer) ) );
			o_printf( "EXIT  AcquireCredentialsHandleA returned SEC_E_OK." );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;

}

SECURITY_STATUS SEC_ENTRY Mine_InitializeSecurityContextA(
    PCredHandle phCredential,               // Cred to base context
    PCtxtHandle phContext,                  // Existing context (OPT)
    SEC_CHAR SEC_FAR * pszTargetName,       // Name of target
    unsigned long fContextReq,              // Context Requirements
    unsigned long Reserved1,                // Reserved, MBZ
    unsigned long TargetDataRep,            // Data rep of target
    PSecBufferDesc pInput,                  // Input Buffers
    unsigned long Reserved2,                // Reserved, MBZ
    PCtxtHandle phNewContext,               // (out) New Context handle
    PSecBufferDesc pOutput,                 // (inout) Output Buffers
    unsigned long SEC_FAR * pfContextAttr,  // (out) Context attrs
    PTimeStamp ptsExpiry                    // (out) Life span (OPT)
    )
{
	SECURITY_STATUS rv;
	char szTSBuffer[128];

    __try 
	{
		o_printf( "" );
		o_printf( "ENTER InitializeSecurityContextA" );
		O_HEX( phCredential );
		O_HEX( phContext );
		O_STRINGA( pszTargetName );
		o_printf( "%-25s = 0x%08x %s", "fContextReq", fContextReq, Get_ISC_REQ_FlagsString( fContextReq ) );
		O_DEC( TargetDataRep );
		O_HEX( pInput );
		DumpSecBufferInputDesc( pInput );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	__try
	{
		if ( NULL != pszTargetName )
		{
			lstrcpy( g_STATUS.g_szSavedSPN, pszTargetName );
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{

		rv = g_DFN.pfnInitializeSecurityContextA( phCredential,
												  phContext,
												  pszTargetName,
												  fContextReq,
												  Reserved1,
												  TargetDataRep,
												  pInput,
												  Reserved2,
												  phNewContext,
												  pOutput,
												  pfContextAttr,
												  ptsExpiry );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		O_HEX( phNewContext );
		O_HEX( pOutput );
		DumpSecBufferOutputDesc( rv, pOutput );
		if ( NULL == pfContextAttr )
		{
			O_HEX( pfContextAttr );	
		}
		else
		{
			o_printf( "%-25s = 0x%08x %s", "pfContextAttr", *pfContextAttr, Get_ISC_RET_FlagsString( *pfContextAttr ) );
		}
		o_printf( "ptsExpiry                 = 0x%08x -> %s", ptsExpiry, DumpTimeStamp( ptsExpiry, szTSBuffer, sizeof(szTSBuffer) ) );
		if ( SEC_E_OK == rv )
		{
			o_printf( "EXIT  InitializeSecurityContextA returned SEC_E_OK" );
		}
		else
		{
			o_printf( "EXIT  InitializeSecurityContextA returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;
}

SECURITY_STATUS SEC_ENTRY Mine_CompleteAuthToken(
  PCtxtHandle phContext, // handle of the context to complete
  PSecBufferDesc pToken  // token to complete
)
{
	SECURITY_STATUS rv;

   __try 
	{
	    o_printf( "" );
		o_printf( "ENTER CompleteAuthToken" );
		O_HEX( pToken );
		DumpSecBufferInputDesc( pToken );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnCompleteAuthToken( phContext,
										 pToken );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	__try
	{
		if ( SEC_E_OK == rv )
		{
			o_printf( "EXIT  CompleteAuthToken returned SEC_E_OK." );
		}
		else
		{
			o_printf( "EXIT  CompleteAuthToken returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;

}

SECURITY_STATUS SEC_ENTRY Mine_AcceptSecurityContext(
	PCredHandle phCredential,  // handle to the credentials
	PCtxtHandle phContext,     // handle of partially formed context
	PSecBufferDesc pInput,     // pointer to the input buffers
	ULONG fContextReq,         // required context attributes
	ULONG TargetDataRep,       // data representation on the target
	PCtxtHandle phNewContext,  // receives the new context handle
	PSecBufferDesc pOutput,    // pointer to the output buffers
	PULONG pfContextAttr,      // receives the context attributes
	PTimeStamp ptsTimeStamp    // receives the life span of the security context
	)
{
	SECURITY_STATUS rv;

    __try 
	{
		o_printf( "" );
		o_printf( "ENTER AcceptSecurityContext" );
		O_HEX( phCredential );
		O_HEX( phContext );
		O_HEX( pInput );
		DumpSecBufferInputDesc( pInput );
		o_printf( "%-25s = 0x%08x %s", "fContextReq", fContextReq, Get_ASC_REQ_FlagsString( fContextReq ) );
		O_DEC( TargetDataRep );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnAcceptSecurityContext( phCredential,
											 phContext,
											 pInput,
											 fContextReq,
											 TargetDataRep,
											 phNewContext,
											 pOutput,
											 pfContextAttr,
											 ptsTimeStamp );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	__try 
	{

		O_HEX( phNewContext );
		O_HEX( pOutput );
		DumpSecBufferOutputDesc( rv, pOutput );
		if ( NULL == pfContextAttr )
		{
			O_HEX( pfContextAttr );	
		}
		else
		{
			o_printf( "%-25s = 0x%08x %s", "pfContextAttr", *pfContextAttr, Get_ASC_RET_FlagsString( *pfContextAttr ) );
		}
		O_HEX( ptsTimeStamp );

		if ( SEC_E_OK == rv )
		{
			o_printf( "EXIT  AcceptSecurityContext returned SEC_E_OK." );
		}
		else
		{
			o_printf( "EXIT  AcceptSecurityContext returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;
}


SECURITY_STATUS SEC_ENTRY Mine_QuerySecurityPackageInfoA(
    SEC_CHAR SEC_FAR * pszPackageName,      // Name of package
    PSecPkgInfoA SEC_FAR *ppPackageInfo              // Receives package info
    )
{
	SECURITY_STATUS rv;
	PSecPkgInfoA pPackageInfo = NULL;

    __try 
	{
		o_printf( "" );
		o_printf( "ENTER QuerySecurityPackageInfoA" );
		O_STRINGA( pszPackageName );
		O_HEX( ppPackageInfo );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnQuerySecurityPackageInfoA( pszPackageName,
												 ppPackageInfo );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	__try 
	{
		if ( SEC_E_OK != rv )
		{
			o_printf( "EXIT  QuerySecurityPackageInfoA returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
		else
		{
			if ( NULL != ppPackageInfo )
			{
				pPackageInfo = *ppPackageInfo;
				O_HEX( pPackageInfo->fCapabilities );
				O_WORD( pPackageInfo->wVersion );
				O_WORD( pPackageInfo->wRPCID );
				O_DEC( pPackageInfo->cbMaxToken );
				O_STRINGA( pPackageInfo->Name );
				O_STRINGA( pPackageInfo->Comment );
			}
			o_printf( "EXIT  QuerySecurityPackageInfoA returned SEC_E_OK." );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;
}

/*
SECURITY_STATUS SEC_ENTRY Mine_FreeContextBuffer( void SEC_FAR * pvContextBuffer )
{
	SECURITY_STATUS rv;

    __try 
	{
		if ( !g_fSupressOutput )
		{
			o_printf( "" );
			o_printf( "ENTER FreeContextBuffer" );
			O_HEX( pvContextBuffer );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnFreeContextBuffer( pvContextBuffer );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if ( SEC_E_OK != rv )
		{
			if ( !g_fSupressOutput ) o_printf( "EXIT  FreeContextBuffer returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
		else
		{
			if ( !g_fSupressOutput ) o_printf( "EXIT  FreeContextBuffer returned SEC_E_OK." );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;
}

SECURITY_STATUS SEC_ENTRY Mine_DeleteSecurityContext( PCtxtHandle phContext )
{
	SECURITY_STATUS rv;

    __try 
	{
		if ( !g_fSupressOutput )
		{
			o_printf( "" );
			o_printf( "ENTER DeleteSecurityContext" );
			O_HEX( phContext );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnDeleteSecurityContext( phContext );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if ( SEC_E_OK != rv )
		{
			if ( !g_fSupressOutput ) o_printf( "EXIT  DeleteSecurityContext returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
		else
		{
			if ( !g_fSupressOutput ) o_printf( "EXIT  DeleteSecurityContext returned SEC_E_OK." );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;
}
*/

SECURITY_STATUS SEC_ENTRY Mine_QueryContextAttributesA(
    PCtxtHandle phContext,              // Context to query
    unsigned long ulAttribute,          // Attribute to query
    void SEC_FAR * pBuffer              // Buffer for attributes
    )
{
	SECURITY_STATUS rv;

    __try 
	{
		o_printf( "" );
		o_printf( "ENTER QueryContextAttributesA" );
		O_HEX( phContext );
		o_printf( "%-25s = 0x%08x %s", "ulAttribute", ulAttribute, GetSecPkgContextAttrString( ulAttribute ) );
		O_HEX( pBuffer );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnQueryContextAttributesA( phContext, ulAttribute, pBuffer );

    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if ( SEC_E_OK != rv )
		{
			o_printf( "EXIT  QueryContextAttributesA returned 0x%08x %s", rv, GetSecurityErrorString(rv) );
		}
		else
		{
			o_printf( "EXIT  QueryContextAttributesA returned SEC_E_OK." );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    return rv;
}

BOOL Mine_ConnectionGetSvrUser( CONNECTIONOBJECT* ConnectionObject, char* szUserName )
{
	BOOL rv;

	 __try 
	{
		o_printf( "" );
		o_printf( "ENTER ConnectionGetSvrUser" );
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	__try 
	{
		rv = g_DFN.ConnectionGetSvrUser( ConnectionObject, szUserName );
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	__try
	{
		O_STRINGA( szUserName );
		o_printf( "EXIT  ConnectionGetSvrUser" );
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};
	
	return rv;

}

BOOL Mine_GenClientContext( DWORD dwKey, BYTE* pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, CHAR *szServerInfo )
{
	BOOL rv;   
	THREAD_USER* pThreadUser = NULL;

	__try 
	{
		o_printf( "" );
		o_printf( "ENTER GenClientContext" );
		O_HEX( dwKey );
		O_HEX( pIn );
		O_DEC( cbIn );
		O_HEX( pOut );
		O_HEX( pcbOut );
		O_HEX( pfDone );
		O_STRINGA( szServerInfo );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	__try
	{
		pThreadUser = GetThreadUser();
		if ( pThreadUser )
		{
			o_printf( "%-25s = %s", "Domain",				pThreadUser->szDomain );
			o_printf( "%-25s = %s", "User",					pThreadUser->szName );
			o_printf( "%-25s = %s", "TokenSource",			pThreadUser->szTokenSource );
			o_printf( "%-25s = %s", "ImpersonationLevel",	GetImpLevelString( pThreadUser->dwImpLevel ) );
			o_printf( "%-25s = %s", "TokenType",			GetTokenTypeString( pThreadUser->dwTokenType ) );
			delete pThreadUser;
			pThreadUser = NULL;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.GenClientContext( dwKey,
									 pIn,
									 cbIn,								
									 pOut,
									 pcbOut,
									 pfDone,
									 szServerInfo );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		O_HEX( pOut );
		if ( NULL != pcbOut ) O_DEC( *pcbOut );
		if ( NULL != pfDone ) O_BOOL( *pfDone );
		O_STRINGA( szServerInfo );
		o_printf( "GenClientContext returned %s", (rv) ? "TRUE" : "FALSE" );
		o_printf( "EXIT  GenClientContext" );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	return rv;

}

BOOL Mine_InitSSPIPackage( DWORD* pcbMaxMessage )
{
	BOOL rv;
    __try 
	{
		o_printf( "" );
		o_printf( "ENTER InitSSPIPackage" );
		O_HEX( pcbMaxMessage );
		if ( NULL != pcbMaxMessage ) O_DEC( *pcbMaxMessage );
		
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.InitSSPIPackage( pcbMaxMessage );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if ( NULL != pcbMaxMessage ) O_DEC( *pcbMaxMessage );
		o_printf( "InitSSPIPackage returned %s", (rv) ? "TRUE" : "FALSE" );
		o_printf( "EXIT  InitSSPIPackage" );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	return rv;

}

BOOL Mine_InitSession( DWORD dwKey )
{
	BOOL rv;
    __try 
	{
		o_printf( "" );
		o_printf( "ENTER InitSession" );
		O_HEX( dwKey );	
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.InitSession( dwKey );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		o_printf( "InitSession returned %s", (rv) ? "TRUE" : "FALSE" );
		o_printf( "EXIT  InitSession" );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	return rv;
}

BOOL Mine_TermSSPIPackage( void )
{
	BOOL rv;
    __try 
	{
		o_printf( "" );
		o_printf( "ENTER TermSSPIPackage" );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.TermSSPIPackage();
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		o_printf( "TermSSPIPackage returned %s", (rv) ? "TRUE" : "FALSE" );
		o_printf( "EXIT  TermSSPIPackage" );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	return rv;
}

BOOL Mine_TermSession( DWORD dwKey )
{
	BOOL rv;
    __try 
	{
		o_printf( "" );
		o_printf( "ENTER TermSession" );
		O_HEX( dwKey );
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.TermSession(dwKey);
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		o_printf( "TermSession returned %s", (rv) ? "TRUE" : "FALSE" );
		o_printf( "EXIT  TermSession" );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	return rv;

}

BOOL __stdcall Mine_CertGetCertificateChain( HCERTCHAINENGINE hChainEngine,
								   PCCERT_CONTEXT pCertContext,
								   LPFILETIME pTime,
								   HCERTSTORE hAdditionalStore,
								   PCERT_CHAIN_PARA pChainPara,
								   DWORD dwFlags,
								   LPVOID pvReserved,
								   PCCERT_CHAIN_CONTEXT* ppChainContext )
{
	BOOL rv;
	g_iStackDepth++;
    __try 
	{
		if (1 == g_iStackDepth)
		{
			o_printf( "" );
			o_printf( "ENTER CertGetCertificateChain" );
			g_pCertContext = pCertContext;
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnCertGetCertificateChain( hChainEngine, 
											   pCertContext,
											   pTime,
											   hAdditionalStore,
											   pChainPara,
											   dwFlags,
											   pvReserved,
											   ppChainContext );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if (1 == g_iStackDepth)
		{
			o_printf( "CertGetCertificateChain returned %s", (rv) ? "TRUE" : "FALSE" );
			if ( !rv ) o_printf( "GetLastError returned %lu\n", GetLastError() );
			o_printf( "EXIT  CertGetCertificateChain" );
		}
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	g_iStackDepth--;
	return rv;

}

 DWORD __stdcall Mine_CertNameToStrW( DWORD dwCertEncodingType,
									  PCERT_NAME_BLOB pName,
									  DWORD dwStrType,
									  LPWSTR psz,
									  DWORD csz )
{
	DWORD rv;
	g_iStackDepth++;
    __try 
	{
		if (1 == g_iStackDepth)
		{
			o_printf( "" );
			o_printf( "ENTER CertNameToStrW" );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnCertNameToStrW( dwCertEncodingType,
									  pName,
									  dwStrType,
									  psz,
									  csz );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if (1 == g_iStackDepth)
		{
			o_printf( "CertNameToStrW returned %lu", rv );
			o_printf( "  dwCertEncodingType = 0x%08x", dwCertEncodingType );
			o_printf( "  dwStrType          = 0x%08x", dwStrType );
			o_printf( "  CertName           = %S", psz );
			if ( !rv ) o_printf( "GetLastError returned %lu\n", GetLastError() );

			WCHAR wszServerName[256];
			size_t cchServerName = sizeof(wszServerName)/sizeof(WCHAR);
			WCHAR wszSubjectName[256];
			size_t cchSubjectName = sizeof(wszSubjectName)/sizeof(WCHAR);
			DWORD cszServerName;
			cszServerName = MultiByteToWideChar( CP_ACP, 
										0, 
										g_STATUS.g_szSavedFQDN, 
										-1, 
										NULL, 
										0 );
			cszServerName = MultiByteToWideChar( CP_ACP, 
										0, 
										g_STATUS.g_szSavedFQDN, 
										-1, 
										wszServerName, 
										cszServerName );
			if (0 ==  cszServerName)
			{
				o_printf("Server Name: [%s] cannot be converted to Unicode, VerifyServerCertificate will return SEC_E_WRONG_PRINCIPAL", g_STATUS.g_szSavedFQDN);
			}

			wcscpy_s(wszSubjectName, cchSubjectName, psz);
			_wcsupr_s( wszSubjectName, cchSubjectName );
			_wcsupr_s( wszServerName, cchServerName );

			if( NULL == wcsstr(wszSubjectName, wszServerName) )
			{
				o_printf("Could not locate server name [%S] in subject [%S], VerifyServerCertificate will return CERT_E_CN_NO_MATCH", wszServerName, wszSubjectName);
			}
			else
			{
				o_printf("Successfully located server name [%S] in subject [%S], VerifyServerCertificate will continue", wszServerName, wszSubjectName);
			}

			o_printf( "EXIT  CertNameToStrW" );
		}
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	g_iStackDepth--;
	return rv;

}

BOOL __stdcall Mine_CertVerifyCertificateChainPolicy( LPCSTR pszPolicyOID,
										              PCCERT_CHAIN_CONTEXT pChainContext,
											          PCERT_CHAIN_POLICY_PARA pPolicyPara,
											          PCERT_CHAIN_POLICY_STATUS pPolicyStatus )
{
	BOOL rv;
	g_iStackDepth++;
    __try 
	{
		if (1 == g_iStackDepth)
		{
			o_printf( "" );
			o_printf( "ENTER CertVerifyCertificateChainPolicy" );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnCertVerifyCertificateChainPolicy( pszPolicyOID,
														pChainContext,
														pPolicyPara,
														pPolicyStatus );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if (1 == g_iStackDepth)
		{
			if ( CERT_CHAIN_POLICY_SSL == pszPolicyOID)
			{
				o_printf("  pszPolicyOID = CERT_CHAIN_POLICY_SSL");
				o_printf("  pChainContext = 0x%08x", pChainContext);
				o_printf("  pPolicyPara->cbSize = %i", pPolicyPara->cbSize);
				o_printf("  pPolicyPara->dwFlags = 0x%08x", pPolicyPara->dwFlags);
				HTTPSPolicyCallbackData*  ppolHttps = NULL;
				ppolHttps = (HTTPSPolicyCallbackData*) pPolicyPara->pvExtraPolicyPara;
				o_printf("  pPolicyPara->pvExtraPolicyPara->pwszServerName = %S", ppolHttps->pwszServerName);
				o_printf("  pPolicyPara->pvExtraPolicyPara->cbStruct = %i", ppolHttps->cbStruct);
				o_printf("  pPolicyPara->pvExtraPolicyPara->dwAuthType = %s", GetAuthType(ppolHttps->dwAuthType));
				o_printf("  pPolicyPara->pvExtraPolicyPara->fdwChecks = 0x%08x", ppolHttps->fdwChecks);
			}
			o_printf( "CertVerifyCertificateChainPolicy returned %s", (rv) ? "TRUE" : "FALSE" );
			if ( pPolicyStatus ) 
			{
				o_printf( "pPolicyStatus->dwError=0x%08x (%s)", pPolicyStatus->dwError, GetCertChainPolicyStatusCode(pPolicyStatus->dwError) );
				if (CERT_CHAIN_POLICY_SSL == pszPolicyOID && pPolicyStatus->dwError != 0)
				{
					o_printf("ENTER DisplayCertChain");
					DisplayCertChain(g_pCertContext, TRUE);
					o_printf("EXIT DisplayCertChain");
				}
			}
			//DisplayCertChain(g_pCertContext, TRUE);

			if ( !rv ) o_printf( "GetLastError returned %lu\n", GetLastError() );
			o_printf( "EXIT  CertVerifyCertificateChainPolicy" );
		}
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	g_iStackDepth--;
	return rv;

}

PCCERT_CHAIN_CONTEXT __stdcall Mine_CertFindChainInStore( HCERTSTORE hCertStore,
												          DWORD dwCertEncodingType,
												          DWORD dwFindFlags,
												          DWORD dwFindType,
												          const void *pvFindPara,
												          PCCERT_CHAIN_CONTEXT pPrevChainContext )
{
	PCCERT_CHAIN_CONTEXT rv;
	g_iStackDepth++;
    __try 
	{
		if (1 == g_iStackDepth)
		{
			o_printf( "" );
			o_printf( "ENTER CertFindChainInStore" );
		}
    } 
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		rv = g_DFN.pfnCertFindChainInStore( hCertStore,
											dwCertEncodingType,
											dwFindFlags,
											dwFindType,
											pvFindPara,
											pPrevChainContext );
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

    __try 
	{
		if (1 == g_iStackDepth)
		{
			o_printf( "CertFindChainInStore returned 0x%08x", rv );
			if ( !rv ) o_printf( "GetLastError returned %lu\n", GetLastError() );
			o_printf( "EXIT  CertFindChainInStore" );
		}
    }
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	g_iStackDepth--;
	return rv;

}

#define ERR_LOAD_FUNCTION( pfunc, funcdef, mod, funcname )			\
	{	pfunc = (funcdef) GetProcAddress( mod, funcname );			\
		if ( NULL == pfunc )										\
		{															\
			o_printf( "Failed to load %s!", funcname );				\
		}															\
	}

HRESULT LoadDLLAndFunctions()
{
	// Attempt to load secur32.dll or security.dll.
	g_hModSecurity = NULL;
	g_hModSecurity = LoadLibrary( "secur32.dll" );
	if ( NULL == g_hModSecurity )
	{
		g_hModSecurity = LoadLibrary( "security.dll" );
	}

	// Attempt to load dbnetlib.dll or dbmssocn.dll.
	g_hModDBNetlib = NULL;
	g_hModDBNetlib = LoadLibrary( "dbnetlib.dll" );
	if ( NULL == g_hModDBNetlib )
	{
		g_hModDBNetlib = LoadLibrary( "dbmssocn.dll" );
	}

	// Attempt to load crypt32.dll.
	g_hModCrypt32 = NULL;
	g_hModCrypt32 = LoadLibrary( "crypt32.dll" );

	if ( NULL == g_hModSecurity ) 
	{
		return E_SSPI_SECUR32_MODULE_LOAD_FAILURE;
	}

	if ( NULL == g_hModDBNetlib )
	{
		return E_SSPI_DBNETLIB_MODULE_LOAD_FAILURE;
	}

	// Now load individual functions.
	ZeroMemory( &g_DFN, sizeof(g_DFN) );

	__try
	{

		// Load secur32.dll functions.
		ERR_LOAD_FUNCTION( g_DFN.pfnAcquireCredentialsHandleA,  
						   ACQUIRE_CREDENTIALS_HANDLE_FN_A,
						   g_hModSecurity, 
						   "AcquireCredentialsHandleA" );
		ERR_LOAD_FUNCTION( g_DFN.pfnInitializeSecurityContextA, 
						   INITIALIZE_SECURITY_CONTEXT_FN_A,
						   g_hModSecurity, 
						   "InitializeSecurityContextA" );
		ERR_LOAD_FUNCTION( g_DFN.pfnCompleteAuthToken, 
						   COMPLETE_AUTH_TOKEN_FN,
						   g_hModSecurity, 
						   "CompleteAuthToken" );
		ERR_LOAD_FUNCTION( g_DFN.pfnAcceptSecurityContext, 
						   ACCEPT_SECURITY_CONTEXT_FN,
						   g_hModSecurity, 
						   "AcceptSecurityContext" );
		ERR_LOAD_FUNCTION( g_DFN.pfnQuerySecurityPackageInfoA,  
						   QUERY_SECURITY_PACKAGE_INFO_FN_A,
						   g_hModSecurity, 
						   "QuerySecurityPackageInfoA" );

		/*
		ERR_LOAD_FUNCTION( g_DFN.pfnFreeContextBuffer,	
						   FREE_CONTEXT_BUFFER_FN,
						   g_hModSecurity, 
						   "FreeContextBuffer" );
		ERR_LOAD_FUNCTION( g_DFN.pfnDeleteSecurityContext,	
						   DELETE_SECURITY_CONTEXT_FN,
						   g_hModSecurity, 
						   "DeleteSecurityContext" );
		*/

		ERR_LOAD_FUNCTION( g_DFN.pfnQueryContextAttributesA,
						   QUERY_CONTEXT_ATTRIBUTES_FN_A,
						   g_hModSecurity, 
						   "QueryContextAttributesA" );

		// Load dbnetlib functions.
		ERR_LOAD_FUNCTION( g_DFN.ConnectionGetSvrUser,
						   ConnectionGetSvrUser_FN,
						   g_hModDBNetlib, 
						   "ConnectionGetSvrUser" );

		ERR_LOAD_FUNCTION( g_DFN.GenClientContext,
						   GenClientContext_FN,
						   g_hModDBNetlib, 
						   "GenClientContext" );

		ERR_LOAD_FUNCTION( g_DFN.InitSSPIPackage,
						   InitSSPIPackage_FN,
						   g_hModDBNetlib, 
						   "InitSSPIPackage" );

		ERR_LOAD_FUNCTION( g_DFN.InitSession,
						   InitSession_FN,
						   g_hModDBNetlib, 
						   "InitSession" );

		ERR_LOAD_FUNCTION( g_DFN.TermSSPIPackage,
						   TermSSPIPackage_FN,
						   g_hModDBNetlib, 
						   "TermSSPIPackage" );

		ERR_LOAD_FUNCTION( g_DFN.TermSession,
						   TermSession_FN,
						   g_hModDBNetlib, 
						   "TermSession" );

		// Load Crypt32 functions.
		if ( NULL != g_hModCrypt32 )
		{
			ERR_LOAD_FUNCTION( g_DFN.pfnCertNameToStrW,
							   CertNameToStrW_FN,
							   g_hModCrypt32, 
							   "CertNameToStrW" );
			ERR_LOAD_FUNCTION( g_DFN.pfnCertGetCertificateChain,
							   CertGetCertificateChain_FN,
							   g_hModCrypt32, 
							   "CertGetCertificateChain" );

			ERR_LOAD_FUNCTION( g_DFN.pfnCertVerifyCertificateChainPolicy,
							   CertVerifyCertificateChainPolicy_FN,
							   g_hModCrypt32, 
							   "CertVerifyCertificateChainPolicy" );

			ERR_LOAD_FUNCTION( g_DFN.pfnCertFindChainInStore,
							   CertFindChainInStore_FN,
							   g_hModCrypt32, 
							   "CertFindChainInStore" );
		}

	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	return S_OK;

}

#define DETOUR_FUNC( pfunc, funcdef, minefunc ) { if ( NULL != pfunc ) pfunc = (funcdef) DetourFunction( (PBYTE) pfunc, (PBYTE) minefunc ); }

HRESULT StartDetouring( void )
{
	HRESULT hr;

	if ( g_fFunctionsDetoured ) 
	{
		return E_SSPI_DETOUR_RESTART_FAILURE;
	}

	hr = LoadDLLAndFunctions();

	if ( FAILED(hr) ) return hr;

	g_STATUS.fLoadDetourDllsAndFunctions = TRUE;

	__try
	{
		// Detour secur32 functions.
		DETOUR_FUNC( g_DFN.pfnAcquireCredentialsHandleA,
					 ACQUIRE_CREDENTIALS_HANDLE_FN_A,
					 Mine_AcquireCredentialsHandleA );

		DETOUR_FUNC( g_DFN.pfnInitializeSecurityContextA,
					 INITIALIZE_SECURITY_CONTEXT_FN_A,
					 Mine_InitializeSecurityContextA );

		DETOUR_FUNC( g_DFN.pfnCompleteAuthToken,
					 COMPLETE_AUTH_TOKEN_FN,
					 Mine_CompleteAuthToken );

		DETOUR_FUNC( g_DFN.pfnAcceptSecurityContext,
					 ACCEPT_SECURITY_CONTEXT_FN,
					 Mine_AcceptSecurityContext );

		DETOUR_FUNC( g_DFN.pfnQuerySecurityPackageInfoA,
					 QUERY_SECURITY_PACKAGE_INFO_FN_A,
					 Mine_QuerySecurityPackageInfoA );
		
		/*
		DETOUR_FUNC( g_DFN.pfnFreeContextBuffer,
					 FREE_CONTEXT_BUFFER_FN,
					 Mine_FreeContextBuffer );

		DETOUR_FUNC( g_DFN.pfnDeleteSecurityContext,
					 DELETE_SECURITY_CONTEXT_FN,
					 Mine_DeleteSecurityContext );
		*/

		DETOUR_FUNC( g_DFN.pfnQueryContextAttributesA,
					 QUERY_CONTEXT_ATTRIBUTES_FN_A,
					 Mine_QueryContextAttributesA );	
		
		// Detour dbnetlib functions. 
		DETOUR_FUNC( g_DFN.ConnectionGetSvrUser,
					 ConnectionGetSvrUser_FN,
					 Mine_ConnectionGetSvrUser );	

		DETOUR_FUNC( g_DFN.GenClientContext,
					 GenClientContext_FN,
					 Mine_GenClientContext );	

		DETOUR_FUNC( g_DFN.InitSSPIPackage,
					 InitSSPIPackage_FN,
					 Mine_InitSSPIPackage );	

		DETOUR_FUNC( g_DFN.InitSession,
					 InitSession_FN,
					 Mine_InitSession );	

		DETOUR_FUNC( g_DFN.TermSSPIPackage,
					 TermSSPIPackage_FN,
					 Mine_TermSSPIPackage );	

		DETOUR_FUNC( g_DFN.TermSession,
					 TermSession_FN,
					 Mine_TermSession );

		// Detour crypt32 functions
		if ( NULL != g_hModCrypt32 )
		{
			DETOUR_FUNC( g_DFN.pfnCertNameToStrW,
						 CertNameToStrW_FN,
						 Mine_CertNameToStrW );
			DETOUR_FUNC( g_DFN.pfnCertGetCertificateChain,
						 CertGetCertificateChain_FN,
						 Mine_CertGetCertificateChain );
			DETOUR_FUNC( g_DFN.pfnCertVerifyCertificateChainPolicy,
						 CertVerifyCertificateChainPolicy_FN,
						 Mine_CertVerifyCertificateChainPolicy );
			DETOUR_FUNC( g_DFN.pfnCertFindChainInStore,
						 CertFindChainInStore_FN,
						 Mine_CertFindChainInStore );	
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	g_STATUS.fAllFunctionsDetoured = TRUE;

	g_fFunctionsDetoured = TRUE;
	return S_OK;
}

#define DETOUR_REMOVE_FUNC( pfunc, minefunc ) { if ( NULL != pfunc ) DetourRemove( (PBYTE) pfunc, (PBYTE) minefunc ); }

HRESULT StopDetouring( void )
{
	if ( !g_fFunctionsDetoured ) 
	{
		return E_SSPI_DETOUR_STOP_FAILURE;
	}

	__try
	{

		// Remove security functions if detoured.
		DETOUR_REMOVE_FUNC( g_DFN.pfnAcquireCredentialsHandleA,
							Mine_AcquireCredentialsHandleA );

		DETOUR_REMOVE_FUNC( g_DFN.pfnInitializeSecurityContextA,
							Mine_InitializeSecurityContextA );

		DETOUR_REMOVE_FUNC( g_DFN.pfnCompleteAuthToken,
							Mine_CompleteAuthToken );

		DETOUR_REMOVE_FUNC( g_DFN.pfnAcceptSecurityContext,
							Mine_AcceptSecurityContext );

		DETOUR_REMOVE_FUNC( g_DFN.pfnQuerySecurityPackageInfoA,
							Mine_QuerySecurityPackageInfoA );

		/*
		DETOUR_REMOVE_FUNC( g_DFN.pfnFreeContextBuffer,
							Mine_FreeContextBuffer );

		DETOUR_REMOVE_FUNC( g_DFN.pfnDeleteSecurityContext,
							Mine_DeleteSecurityContext );
		*/

		DETOUR_REMOVE_FUNC( g_DFN.pfnQueryContextAttributesA,
							Mine_QueryContextAttributesA );

		// Remove dbnetlib detours.
		DETOUR_REMOVE_FUNC( g_DFN.ConnectionGetSvrUser,
							Mine_ConnectionGetSvrUser );

		DETOUR_REMOVE_FUNC( g_DFN.GenClientContext,
							Mine_GenClientContext );

		DETOUR_REMOVE_FUNC( g_DFN.InitSSPIPackage,
							Mine_InitSSPIPackage );

		DETOUR_REMOVE_FUNC( g_DFN.InitSession,
							Mine_InitSession );

		DETOUR_REMOVE_FUNC( g_DFN.TermSSPIPackage,
							Mine_TermSSPIPackage );

		DETOUR_REMOVE_FUNC( g_DFN.TermSession,
							Mine_TermSession );
	
		// Remove crypt32.dll functions
		if ( NULL != g_hModCrypt32 )
		{
			DETOUR_REMOVE_FUNC( g_DFN.pfnCertNameToStrW,
								Mine_CertNameToStrW );
			/*
			DETOUR_REMOVE_FUNC( g_DFN.pfnCertGetCertificateChain,
								Mine_CertGetCertificateChain );
			DETOUR_REMOVE_FUNC( g_DFN.pfnCertVerifyCertificateChainPolicy,
								Mine_CertVerifyCertificateChainPolicy );
			DETOUR_REMOVE_FUNC( g_DFN.pfnCertFindChainInStore,
								Mine_CertFindChainInStore );
			*/
		}

	}
	__except(EXCEPTION_EXECUTE_HANDLER) {};

	g_fFunctionsDetoured = FALSE;
	return S_OK;
}

HRESULT OpenLogFile( char * pszLogFileName )
{
	DWORD dwPID = GetCurrentProcessId();
	HANDLE hLogFile = NULL;

	if ( NULL != g_hLogFile )   return E_ABORT;

	hLogFile = CreateFileA( pszLogFileName, 
	  				        GENERIC_READ | GENERIC_WRITE,
						    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						    NULL,							
						    OPEN_ALWAYS,					
						    FILE_ATTRIBUTE_NORMAL,			
						    NULL 							
   						  );

	if ( hLogFile == INVALID_HANDLE_VALUE ) 
	{
		return GetLastError() + E_SSPI_BASE_ERROR;
	}

	SetFilePointer( hLogFile, 0, NULL, FILE_END );

	// Only initialize critical section 1 time.
	if ( NULL == g_pLogFileLock )
	{
		g_pLogFileLock = new CRITICAL_SECTION;
		if ( NULL != g_pLogFileLock )
		{
			InitializeCriticalSection( g_pLogFileLock );
		}
		else
		{
			return E_OUTOFMEMORY;
		}
	}

	// After critsec is ready, then enable logging via setting g_hLogFile to valid handle.
	g_hLogFile = hLogFile;
	return S_OK;

}

HRESULT CloseLogFile()
{
	DWORD dwPID = GetCurrentProcessId();

	// Must have critsec and valid log file handle.
	if ( NULL == g_pLogFileLock ) return E_OUTOFMEMORY;
	if ( NULL == g_hLogFile )     return E_OUTOFMEMORY;

	ENTER_API_CS;
	CloseHandle( g_hLogFile );
	g_hLogFile = NULL;
	LEAVE_API_CS;

	return S_OK;
}

VOID NullExport()
{
}
