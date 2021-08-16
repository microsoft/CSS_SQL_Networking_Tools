#pragma once

#include <wincrypt.h>

typedef BOOL (WINAPI * CertGetCertificateChain_FN)(
    HCERTCHAINENGINE hChainEngine,
    PCCERT_CONTEXT pCertContext,
    LPFILETIME pTime,
    HCERTSTORE hAdditionalStore,
    PCERT_CHAIN_PARA pChainPara,
    DWORD dwFlags,
    LPVOID pvReserved,
    PCCERT_CHAIN_CONTEXT* ppChainContext
    );

typedef DWORD (WINAPI * CertNameToStrW_FN)(
    DWORD dwCertEncodingType,
    PCERT_NAME_BLOB pName,
    DWORD dwStrType,
    LPWSTR psz,
    DWORD csz
    );

typedef BOOL (WINAPI * CertVerifyCertificateChainPolicy_FN)(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
    );

typedef PCCERT_CHAIN_CONTEXT (WINAPI * CertFindChainInStore_FN)(
    HCERTSTORE hCertStore,
    DWORD dwCertEncodingType,
    DWORD dwFindFlags,
    DWORD dwFindType,
    const void *pvFindPara,
    PCCERT_CHAIN_CONTEXT pPrevChainContext
    );

HRESULT StartDetouring(void);
HRESULT StopDetouring(void);

HRESULT OpenLogFile( char* pszLogFileName );
HRESULT CloseLogFile();
void o_printf( char* lpszFormat, ... );
BSTR AnsiToBSTR( char* s );
void DumpHex( void* pData, unsigned long length );

#define TOKEN_SOURCE_LEN ((8+1) * 2)
#define MAX_USERNAME  ((256+1) * 2)
#define MAX_DOMAINNAME ((256+1) * 2)

#define SZ_TOKEN_LEVEL_ANON        L"The token impersonation level is SecurityAnonymous\r\n"
#define SZ_TOKEN_LEVEL_IDENT       L"The token impersonation level is SecurityIdentification\r\n"
#define SZ_TOKEN_LEVEL_IMP         L"The token impersonation level is SecurityImpersonation\r\n"
#define SZ_TOKEN_LEVEL_DEL         L"The token impersonation level is SecurityDelegation\r\n"

#define SZ_TOKEN_TYPE_PRI          L"The token type is TokenPrimary\r\n"
#define SZ_TOKEN_TYPE_IMP          L"The token type is TokenImpersonation\r\n"

#define SZ_TOKEN_OPENED_AS_PROC    L"The token is a Process token\r\n"
#define SZ_TOKEN_OPENED_AS_THREAD  L"The token is a Thread token\r\n"

typedef struct _THREAD_USER 
{
    char  szName[255];
    char  szDomain[255];
    char  szTokenSource[8];
	DWORD dwImpLevel;							  // 0 for SecurityAnonymous, 1 for SecurityIdentification, 2 for SecurityImpersonation, 3 for SecurityDelegation
    TOKEN_TYPE  dwTokenType;					  // 1 for TokenPrimary, 2 for TokenImpersonation.
    DWORD  dwProcId;
    DWORD  dwThreadOrProc;						  // 0 for Process token, 1 for Thread token.
} _THREAD_USER, THREAD_USER, *PTHREAD_USER;

extern BOOL		g_fFunctionsDetoured;
extern HANDLE	g_hLogFile;
extern BOOL		g_fSupressOutput;
