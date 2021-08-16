#pragma once

void CheckDomainInfo();

typedef DWORD (SEC_ENTRY * DSBIND_FN)( CHAR * DomainControllerAddress,   // in, optional
                                     CHAR * DnsDomainName,             // in, optional
                                     HANDLE * phDS);
typedef DWORD (SEC_ENTRY * DSUNBIND_FN)( HANDLE * phDS);
typedef DWORD (SEC_ENTRY * DSGETSPN_FN)( DS_SPN_NAME_TYPE ServiceType,
                                      LPCTSTR ServiceClass,
                                      LPCTSTR ServiceName,
                                      USHORT InstancePort,
                                      USHORT cInstanceNames,
                                      LPCTSTR *pInstanceNames,
                                      const USHORT *pInstancePorts,
                                      DWORD *pcSpn,
                                      LPTSTR **prpszSpn);
typedef VOID (SEC_ENTRY * DSFREESPNARRAY_FN)( DWORD cSpn,
                                           LPTSTR *rpszSpn);
typedef DWORD (SEC_ENTRY * DSWRITEACCOUNTSPN_FN)( HANDLE hDS,
                                               DS_SPN_WRITE_OP Operation,
                                               LPCTSTR pszAccount,
                                               DWORD cSpn,
                                               LPCTSTR *rpszSpn);
typedef VOID (SEC_ENTRY * DSFREENAMERESULT_FN)( DS_NAME_RESULTA *pResult);
typedef DWORD (SEC_ENTRY * DSCRACKNAMES_FN)( HANDLE hDS,
                                          DS_NAME_FLAGS flags,
                                          DS_NAME_FORMAT formatOffered,
                                          DS_NAME_FORMAT formatDesired,
                                          DWORD cNames,
                                          LPTSTR *rpNames,
                                          PDS_NAME_RESULT *ppResult);
typedef DWORD (SEC_ENTRY * DSGETDCNAME_FN)( LPCTSTR ComputerName,
                                            LPCTSTR DomainName,
                                            GUID *DomainGuid,
                                            LPCTSTR SiteName,
                                            ULONG Flags,
                                            PDOMAIN_CONTROLLER_INFO *DomainControllerInfo);

typedef BOOLEAN (SEC_ENTRY * GETUSERNAMEEXFN)( EXTENDED_NAME_FORMAT NameFormat,  
                                               LPTSTR lpNameBuffer,
                                               PULONG nSize);

typedef BOOLEAN (SEC_ENTRY * GETCOMPUTEROBJECTFN)( EXTENDED_NAME_FORMAT  NameFormat,
                                                   LPSTR lpNameBuffer,
                                                   PULONG nSize );

typedef NET_API_STATUS (SEC_ENTRY * NETAPIBUFFERFREEFN)( LPVOID Buffer );

typedef struct _DsFunctionTable
{
    DSBIND_FN DsBind;
	DSGETDCNAME_FN DsGetDcName;
	DSCRACKNAMES_FN DsCrackNames;
	DSFREENAMERESULT_FN DsFreeNameResult;
    DSUNBIND_FN DsUnBind;
	DSFREESPNARRAY_FN DsFreeSpnArray;
	NETAPIBUFFERFREEFN NetApiBufferFree;
	GETCOMPUTEROBJECTFN GetComputerObjectName;
	GETUSERNAMEEXFN GetUserNameEx;
} DsFunctionTable;