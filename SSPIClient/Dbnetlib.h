#pragma once

#define RETCODE 	int
#define PASCALENTRY _cdecl
#define TIMEINT	    USHORT
#define IOINT DWORD
#define NETERR LONG
#define MAX_ERROR_SIZE	256

typedef enum {      // connection interface status values
    NET_IDLE,       // connection is idle
    NET_BUSY,       // connection is reading or writing
    NET_ERROR       // error occurred during last oper.
} CO_STAT;

typedef enum {      // connection mode values
    ASYNC_MODE,     // asynchronous operation
    BLOCK_MODE      // blocking mode
} CO_MODE;

typedef enum { NLOPT_SET_ENCRYPT, 
			   NLOPT_SET_PACKET_SIZE };

typedef struct _OPTSTRUCT
{
    int   iSize;
    BOOL  fEncrypt;
	int   iRequest;
	DWORD dwPacketSize;
} OPTSTRUCT;

// Define shared memory structures
typedef struct ServerData
{
	DWORD  dwCurrentID;
	ULONG  ulVersion;
} 
SERVERDATA;

// Now describe Shared-Memory Header
typedef struct QueryInfo
{
	UINT_PTR  dwClientPort;
	UINT_PTR  dwServerPort;
	DWORD  dwServerWriteBytesAvailable;
	DWORD  dwClientWriteBytesAvailable;
	BOOL   fServerPeekPosted;
	BOOL   fServerAsyncReadPosted;
	BOOL   fClientAttentionPosted;
	BOOL   fClientOrServerClosed;
	BYTE   AttentionPacket[8];
	DWORD  dwConnectionID;
	// MATTN
	//BYTE   QueryData[];
	// MATTN
	// MATTN
	BYTE   QueryData[1];  // Changing this to avoid C4200 compiler error.
	// MATTN
} QUERY_INFO;

// Define Shared-Memory Header size
#define SM_HEADER_SIZE	sizeof( QUERY_INFO )

typedef struct pConnectionObject
{
    unsigned long ulSocketIndicator;
    HANDLE        hPort;
	HANDLE        hData;
	QUERY_INFO  * pQueryInfo;
	ULONG		  ulBufferSize;
	CHAR		  szPortName[MAX_PATH];
    USHORT        pdwNetError;
    USHORT        mapErrno;
    char        * netLibApi;
    char        * szAPI;
    CHAR          szErrMsg[MAX_ERROR_SIZE];
    WCHAR         wszErrMsg[MAX_ERROR_SIZE];
    CO_STAT       Status;
    BYTE        * pBuffer;

	HANDLE		  hClientReadPostedEvent;
	HANDLE		  hClientReadCompletedEvent;
	HANDLE		  hClientWritePostedEvent;
	HANDLE		  hServerReadPostedEvent;
	HANDLE		  hServerWritePostedEvent;
	HANDLE		  hServerAliveEvent;

	HANDLE        hClientMemoryAllocatedEvent;

	HANDLE		  hServerMutex;
	HANDLE		  hAcceptReady;
    DWORD         dwWriteCount;
    DWORD         dwBytesWritten;
    DWORD         dwBytesRead;
    DWORD         dwBytesRemaining;

	BOOL		  fReadBytesPending;

	HANDLE		 hServerData;
	SERVERDATA * pServerData;

} CONNECTIONOBJECT; 


typedef RETCODE (PASCALENTRY * ConnectionCheckForData_FN)( CONNECTIONOBJECT* ConnectionObject, LONG* bytesavail, NETERR* neterrno );

typedef BOOL (PASCALENTRY * ConnectionError_FN)( CONNECTIONOBJECT* ConnectionObject, NETERR* neterrno, CHAR** ppszMsg, NETERR* mapError );
typedef BOOL (PASCALENTRY * ConnectionErrorW_FN)( CONNECTIONOBJECT* ConnectionObject, NETERR* neterrno, WCHAR** ppwszMsg, NETERR* mapError );

typedef RETCODE (PASCALENTRY * ConnectionOpen_FN)( CONNECTIONOBJECT* ConnectionObject, CHAR* szConnectionString, NETERR* neterrno );
typedef RETCODE (PASCALENTRY * ConnectionOpenW_FN)( CONNECTIONOBJECT* ConnectionObject, WCHAR* wszServerName, NETERR* neterrno );
typedef RETCODE (PASCALENTRY * ConnectionClose_FN)( CONNECTIONOBJECT* ConnectionObject, NETERR* neterrno );

typedef BOOL (PASCALENTRY * ConnectionOption_FN)( CONNECTIONOBJECT* ConnectionObject, OPTSTRUCT* pOptions );

typedef IOINT (PASCALENTRY * ConnectionRead_FN)( CONNECTIONOBJECT* ConnectionObject, BYTE* buffer, IOINT readcount, IOINT readmax, TIMEINT timeout, NETERR* neterrno );
typedef IOINT (PASCALENTRY * ConnectionWrite_FN)( CONNECTIONOBJECT* ConnectionObject, BYTE* buffer, IOINT writecount, NETERR* neterrno );
typedef IOINT (PASCALENTRY * ConnectionWriteOOB_FN)( CONNECTIONOBJECT* ConnectionObject, BYTE* buffer, IOINT writecount, NETERR* neterrno );

typedef BOOL (PASCALENTRY * ConnectionGetSvrUser_FN)( CONNECTIONOBJECT* ConnectionObject, char* szUserName );
typedef BOOL (PASCALENTRY * GenClientContext_FN)( DWORD dwKey, BYTE* pIn, DWORD cbIn, BYTE	*pOut, DWORD *pcbOut, BOOL *pfDone, CHAR *szServerInfo );
typedef BOOL (PASCALENTRY * InitSSPIPackage_FN)( DWORD* pcbMaxMessage );
typedef BOOL (PASCALENTRY * InitSession_FN)( DWORD dwKey );
typedef BOOL (PASCALENTRY * TermSSPIPackage_FN)( void );
typedef BOOL (PASCALENTRY * TermSession_FN)( DWORD dwKey);