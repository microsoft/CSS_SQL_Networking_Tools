// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Written by the Microsoft CSS SQL Networking Team
//
// SSPIClientDlg.cpp : implementation file
//

#include "stdafx.h"
#include "SSPIClient.h"
#include "SSPIClientDlg.h"
#include "DynamicLSA.h"
#include "DynamicADSI.h"
#include "DetourFunctions.h"
#include "DynamicDCInfo.h"
#include "FileInfo.h"
#include ".\sspiclientdlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Helpful structure+union to crack IP addresses.
struct B4
{
	BYTE b1;
	BYTE b2;
	BYTE b3;
	BYTE b4;
};

union IP_CRACKER
{
	DWORD IP;
	B4 Bytes;
};

#define SAFE_RELEASE(x) { if ( NULL != x ) { x->Release(); x = NULL; } }
#define SAFE_SYSFREE(x) { if ( NULL != x ) { SysFreeString(x); x = NULL; } }

/////////////////////////////////////////////////////////////////////////////
// CSSPIClientDlg dialog

CSSPIClientDlg::CSSPIClientDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSSPIClientDlg::IDD, pParent)
	, m_fUseIntegrated(FALSE)
	, m_strPassword(_T(""))
	, m_strUserId(_T(""))
	, m_fUseSQLNCLI(FALSE)
{
	//{{AFX_DATA_INIT(CSSPIClientDlg)
	m_strConnect = _T("<Enter your SQL Server Name Here>");
	m_strLogFile = _T("C:\\SSPIClient\\SSPIClient.log");
	m_fUseIntegrated = TRUE;
	m_fEncryptionTest = FALSE;
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSSPIClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSSPIClientDlg)
	DDX_Text(pDX, IDC_EDT_CONNECT, m_strConnect);
	DDX_Text(pDX, IDC_EDT_LOGFILE, m_strLogFile);
	//}}AFX_DATA_MAP
	DDX_Check(pDX, IDC_CHECK1, m_fUseIntegrated);
	DDX_Text(pDX, IDC_EDT_PASSWORD, m_strPassword);
	DDX_Text(pDX, IDC_EDT_USERID, m_strUserId);
	DDX_Check(pDX, IDC_CHECK2, m_fUseSQLNCLI);
}

BEGIN_MESSAGE_MAP(CSSPIClientDlg, CDialog)
	//{{AFX_MSG_MAP(CSSPIClientDlg)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_CONNECT, OnBtnConnect)
	ON_BN_CLICKED(IDOK, OnBtnConnect)
	ON_WM_LBUTTONDBLCLK()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BTN_CONNECT2, OnBnClickedBtnConnect2)
	ON_BN_CLICKED(IDC_CHECK1, OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_BTN_CONNECT3, OnBnClickedBtnConnect3)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSSPIClientDlg message handlers
BOOL CSSPIClientDlg::OnInitDialog()
{
	char szCurDir[2048];
	char* s = NULL;
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	LoadLibrary( "dbnetlib.dll" );
	LoadLibrary( "dbmssocn.dll" );

	OnBnClickedCheck1();

	LoadLSA();

	ZeroMemory( szCurDir, sizeof(szCurDir) );
	GetCurrentDirectory( sizeof(szCurDir), szCurDir );

	// Remove trailing slash from szCurDir if found.
	s = szCurDir;
	while ( *s ) s++;
	s--;
	while ( s > szCurDir )
	{
		if ( '\\' == *s )
		{
			*s = '\0';
			s--;
		}
		else
		{
			break;
		}
	}

	// Just in case we get munged current folder.
	if ( lstrlen( szCurDir ) < 2 )
	{
		lstrcpy( szCurDir, "C:" );
	}

	m_strLogFile.Format( "%s\\SSPIClient.log", szCurDir );

	UpdateData(FALSE);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CSSPIClientDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CSSPIClientDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

BOOL GetLSAStatusError( NTSTATUS Status, char* pszErrorBuffer, DWORD dwErrorBufferLength )
{
	char* s = NULL;
	DWORD dwRes, dwError;

	// Convert the NTSTATUS to Winerror. Then call ShowLastError().
	dwError = LsaNtStatusToWinError( Status );

	dwRes = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM,
						   NULL,
						   dwError,
						   MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US),
						   pszErrorBuffer,
						   dwErrorBufferLength,
						   NULL );
	if ( 0 == dwRes ) return FALSE;

	// Remove tabs, carriage returns, and linefeeds.
	// I don't know why this crap is always in the string.
	s = pszErrorBuffer;
	while (*s)
	{
		if ( '\n' == *s ) *s = ' ';
		if ( '\r' == *s ) *s = ' ';
		if ( '\t' == *s ) *s = ' ';
		s++;
	}

	// Remove trailing spaces.
	s = &pszErrorBuffer[lstrlen(pszErrorBuffer)-1];
	while ( s > pszErrorBuffer )
	{
		if ( ' ' != *s ) break;
		*s = '\0';
		s--;
	}
	return TRUE;
}

// Helper function for printing out ODBC errors. 
BOOL DUMP_ODBC_ERRORS( RETCODE rc, HENV henv, HDBC hdbc )
{
	// Helper function for debugging those cryptic ODBC errors.
	unsigned char szErrorMsg[1024];
	unsigned char szSQLState[1024];
	long          lNativeError;  
	short         nErrorMsg;
	short         nErrorMsgMax = 1024;
	int			  intErrorNumber = 0;
	HSTMT hstmt = NULL;
	CString strODBCErrors;
	CString strItem;

	if ( SQL_SUCCEEDED(rc) ) return FALSE;  // Skip if everything is ok.

	strODBCErrors = "Connection Error: \n";

	o_printf( "******************** ODBC Errors ********************" );
	o_printf( "Return code = %d.", rc );
	for ( ; ; )
	{
		rc = SQLError( henv, hdbc, hstmt, szSQLState, &lNativeError, szErrorMsg, nErrorMsgMax, &nErrorMsg );
		if ( ( rc != SQL_SUCCESS ) && ( rc != SQL_SUCCESS_WITH_INFO ) ) break;
		o_printf( "SQLError[%02d] SQLState    '%s'", intErrorNumber, szSQLState   );
		o_printf( "SQLError[%02d] NativeError %lu",  intErrorNumber, lNativeError );
		o_printf( "SQLError[%02d] Message     '%s'", intErrorNumber, szErrorMsg   );
		strODBCErrors += (char*)szErrorMsg;
		strODBCErrors += "\n";
		intErrorNumber++;
	}
	if (intErrorNumber == 0)
	{
		o_printf( "First call to SQLError failed with an un-identified RETCODE = %d", rc );
		if ( rc == SQL_NO_DATA_FOUND )  
		{
			o_printf( "First call to SQLError failed with RETCODE = SQL_NO_DATA_FOUND (See SQLError documentation)" );
		}
		if ( rc == SQL_ERROR )
		{
			o_printf( "First call to SQLError failed with RETCODE = SQL_ERROR (See SQLError documentation)" );
		}
		if ( rc == SQL_INVALID_HANDLE ) 
		{
			o_printf( "First call to SQLError failed with RETCODE = SQL_INVALID_HANDLE (See SQLError documentation)" );
		}
	}
	o_printf( "******************** ODBC Errors ********************" );

	::MessageBox( NULL, strODBCErrors, "SSPIClient", MB_OK );
	return TRUE;

}

char* GetWinSockErrorString( int neterrno )
{
	switch ( neterrno )
	{
		case WSAEINTR:						return "WSAEINTR (A blocking operation was interrupted by a call to WSACancelBlockingCall)";
		case WSAEBADF:						return "WSAEBADF (The file handle supplied is not valid)";
		case WSAEACCES:						return "WSAEACCES (An attempt was made to access a socket in a way forbidden by its access permissions)";
		case WSAEFAULT:						return "WSAEFAULT (The system detected an invalid pointer address in attempting to use a pointer argument in a call)";
		case WSAEINVAL:						return "WSAEINVAL (An invalid argument was supplied)";
		case WSAEMFILE:						return "WSAEMFILE (Too many open sockets)";
		case WSAEWOULDBLOCK:				return "WSAEWOULDBLOCK (A non-blocking socket operation could not be completed immediately)";
		case WSAEINPROGRESS:				return "WSAEINPROGRESS (A blocking operation is currently executing)";
		case WSAEALREADY:					return "WSAEALREADY (An operation was attempted on a non-blocking socket that already had an operation in progress)";
		case WSAENOTSOCK:					return "WSAENOTSOCK (An operation was attempted on something that is not a socket)";
		case WSAEDESTADDRREQ:				return "WSAEDESTADDRREQ (A required address was omitted from an operation on a socket)";
		case WSAEMSGSIZE:					return "WSAEMSGSIZE (A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself)";
		case WSAEPROTOTYPE:					return "WSAEPROTOTYPE (A protocol was specified in the socket function call that does not support the semantics of the socket type requested)";
		case WSAENOPROTOOPT:				return "WSAENOPROTOOPT (An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call)";
		case WSAEPROTONOSUPPORT:			return "WSAEPROTONOSUPPORT (The requested protocol has not been configured into the system, or no implementation for it exists)";
		case WSAESOCKTNOSUPPORT:			return "WSAESOCKTNOSUPPORT (The support for the specified socket type does not exist in this address family)";
		case WSAEOPNOTSUPP:					return "WSAEOPNOTSUPP (The attempted operation is not supported for the type of object referenced)";
		case WSAEPFNOSUPPORT:				return "WSAEPFNOSUPPORT (The protocol family has not been configured into the system or no implementation for it exists)";
		case WSAEAFNOSUPPORT:				return "WSAEAFNOSUPPORT (An address incompatible with the requested protocol was used)";
		case WSAEADDRINUSE:					return "WSAEADDRINUSE (Only one usage of each socket address (protocol/network address/port) is normally permitted)";
		case WSAEADDRNOTAVAIL:				return "WSAEADDRNOTAVAIL (The requested address is not valid in its context)";
		case WSAENETDOWN:					return "WSAENETDOWN (A socket operation encountered a dead network)";
		case WSAENETUNREACH:				return "WSAENETUNREACH (A socket operation was attempted to an unreachable network)";
		case WSAENETRESET:					return "WSAENETRESET (The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress)";
		case WSAECONNABORTED:				return "WSAECONNABORTED (An established connection was aborted by the software in your host machine)";
		case WSAECONNRESET:					return "WSAECONNRESET (An existing connection was forcibly closed by the remote host)";
		case WSAENOBUFS:					return "WSAENOBUFS (An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full)";
		case WSAEISCONN:					return "WSAEISCONN (A connect request was made on an already connected socket)";
		case WSAENOTCONN:					return "WSAENOTCONN (A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied)";
		case WSAESHUTDOWN:					return "WSAESHUTDOWN (A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call)";
		case WSAETOOMANYREFS:				return "WSAETOOMANYREFS (Too many references to some kernel object)";
		case WSAETIMEDOUT:					return "WSAETIMEDOUT (A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond)";
		case WSAECONNREFUSED:				return "WSAECONNREFUSED (No connection could be made because the target machine actively refused it)";
		case WSAELOOP:						return "WSAELOOP (Cannot translate name)";
		case WSAENAMETOOLONG:				return "WSAENAMETOOLONG (Name component or name was too long)";
		case WSAEHOSTDOWN:					return "WSAEHOSTDOWN (A socket operation failed because the destination host was down)";
		case WSAEHOSTUNREACH:				return "WSAEHOSTUNREACH (A socket operation was attempted to an unreachable host)";
		case WSAENOTEMPTY:					return "WSAENOTEMPTY (Cannot remove a directory that is not empty)";
		case WSAEPROCLIM:					return "WSAEPROCLIM (A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously)";
		case WSAEUSERS:						return "WSAEUSERS (Ran out of quota)";
		case WSAEDQUOT:						return "WSAEDQUOT (Ran out of disk quota)";
		case WSAESTALE:						return "WSAESTALE (File handle reference is no longer available)";
		case WSAEREMOTE:					return "WSAEREMOTE (Item is not available locally)";
		case WSASYSNOTREADY:				return "WSASYSNOTREADY (WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable)";
		case WSAVERNOTSUPPORTED:			return "WSAVERNOTSUPPORTED (The Windows Sockets version requested is not supported)";
		case WSANOTINITIALISED:				return "WSANOTINITIALISED (Either the application has not called WSAStartup, or WSAStartup failed)";
		case WSAEDISCON:					return "WSAEDISCON (Returned by WSARecv or WSARecvFrom to indicate the remote party has initiated a graceful shutdown sequence)";
		case WSAENOMORE:					return "WSAENOMORE (No more results can be returned by WSALookupServiceNext)";
		case WSAECANCELLED:					return "WSAECANCELLED (A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled)";
		case WSAEINVALIDPROCTABLE:			return "WSAEINVALIDPROCTABLE (The procedure call table is invalid)";
		case WSAEINVALIDPROVIDER:			return "WSAEINVALIDPROVIDER (The requested service provider is invalid)";
		case WSAEPROVIDERFAILEDINIT:        return "WSAEPROVIDERFAILEDINIT (The requested service provider could not be loaded or initialized)";
		case WSASYSCALLFAILURE:				return "WSASYSCALLFAILURE (A system call that should never fail has failed)";
		case WSASERVICE_NOT_FOUND:			return "WSASERVICE_NOT_FOUND (No such service is known. The service cannot be found in the specified name space)";
		case WSATYPE_NOT_FOUND:				return "WSATYPE_NOT_FOUND (The specified class was not found)";
		case WSA_E_NO_MORE:					return "WSA_E_NO_MORE (No more results can be returned by WSALookupServiceNext)";
		case WSA_E_CANCELLED:				return "WSA_E_CANCELLED (A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled)";
		case WSAEREFUSED:					return "WSAEREFUSED (A database query failed because it was actively refused)";
		case WSAHOST_NOT_FOUND:				return "WSAHOST_NOT_FOUND (No such host is known)";
		case WSATRY_AGAIN:					return "WSATRY_AGAIN (This is usually a temporary error during hostname resolution and means that the local server did not receive a response from an authoritative server)";
		case WSANO_RECOVERY:				return "WSANO_RECOVERY (A non-recoverable error occurred during a database lookup)";
		case WSANO_DATA:					return "WSANO_DATA (The requested name is valid and was found in the database, but it does not have the correct associated data being resolved for)";
		case WSA_QOS_RECEIVERS:				return "WSA_QOS_RECEIVERS (At least one reserve has arrived)";
		case WSA_QOS_SENDERS:				return "WSA_QOS_SENDERS (At least one path has arrived)";
		case WSA_QOS_NO_SENDERS:			return "WSA_QOS_NO_SENDERS (There are no senders)";
		case WSA_QOS_NO_RECEIVERS:			return "WSA_QOS_NO_RECEIVERS (There are no receivers)";
		case WSA_QOS_REQUEST_CONFIRMED:     return "WSA_QOS_REQUEST_CONFIRMED (Reserve has been confirmed)";
		case WSA_QOS_ADMISSION_FAILURE:     return "WSA_QOS_ADMISSION_FAILURE (Error due to lack of resources)";
		case WSA_QOS_POLICY_FAILURE:        return "WSA_QOS_POLICY_FAILURE (Rejected for administrative reasons - bad credentials)";
		case WSA_QOS_BAD_STYLE:				return "WSA_QOS_BAD_STYLE (Unknown or conflicting style)";
		case WSA_QOS_BAD_OBJECT:			return "WSA_QOS_BAD_OBJECT (Problem with some part of the filterspec or providerspecific buffer in general)";
		case WSA_QOS_TRAFFIC_CTRL_ERROR:	return "WSA_QOS_TRAFFIC_CTRL_ERROR (Problem with some part of the flowspec)";
		case WSA_QOS_GENERIC_ERROR:         return "WSA_QOS_GENERIC_ERROR (General QOS error)";
		case WSA_QOS_ESERVICETYPE:			return "WSA_QOS_ESERVICETYPE (An invalid or unrecognized service type was found in the flowspec)";
		case WSA_QOS_EFLOWSPEC:				return "WSA_QOS_EFLOWSPEC (An invalid or inconsistent flowspec was found in the QOS structure)";
		case WSA_QOS_EPROVSPECBUF:			return "WSA_QOS_EPROVSPECBUF (Invalid QOS provider-specific buffer)";
		case WSA_QOS_EFILTERSTYLE:			return "WSA_QOS_EFILTERSTYLE (An invalid QOS filter style was used)";
		case WSA_QOS_EFILTERTYPE:			return "WSA_QOS_EFILTERTYPE (An invalid QOS filter type was used)";
		case WSA_QOS_EFILTERCOUNT:			return "WSA_QOS_EFILTERCOUNT (An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR)";
		case WSA_QOS_EOBJLENGTH:			return "WSA_QOS_EOBJLENGTH (An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer)";
		case WSA_QOS_EFLOWCOUNT:			return "WSA_QOS_EFLOWCOUNT (An incorrect number of flow descriptors was specified in the QOS structure)";
		case WSA_QOS_EUNKOWNPSOBJ:			return "WSA_QOS_EUNKOWNPSOBJ (An unrecognized object was found in the QOS provider-specific buffer)";
		case WSA_QOS_EPOLICYOBJ:			return "WSA_QOS_EPOLICYOBJ (An invalid policy object was found in the QOS provider-specific buffer)";
		case WSA_QOS_EFLOWDESC:				return "WSA_QOS_EFLOWDESC (An invalid QOS flow descriptor was found in the flow descriptor list)";
		case WSA_QOS_EPSFLOWSPEC:			return "WSA_QOS_EPSFLOWSPEC (An invalid or inconsistent flowspec was found in the QOS provider specific buffer)";
		case WSA_QOS_EPSFILTERSPEC:         return "WSA_QOS_EPSFILTERSPEC (An invalid FILTERSPEC was found in the QOS provider-specific buffer)";
		case WSA_QOS_ESDMODEOBJ:			return "WSA_QOS_ESDMODEOBJ (An invalid shape discard mode object was found in the QOS provider specific buffer)";
		case WSA_QOS_ESHAPERATEOBJ:         return "WSA_QOS_ESHAPERATEOBJ (An invalid shaping rate object was found in the QOS provider-specific buffer)";
		case WSA_QOS_RESERVED_PETYPE:       return "WSA_QOS_RESERVED_PETYPE (A reserved policy element was found in the QOS provider-specific buffer)";
	}
	return "Unknown WinSock Error Code";
}


#define BITFLAG_TEST(x) if ( ulFlags & x ) { if ( lstrlen(szFS) > 0 ) lstrcat( szFS,"|" ); lstrcat( szFS, #x ); }

char* GetKERB_TICKET_FLAGSString( ULONG ulFlags )
{
	static char szFS[1024];
	ZeroMemory( szFS, sizeof(szFS) );
	BITFLAG_TEST(KERB_TICKET_FLAGS_renewable);
	BITFLAG_TEST(KERB_TICKET_FLAGS_initial);
	BITFLAG_TEST(KERB_TICKET_FLAGS_invalid);
	BITFLAG_TEST(KERB_TICKET_FLAGS_reserved);
	BITFLAG_TEST(KERB_TICKET_FLAGS_forwardable);
	BITFLAG_TEST(KERB_TICKET_FLAGS_forwarded);
	BITFLAG_TEST(KERB_TICKET_FLAGS_proxiable);
	BITFLAG_TEST(KERB_TICKET_FLAGS_proxy);
	BITFLAG_TEST(KERB_TICKET_FLAGS_may_postdate);
	BITFLAG_TEST(KERB_TICKET_FLAGS_postdated);
	BITFLAG_TEST(KERB_TICKET_FLAGS_pre_authent);
	BITFLAG_TEST(KERB_TICKET_FLAGS_hw_authent);
	BITFLAG_TEST(KERB_TICKET_FLAGS_ok_as_delegate);
	BITFLAG_TEST(KERB_TICKET_FLAGS_reserved1);
	return szFS;
}

#define CONST_CASE(x) case x: return #x

char* GetEncryptionTypeString( long lEncryptionType )
{
	switch( lEncryptionType )
	{
		CONST_CASE(KERB_ETYPE_NULL);
		CONST_CASE(KERB_ETYPE_DES_CBC_CRC);
		CONST_CASE(KERB_ETYPE_DES_CBC_MD4);
		CONST_CASE(KERB_ETYPE_DES_CBC_MD5);
		CONST_CASE(KERB_ETYPE_RC4_MD4);
		CONST_CASE(KERB_ETYPE_RC4_PLAIN2);
		CONST_CASE(KERB_ETYPE_RC4_LM);
		CONST_CASE(KERB_ETYPE_RC4_SHA);
		CONST_CASE(KERB_ETYPE_DES_PLAIN);
		CONST_CASE(KERB_ETYPE_RC4_HMAC_OLD);
		CONST_CASE(KERB_ETYPE_RC4_PLAIN_OLD);
		CONST_CASE(KERB_ETYPE_RC4_HMAC_OLD_EXP);
		CONST_CASE(KERB_ETYPE_RC4_PLAIN_OLD_EXP);
		CONST_CASE(KERB_ETYPE_RC4_PLAIN);
		CONST_CASE(KERB_ETYPE_RC4_PLAIN_EXP);
		CONST_CASE(KERB_ETYPE_DSA_SHA1_CMS);
		CONST_CASE(KERB_ETYPE_RSA_MD5_CMS);
		CONST_CASE(KERB_ETYPE_RSA_SHA1_CMS);
		CONST_CASE(KERB_ETYPE_RC2_CBC_ENV);
		CONST_CASE(KERB_ETYPE_RSA_ENV);
		CONST_CASE(KERB_ETYPE_RSA_ES_OEAP_ENV);
		CONST_CASE(KERB_ETYPE_DES_EDE3_CBC_ENV);
		CONST_CASE(KERB_ETYPE_DSA_SIGN);
		/*
		CONST_CASE(KERB_ETYPE_RSA_PRIV);
		CONST_CASE(KERB_ETYPE_RSA_PUB);
		CONST_CASE(KERB_ETYPE_RSA_PUB_MD5);
		CONST_CASE(KERB_ETYPE_RSA_PUB_SHA1);
		CONST_CASE(KERB_ETYPE_PKCS7_PUB);
		*/
		CONST_CASE(KERB_ETYPE_DES_CBC_MD5_NT);
		CONST_CASE(KERB_ETYPE_RC4_HMAC_NT);
		CONST_CASE(KERB_ETYPE_RC4_HMAC_NT_EXP);
		CONST_CASE(KERB_ETYPE_AES128_CTS_HMAC_SHA1_96);
		CONST_CASE(KERB_ETYPE_AES256_CTS_HMAC_SHA1_96);
	}
	return "KERB_ETYPE_UNKNOWN";
}

void VerifySQLServerInfo( char* pszSQLServerInput )
{
	HOSTENT * hostent  = NULL;
	ULONG     ulIpAddr = 0;
	WSADATA wsadata;
	char pszSQLServer[1024];
	char szIP[255];
	char szFQDN[1024];
	char* s = NULL;
	int neterrno  = 0;
	IP_CRACKER ipCracker;

	WSAStartup( (WORD)0x0101, &wsadata );

	// Check inputs.
	if ( NULL == pszSQLServer )	return;
	if ( lstrlen(pszSQLServerInput) >= sizeof(pszSQLServer) ) return;

	// Create working string for extracting host.
	lstrcpy( pszSQLServer, pszSQLServerInput );

	// Save off original SQL Server name.
	lstrcpy( g_STATUS.g_szSavedSQLServer, pszSQLServer );

	// Remove instance name.
	s = pszSQLServer;
	while (*s)
	{
		if ( '\\' == *s )
		{
			*s = '\0';
			break;
		}
		s++;
	}

	// Save off host.
	lstrcpy( g_STATUS.g_szSavedSQLServer, pszSQLServer );

	o_printf( "Performing forward and reverse lookup test of server name/ip address." );

	// Determine if host name or IP address entered.
	ulIpAddr  = inet_addr( pszSQLServer );

	if( INADDR_NONE == ulIpAddr )
	{
		hostent = gethostbyname( pszSQLServer );
		if ( NULL == hostent ) 
		{
			neterrno = WSAGetLastError();
			o_printf( "InputSQLServerName=[%s] API=[gethostbyname] ResolvedIPAddress=[FAILED]", pszSQLServerInput );
			o_printf( "WSAGetLastError=[%d] ErrorMessage=[%s]", neterrno, GetWinSockErrorString(neterrno) );
			goto VerifySQLServerInfoExit;
		}

		g_STATUS.fGetHostByName = TRUE;

		if ( hostent )
		{
			ipCracker.IP = (DWORD) *(unsigned long*)hostent->h_addr_list[0];
			sprintf_s( szIP, sizeof(szIP),
					   "%d.%d.%d.%d", 
					   ipCracker.Bytes.b1, 
					   ipCracker.Bytes.b2, 
					   ipCracker.Bytes.b3, 
					   ipCracker.Bytes.b4 );
												 
			o_printf( "InputSQLServerName=[%s] API=[gethostbyname] ResolvedIPAddress=[%s]", pszSQLServerInput, szIP );
			o_printf( "InputSQLServerName=[%s] API=[gethostbyname] ResolvedDNSAddress=[%s]", pszSQLServerInput, hostent->h_name );

			// Save off FQDN and IP for later use.
			lstrcpy( g_STATUS.g_szSavedFQDN, hostent->h_name );
			lstrcpy( g_STATUS.g_szSavedIP, szIP );
			
		}
	}
	else
	{
		// Host IP address entered in the form of xxx.xxx.xxx.xxx
		hostent = gethostbyaddr( (char *)&ulIpAddr, 
								 sizeof(ULONG), 
								 AF_INET );
		if ( NULL == hostent )
		{
			neterrno = WSAGetLastError();
			o_printf( "InputIP=[%s] API=[gethostbyaddr] ResolvedServerName=[FAILED]", pszSQLServerInput );
			o_printf( "WSAGetLastError=[%d] ErrorMessage=[%s]", neterrno, GetWinSockErrorString(neterrno) );
		}
		else
		{
			g_STATUS.fGetHostByAddr = TRUE;
			lstrcpy( szFQDN, hostent->h_name );
			lstrcpy( g_STATUS.g_szSavedFQDN, hostent->h_name );
			lstrcpy( g_STATUS.g_szSavedIP, pszSQLServerInput );
			o_printf( "InputIP=[%s] API=[gethostbyaddr] ResolvedServerName=[%s]", pszSQLServerInput, szFQDN );
		}
	}

VerifySQLServerInfoExit:

	o_printf( "" );

}

// Most of this code was nicked from KerbTray tool.

#define SEC_SUCCESS(Status) ((Status) >= 0)
#define TPS (10*1000*1000)

// Converts UNICODE_STRING into ANSI string, returns pointer to string.
// Checks for buffer overflow and NULL UNICODE_STRING.
// Properly null terminates string.
// Minimum usBufferLength is 8 to allow returning "(NULL)" for NULL cases.
// If pszBuffer is NULL or usBufferLength < 8, returns "(#ERROR)".
char* US2A( char* pszBuffer, USHORT usBufferLength, PUNICODE_STRING pUS )
{
	USHORT i, ulCopyLength;
	char* s;
	char* d;

	// Check input buffer constraints.
	if ( ( NULL == pszBuffer ) || ( usBufferLength < 8 ) )
	{
		return "(#ERROR)";
	}

	// Check PUNICODE_STRING for NULL conditions.
	if ( ( NULL == pUS ) || ( NULL == pUS->Buffer ) )
	{
		sprintf_s( pszBuffer, usBufferLength, "(NULL)" );
		return pszBuffer;
	}

	// Setup source and destination pointers.
	s = (char*) pUS->Buffer;
	d = pszBuffer;

	// Calculate buffer length, check for overflow.
	ulCopyLength = pUS->Length / 2;
	if ( ulCopyLength > usBufferLength ) ulCopyLength = usBufferLength - 1;

	// Copy over string.
	for ( i=0; i<ulCopyLength; i++ )
	{
		d[i] = s[i*2];
		if ( '\0' == d[i] ) break;
	}

	d[i] = '\0';

	return pszBuffer;

}

// Converts FILETIME to string.
char* StringTimeFromFileTime( FILETIME* pFT )
{
	static char szTime[255];
	SYSTEMTIME ST;
	FileTimeToSystemTime( pFT, &ST );
	sprintf_s( szTime, sizeof(szTime),
			 "%04d-%02d-%02d %02d:%02d:%02d", 
			 ST.wYear, ST.wMonth, ST.wDay,
			 ST.wHour, ST.wMinute, ST.wSecond );
	return szTime;
}

char* GetDateDiff( FILETIME* pStart, FILETIME* pExpire )
{
	static char szDiff[255];
	__int64 i64Start, i64Expire, i64Diff, i64Hours, i64Mins, i64Secs;
	BOOL fExpired = FALSE;

	szDiff[0] = '\0';
	szDiff[1] = '\0';

	if ( ( pStart->dwHighDateTime > 0x7FFF0000 ) || ( pExpire->dwHighDateTime > 0x7FFF0000 ) )
	{
		sprintf_s( szDiff, sizeof(szDiff), "(Infinite)" );
		return szDiff;
	}

	i64Start  = *(__int64*)pStart;
	i64Expire = *(__int64*)pExpire;
	if ( i64Expire < i64Start )
	{
		fExpired = TRUE;
		i64Diff = i64Start - i64Expire;
	}
	else
	{
		fExpired = FALSE;
		i64Diff = i64Expire - i64Start;
	}

	// lDiffHours is in 100 nanoseconds units.
	// Convert this to seconds.
	i64Secs = i64Diff/10000000; 
	
	// Calculate hours, minutes, and seconds.
	i64Mins    = i64Secs/60;
	i64Secs    = i64Secs - (i64Mins*60);
	i64Hours   = i64Mins/60;
	i64Mins    = i64Mins - (i64Hours*60);

	sprintf_s( szDiff, sizeof(szDiff), "(%02I64u:%02I64u:%02I64u diff)",
			 i64Hours, i64Mins, i64Secs );

	return szDiff;
}

// Dumps a KERB_TICKET_CACHE_INFO structure to SSPILog.
void DumpKERB_TICKET_CACHE_INFO( ULONG ulTicketNumber, PKERB_TICKET_CACHE_INFO pTicketCI )
{
	char szBuffer[1024];
	SYSTEMTIME ST;
	FILETIME FT;
	long comp;

	if ( NULL == pTicketCI ) return;

	__try
	{
		o_printf( "KERB_TICKET_CACHE_INFO[%lu]", ulTicketNumber );
		o_printf( "  ServerName     = %s", US2A( szBuffer, sizeof(szBuffer), &pTicketCI->ServerName ) );
		o_printf( "  RealmName      = %s", US2A( szBuffer, sizeof(szBuffer), &pTicketCI->RealmName ) );
		o_printf( "  StartTime      = %s", StringTimeFromFileTime( (FILETIME*) &pTicketCI->StartTime ) );

		// Check expiration date...
		GetSystemTime( &ST );
		SystemTimeToFileTime( &ST, &FT );
		comp  = CompareFileTime( (FILETIME*)&pTicketCI->EndTime, &FT );

		o_printf( "  EndTime        = %s %s %s", 
				  StringTimeFromFileTime( (FILETIME*) &pTicketCI->EndTime ),
				  (char*) ( ( comp <= 0 ) ? "*** EXPIRED ***" : "STILL VALID" ),
				  GetDateDiff( (FILETIME*) &pTicketCI->StartTime, (FILETIME*) &pTicketCI->EndTime ) );

		o_printf( "  RenewTime      = %s", StringTimeFromFileTime( (FILETIME*) &pTicketCI->RenewTime ) );
		o_printf( "  EncryptionType = %lu (%s)", pTicketCI->EncryptionType, GetEncryptionTypeString( pTicketCI->EncryptionType) );
		o_printf( "  TicketFlags    = 0x%08x (%s)", pTicketCI->TicketFlags, GetKERB_TICKET_FLAGSString(pTicketCI->TicketFlags) );
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		o_printf( "\r\n*** Error in DumpKERB_TICKET_CACHE_INFO ***" );
	}

}

// Converts a KERB_EXTERNAL_NAME structure into an ANSI string.
char* GetKERB_EXTERNAL_NAME( PKERB_EXTERNAL_NAME pName )
{
	USHORT i;
	char szBuffer[1024];
	static char szFinalString[2048];
	
	if ( NULL == pName ) 
	{
		return "(NULL)";
	}

	if ( 0 == pName->NameCount )
	{
		sprintf_s( szFinalString, sizeof(szFinalString), "(NULL) (NameCount=0)" );
		return szFinalString;
	}

	__try
	{
		// Otherwise, we have multiple names.
		// Concat mulitple names together.
		ZeroMemory( szFinalString, sizeof(szFinalString) );
		for ( i=0; i<pName->NameCount; i++ )
		{
			ZeroMemory( szBuffer, sizeof(szBuffer) );
			lstrcat( szFinalString, US2A( szBuffer, sizeof(szBuffer), &pName->Names[i] ) );
			if ( i < (pName->NameCount-1) ) lstrcat( szFinalString, "|" );
		}
	
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		o_printf( "\r\n*** Error in GetKERB_EXTERNAL_NAME ***" );
	}

	return szFinalString;

}

// Dumps a KERB_EXTERNAL_TICKET structure to the SSPILog.
void DumpKERB_EXTERNAL_TICKET( PKERB_EXTERNAL_TICKET pExTicket )
{
	char szBuffer[1024];
	SYSTEMTIME ST;
	FILETIME FT;
	long comp;

	if ( NULL == pExTicket ) return;

	__try
	{

		o_printf( "KERB_EXTERNAL_TICKET" );

		o_printf( "  ServiceName         = %s", GetKERB_EXTERNAL_NAME(pExTicket->ServiceName) );
		o_printf( "  TargetName          = %s", GetKERB_EXTERNAL_NAME(pExTicket->TargetName) );
		o_printf( "  ClientName          = %s", GetKERB_EXTERNAL_NAME(pExTicket->ClientName) );
		o_printf( "  DomainName          = %s", US2A( szBuffer, sizeof(szBuffer), &pExTicket->DomainName ) );
		o_printf( "  TargetDomainName    = %s", US2A( szBuffer, sizeof(szBuffer), &pExTicket->TargetDomainName ) );
		o_printf( "  AltTargetDomainName = %s", US2A( szBuffer, sizeof(szBuffer), &pExTicket->AltTargetDomainName ) );

		o_printf( "  SessionKey.KeyType  = %lu (%s)", pExTicket->SessionKey.KeyType, GetEncryptionTypeString( pExTicket->SessionKey.KeyType ) );
		o_printf( "  SessionKey.Length   = %lu", pExTicket->SessionKey.Length );
		o_printf( "  SessionKey.Value    = " );
		DumpHex( pExTicket->SessionKey.Value, pExTicket->SessionKey.Length );

		o_printf( "  TicketFlags         = 0x%08x (%s)", pExTicket->TicketFlags, GetKERB_TICKET_FLAGSString(pExTicket->TicketFlags) );

		o_printf( "  Flags               = 0x%08x", pExTicket->Flags ); 

		o_printf( "  KeyExpirationTime   = %i64", (__int64) pExTicket->KeyExpirationTime.QuadPart );
		o_printf( "  StartTime           = %s", StringTimeFromFileTime( (FILETIME*) &pExTicket->StartTime ) );

		// Check expiration date...
		GetSystemTime( &ST );
		SystemTimeToFileTime( &ST, &FT );
		comp  = CompareFileTime( (FILETIME*)&pExTicket->EndTime, &FT );

		o_printf( "  EndTime             = %s %s %s", 
				  StringTimeFromFileTime( (FILETIME*) &pExTicket->EndTime ),
				  (char*) ( ( comp <= 0 ) ? "*** EXPIRED ***" : "STILL VALID" ),
				  GetDateDiff( (FILETIME*) &pExTicket->StartTime, (FILETIME*) &pExTicket->EndTime ) );

		o_printf( "  RenewUntil          = %s", StringTimeFromFileTime( (FILETIME*) &pExTicket->RenewUntil ) );
		o_printf( "  TimeSkew            = %i64", (__int64) pExTicket->TimeSkew.QuadPart );

		o_printf( "  EncodedTicketSize   = %lu", pExTicket->EncodedTicketSize );
		o_printf( "  EncodedTicket       = 0x%08x", pExTicket->EncodedTicket );

		// Skipping this for now, it's not very useful and it fills the log up.
		// DumpHex( pExTicket->EncodedTicket, pExTicket->EncodedTicketSize );

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		o_printf( "\r\n*** Error in DumpKERB_EXTERNAL_TICKET ***" );
	}

}

HRESULT FindSPNViaAD( char* pszSPN )
{
    HRESULT hr		= E_FAIL;
	VARIANT var;
	ULONG lFetch;
	DWORD dwSPNCount, dwColCount;
    IDirectorySearch *pIDirectorySearch	= NULL;
	IADsContainer *pIADsContainer		= NULL;
    IUnknown* pIUnknown					= NULL;
	IEnumVARIANT *pIEnumVARIANT			= NULL;
   	IDispatch *pIDispatch				= NULL;
    IADs *pADs							= NULL;
	#define ATTRIBUTE_COUNT 2
	ADS_SEARCHPREF_INFO SearchPrefs;
	SearchPrefs.dwSearchPref	= ADS_SEARCHPREF_SEARCH_SCOPE;
	SearchPrefs.vValue.dwType	= ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer	= ADS_SCOPE_SUBTREE;
	DWORD dwNumPrefs			= 1;
	ADS_SEARCH_COLUMN col1;
	ADS_SEARCH_HANDLE hSearch   = NULL;
	LPOLESTR rgwszAttributes[ATTRIBUTE_COUNT] = { L"dnsHostName", L"distinguishedName" };
	WCHAR wszSearchFilter[1024];
	LPWSTR pszColumn = NULL;
	BSTR bstrSPN = NULL;

	__try
	{

		bstrSPN = AnsiToBSTR( pszSPN );

		wsprintfW( wszSearchFilter, L"(servicePrincipalName=%s)", (WCHAR*) bstrSPN );

		o_printf( "" );
		o_printf( "Attempting to load up Active Directory dll and check AD for SPN" );

		if ( !LoadADSI() ) 
		{
			o_printf( "Failed to load activeds.dll, cannot talk to AD.  This can happen on Windows 9x and NT 4 machines." );
			return E_FAIL;
		}

		g_STATUS.fLoadedADSI = TRUE;

		hr = GetGCIADsContainer( &pIADsContainer );
		if ( FAILED(hr) )
		{
			o_printf( "ADsOpenObject( \"GC:\",...,ADS_SECURE_AUTHENTICATION) failed with HRESULT=0x%08x", hr );
			return hr;
		}

		g_STATUS.fGetGCIADsContainer = TRUE;

		hr = pIADsContainer->get__NewEnum( &pIUnknown );
		if (FAILED(hr))
		{
			o_printf( "get__NewEnum failed, hr=0x%08x", hr );
			goto FindSPNViaADExit;
		}

		hr = pIUnknown->QueryInterface( IID_IEnumVARIANT, (void**) &pIEnumVARIANT );
		if (FAILED(hr))
		{
			o_printf( "QueryInterface(IID_IEnumVARIANT) failed, hr=0x%08x", hr );
			goto FindSPNViaADExit;
		}

		// Now Enumerate--there should be only one item.
		hr = pIEnumVARIANT->Next( 1, &var, &lFetch );
		if (FAILED(hr))
		{
			o_printf( "pIEnumVARIANT->Next failed, hr=0x%08x", hr );
			goto FindSPNViaADExit;
		}

		// QI for pIDirectorySearch interface.
		pIDispatch = V_DISPATCH(&var);
		hr = pIDispatch->QueryInterface( __uuidof(guid_IID_IDirectorySearch), (void**)&pIDirectorySearch ); 
		VariantClear(&var);
		pIDispatch = NULL; // Set this to NULL because we already released the interface with VariantClear.

		if ( FAILED(hr) )
		{
			o_printf( "QueryInterface(IID_IDirectorySearch) failed, hr=0x%08x", hr );
			goto FindSPNViaADExit;
		}
		
		// Set the search preference
		hr = pIDirectorySearch->SetSearchPreference( &SearchPrefs, dwNumPrefs );
		if ( FAILED(hr) )
		{
			o_printf( "SetSearchPreference failed, hr=0x%08x", hr );
			goto FindSPNViaADExit;
		}
		
		// Execute the search
		hr = pIDirectorySearch->ExecuteSearch( wszSearchFilter,
											   rgwszAttributes,
											   ATTRIBUTE_COUNT,
											   &hSearch	);
		if ( FAILED(hr) )
		{
			o_printf( "ExecuteSearch failed, hr=0x%08x", hr );
			goto FindSPNViaADExit;
		}

		g_STATUS.fExecuteSearch = TRUE;

		if( S_ADS_NOMORE_ROWS == pIDirectorySearch->GetFirstRow( hSearch ) )
		{
			o_printf( "SPN %s not found anywhere in Active Directory", pszSPN );
			goto FindSPNViaADExit;
		}

		g_STATUS.fSPNFoundInAD = TRUE;

		dwSPNCount = 0;
		o_printf( "" );
		o_printf( "Searching AD for SPN complete." );
		o_printf( "SPN %s found on following object(s) in AD:", pszSPN );
		do
		{	
			dwSPNCount++;
			dwColCount = 0;
			while( pIDirectorySearch->GetNextColumnName( hSearch, &pszColumn ) != S_ADS_NOMORE_COLUMNS )
			{
				// Get the data for this column
				hr  = pIDirectorySearch->GetColumn( hSearch, pszColumn, &col1 );

				if ( SUCCEEDED(hr) )
				{
					dwColCount++;
					if ( 1 == dwColCount )
					{
						o_printf( "  %02lu. %20S = %S", 
								  dwSPNCount,
								  pszColumn,
								  col1.pADsValues->CaseIgnoreString );
					}
					else
					{
						o_printf( "      %20S = %S", 
								  pszColumn,
								  col1.pADsValues->CaseIgnoreString );
					}
					pIDirectorySearch->FreeColumn( &col1 );
				}
				// 	FreeADsMem( pszColumn ); Leaking this for now, don't want to bind to adsi.
			}
			
			if ( dwSPNCount > 1 ) g_STATUS.fDuplicateSPNFound = TRUE;
			
		}
		while ( S_ADS_NOMORE_ROWS != pIDirectorySearch->GetNextRow( hSearch ) );

		// Close the search handle to clean up
		pIDirectorySearch->CloseSearchHandle(hSearch);
	
FindSPNViaADExit:

		SAFE_RELEASE( pIDirectorySearch );
		SAFE_RELEASE( pIEnumVARIANT );
		SAFE_RELEASE( pIUnknown );
		SAFE_RELEASE( pIADsContainer );
		SAFE_SYSFREE( bstrSPN );
		return hr;

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		o_printf( "\r\n*** Error in FindSPNViaAD ***" );
	}

	return E_FAIL;


}

void DumpKerberosTickets()
{
	NTSTATUS Status, SubStatus;
	KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
	ULONG ulResponseSize;
	ULONG ulPackageId;
	LSA_STRING Name;
	HANDLE hLogonHandle = NULL;
	PKERB_QUERY_TKT_CACHE_RESPONSE pTickets  = NULL;
	PKERB_RETRIEVE_TKT_RESPONSE pTicketEntry = NULL;
	PKERB_EXTERNAL_TICKET pExTicket			 = NULL;
	PKERB_TICKET_CACHE_INFO pTicketCI        = NULL;
	ULONG i;
	char szErrorBuffer[1024];

	o_printf( "Dumping Kerberos tickets for local client machine." );

	// Connect to LSA.
    Status = pfnLsaConnectUntrusted( &hLogonHandle );
    if ( !SEC_SUCCESS( Status ) ) 
	{
		o_printf( "LsaConnectUntrusted failed, Status=0x%08x\n", Status );
        goto DumpKerberosTicketsExit;
    }

	// Get the Kerberos package.
    Name.Buffer = MICROSOFT_KERBEROS_NAME_A;
    Name.Length = (USHORT) strlen(Name.Buffer);
    Name.MaximumLength = Name.Length + 1;
    Status = pfnLsaLookupAuthenticationPackage( hLogonHandle,
											    &Name,
											    &ulPackageId
										      );
    if ( !SEC_SUCCESS(Status) ) 
	{
		o_printf( "LsaLookupAuthenticationPackage failed, Status=0x%08x\n", Status );
        goto DumpKerberosTicketsExit;
    }

	// Get the KerbRetrieveTicketMessage message.
    CacheRequest.MessageType	  = KerbRetrieveTicketMessage;
    CacheRequest.LogonId.LowPart  = 0;
    CacheRequest.LogonId.HighPart = 0;
    Status = pfnLsaCallAuthenticationPackage( hLogonHandle,
                                              ulPackageId,
										      &CacheRequest,
										      sizeof(CacheRequest),
										      (PVOID *) &pTicketEntry,
										      &ulResponseSize,
										      &SubStatus );
    if ( !SEC_SUCCESS(Status) || !SEC_SUCCESS(SubStatus) ) 
	{
		// Failed to get the ticket.
		o_printf( "LsaCallAuthenticationPackage(KerbRetrieveTicketMessage) failed, Status=0x%08x, SubStatus=0x%08x\n", Status, SubStatus );
		if ( GetLSAStatusError( SubStatus, szErrorBuffer, sizeof(szErrorBuffer) ) )
		{
			o_printf( "  SubStatus=0x%08x -> %s", SubStatus, szErrorBuffer );
		}
    }
    else 
	{
		// Dump out KerbRetrieveTicketMessage ticket.
        pExTicket = &(pTicketEntry->Ticket);

		DumpKERB_EXTERNAL_TICKET( pExTicket );

        pfnLsaFreeReturnBuffer( pTicketEntry );
		pTicketEntry = NULL;

    }

    CacheRequest.MessageType = KerbQueryTicketCacheMessage;
    CacheRequest.LogonId.LowPart = 0;
    CacheRequest.LogonId.HighPart = 0;

    Status = pfnLsaCallAuthenticationPackage( hLogonHandle,
                                              ulPackageId,
                                              &CacheRequest,
                                              sizeof(CacheRequest),
                                              (PVOID *) &pTickets,
                                              &ulResponseSize,
                                              &SubStatus );
    if ( SEC_SUCCESS(Status) && SEC_SUCCESS(SubStatus) ) 
	{
        for ( i=0; i<pTickets->CountOfTickets; i++ ) 
		{
			pTicketCI = &pTickets->Tickets[i];
			DumpKERB_TICKET_CACHE_INFO( i, pTicketCI );
        }
        pfnLsaFreeReturnBuffer( pTickets );
		pTickets = NULL;
    }

DumpKerberosTicketsExit:

	if ( pTickets )
	{
		pfnLsaFreeReturnBuffer( pTickets );
		pTickets = NULL;
	}

	if ( pTicketEntry )
	{
        pfnLsaFreeReturnBuffer( pTicketEntry );
		pTicketEntry = NULL;
	}

	if ( hLogonHandle ) pfnLsaDeregisterLogonProcess( hLogonHandle );
	o_printf( "" );

}

void VerifySPN( char* pszSPN )
{
	NTSTATUS Status, SubStatus;
	ULONG ulResponseSize, ulRequestSize, ulPackageId;
	LSA_STRING Name;
	HANDLE hLogonHandle						   = NULL;
	PKERB_RETRIEVE_TKT_RESPONSE pCacheResponse = NULL;
	PKERB_RETRIEVE_TKT_REQUEST pCacheRequest   = NULL;
	PKERB_EXTERNAL_TICKET pExTicket			   = NULL;
	UNICODE_STRING usSPN, usTarget;
	KERB_QUERY_TKT_CACHE_REQUEST tgtCacheRequest;
	PKERB_RETRIEVE_TKT_RESPONSE  pTicketEntry  = NULL;
	char szErrorBuffer[1024];
	BSTR bstrSPN = NULL;

	__try
	{

		bstrSPN = AnsiToBSTR( pszSPN );

		o_printf( "" );
		o_printf( "Attempting to manually verify Kerberos ticket for SPN" );

		// Connect to LSA.
		Status = pfnLsaConnectUntrusted( &hLogonHandle );
		if ( !SEC_SUCCESS( Status ) ) 
		{
			o_printf( "LsaConnectUntrusted failed, Status=0x%08x", Status );
			goto VerifySPNExit;
		}

		g_STATUS.fLsaConnectUntrusted = TRUE;

		o_printf( "Attempting to get TGT" );

		// Get the Kerberos package.
		Name.Buffer = MICROSOFT_KERBEROS_NAME_A;
		Name.Length = (USHORT) strlen(Name.Buffer);
		Name.MaximumLength = Name.Length + 1;
		Status = pfnLsaLookupAuthenticationPackage( hLogonHandle,
													&Name,
													&ulPackageId );
		if ( !SEC_SUCCESS(Status) ) 
		{
			o_printf( "LsaLookupAuthenticationPackage failed, Status=0x%08x\n", Status );
			goto VerifySPNExit;
		}

		// See if we can get the TGT first.
		ZeroMemory( &tgtCacheRequest, sizeof(tgtCacheRequest) );
		tgtCacheRequest.MessageType      = KerbRetrieveTicketMessage; // Retrieve TGT message
		tgtCacheRequest.LogonId.LowPart  = 0;                         // LUID, zero indicates 
		tgtCacheRequest.LogonId.HighPart = 0;                         //   current logon session

		Status = pfnLsaCallAuthenticationPackage( hLogonHandle,            // [IN] LSA connection handle
												 ulPackageId,              // [IN] Kerberos package ID
												 &tgtCacheRequest,         // [IN] Request message
												 sizeof(tgtCacheRequest),  // [IN] Message length
												 (PVOID *) &pTicketEntry,  // [OUT] Response buffer
												 &ulResponseSize,          // [OUT] Response length
												 &SubStatus );             // [OUT] Completion status


		if ( ( !SEC_SUCCESS(Status) ) || ( !SEC_SUCCESS(SubStatus) ) )
		{
			o_printf( "LsaCallAuthenticationPackage failed attempting to get TGT, Status=0x%08x, SubStatus=0x%08x", Status, SubStatus );
			if ( GetLSAStatusError( SubStatus, szErrorBuffer, sizeof(szErrorBuffer) ) )
			{
				o_printf( "  SubStatus=0x%08x -> %s", SubStatus, szErrorBuffer );
			}
			goto VerifySPNExit;
		}

		g_STATUS.fSPNResolvedToTGT = TRUE;

		o_printf( "Successfully retrieved TGT, displaying TGT" );
		pExTicket = &(pTicketEntry->Ticket);
		DumpKERB_EXTERNAL_TICKET( pExTicket );

		ZeroMemory( &usSPN, sizeof(usSPN) );
		ZeroMemory( &usTarget, sizeof(usTarget) );

		// Setup target UNICODE_STRING structure.
		usSPN.Buffer        = (BSTR)bstrSPN;
		usSPN.Length        = SysStringLen(bstrSPN)*sizeof(WCHAR);
		usSPN.MaximumLength = usSPN.Length + sizeof(WCHAR);

		// Allocate pCacheRequest from local heap.
		ulRequestSize = usSPN.Length + sizeof(KERB_RETRIEVE_TKT_REQUEST);
		pCacheRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc( LMEM_ZEROINIT, ulRequestSize+sizeof(WCHAR) );

		// Point target UNICODE_STRING to buffer space following request structure
		usTarget.Buffer = (LPWSTR) (pCacheRequest + 1);    // First byte after request structure
		usTarget.Length = usSPN.Length;					   // Length of requested SPN
		usTarget.MaximumLength = usSPN.MaximumLength;      // Maximum length of requested SPN

		ZeroMemory( usTarget.Buffer, usSPN.Length+sizeof(WCHAR) );
		CopyMemory( usTarget.Buffer, usSPN.Buffer, usSPN.Length );   // Copy SPN to buffer

		// Setup cache request structure
		pCacheRequest->MessageType       = KerbRetrieveEncodedTicketMessage ;	// Get ticket
		pCacheRequest->LogonId.LowPart   = 0;									// LUID, zero indicates
		pCacheRequest->LogonId.HighPart  = 0;									// current logon session
		pCacheRequest->CacheOptions      = KERB_RETRIEVE_TICKET_DONT_USE_CACHE;	// Do not read ticket from cache.
		pCacheRequest->EncryptionType    = KERB_ETYPE_NULL;						// No encryption.
		pCacheRequest->CredentialsHandle.dwLower = 0;							// Null cred handle means use current creds.
		pCacheRequest->CredentialsHandle.dwUpper = 0;							// Null cred handle means use current creds.
		pCacheRequest->TargetName		 = usTarget;							// Target SPN
		pCacheRequest->TicketFlags       = 0;									// Request ticket as needed.

		// Null out params.
		pCacheResponse = NULL;
		ulResponseSize = 0;
		SubStatus      = 0;

		o_printf( "" );
		o_printf( "Attempting to get ticket to SPN with KERB_RETRIEVE_TICKET_DONT_USE_CACHE (meaning don't use ticket from cache)" );

		// Request ticket.
		Status = pfnLsaCallAuthenticationPackage( hLogonHandle,              // [IN] LSA connection handle
												 ulPackageId,                // [IN] Kerberos package ID
												 pCacheRequest,              // [IN] Request message
												 ulRequestSize,              // [IN] Message length
												 (PVOID *) &pCacheResponse,  // [OUT] Response buffer
												 &ulResponseSize,            // [OUT] Response length
												 &SubStatus );               // [OUT] Completion status

		if ( ( !SEC_SUCCESS(Status) ) || ( !SEC_SUCCESS(SubStatus) ) )
		{
			o_printf( "LsaCallAuthenticationPackage failed attempting to get ticket for %S, Status=0x%08x, SubStatus=0x%08x", bstrSPN, Status, SubStatus );

			if ( 0xc000018b == SubStatus )
			{
				o_printf( "NOTE! SubStatus=0xc000018b typically means that the SPN does not exist, this error is normal if the SPN truely does not exist." );
			}

			if ( GetLSAStatusError( SubStatus, szErrorBuffer, sizeof(szErrorBuffer) ) )
			{
				o_printf( "  SubStatus=0x%08x -> %s", SubStatus, szErrorBuffer );
			}
			goto VerifySPNExit;
		}
		else
		{
			g_STATUS.fSPNResolvedToTGTNoCache = TRUE;
			o_printf( "Successfully retrieved ticket for SPN, displaying SPN ticket" );
			pExTicket = &(pCacheResponse->Ticket);
			DumpKERB_EXTERNAL_TICKET( pExTicket );
		}

	VerifySPNExit:

		if ( pTicketEntry )
		{
			pfnLsaFreeReturnBuffer( pTicketEntry );
			pTicketEntry = NULL;
		}

		if (pCacheResponse)
		{
			pfnLsaFreeReturnBuffer( pCacheResponse );
			pCacheResponse = NULL;
		}

		if ( pCacheRequest )
		{
			LocalFree( pCacheRequest );
			pCacheRequest = NULL;
		}

		SAFE_SYSFREE( bstrSPN );

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		o_printf( "[VerifySPN] Unexpected error in VerifySPN" );
	}

}

// Purges a ticket from Kerberos ticket cache.
BOOL PurgeTicket( HANDLE LogonHandle, ULONG PackageId, LPWSTR Server, DWORD cbServer, LPWSTR Realm, DWORD cbRealm )
{
    NTSTATUS Status;
    PVOID Response;
    ULONG ResponseSize;
    NTSTATUS SubStatus=0;

    PKERB_PURGE_TKT_CACHE_REQUEST pCacheRequest = NULL;

	__try
	{

		pCacheRequest = (PKERB_PURGE_TKT_CACHE_REQUEST)	
			LocalAlloc(LMEM_ZEROINIT, cbServer + cbRealm + sizeof(KERB_PURGE_TKT_CACHE_REQUEST));
		if (pCacheRequest == NULL)
		{
			o_printf( "[PurgeTicket] LocalAlloc failed to allocate Memory.");
			return FALSE;
		}

		pCacheRequest->MessageType		= KerbPurgeTicketCacheMessage;
		pCacheRequest->LogonId.LowPart	= 0;
		pCacheRequest->LogonId.HighPart = 0;

		CopyMemory( (LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST),
					Server,
					cbServer );
		CopyMemory( (LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST)+cbServer,
					Realm,
					cbRealm );

		pCacheRequest->ServerName.Buffer = (LPWSTR)((LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST));

		pCacheRequest->ServerName.Length = (unsigned short)cbServer;

		pCacheRequest->ServerName.MaximumLength = (unsigned short)cbServer;

		pCacheRequest->RealmName.Buffer = (LPWSTR)((LPBYTE)pCacheRequest+sizeof(KERB_PURGE_TKT_CACHE_REQUEST)+cbServer);

		pCacheRequest->RealmName.Length = (unsigned short)cbRealm;

		pCacheRequest->RealmName.MaximumLength = (unsigned short)cbRealm;

		Status = pfnLsaCallAuthenticationPackage( LogonHandle,
												  PackageId,
												  pCacheRequest,
												  sizeof(KERB_PURGE_TKT_CACHE_REQUEST)+cbServer+cbRealm,
												  &Response,
												  &ResponseSize,
												  &SubStatus );

		if (!SEC_SUCCESS(Status) || !SEC_SUCCESS(Status))
		{
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		o_printf( "[PurgeTicket] Unexpected error in PurgeTicket" );
	}

	return FALSE;

}

void FlushAllKerberosTickets()
{
	NTSTATUS Status, SubStatus;
	KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
	ULONG ulResponseSize;
	ULONG ulPackageId;
	LSA_STRING Name;
	HANDLE hLogonHandle = NULL;
	PKERB_QUERY_TKT_CACHE_RESPONSE pTickets  = NULL;
	PKERB_RETRIEVE_TKT_RESPONSE pTicketEntry = NULL;
	PKERB_EXTERNAL_TICKET pExTicket			 = NULL;
	PKERB_TICKET_CACHE_INFO pTicketCI        = NULL;
	ULONG i;
	BOOL fPurged;

	__try
	{

		// Connect to LSA.
		Status = pfnLsaConnectUntrusted( &hLogonHandle );
		if ( !SEC_SUCCESS( Status ) ) 
		{
			// o_printf( "LsaConnectUntrusted failed, Status=0x%08x", Status );
			goto FlushAllKerberosTicketsExit;
		}

		g_STATUS.fLsaConnectUntrusted = TRUE;

		// Get the Kerberos package.
		Name.Buffer = MICROSOFT_KERBEROS_NAME_A;
		Name.Length = (USHORT) strlen(Name.Buffer);
		Name.MaximumLength = Name.Length + 1;
		Status = pfnLsaLookupAuthenticationPackage( hLogonHandle,
													&Name,
													&ulPackageId
												  );
		if ( !SEC_SUCCESS(Status) ) 
		{
			//o_printf( "LsaLookupAuthenticationPackage failed, Status=0x%08x", Status );
			goto FlushAllKerberosTicketsExit;
		}

		g_STATUS.fLsaLookupAuthenticationPackage = TRUE;

		CacheRequest.MessageType = KerbQueryTicketCacheMessage;
		CacheRequest.LogonId.LowPart = 0;
		CacheRequest.LogonId.HighPart = 0;

		Status = pfnLsaCallAuthenticationPackage( hLogonHandle,
												  ulPackageId,
												  &CacheRequest,
												  sizeof(CacheRequest),
												  (PVOID *) &pTickets,
												  &ulResponseSize,
												  &SubStatus );
		if ( SEC_SUCCESS(Status) && SEC_SUCCESS(SubStatus) ) 
		{
			g_STATUS.fLsaCallAuthenticationPackage = TRUE;
			for ( i=0; i<pTickets->CountOfTickets; i++ ) 
			{
				pTicketCI = &pTickets->Tickets[i];
				fPurged = PurgeTicket( hLogonHandle,
 									   ulPackageId,
									   pTickets->Tickets[i].ServerName.Buffer,
									   pTickets->Tickets[i].ServerName.Length,
									   pTickets->Tickets[i].RealmName.Buffer,
									   pTickets->Tickets[i].RealmName.Length );
			}
			pfnLsaFreeReturnBuffer( pTickets );
			pTickets = NULL;
		}

FlushAllKerberosTicketsExit:

		if ( pTickets )
		{
			pfnLsaFreeReturnBuffer( pTickets );
			pTickets = NULL;
		}

		if ( pTicketEntry )
		{
			pfnLsaFreeReturnBuffer( pTicketEntry );
			pTicketEntry = NULL;
		}

		// if ( hLogonHandle ) pfnLsaDeregisterLogonProcess( hLogonHandle );
		// o_printf( "[FlushAllKerberosTickets] Kerberos ticket flush complete." );

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		// o_printf( "[FlushAllKerberosTickets] Unexpected error in FlushAllKerberosTickets" );
	}

	// o_printf( "" );

}

void CheckKeyFiles()
{
	const char* pszVersion = NULL;
	char szFileName[MAX_PATH];

	__try
	{
		// Check a few key files to gather some minimal data on customer's environment.
		strcpy_s( szFileName, sizeof(szFileName), GetSystemFolder() );
		strcat_s( szFileName, sizeof(szFileName),"dbnetlib.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) o_printf( "dbnetlib.dll v.%s", pszVersion );

		strcpy_s( szFileName, sizeof(szFileName),GetSystemFolder() );
		strcat_s( szFileName, sizeof(szFileName),"sqlsrv32.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) o_printf( "sqlsrv32.dll v.%s", pszVersion );

		strcpy_s( szFileName, sizeof(szFileName),GetSystemFolder() );
		strcat_s( szFileName, sizeof(szFileName),"sqlncli.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) 
		{
			g_STATUS.fSnac9Available = TRUE;
			o_printf( "sqlncli.dll v.%s", pszVersion );
		}

		strcpy_s( szFileName, sizeof(szFileName),GetSystemFolder() );
		strcat_s( szFileName, sizeof(szFileName),"sqlncli10.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) 
		{
			g_STATUS.fSnac10Available = TRUE;
			o_printf( "sqlncli10.dll v.%s", pszVersion );
		}

		strcpy_s(szFileName, sizeof(szFileName), GetSystemFolder());
		strcat_s(szFileName, sizeof(szFileName), "sqlncli11.dll");
		pszVersion = GetFileVersion(szFileName);
		if ('\0' != pszVersion[0])
		{
			g_STATUS.fSnac11Available = TRUE;
			o_printf("sqlncli11.dll v.%s", pszVersion);
		}

		strcpy_s(szFileName, sizeof(szFileName), GetSystemFolder());
		strcat_s(szFileName, sizeof(szFileName), "msodbcsql11.dll");
		pszVersion = GetFileVersion(szFileName);
		if ('\0' != pszVersion[0])
		{
			g_STATUS.fodbc11Available = TRUE;
			o_printf("msodbcsql11.dll v.%s", pszVersion);
		}

		strcpy_s(szFileName, sizeof(szFileName), GetSystemFolder());
		strcat_s(szFileName, sizeof(szFileName), "msodbcsql13.dll");
		pszVersion = GetFileVersion(szFileName);
		if ('\0' != pszVersion[0])
		{
			g_STATUS.fodbc13Available = TRUE;
			o_printf("msodbcsql13.dll v.%s", pszVersion);
		}

		strcpy_s(szFileName, sizeof(szFileName), GetSystemFolder());
		strcat_s(szFileName, sizeof(szFileName), "msodbcsql17.dll");
		pszVersion = GetFileVersion(szFileName);
		if ('\0' != pszVersion[0])
		{
			g_STATUS.fodbc17Available = TRUE;
			o_printf("msodbcsql17.dll v.%s", pszVersion);
		}

		strcpy_s(szFileName, sizeof(szFileName), GetSystemFolder());
		strcat_s(szFileName, sizeof(szFileName), "msodbcsql18.dll");
		pszVersion = GetFileVersion(szFileName);
		if ('\0' != pszVersion[0])
		{
			g_STATUS.fodbc18Available = TRUE;
			o_printf("msodbcsql18.dll v.%s", pszVersion);
		}

		strcpy_s( szFileName, sizeof(szFileName),GetADOFolder() );
		strcat_s( szFileName, sizeof(szFileName),"msado15.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) o_printf( "msado15.dll  v.%s", pszVersion );

		strcpy_s( szFileName, sizeof(szFileName),GetSystemFolder() );
		strcat_s( szFileName, sizeof(szFileName),"kerberos.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) o_printf( "kerberos.dll v.%s", pszVersion );

		strcpy_s( szFileName, sizeof(szFileName),GetSystemFolder() );
		strcat_s( szFileName, sizeof(szFileName),"secur32.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) o_printf( "secur32.dll  v.%s", pszVersion );

		strcpy_s( szFileName, sizeof(szFileName),GetSystemFolder() );
		strcat_s( szFileName, sizeof(szFileName),"ntdll.dll" );
		pszVersion = GetFileVersion( szFileName );
		if ( '\0' != pszVersion[0] ) o_printf( "ntdll.dll    v.%s", pszVersion );
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}

	o_printf( "" );

}

void CSSPIClientDlg::OnBtnConnect() 
{
	HRESULT hr;
	CString strMessage;
	HENV henv   = NULL;
	HDBC hdbc   = NULL;
	HSTMT hstmt = NULL;
	RETCODE rc;
	SQLCHAR szConnectIn[2048];
	SQLCHAR szConnectOut[2048];
	SQLSMALLINT ssicbConnStringOut;
	BOOL fConnected = FALSE;
	int index, port;
	BOOL fUserSetProtocol = FALSE;
	CString strActualConnect, strTempConnect;
	char* pszDriver = NULL;
	
	UpdateData( TRUE );

	BeginWaitCursor();

	// Check for basic UI mistakes first.
	if ( 0 == m_strConnect.GetLength() )
	{
		MessageBox( "Target SQL Server is blank, please enter a SQL Server.", "SSPIClient" );
		return;
	}

	if ( 0 == m_strConnect.Compare( "<Enter your SQL Server Name Here>" ) )
	{
		MessageBox( "Please enter the name of your SQL Server.", "SSPIClient" );
		return;
	}

	if ( 0 == m_strLogFile.GetLength() )
	{
		MessageBox( "Log file name is blank, please enter a valid log file name.", "SSPIClient" );
		return;
	}

	if ( !m_fUseIntegrated )
	{
		if ( 0 == m_strUserId.GetLength() )
		{
			MessageBox( "User id entered is blank, please enter a user id.", "SSPIClient" );
			return;
		}
	}

	strTempConnect = m_strConnect;

	// Connection string possible formats:
	// tcp:foo,1433
	// foo
	// foo,1433
	// tcp:foo
	port  = 1433;
	index = strTempConnect.Find(":");
	if ( index > -1 )
	{
		// Strip off protocol prefix.
		strTempConnect = strTempConnect.Right( strTempConnect.GetLength()-(index+1) );
		fUserSetProtocol = TRUE;
	}

	index = strTempConnect.Find(",");
	if ( index > -1 )
	{
		// Strip off port.
		port = atol( strTempConnect.Right( strTempConnect.GetLength()-(index+1) ) );
		if ( 0 == port ) port = 1433;
		if (port < 1 || port > 65535) port = 1433;
		strTempConnect = strTempConnect.Left( index );
	}

	strActualConnect = m_strConnect;
	m_strConnect = strTempConnect;

	ZeroMemory( &g_STATUS, sizeof(g_STATUS) );

	hr = OpenLogFile( m_strLogFile.GetBuffer(0) );
	if ( FAILED(hr) )
	{
		MessageBox( "Failed to open log file for write, cannot continue.", "SSPIClient" );
		return;
	}

	o_printf( "*** Opening SSPIClient log v.2022.10.07 PID=%lu ***", GetCurrentProcessId() );
	o_printf( "" );

	// Dump out what sort of test we are performing.
	if ( m_fEncryptionTest )
	{
		o_printf( "User clicked 'Run Client Certificate Test' button to test an encrypted connection and certificate validation." );
		o_printf( "" );
	}
	else
	{
		o_printf( "User clicked 'Run SSPI Connection Test' button." );
		o_printf( "" );
	}

	// Check domain information.
	CheckDomainInfo();

	// Start detouring if it is not already started.
	if ( !g_fFunctionsDetoured ) 
	{
		hr = StartDetouring();
		if ( FAILED(hr) )
		{
			strMessage.Format( "SSPI logging initialization failed. hr=0x%08x", hr );
			MessageBox( strMessage, "SSPIClient" );
			goto SSPITestExit;
		}
	}

	// Perform forward, reverse lookup of SQL Server name/IP.
	VerifySQLServerInfo( m_strConnect.GetBuffer(0) );

	// Dump all kerberos tickets prior to connection attempt.
	if ( g_fKerberosLoaded )
	{
		if ( m_fUseIntegrated ) DumpKerberosTickets();
	}
	else
	{
		o_printf( "Failed to load Kerberos APIs, skipping Kerberos test." );
		o_printf( "" );
	}

	// Check key files, gather info on these.
	CheckKeyFiles();

	// Now attempt to connect using straight ODBC API.
	rc = SQLAllocEnv( &henv );

	rc = SQLAllocConnect( henv, &hdbc );

	// Select driver.  By default just use SQL Server driver (MDAC version).
	pszDriver = "SQL Server";

	if ( m_fUseSQLNCLI )
	{
		// Check which version of SNAC is available and try to use latest.
		o_printf( "Attempting to connect using the latest driver.");
		if ( g_STATUS.fSnac9Available )
		{
			pszDriver = "SQL Native Client";
			o_printf( "Detected SNAC9." );
		}

		if ( g_STATUS.fSnac10Available )
		{
			pszDriver = "SQL Server Native Client 10.0";
			o_printf( "Detected SNAC10." );
		}

		if (g_STATUS.fSnac11Available)
		{
			pszDriver = "SQL Server Native Client 11.0";
			o_printf("Detected SNAC11.");
		}

		if (g_STATUS.fodbc11Available)
		{
			pszDriver = "ODBC Driver 11 for SQL Server";
			o_printf("Detected ODBC Driver 11.");
		}

		if (g_STATUS.fodbc13Available)
		{
			pszDriver = "ODBC Driver 13 for SQL Server";
			o_printf("Detected ODBC Driver 13.");
		}

		if (g_STATUS.fodbc17Available)
		{
			pszDriver = "ODBC Driver 17 for SQL Server";
			o_printf("Detected ODBC Driver 17.");
		}

		if (g_STATUS.fodbc18Available)
		{
			pszDriver = "ODBC Driver 18 for SQL Server";
			o_printf("Detected ODBC Driver 18.");
		}

		o_printf( "Selected latest detected Driver=%s.", pszDriver );
	}

	if ( m_fUseIntegrated )
	{
		// Create connection string using integrated security.
		sprintf_s( (char*)szConnectIn, sizeof(szConnectIn),
				 "Driver=%s;Server=%s%s;Trusted_Connection=Yes;%s",
				  pszDriver,
				  ( fUserSetProtocol ) ? "" : "tcp:",
				  strActualConnect.GetBuffer(0),
				  ( m_fEncryptionTest ) ? "Encrypt=Yes;" : "Encrypt=No" );   // explicitly turn it off since the ODBC Driver 18 and later enable encryption by default
		strTempConnect = szConnectIn;
	}
	else
	{
		// Create connection string using userid and password (standard login).
		sprintf_s( (char*)szConnectIn, sizeof(szConnectIn),
				 "Driver=%s;Server=%s%s;UID=%s;PWD=%s;%s",
				  pszDriver,
				  ( fUserSetProtocol ) ? "" : "tcp:",
				  strActualConnect.GetBuffer(0),
				  m_strUserId.GetBuffer(0),
				  m_strPassword.GetBuffer(0),
				  ( m_fEncryptionTest ) ? "Encrypt=Yes;" : "Encrypt=No" );    // explicitly turn it off since the ODBC Driver 18 and later enable encryption by default

		strTempConnect.Format( "Driver=%s;Server=%s%s;UID=%s;PWD=*****;%s",
							   pszDriver,
							   ( fUserSetProtocol ) ? "" : "tcp:",
							   strActualConnect.GetBuffer(0),
							   m_strUserId.GetBuffer(0),
							   ( m_fEncryptionTest ) ? "Encrypt=Yes;" : "Encrypt=No" );   // explicitly turn it off since the ODBC Driver 18 and later enable encryption by default

	}
	
	o_printf( "Connecting via ODBC to [%s]", strTempConnect.GetBuffer(0) );

	ssicbConnStringOut = 0;
	rc = SQLDriverConnect( hdbc, 
						   m_hWnd, 
						   szConnectIn, 
						   SQL_NTS, 
						   szConnectOut, 
						   sizeof(szConnectOut), 
						   &ssicbConnStringOut, 
						   SQL_DRIVER_NOPROMPT );

	if ( !SQL_SUCCEEDED(rc) )
	{
		o_printf( "" );
		DUMP_ODBC_ERRORS( rc, henv, hdbc );
	}
	else
	{
		g_STATUS.fODBCConnected = TRUE;
		fConnected = TRUE;

		// Send over a test SQL statement (will be used later to check for encryption).
		rc = SQLAllocStmt( hdbc, &hstmt );
		rc = SQLExecDirect( hstmt, (SQLCHAR*)"SELECT '**** SSPICLIENT SUCCESS ****'", SQL_NTS );
		rc = SQLFreeStmt( hstmt, SQL_DROP );
		hstmt = NULL;

		o_printf( "" );
		o_printf( "Successfully connected to SQL Server '%s'", m_strConnect.GetBuffer(0) );
		strMessage.Format( "Successfully connected to SQL Server '%s'", m_strConnect );
		MessageBox( strMessage, "SSPIClient" );
	}

	// Only do kerberos checks if we are using integrated login.
	if ( m_fUseIntegrated ) 
	{
		// Temporarily supress output from detours (cleans up some junk output).
		g_fSupressOutput = TRUE;

		// See if SPN was located, if not, try to build a fake one.
		if ( 0 == lstrlen(g_STATUS.g_szSavedSPN) )
		{
			o_printf( "WARNING! SQL driver did not create or use an SPN, creating one using FQDN." );
			if ( 0 == lstrlen(g_STATUS.g_szSavedFQDN) )
			{
				o_printf( "Could not resolve FQDN either, so cannot check for SPN in AD." );
			}
			else
			{
				sprintf_s( g_STATUS.g_szSavedSPN, sizeof(g_STATUS.g_szSavedSPN), "MSSQLSvc/%s:%d", g_STATUS.g_szSavedFQDN, port );
				o_printf( "Guessing that SPN is %s, this may not be correct as I may not have the correct port number.", g_STATUS.g_szSavedSPN );
			}
		}

		// Try to grab SPN and test it out.
		if ( lstrlen(g_STATUS.g_szSavedSPN) > 0 )
		{
			g_STATUS.fSPNResolved = TRUE;
			o_printf( "" );
			o_printf( "Target SQL Server SPN is [%s]", g_STATUS.g_szSavedSPN );

			// Try to verify SPN using Kerberos.
			VerifySPN( g_STATUS.g_szSavedSPN );

			// Try to verify SPN using Active Directory.
			FindSPNViaAD( g_STATUS.g_szSavedSPN );
		}


		// Dump all kerberos tickets after to connection attempt.
		if ( g_fKerberosLoaded )
		{
			o_printf( "" );
			DumpKerberosTickets();
		}

	}

SSPITestExit:

	if ( NULL != hdbc )
	{
		if ( fConnected ) SQLDisconnect( hdbc );
		SQLFreeConnect( hdbc );
		hdbc = NULL;
	}

	if ( NULL != henv )
	{
		SQLFreeEnv( henv );
		henv = NULL;
	}

	o_printf( "*** Closing SSPIClient log v.2021.08.13 PID %lu ***", GetCurrentProcessId() );
	CloseLogFile();
	g_fSupressOutput = FALSE;
	EndWaitCursor();
	MessageBox( "SSPIClient test complete.", "SSPIClient" );

}

void shell( char* pszCommand, BOOL fWait )
{
	STARTUPINFO SI;
	PROCESS_INFORMATION PI;
	
	ZeroMemory( &SI, sizeof(SI) );
	ZeroMemory( &PI, sizeof(PI) );
	CreateProcess( NULL, 
				   pszCommand, 
				   NULL, 
				   NULL, 
				   TRUE, 
				   NORMAL_PRIORITY_CLASS, 
				   NULL, 
				   NULL, 
				   &SI, 
				   &PI );
	if ( fWait ) WaitForSingleObject( PI.hProcess, INFINITE );
	CloseHandle( PI.hProcess );
}

void CSSPIClientDlg::OnLButtonDblClk(UINT nFlags, CPoint point) 
{
	CString strCommand;
	
	strCommand.Format( "notepad.exe \"%s\"", m_strLogFile.GetBuffer(0) );
	shell( strCommand.GetBuffer(0), TRUE );

	strCommand.Format( "Delete log file '%s'?", m_strLogFile.GetBuffer(0) );
	if ( IDYES == MessageBox( strCommand, "SSPIClient", MB_ICONQUESTION|MB_YESNO ) )
	{
		DeleteFile( m_strLogFile.GetBuffer(0) );
	}

	CDialog::OnLButtonDblClk(nFlags, point);
}
void CSSPIClientDlg::OnBnClickedBtnConnect2()
{
	// Flush all kerberos tickets for client.
	FlushAllKerberosTickets();
}

void CSSPIClientDlg::OnBnClickedCheck1()
{
	UpdateData(TRUE);
	GetDlgItem(IDC_EDT_USERID)->EnableWindow( !m_fUseIntegrated );
	GetDlgItem(IDC_EDT_PASSWORD)->EnableWindow( !m_fUseIntegrated );
	RECT r;
	this->GetWindowRect( &r );
	if ( m_fUseIntegrated )
	{
		r.bottom -= 35;
	}
	else
	{
		r.bottom += 35;
	}
	
	this->SetWindowPos(NULL,0,0,r.right-r.left,r.bottom-r.top, SWP_NOMOVE );
}

void CSSPIClientDlg::OnBnClickedBtnConnect3()
{
	m_fEncryptionTest = TRUE;
	OnBtnConnect();
	m_fEncryptionTest = FALSE;
}
