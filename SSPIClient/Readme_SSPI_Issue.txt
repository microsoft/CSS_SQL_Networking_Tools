Instructions for setting up and running SSPIClient v.2008.05.20.1 utility
Use these instructions if you are debugging an SSPI issue
================================================================================

1. On the client machine, create a folder named C:\SSPIClient.  Extract SSPIClient.zip to 
   this folder on the client machine.  You should see the following files:

	SSPIClient.exe
	Readme_SSPI_Issue.txt
	Readme_Cert_Issue.txt

2. At this point, the client machine is ready for testing.

3. Go to the client machine and run SSPIClient.exe to start the client tool.

4. When this tool starts up, you will see 2 text boxes with the following text:

 	SQL Server: <Enter your SQL Server Name Here>

	Log File Name:  C:\SSPIClient\SSPIClient.log

5. Enter the name of your SQL Server.  You can use the short name or the fully qualified
   domain name (FQDN) of the SQL Server.

6. Click on the "Run SSPI Connection Test" button.  This will initiate the test, it may
   take 20-30 seconds for the test to complete.

Once the test is complete, you should have client log file named C:\SSPIClient\SSPIClient.log 
with a lot of debug spew in it.  Send this file to your Product Support engineer.


More Information On Reading The SSPILog Output Log File
==================================================================================

SSPIClient first attempts to contact the domain controller and dump out domain controller information as well as the
client's user information (the user running SSPIClient tool).

2004-06-09 17:29:32.957 *** Opening SSPIClient log v.2008.05.20 PID=1016 ***
2004-06-09 17:29:32.957 
2004-06-09 17:29:32.957 Checking user's logon name and domain information using advanced security APIs.
2004-06-09 17:29:32.957 Note that these checks may fail on NT4 and older systems.
2004-06-09 17:29:32.957 DomainControllerName        = '\\CLT-DC-02.myregion.corp.mycompany.com'
2004-06-09 17:29:32.957 DomainControllerAddress     = '\\65.53.63.16'
2004-06-09 17:29:32.957 DomainGuid                  = '{98C2E585-25E8-11D3-A5EA-00805F9F21F5}'
2004-06-09 17:29:32.957 DomainName                  = 'myregion.corp.mycompany.com'
2004-06-09 17:29:32.957 DnsForestName               = 'corp.mycompany.com'
2004-06-09 17:29:32.957 Flags                       = 0xe00001fc (DS_DNS_CONTROLLER_FLAG|DS_DNS_DOMAIN_FLAG|DS_DNS_FOREST_FLAG|DS_DS_FLAG|DS_GC_FLAG|DS_KDC_FLAG|DS_TIMESERV_FLAG|DS_WRITABLE_FLAG)
2004-06-09 17:29:32.957 DcSiteName                  = 'NA-NC-CLT'
2004-06-09 17:29:32.957 ClientSiteName              = 'NA-NC-CLT'
2004-06-09 17:29:32.957 Attempting to bind to DC.
2004-06-09 17:29:33.004 Successfully bound to DC, hDs=0x0014d0d8.
2004-06-09 17:29:33.004 GetUserName returned 'MyUser'.
2004-06-09 17:29:33.004 GetUserNameEx returned 'myregion\MyUser'.
2004-06-09 17:29:33.019 DsCrackNames successful. Dumping items.
2004-06-09 17:29:33.019 rItems[0].status  = 0x00000000
2004-06-09 17:29:33.019 rItems[0].pDomain = 'myregion.corp.mycompany.com'
2004-06-09 17:29:33.019 rItems[0].pName   = 'CN=My User,CN=Users,DC=myregion,DC=corp,DC=mycompany,DC=com'

Note here I attempt to bind to the domain controller (Attempting to bind to DC), if this fails this usually means the client 
computer cannot contact the domain controller.  Since the KDC resides on the domain controller, this will cause Kerberos 
to fail if we don't already have a ticket to the target SQL Server.

Note I also dump out the client user name information (GetUserName and GetUserNameEx).

The next section of the log file does a forward and reverse lookup of the target SQL Server name using gethostbyname
to resolve the FQDN of the SQL Server:

2004-06-09 17:29:33.019 Performing forward and reverse lookup test of server name/ip address.
2004-06-09 17:29:33.019 InputSQLServerName=[cprwebdata] API=[gethostbyname] ResolvedIPAddress=[10.1.1.1]
2004-06-09 17:29:33.019 InputSQLServerName=[cprwebdata] API=[gethostbyname] ResolvedDNSAddress=[cprwebdata.myregion.corp.mycompany.com]

This is important to insure that the client can properly resolve the FQDN of the SQL Server here, because the FQDN is used to
form the SPN for SQL Server.

Next I dump out the Kerberos ticket cache PRIOR to attempting to connect to the target SQL Server.  I dump out the tickets before and
after connecting to SQL Server to insure that we pick up a Kerberos ticket for the target SQL Server.  The key thing to look out for
here are expired tickets that do not get renewed after the connection.  You may see a ticket for your SQL Server in the
list of Kerberos tickets (look for ticket with ServerName set to your target SPN):

2004-06-09 17:29:34.554 KERB_TICKET_CACHE_INFO[3]
2004-06-09 17:29:34.554   ServerName     = MSSQLSvc/cprwebdata.myregion.corp.mycompany.com:1433
2004-06-09 17:29:34.554   RealmName      = myregion.CORP.mycompany.COM
2004-06-09 17:29:34.554   StartTime      = 2004-06-09 17:29:15
2004-06-09 17:29:34.554   EndTime        = 2004-06-10 00:58:54 STILL VALID (07:29:39 diff) <- This is how much time is left on the ticket
2004-06-09 17:29:34.554   RenewTime      = 2004-06-16 14:58:51
2004-06-09 17:29:34.554   EncryptionType = 23 (KERB_ETYPE_RC4_HMAC_NT)
2004-06-09 17:29:34.554   TicketFlags    = 0x40a00000 

After dumping the Kerberos tickets I next attempt to connect to the SQL Server using ODBC, you should see the target connection
string:

2004-06-09 17:29:33.035 Connecting via ODBC to [DRIVER=SQL Server;Trusted_Connection=Yes;Server=cprwebdata;Network=DBMSSOCN;]

After this you will see a bunch of API calls to various internal security functions logged out.  The key function to watch is 
the InitializeSecurityContextA function:

2004-06-09 17:29:33.238 ENTER InitializeSecurityContextA
2004-06-09 17:29:33.238 phCredential              = 0x00368e94
2004-06-09 17:29:33.238 phContext                 = 0x00000000
2004-06-09 17:29:33.238 pszTargetName             = 'MSSQLSvc/cprwebdata.myregion.corp.mycompany.com:1433'
2004-06-09 17:29:33.238 fContextReq               = 0x00000003 ISC_REQ_DELEGATE|ISC_REQ_MUTUAL_AUTH
2004-06-09 17:29:33.238 TargetDataRep             = 16
2004-06-09 17:29:33.238 pInput                    = 0x00000000
2004-06-09 17:29:33.270 phNewContext              = 0x00368ea4
2004-06-09 17:29:33.270 pOutput                   = 0x0012d54c
2004-06-09 17:29:33.270 pOutput->ulVersion        = 0
2004-06-09 17:29:33.270 pOutput->cBuffers         = 1
2004-06-09 17:29:33.270 pBuffers[00].cbBuffer   = 2722
2004-06-09 17:29:33.270 pBuffers[00].BufferType = 2 SECBUFFER_TOKEN
2004-06-09 17:29:33.270 pBuffers[00].pvBuffer   = 0x00dfc608
2004-06-09 17:29:33.270 00dfc608  60 82 0a 9e 06 06 2b 06 01 05 05 02 a0 82 0a 92   `.....+.........
2004-06-09 17:29:33.270 00dfc618  30 82 0a 8e a0 24 30 22 06 09 2a 86 48 82 f7 12   0....$0"..*.H...
2004-06-09 17:29:33.270 00dfc628  01 02 02 06 09 2a 86 48 86 f7 12 01 02 02 06 0a   .....*.H........
2004-06-09 17:29:33.270 00dfc638  2b 06 01 04 01 82 37 02 02 0a a2 82 0a 64 04 82   +.....7......d..
2004-06-09 17:29:33.270 00dfc648  0a 60 60 82 0a 5c 06 09 2a 86 48 86 f7 12 01 02   .``..\..*.H.....
2004-06-09 17:29:33.270 00dfc658  02 01 00 6e 82 0a 4b 30 82 0a 47 a0 03 02 01 05   ...n..K0..G.....
2004-06-09 17:29:33.270 00dfc668  a1 03 02 01 0e a2 07 03 05 00 20 00 00 00 a3 82   .......... .....
2004-06-09 17:29:33.270 00dfc678  09 5f 61 82 09 5b 30 82 09 57 a0 03 02 01 05 a1   ._a..[0..W......


Key things to check here:

pszTargetName should be the correct target SPN for your SQL Server.  Note you may see multiple calls to InitializeSecurityContextA
with a NULL pszTargetName, these are calls to encrypt the login packet.  Look for the first call to InitializeSecurityContextA with
a non-null pszTargetName, this will be the first call to start SSPI interaction with the server.

In the first call to InitializeSecurityContextA with a non-null pszTargetName you will see an output buffer and also a hex dump of
this buffer.  If the output buffer starts with NTLMSSP, then this is an NTLM token and you are not using Kerberos to SQL Server.
If you see NTLMSSP, then what this means is the client could not find the target SPN in Active Directory.

Here is an example of what you will see if you get an NTLM token (above example is a Kerberos token):

2004-06-09 17:35:39.150 ENTER InitializeSecurityContextA
2004-06-09 17:35:39.150 phCredential              = 0x00368e94
2004-06-09 17:35:39.150 phContext                 = 0x00368ea4
2004-06-09 17:35:39.150 pszTargetName             = 'MSSQLSvc/cprwebdata.myregion.corp.mycompany.com:1433'
2004-06-09 17:35:39.150 fContextReq               = 0x00000003 ISC_REQ_DELEGATE|ISC_REQ_MUTUAL_AUTH
2004-06-09 17:35:39.150 TargetDataRep             = 16
2004-06-09 17:35:39.150 pInput                    = 0x0012d760
2004-06-09 17:35:39.150 pInput->ulVersion         = 0
2004-06-09 17:35:39.150 pInput->cBuffers          = 1
2004-06-09 17:35:39.150 pBuffers[00].cbBuffer   = 330
2004-06-09 17:35:39.150 pBuffers[00].BufferType = 2 SECBUFFER_TOKEN
2004-06-09 17:35:39.150 pBuffers[00].pvBuffer   = 0x00dfc608
2004-06-09 17:35:39.150 00dfc608  4e 54 4c 4d 53 53 50 00 02 00 00 00 18 00 18 00   NTLMSSP......... <- Note NTLMSSP here...
2004-06-09 17:35:39.150 00dfc618  38 00 00 00 05 82 89 a2 7d 32 56 6c 87 66 e2 43   8.......}2Vl.f.C
2004-06-09 17:35:39.150 00dfc628  00 00 00 00 00 00 00 00 fa 00 fa 00 50 00 00 00   ............P...

...

Note also the output buffer size is very small as well when using NTLM, with Kerberos it is usually > 1000 bytes.

Look at the final return code from InitializeSecurityContextA, this will give you an indication of why SSPI failed:

The most common error is:

EXIT  InitializeSecurityContextA returned 0x80090322 SEC_E_WRONG_PRINCIPAL (The target principal name is incorrect)

What this means is that there is at least one invalid SPN set for the SQL Server, the SPN is set to the wrong account for example. 

I also make some specific checks for the target SPN, here is an example where the check for the SPN fails (SPN not in AD):

2004-06-09 17:35:39.980 Target SQL Server SPN is [MSSQLSvc/cprwebdata.myregion.corp.mycompany.com:1433]
2004-06-09 17:35:39.980 
2004-06-09 17:35:39.980 Attempting to manually verify Kerberos ticket for SPN
2004-06-09 17:35:39.980 Attempting to get TGT
2004-06-09 17:35:39.980 Successfully retrieved TGT, displaying TGT
2004-06-09 17:35:39.980 KERB_EXTERNAL_TICKET
2004-06-09 17:35:39.980   ServiceName         = krbtgt|myregion.CORP.mycompany.COM
2004-06-09 17:35:39.980   TargetName          = krbtgt|myregion.CORP.mycompany.COM
2004-06-09 17:35:39.980   ClientName          = MyUser
2004-06-09 17:35:39.980   DomainName          = myregion.CORP.mycompany.COM
2004-06-09 17:35:39.980   TargetDomainName    = myregion.CORP.mycompany.COM
2004-06-09 17:35:39.980   AltTargetDomainName = myregion.CORP.mycompany.COM
2004-06-09 17:35:39.980   SessionKey.KeyType  = 0 (KERB_ETYPE_NULL)
2004-06-09 17:35:39.980   SessionKey.Length   = 0
2004-06-09 17:35:39.980   SessionKey.Value    = 
2004-06-09 17:35:39.980   TicketFlags         = 0x40e00000 (KERB_TICKET_FLAGS_renewable|KERB_TICKET_FLAGS_initial|KERB_TICKET_FLAGS_forwardable|KERB_TICKET_FLAGS_pre_authent)
2004-06-09 17:35:39.980   Flags               = 0x00000000
2004-06-09 17:35:39.980   KeyExpirationTime   = 064
2004-06-09 17:35:39.980   StartTime           = 2004-06-09 17:34:55
2004-06-09 17:35:39.980   EndTime             = 2004-06-10 03:34:55 STILL VALID (10:00:00 diff)
2004-06-09 17:35:39.980   RenewUntil          = 2004-06-16 17:34:55
2004-06-09 17:35:39.980   TimeSkew            = 064
2004-06-09 17:35:39.980   EncodedTicketSize   = 2301
2004-06-09 17:35:39.980   EncodedTicket       = 0x00f501fa
2004-06-09 17:35:39.980 
2004-06-09 17:35:39.980 Attempting to get ticket to SPN with KERB_RETRIEVE_TICKET_DONT_USE_CACHE (meaning don't use ticket from cache)
2004-06-09 17:35:39.980 LsaCallAuthenticationPackage failed attempting to get ticket for M, Status=0x00000000, SubStatus=0xc000018b
2004-06-09 17:35:39.980 NOTE! SubStatus=0xc000018b typically means that the SPN does not exist, this error is normal if the SPN truely does not exist.
2004-06-09 17:35:39.995   SubStatus=0xc000018b -> The security database on the server does not have a computer account for this workstation trust relationship.
2004-06-09 17:35:39.995 

Note check this enumeration to see if you have duplicate SPNs:

2004-06-09 17:35:39.995 Attempting to load up Active Directory dll and check AD for SPN
2004-06-09 17:35:40.058 SPN MSSQLSvc/cprwebdata.myregion.corp.mycompany.com:1433 not found anywhere in Active Directory

Here is an example of where the SPN is found in AD:

2004-06-09 17:55:10.037 Target SQL Server SPN is [MSSQLSvc/cprwebdata.myregion.corp.mycompany.com:1433]
2004-06-09 17:55:10.037 
2004-06-09 17:55:10.037 Attempting to manually verify Kerberos ticket for SPN
2004-06-09 17:55:10.037 Attempting to get TGT
2004-06-09 17:55:10.037 Successfully retrieved TGT, displaying TGT
2004-06-09 17:55:10.037 KERB_EXTERNAL_TICKET
2004-06-09 17:55:10.037   ServiceName         = krbtgt|myregion.CORP.mycompany.COM
2004-06-09 17:55:10.037   TargetName          = krbtgt|myregion.CORP.mycompany.COM
2004-06-09 17:55:10.037   ClientName          = MyUser
2004-06-09 17:55:10.037   DomainName          = myregion.CORP.mycompany.COM
2004-06-09 17:55:10.037   TargetDomainName    = myregion.CORP.mycompany.COM
2004-06-09 17:55:10.037   AltTargetDomainName = myregion.CORP.mycompany.COM
2004-06-09 17:55:10.037   SessionKey.KeyType  = 0 (KERB_ETYPE_NULL)
2004-06-09 17:55:10.037   SessionKey.Length   = 0
2004-06-09 17:55:10.037   SessionKey.Value    = 
2004-06-09 17:55:10.037   TicketFlags         = 0x40e00000 (KERB_TICKET_FLAGS_renewable|KERB_TICKET_FLAGS_initial|KERB_TICKET_FLAGS_forwardable|KERB_TICKET_FLAGS_pre_authent)
2004-06-09 17:55:10.037   Flags               = 0x00000000
2004-06-09 17:55:10.037   KeyExpirationTime   = 064
2004-06-09 17:55:10.037   StartTime           = 2004-06-09 17:54:40
2004-06-09 17:55:10.037   EndTime             = 2004-06-10 03:54:40 STILL VALID (10:00:00 diff)
2004-06-09 17:55:10.037   RenewUntil          = 2004-06-16 17:54:39
2004-06-09 17:55:10.037   TimeSkew            = 064
2004-06-09 17:55:10.037   EncodedTicketSize   = 2301
2004-06-09 17:55:10.037   EncodedTicket       = 0x010501fa
2004-06-09 17:55:10.037 
2004-06-09 17:55:10.037 Attempting to get ticket to SPN with KERB_RETRIEVE_TICKET_DONT_USE_CACHE (meaning don't use ticket from cache)
2004-06-09 17:55:10.068 Successfully retrieved ticket for SPN, displaying SPN ticket
2004-06-09 17:55:10.068 KERB_EXTERNAL_TICKET
2004-06-09 17:55:10.068   ServiceName         = MSSQLSvc|cprwebdata.myregion.corp.mycompany.com:1433
2004-06-09 17:55:10.068   TargetName          = MSSQLSvc|cprwebdata.myregion.corp.mycompany.com:1433
2004-06-09 17:55:10.068   ClientName          = MyUser
2004-06-09 17:55:10.068   DomainName          = myregion.CORP.mycompany.COM
2004-06-09 17:55:10.068   TargetDomainName    = myregion.CORP.mycompany.COM
2004-06-09 17:55:10.068   AltTargetDomainName = myregion.CORP.mycompany.COM
2004-06-09 17:55:10.068   SessionKey.KeyType  = 23 (KERB_ETYPE_RC4_HMAC_NT)
2004-06-09 17:55:10.068   SessionKey.Length   = 16
2004-06-09 17:55:10.068   SessionKey.Value    = 
2004-06-09 17:55:10.068 01060242  70 5f 06 7c e5 46 c0 42 69 35 29 ab f9 39 8d 8b   p_.|.F.Bi5)..9..
2004-06-09 17:55:10.068   TicketFlags         = 0x40a00000 (KERB_TICKET_FLAGS_renewable|KERB_TICKET_FLAGS_forwardable|KERB_TICKET_FLAGS_pre_authent)
2004-06-09 17:55:10.068   Flags               = 0x00000000
2004-06-09 17:55:10.068   KeyExpirationTime   = 064
2004-06-09 17:55:10.068   StartTime           = 2004-06-09 17:54:53
2004-06-09 17:55:10.068   EndTime             = 2004-06-10 03:54:40 STILL VALID (09:59:47 diff)
2004-06-09 17:55:10.068   RenewUntil          = 2004-06-16 17:54:39
2004-06-09 17:55:10.068   TimeSkew            = 064
2004-06-09 17:55:10.068   EncodedTicketSize   = 2399
2004-06-09 17:55:10.068   EncodedTicket       = 0x01060252

Note check this enumeration to see if you have duplicate SPNs:

2004-06-09 17:55:10.068 Attempting to load up Active Directory dll and check AD for SPN
2004-06-09 17:55:10.131 
2004-06-09 17:55:10.131 Searching AD for SPN complete.
2004-06-09 17:55:10.131 SPN MSSQLSvc/cprwebdata.myregion.corp.mycompany.com:1433 found on following object(s) in AD:
2004-06-09 17:55:10.240   01.    distinguishedName = CN=CPRWEBDATA,CN=Computers,DC=myregion,DC=corp,DC=mycompany,DC=com
2004-06-09 17:55:10.240                dNSHostName = cprwebdata.myregion.corp.mycompany.com
