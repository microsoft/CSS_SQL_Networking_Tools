Instructions for setting up and running SSPIClient v.2008.05.20.1 utility
Use these instructions if you are debugging a SSL client certificate issue
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

6. Click on the "Run Client Certificate Test" button.  This will initiate the test, it may
   take 20-30 seconds for the test to complete.

Note if you need to use standard login to SQL Server, uncheck the "Use Integrated Login" check box, and enter 
the appropriate user id and password.

Once the test is complete, you should have client log file named C:\SSPIClient\SSPIClient.log 
with a lot of debug spew in it.  Send this file to your Product Support engineer.

More Information On Reading The SSPILog Output Log File
==================================================================================

The key sections to look for when debugging certificate issues:

First section is the call to CertNameToStrW, here the client driver is reading the Subject section of the 
certificate, to verify that the CN= section of the Subject contains the name of the target SQL Server.

So what happens is the client first does a forward and reverse lookup of the SQL Server name to determine the FQDN
of the SQL Server.  Then the FQDN is compared against the CN= section in the subject of the certificate to look for
a match. Resolved FQDN must be contained in CN= section, so the following examples demonstrate how this works:

 Resolved FQDN (forward and reverse lookup)    CN= Section In Subject Of Certificate         Result
--------------------------------------------- --------------------------------------------- ---------
 MySQLServer                                   mysqlserver.northamerica.corp.mycompany.com   SUCCESS
 mysqlserver.northamerica.corp.mycompany.com   mysqlserver.northamerica.corp.mycompany.com   SUCCESS
 MySQLServer                                   MySQLServer                                   SUCCESS
 mysqlserver.northamerica.corp.mycompany.com   MySQLServer                                   FAIL

So the resolved FQDN must match or be a sub-string of the CN= section.

So you must always use a certificate with the FQDN of the SQL Server in the CN= section of the subject.

In the case below the subject of the certificate is correctly set to the FQDN of the server:

2004-10-09 20:54:06.705 ENTER CertNameToStrW
2004-10-09 20:54:06.721 CertNameToStrW returned 46
2004-10-09 20:54:06.721   dwCertEncodingType = 0x00000001
2004-10-09 20:54:06.721   dwStrType          = 0x20000003
2004-10-09 20:54:06.721   CertName           = CN=mysqlserver.northamerica.corp.mycompany.com
2004-10-09 20:54:06.721 Successfully located server name [MYSQLSERVER.NORTHAMERICA.CORP.MYCOMPANY.COM] in subject [CN=MYSQLSERVER.NORTHAMERICA.CORP.MYCOMPANY.COM], VerifyServerCertificate will continue
2004-10-09 20:54:06.721 EXIT  CertNameToStrW

In the case below the subject of the certificate is not correctly set to the FQDN of the server and the connection will fail:

2004-10-11 17:17:30.312 ENTER CertNameToStrW
2004-10-11 17:17:30.312 CertNameToStrW returned 79
2004-10-11 17:17:30.312   dwCertEncodingType = 0x00000001
2004-10-11 17:17:30.312   dwStrType          = 0x20000003
2004-10-11 17:17:30.312   CertName           = CN=mysqlserver
2004-10-11 17:17:30.312 Could not locate server name [MYSQLSERVER.NORTHAMERICA.CORP.MYCOMPANY.COM] in subject [CN=MYSQLSERVER], VerifyServerCertificate will return CERT_E_CN_NO_MATCH
2004-10-11 17:17:30.312 EXIT  CertNameToStrW

Here we load the certificate chain, if this fails the cert may be corrupt.

2004-10-09 20:54:06.721 
2004-10-09 20:54:06.721 ENTER CertGetCertificateChain
2004-10-09 20:54:06.987 CertGetCertificateChain returned TRUE
2004-10-09 20:54:06.987 EXIT  CertGetCertificateChain

Next we verify that the client trusts the root of the certificate.  This is the second critical check made when
using client initiated SSL encryption.  The entire certificate chain of the certificate is walked to the root (topmost)
certificate, then we check to see if this certificate is trusted by the client.

In the case below, we DO NOT trust the root, we see pPolicyStatus->dwError = (CERT_E_UNTRUSTEDROOT):

2004-10-09 20:54:06.987 
2004-10-09 20:54:06.987 ENTER CertVerifyCertificateChainPolicy
2004-10-09 20:54:06.987   pszPolicyOID = CERT_CHAIN_POLICY_SSL
2004-10-09 20:54:06.987   pChainContext = 0x001c0c30
2004-10-09 20:54:06.987   pPolicyPara->cbSize = 12
2004-10-09 20:54:06.987   pPolicyPara->dwFlags = 0x00000000
2004-10-09 20:54:06.987   pPolicyPara->pvExtraPolicyPara->pwszServerName = MYSQLSERVER.NORTHAMERICA.CORP.MYCOMPANY.COM
2004-10-09 20:54:06.987   pPolicyPara->pvExtraPolicyPara->cbStruct = 16
2004-10-09 20:54:06.987   pPolicyPara->pvExtraPolicyPara->dwAuthType = AUTHTYPE_SERVER
2004-10-09 20:54:06.987   pPolicyPara->pvExtraPolicyPara->fdwChecks = 0x00000000
2004-10-09 20:54:06.987 CertVerifyCertificateChainPolicy returned TRUE
2004-10-09 20:54:06.987 pPolicyStatus->dwError=0x800b0109 (CERT_E_UNTRUSTEDROOT)
2004-10-09 20:54:06.987 ENTER DisplayCertChain
2004-10-09 20:54:06.987 Certificate Subject (simple): mysqlserver.northamerica.corp.mycompany.com
2004-10-09 20:54:06.987 Certificate Subject: CN=mysqlserver.northamerica.corp.mycompany.com
2004-10-09 20:54:06.987 Issuer: DC=com, DC=mycompany, DC=corp, DC=northamerica, CN=bogus_cert_server
2004-10-09 20:54:06.987 EXIT DisplayCertChain
2004-10-09 20:54:06.987 EXIT  CertVerifyCertificateChainPolicy

In this case, we do trust the root, examine pPolicyStatus->dwError=0x00000000 (S_OK)

2004-10-09 21:15:28.799 ENTER CertVerifyCertificateChainPolicy
2004-10-09 21:15:28.799   pszPolicyOID = CERT_CHAIN_POLICY_SSL
2004-10-09 21:15:28.799   pChainContext = 0x001bba40
2004-10-09 21:15:28.799   pPolicyPara->cbSize = 12
2004-10-09 21:15:28.799   pPolicyPara->dwFlags = 0x00000000
2004-10-09 21:15:28.799   pPolicyPara->pvExtraPolicyPara->pwszServerName = MYSQLSERVER.NORTHAMERICA.CORP.MYCOMPANY.COM
2004-10-09 21:15:28.799   pPolicyPara->pvExtraPolicyPara->cbStruct = 16
2004-10-09 21:15:28.799   pPolicyPara->pvExtraPolicyPara->dwAuthType = AUTHTYPE_SERVER
2004-10-09 21:15:28.799   pPolicyPara->pvExtraPolicyPara->fdwChecks = 0x00000000
2004-10-09 21:15:28.799 CertVerifyCertificateChainPolicy returned TRUE
2004-10-09 21:15:28.799 pPolicyStatus->dwError=0x00000000 (S_OK)
2004-10-09 21:15:28.799 EXIT  CertVerifyCertificateChainPolicy