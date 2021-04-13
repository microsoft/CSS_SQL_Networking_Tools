// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Data;
using System.IO;
using System.Net;
using System.Collections.Specialized;
using System.DirectoryServices.ActiveDirectory;
using System.Management;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.Collections;
using System.DirectoryServices;
using System.Diagnostics;

namespace SQLCheck
{
    static class Collectors
    {
        public static void Collect(DataSet ds)
        {
            //
            // Calls top-level collectors
            // These call child collectors, and child collectors call their children, in turn
            //

            CollectComputer(ds);  // computer needs to be called first; even Domain has dependencies on it
            CollectDomain(ds);
            CollectSecurity(ds);
            CollectTLS(ds);
            CollectProtocolOrder(ds);
            CollectNetwork(ds);
            CollectNetworkAdapter(ds);
            CollectODBC(ds);
            CollectDiskDrive(ds);
            CollectHostAlias(ds);
            CollectIPAddress(ds);
            CollectDatabaseDriver(ds);
            CollectSQLAlias(ds);
            CollectClientSNI(ds);
            CollectService(ds);
            CollectSPNAccount(ds);
            CollectSQLInstance(ds);   // dropped SQL 2000 and RS 2000
            CollectSQLServer(ds);
            // Collect SSRS
            // Collect OLAP
            // Collect TLS enabled - 3 values for enabled/disabled/unsupported: (1) Default, (2) Local setting, (3) Policy setting
            // Collect Cipher Suites - defaults per TLS version enabled, current settings, policy?

            // Other items:
            // 1. SQL Keep-alive time and interval
            // 2. ODBC Driver 17.4 keep-alive time and interval on ODBC Driver and DSN entries: https://docs.microsoft.com/en-us/sql/connect/odbc/windows/features-of-the-microsoft-odbc-driver-for-sql-server-on-windows?view=sql-server-ver15
            ds.AcceptChanges();

        }

        public static void CollectComputer(DataSet ds)
        {
            DataTable dt = ds.Tables["Computer"];
            DataRow Computer = dt.NewRow();
            dt.Rows.Add(Computer);

            //
            // Computer NETBIOS name, fully qualified domain name (FQDN), and DNS suffix
            //

            string NETBIOSName = Environment.MachineName;
            Computer["NETBIOSName"] = NETBIOSName;

            IPHostEntry Hostentry = Dns.GetHostEntry(NETBIOSName);
            string FQDN = Hostentry.HostName;
            Computer["FQDN"] = FQDN;

            string DNSSuffix = SmartString.GetRemainder(FQDN, ".");  // outputs everything after the period
            Computer["DNSSuffix"] = DNSSuffix;

            //
            // Computer Role, Joined to Domain, Domain or WorkGroup Name
            //

            StringDictionary d = Utility.ManagementHelper("Win32_ComputerSystem", "Domain", "DomainRole");
            bool JoinedToDomain = false;
            if (d != null)
            {
                JoinedToDomain = d["DomainRole"] != "0" && d["DomainRole"] != "2";  // 0 = standalone workstation; 2 = standalone server
                Computer["JoinedToDomain"] = JoinedToDomain;
                if (JoinedToDomain == false) Computer.LogWarning("This computer belongs to a workgroup and not a domain. This can cause authentication and delegation issues.");

                string ComputerRole = Utility.Translate(d["DomainRole"], "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controler", "Primary Domain Controler");
                Computer["ComputerRole"] = ComputerRole;

                string DomainOrWorkgroupName = d["Domain"];
                Computer["DomainOrWorkgroupName"] = DomainOrWorkgroupName;
                if (DomainOrWorkgroupName.Contains("Domain")) Computer.LogWarning("Server apps may have issues running on domain contollers.");
            }

            //
            // Current DC the computer is connected to
            //

            if (JoinedToDomain)
            {
                d = Utility.DirectoryHelper(@"LDAP://rootDSE", "defaultNamingContext", "dnsHostName");
                if (d != null)
                {
                    Computer["ConnectedToDomain"] = true;
                    Computer["ExpandedName"] = d["defaultNamingContext"];
                    Computer["CurrentDC"] = d["dnsHostName"];
                }
            }
            else
            {
                Computer["ConnectedToDomain"] = false;
            }

            //
            // OS Bitness, Windows and .NET Framework versions
            //

            Computer["CPU64Bit"] = Environment.Is64BitOperatingSystem;
            Computer["ProgramFilesFolder"] = Environment.GetEnvironmentVariable("ProgramFiles");
            if (Computer.GetString("ProgramFilesFolder").StartsWith(@"C:\") == false) Computer.LogWarning($"The Program Files folder is not on the C: drive. Currently: {Computer.GetString("ProgramFilesFolder")}");
            Computer["CommonFilesFolder"] = Environment.GetEnvironmentVariable("CommonProgramFiles");
            if (Computer.GetString("CommonFilesFolder").StartsWith(@"C:\") == false) Computer.LogCritical($"The Common Files folder must be on the C: drive or installation issues may occur. Currently: {Computer.GetString("CommonFilesFolder")}");
            if (Environment.Is64BitOperatingSystem)
            {
                Computer["ProgramFilesx86Folder"] = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
                if (Computer.GetString("ProgramFilesx86Folder").StartsWith(@"C:\") == false) Computer.LogWarning($"The Program Files (x86) folder is not on the C: drive. Currently: {Computer.GetString("ProgramFilesx86Folder")}");
                Computer["CommonFilesx86Folder"] = Environment.GetEnvironmentVariable("CommonProgramFiles(x86)");
                if (Computer.GetString("CommonFilesx86Folder").StartsWith(@"C:\") == false) Computer.LogCritical($"The Common Files (x86) folder must be on the C: drive or installation issues may occur. Currently: {Computer.GetString("CommonFilesx86Folder")}");
            }
            int majorVersion = 0, minorVersion = 0, ubr = 0;
            string releaseID = "";
            Computer["WindowsVersion"] = Environment.OSVersion.VersionString;  // not really valid past Windows 2012
            majorVersion = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentMajorVersionNumber", 0).ToInt();
            Computer["MajorVersion"] = majorVersion.ToString();
            minorVersion = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentMinorVersionNumber", 0).ToInt();
            Computer["MinorVersion"] = minorVersion.ToString();
            Computer["WindowsName"] = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "").ToString();
            Computer["WindowsBuild"] = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild", "").ToString();
            releaseID = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseID", "").ToString();
            Computer["WindowsReleaseID"] = releaseID;
            ubr = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", 0).ToInt();  // UBR = Update Build Revision
            Computer["WindowsUBR"] = ubr.ToString();

            if (majorVersion != 0) Computer["WindowsVersion"] = $"{majorVersion}.{minorVersion}.{Computer["WindowsBuild"].ToString()}.{ubr}";
            if (releaseID != "") Computer["WindowsName"] = Computer["WindowsName"].ToString() + $" ({releaseID})";

            //
            // CLR 4 version - ADO.NET support for TLS 1.2 is available only in the .NET Framework 4.6
            //

            string CLR4Version = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client\1033", "Version", "").ToString();
            if (CLR4Version == "") CLR4Version = "Not Installed";
            Computer["CLR4Version"] = CLR4Version;
            if (CLR4Version.StartsWith("4.0.") || CLR4Version.StartsWith("4.5."))  // No versions 4.1, 4.2, 4.3, or 4.4
            {
                Computer.LogWarning(".NET 2.x/3.x Framework is present but has not been updated to support TLS 1.2.");
            }


            //
            // CLR 2 version - try 3.5, then 3.0, then 2.0 - ADO.NET support for TLS 1.2 is available only in the .NET Framework 2.0 SP2, 3.0 SP2, 3.5 SP1
            //

            string CLR2Version = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5\1033", "Version", "").ToString();
            string ServicePack = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5\1033", "SP", "").ToString();
            if (CLR2Version == "")
            {
                CLR2Version = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0\Setup\1033", "Version", "").ToString();
                ServicePack = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0\Setup\1033", "SP", "").ToString();
                if (CLR2Version == "")
                {
                    CLR2Version = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727\1033", "Version", "").ToString();
                    ServicePack = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727\1033", "SP", "").ToString();
                    if (CLR2Version == "")
                    {
                        CLR2Version = "Not installed";
                        ServicePack = "";
                    }
                }
            }
            if (ServicePack != "") CLR2Version += $" (SP{ServicePack})";
            Computer["Clr2Version"] = CLR2Version;
            if ((CLR2Version.StartsWith("3.5.") && ServicePack != "1") ||   // check if the latest service pack has been installed
                (CLR2Version.StartsWith("3.0.") && ServicePack != "2") ||
                (CLR2Version.StartsWith("2.0.") && ServicePack != "2"))
            {
                Computer.LogWarning(".NET 2.x/3.x Framework is present but has not been updated to support TLS 1.2.");
            }

            //
            // Cluster settings and Remap Pipe Names
            //

            string c = Utility.CheckRegistryKeyExists(@"HKLM\CLUSTER");
            switch (c)
            {
                case "0":
                    Computer["Clustered"] = false;
                    break;
                case "1":
                    Computer["Clustered"] = true;

                    //
                    // Check RemapPipeNames
                    //

                    RegistryKey hive = null;
                    RegistryKey resources = null;
                    RegistryKey parameters = null;
                    try
                    {
                        hive = Registry.LocalMachine;
                        resources = hive.OpenSubKey(@"CLUSTER\Resources", RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ExecuteKey);
                        string[] keyNames = resources.GetSubKeyNames();
                        foreach (string keyName in keyNames)
                        {
                            try
                            {
                                parameters = resources.OpenSubKey(keyName + @"\Parameters", RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ExecuteKey);
                                string instanceName = (string)parameters.GetValue("Name", "");
                                int remapPipeNames = (int)parameters.GetValue("RemapPipeNames", -1);
                                if (remapPipeNames == 0)  // ignore: 1 = good, -1 = missing. There are other clustered resources besides SQL.
                                {
                                    Computer.LogWarning($@"{instanceName}!RemapPipeNames is 0 instead of 1. This may result in cluster connectivity issues on this node.");
                                }
                            }
                            catch (Exception ex)
                            {
                                Computer.LogException($@"Error accessing cluster registry key {keyName}\Parameters.", ex);
                            }
                            finally
                            {
                                if (parameters != null) parameters.Close();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Computer.LogException(@"Error accessing CLUSTER\Resources registry key.", ex);
                    }
                    finally
                    {
                        if (resources != null) resources.Close();
                        if (hive != null) hive.Close();
                    }

                    break;
            }

            //
            // Diffie-Hellman Version
            //
            // Windows versions that contain the leading zero fixes for TLS_DHE:
            // Windows Server 2016, version 1607
            // KB 4537806: February 25, 2020-KB4537806(OS Build 14393.3542)
            // KB 4540670: March 10, 2020-KB4540670(OS Build 14393.3564)
            // Updates that supersede KB4537806 and KB4540670 for the respective OS versions
            // Windows Server 2019 RTM and later versions.
            // Windows 10, version 1511, and later versions of Windows 10 (see release history)
            //
            // Windows versions that don't contain the leading zero fixes for TLS_DHE:
            // Windows Server 2016, version 1607 servers that don't have the patches KB 4537806 and KB 4540670 applied.
            // Windows 10, version 1507
            // Windows 8.1
            // Windows 7
            // Windows Server 2012 R2 and earlier versions of Windows Server
            //

            string dheVersion = "2";

            if (majorVersion < 10)  // versions before Windows 10 have the old version
            {
                dheVersion = "1";
            }
            else if (majorVersion == 10) // some have the old algorithm and some have the new algorithm
            {
                if (Computer.GetString("WindowsName").ToUpper().Contains("SERVER"))  // client and server got the upgrade in different builds
                {
                    // SQL 2016 or later
                    if (Utility.CompareVersion(Computer.GetString("WindowsVersion"), "10.0.14393.3542") == "<") dheVersion = "1";
                }
                else
                {
                    // Windows 10 client builds 1511 and later have version 2 of the algorithm
                    if (releaseID.ToInt() < 1511) dheVersion = "1";
                }
            }
            Computer["DiffieHellmanVersion"] = dheVersion;
        }

        public static void CollectDomain(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            if (Computer.GetBoolean("JoinedToDomain") == false) return;

            DataRow DomainRow = ds.Tables["Domain"].NewRow();
            Domain domain = Domain.GetComputerDomain();
            Domain parent = domain.Parent;
            Forest forest = domain.Forest;
            DomainRow["DomainName"] = domain.Name;
            DomainRow["DomainMode"] = domain.DomainMode.ToString();
            if (parent != null) DomainRow["ParentDomain"] = parent.Name;
            if (forest != null)
            {
                DomainRow["ForestName"] = forest.Name;
                DomainRow["ForestMode"] = forest.ForestMode.ToString();
                Domain rootDomain = forest.RootDomain;
                if (rootDomain != null) DomainRow["RootDomain"] = forest.RootDomain.Name;
            }
            ds.Tables["Domain"].Rows.Add(DomainRow);

            //
            // Get related domains
            //

            try
            {
                DataTable dtRelatedDomain = ds.Tables["RelatedDomain"];
                TrustRelationshipInformationCollection relatedDomains = domain.GetAllTrustRelationships();
                foreach (TrustRelationshipInformation rd in relatedDomains)
                {
                    DataRow RelatedDomain = dtRelatedDomain.NewRow();
                    dtRelatedDomain.Rows.Add(RelatedDomain);
                    try
                    {
                        RelatedDomain["SourceDomain"] = rd.SourceName;
                        RelatedDomain["TargetDomain"] = rd.TargetName;
                        RelatedDomain["TrustType"] = rd.TrustType.ToString();
                        RelatedDomain["TrustDirection"] = rd.TrustDirection.ToString();
                        RelatedDomain["SelectiveAuthentication"] = domain.GetSelectiveAuthenticationStatus(rd.TargetName);
                    }
                    catch (Exception ex2)
                    {
                        RelatedDomain.LogException("Error reading related domain properties.", ex2);
                    }
                }
            }
            catch (Exception ex)
            {
                DomainRow.LogException("Error enumerating related domains.", ex);
            }
        }

        public static void CollectSecurity(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataRow Security = ds.Tables["Security"].NewRow();
            ds.Tables["Security"].Rows.Add(Security);

            //
            // CrashOnAuditFail - prevents non-Admins from loggin in
            //

            string crashOnAuditFail = Utility.GetRegistryValueAsString(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "CrashOnAuditFail", RegistryValueKind.DWord, 0);
            Security["CrashOnAuditFail"] = crashOnAuditFail;
            Security.CheckRange("CrashOnAuditFail", crashOnAuditFail, 0, 2);
            if (crashOnAuditFail == "1") Security.LogWarning("CrashOnAuditFail: Non-Administrators may get locked out if the security log fills up.");
            if (crashOnAuditFail == "2") Security.LogCritical("CrashOnAuditFail: Non-Administrators cannot log in. See http://support.microsoft.com/default.aspx/kb/832981.");

            //
            // DisableLoopbackCheck and BackConnectHostNames
            //

            string disableLoopbackCheck = Utility.GetRegistryValueAsString(@"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "DisableLoopbackCheck", RegistryValueKind.DWord, 0);
            Security["DisableLoopBackCheck"] = disableLoopbackCheck;
            Security.CheckRange("DisableLoopBackCheck", disableLoopbackCheck, 0, 1);

            string backConnectionHostNames = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "BackConnectionHostNames", RegistryValueKind.MultiString, "");
            Security["BackConnectionHostNames"] = backConnectionHostNames;
            
            if (disableLoopbackCheck == "1")
            {
                Security.LogInfo("NTLM callbacks should succeed.");
            }
            else if (backConnectionHostNames == "")
            {
                Security.LogWarning("NTLM callbacks should fail. Neither DisableLoopbackCheck nor BackConnectionHostNames is set.");
            }
            else
            {
                Security.LogWarning("NTLM callbacks will only succeed for those names in the BackConnectionHostNames setting.");
            }

            //
            // Kerberos MaxTokenSize
            //
            // Default size 12000 on Win 2008 R2 and earlier, 48000 on Win 8/Win 2012 (build 6.2.xxxx.xxx) and later
            //

            int defaultTokenSize = 12000;  // Windows 6.1.xxx.xxx = Windows 7.1 / 2008 R2 and lower
            if ((Environment.OSVersion.Platform == PlatformID.Win32NT) && (((Environment.OSVersion.Version.Major != 6) || (Environment.OSVersion.Version.Minor < 2)) ? (Environment.OSVersion.Version.Major > 6) : true))
            {
                defaultTokenSize = 48000;  // Windows 6.2 and higher = Window s8 and Windos 2012 and above
            }
            string maxTokenSize = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters", "MaxTokenSize", RegistryValueKind.DWord, defaultTokenSize);
            Security["MaxTokenSize"] = maxTokenSize;
            int maxSize = maxTokenSize.ToInt();
            Security.CheckRange("MaxTokenSize", maxSize, 0, 65535);
            if (maxSize < 12000) Security.LogWarning("MaxTokenSize is low and you may experience Kerberos issues for users that belong to many groups.");
            if (maxSize > 48000) Security.LogWarning("MaxTokenSize is high and you may experience size issues with web request base64 encoding.");

            //
            // Kerberos Log Level
            //

            string logLevel = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters", "LogLevel", RegistryValueKind.DWord, 0);
            Security["KerberosLogLevel"] = logLevel;
            Security.CheckRange("Kerberos LogLevel", logLevel, 0, 1);
            if (logLevel == "1") Security.LogWarning("Kerberos logging is enabled and may cause performance issues.");

            //
            // Kerbeos enabled encryption methods
            //

            string kerbEncrypt = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters", "SupportedEncryptionTypes", RegistryValueKind.DWord, 0);
            int encrypt = kerbEncrypt.ToInt();
            if (encrypt == 0) encrypt = 4; // RC4
            string encryptNames = Utility.KerbEncryptNames(encrypt);
            Security["KerberosLocalEncryption"] = $"{kerbEncrypt} ({encryptNames})";
            if (encrypt != 0 && encrypt != 4) Security.LogWarning("RC4 encryption for Kerberos has been disabled.");

            //
            // Warn if change in cryptography providers (default is rsaenh.dll) in:
            //
            // HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft RSA SChannel Cryptographic Provider
            // HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft Base Cryptographic Provider v1.0
            // HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft Enhanced Cryptographic Provider v1.0
            //
            // Also warn if HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Offload key exists
            //

            string temp = "";
            temp = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft RSA SChannel Cryptographic Provider", "Image Path", RegistryValueKind.String, "");
            if (temp != "" && temp != "rsaenh.dll" && temp.EndsWith(@"\rsaenh.dll") == false)
            {
                Security.LogWarning($"Microsoft RSA SChannel Cryptographic Provider is {temp} instead of rsaenh.dll.");
            }
            temp = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft Base Cryptographic Provider v1.0", "Image Path", RegistryValueKind.String, "");
            if (temp != "" && temp != "rsaenh.dll" && temp.EndsWith(@"\rsaenh.dll") == false)
            {
                Security.LogWarning($"Microsoft Base Cryptographic Provider v1.0 is {temp} instead of rsaenh.dll.");
            }
            temp = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\Microsoft Enhanced Cryptographic Provider v1.0", "Image Path", RegistryValueKind.String, "");
            if (temp != "" && temp != "rsaenh.dll" && temp.EndsWith(@"\rsaenh.dll") == false)
            {
                Security.LogWarning($"Microsoft Enhanced Cryptographic Provider v1.0 is {temp} instead of rsaenh.dll.");
            }
            temp = Utility.CheckRegistryKeyExists(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Offload");
            if (temp == "1")
            {
                Security.LogWarning(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography has the Offload subkey. Security functions may be offloaded to a 3rd-party provider.");
            }
        }

        public static void CollectTLS(DataSet ds)
        {
            string[] TLSVersions = new string[] { "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2" };
            string[] ClientServer = new string[] { "Client", "Server" };
            string[] ValueNames = new string[] { "DisabledByDefault", "Enabled" };  // DWORD
            object temp = null;

            foreach (string cs in ClientServer)
            {
                foreach (string tlsVersion in TLSVersions)
                {
                    foreach (string valueName in ValueNames)
                    {
                        DataRow TLS = ds.Tables["TLS"].NewRow();
                        ds.Tables["TLS"].Rows.Add(TLS);
                        TLS["ClientOrServer"] = cs;
                        TLS["TLSVersion"] = tlsVersion;
                        TLS["ValueName"] = valueName;
                        TLS["Defaultvalue"] = "TODO";              // TODO
                        temp = Registry.GetValue($@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{tlsVersion}\{cs}", valueName, "");
                        TLS["RegistryValue"] = temp == null ? "" : ((temp.ToInt() != 0) ? $"True " : "False") + $" (0x{temp.ToInt().ToString("X8")})" + CheckTLS(tlsVersion, valueName, temp.ToInt());
                        TLS["PolicyValue"] = "TODO";               // TODO
                    }
                }
            }
        }

        public static string CheckTLS(string TLSVersion, string ValueName, int Value)
        {
            switch (TLSVersion)  // returns a leading space for xx and check mark
            {                                                     // Enabled                 // DisabledByDefault
                case "SSL 2.0": return (ValueName == "Enabled") ? (Value == 0 ? " ok" : " x") : (Value != 0 ? " ok" : " x");   // should be disabled
                case "SSL 3.0": return (ValueName == "Enabled") ? (Value == 0 ? " ok" : " x") : (Value != 0 ? " ok" : " x");   // should be disabled
                case "TLS 1.0": return (ValueName == "Enabled") ? (Value == 0 ? " ok" : "")   : (Value != 0 ? " ok" : "");     // ought to be disabled
                case "TLS 1.1": return (ValueName == "Enabled") ? (Value == 0 ? " ok" : "")   : (Value != 0 ? " ok" : "");     // ought to be disabled
                case "TLS 1.2": return (ValueName == "Enabled") ? (Value == 0 ? " x" : " ok") : (Value != 0 ? " x"  : " ok");  // ought to be enabled
            }
            return " ?";
        }

        public static void CollectProtocolOrder(DataSet ds)
        {
            DataTable dtProtocolOrder = ds.Tables["ProtocolOrder"];
            DataRow ProtocolOrder = null;

            ProtocolOrder = dtProtocolOrder.NewRow();
            dtProtocolOrder.Rows.Add(ProtocolOrder);

            // From HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 | Functions REG_MULTI_SZ

            object prot = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002", "Functions", "");
            if (prot != null)
            {
                string[] po = (string[])prot;
                ProtocolOrder["RegistryList"] = string.Join(",", po);
            }

            // From HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002 ! Functions REG_SZ, comma-delimited

            ProtocolOrder["PolicyList"] = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002", "Functions", null);
        }

        public static void CollectNetwork(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataRow Network = ds.Tables["Network"].NewRow();
            string netshOut = "";

            //
            // TcpMaxDataRetransmissions
            //
            // Valid Range: 0 - 0xFFFFFFFF
            // Default: 5
            //

            string maxRetransmissions = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpMaxDataRetransmissions", RegistryValueKind.DWord, "");
            int maxRetrans = maxRetransmissions.ToInt();  // defaults to 0 if emptystring or any other issues in the conversion
            if (maxRetransmissions != "")  // no warnings if blank or missing
            {
                if (maxRetrans == 0)
                {
                    Network.LogCritical("0 retransmissions could result in frequent network stability issues.");
                }
                else if (maxRetrans < 4)
                {
                    Network.LogWarning("TcpMaxDataRetransmissions values less than 5 could result in network stability issues.");
                }
                else if (maxRetrans > 8)
                {
                    Network.LogWarning("TcpMaxDataRetransmissions has been increased significantly above the default of 5.");
                }
            }

            //
            // Get NETSH output - TCP settings
            //

            netshOut = Utility.GetExecutableSTDOUT("NETSH.EXE", "INT TCP SHOW GLOBAL");

            //
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters!EnableRSS
            //
            // drChild!EnableRSS = scUtility.GetDWORDValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableRSS")
            // CheckRange("EnableRSS", drChild!EnableRSS, 0, 1)
            // If drChild!EnableRSS.ToString() = "1" Then LogWarning("Receive Side Scaling is enabled.")
            //

            Network["EnableRSS"] = SmartString.GetRemainder(SmartString.GetStringLine(netshOut, "Receive-Side Scaling State"), ":", true, true);  // whatever is after : and trim it

            //
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters!EnableTCPChimney
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters!EnableTCPA
            //
            // drChild!EnableTCPChimney = scUtility.GetDWORDValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableTCPChimney")
            // CheckRange("EnableTCPChimney", drChild!EnableTCPChimney, 0, 1)
            // drChild!EnableTCPA = scUtility.GetDWORDValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableTCPA")
            // CheckRange("EnableTCPA", drChild!EnableTCPA, 0, 1)
            // If drChild!EnableTCPA.ToString() = "1" Or drChild!EnableTCPChimney.ToString() = "1" Then LogWarning("TCP Chimney may be enabled.")

            Network["EnableTCPChimney"] = SmartString.GetRemainder(SmartString.GetStringLine(netshOut, "Chimney Offload State"), ":", true, true);  // whatever is after : and trim it
            Network["EnableTCPA"] = SmartString.GetRemainder(SmartString.GetStringLine(netshOut, "NetDMA State"), ":", true, true);  // whatever is after : and trim it

            //
            // Get NETSH output - ephemeral port range
            //

            netshOut = Utility.GetExecutableSTDOUT("NETSH.EXE", "INT IPV4 SHOW DYNAMICPORT TCP");

            //
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters!MaxUserPort
            //

            string minUP = SmartString.GetRemainder(SmartString.GetStringLine(netshOut, "Start Port"), ":", true, true);  // whatever is after : and trim it
            string numPorts = SmartString.GetRemainder(SmartString.GetStringLine(netshOut, "Number of Ports"), ":", true, true);  // whatever is after : and trim it
            
            Network["MinUserPort"] = minUP;
            Network["MaxUserPort"] = (minUP.ToInt() + numPorts.ToInt() - 1).ToString();  // beware of Obi Wan error

            //
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters!TcpTimedWaitDelay
            // Range: 0..300
            // Default: 240 (on Windows)
            //

            string twd = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpTimedWaitDelay", RegistryValueKind.DWord, "");
            Network["TcpTimedWaitDelay"] = twd;
            Network.CheckRange("TcpTimedWaitDelay", twd, 0, 300);
            if (twd != "")  // no warnings if blank or missing
            {
                int t = twd.ToInt();  // returns 0 if any problems converting
                if (t < 30) Network.LogWarning("TcpTimedWaitDelay is lower than 30.");
                if (t > 240) Network.LogWarning("TcpTimedWaitDelay is greater than 240. You may experience outbound connectivity issues.");
            }

            //
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters!SynAttackProtect
            //

            string sap = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "SynAttackProtect", RegistryValueKind.DWord, "");
            Network["SynAttackProtect"] = sap;
            Network.CheckRange("SynAttackProtect", sap, 0, 1);
            if (sap == "1") Network.LogWarning("Enabling SynAttackProtect may cause connectivity issues.");

            ds.Tables["Network"].Rows.Add(Network);
        }

        public static void CollectODBC(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataRow ODBC = ds.Tables["ODBC"].NewRow();

            string user = "";
            string machine = "";
            string userWow = "";
            string machineWow = "";

            // use of double assignments
            ODBC["ODBC_User_Trace"] = user = Utility.GetRegistryValueAsString(@"HKEY_CURRENT_USER\Software\ODBC\ODBC.INI\ODBC", "Trace", RegistryValueKind.DWord, 0);
            ODBC.CheckRange("ODBC User Trace", user, 0, 1);
            ODBC["ODBC_Machine_Trace"] = machine = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\Software\ODBC\ODBC.INI\ODBC", "Trace", RegistryValueKind.DWord, 0);
            ODBC.CheckRange("ODBC Machine Trace", machine, 0, 1);

            if (Computer["CPU64Bit"].ToBoolean() == true)
            {
                ODBC["ODBC_User_Trace_WOW"] = userWow = Utility.GetRegistryValueAsString(@"HKEY_CURRENT_USER\Software\Wow6432Node\ODBC\ODBC.INI\ODBC", "Trace", RegistryValueKind.DWord, 0);
                ODBC.CheckRange("32-bit ODBC User Trace", userWow, 0, 1);
                ODBC["ODBC_Machine_Trace_WOW"] = machineWow = Utility.GetRegistryValueAsString(@"HKEY_LOCAL_MACHINE\Software\Wow6432Node\ODBC\ODBC.INI\ODBC", "Trace", RegistryValueKind.DWord, 0);
                ODBC.CheckRange("32-bit ODBC Machine Trace", machineWow, 0, 1);
            }

            if (user == "1" || machine == "1" || userWow == "1" || machineWow == "1") ODBC.LogWarning("ODBC Tracing is enabled. You may experience slow performance with database applications.");

            ds.Tables["ODBC"].Rows.Add(ODBC);
        }

        public static void CollectDiskDrive(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];

            int pctFree = 0;

            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                DataRow DiskDrive = ds.Tables["DiskDrive"].NewRow();
                DiskDrive["Drive"] = drive.Name;
                DiskDrive["DriveType"] = drive.DriveType.ToString();
                if (drive.IsReady)
                {
                    DiskDrive["DriveFormat"] = drive.DriveFormat;
                    DiskDrive["Capacity"] = drive.TotalSize.ToString("#,##0");
                    DiskDrive["BytesFree"] = drive.TotalFreeSpace.ToString("#,##0");
                    pctFree = (int)((drive.TotalFreeSpace * 100.0) / drive.TotalSize);
                    DiskDrive["PctFree"] = $"{pctFree}%";
                    if (pctFree < 10) DiskDrive["Message"] = "Low Disk Space";
                }
                ds.Tables["DiskDrive"].Rows.Add(DiskDrive);
            }
        }

        public static void CollectNetworkAdapter(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];

            SelectQuery query = null;
            ManagementObjectSearcher searcher = null;
            string adapterPath = "";
            RegistryKey hive = null, adapterKey = null;
            NICInfo info = null;

            try
            {
                try
                {
                    hive = Registry.LocalMachine;
                    query = new SelectQuery("SELECT * FROM WIN32_NETWORKADAPTER");
                    searcher = new ManagementObjectSearcher(query);
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        try
                        {
                            adapterPath = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\" + mo["DeviceID"].ToString().PadLeft(4, '0');
                            adapterKey = hive.OpenSubKey(adapterPath, RegistryKeyPermissionCheck.ReadSubTree,
                                                         System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                         System.Security.AccessControl.RegistryRights.ReadKey |
                                                         System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                         System.Security.AccessControl.RegistryRights.QueryValues);
                            if (adapterKey == null)
                            {
                                Computer.LogCritical($"Registry key should exist but it does not: {adapterPath}");
                            }
                            else
                            {
                                if (mo["AdapterType"] != null && mo["AdapterType"].ToString() != "Tunnel")
                                {
                                    DataRow NetworkAdapter = ds.Tables["NetworkAdapter"].NewRow();
                                    ds.Tables["NetworkAdapter"].Rows.Add(NetworkAdapter);
                                    try
                                    {
                                        NetworkAdapter["Name"] = adapterKey.GetValue("DriverDesc").ToString();
                                        NetworkAdapter["AdapterType"] = mo["AdapterType"].ToString();
                                        NetworkAdapter["DriverDate"] = adapterKey.GetValue("DriverDate").ToString();
                                        NetworkAdapter["Speed"] = mo["speed"] == null ? "" : Utility.TranslateSpeed(mo["Speed"].ToString());
                                        NetworkAdapter["SpeedDuplex"] = GetEnumInfo(adapterKey, "*SpeedDuplex", "Speed/Duplex", NetworkAdapter).ToValueString();
                                        NetworkAdapter["FlowControl"] = GetEnumInfo(adapterKey, "*FlowControl", "Flow Control", NetworkAdapter).ToValueString();
                                        NetworkAdapter["NICTeaming"] = Array.IndexOf(adapterKey.GetSubKeyNames(), "TeamAdapters") >= 0;
                                        // RSS
                                        if (Array.IndexOf(adapterKey.GetValueNames(), "RSS") >= 0)
                                        {
                                            NetworkAdapter["RSS"] = GetEnumInfo(adapterKey, "RSS", "Receive Side Scaling", NetworkAdapter).ToValueString();
                                        }
                                        if (Array.IndexOf(adapterKey.GetValueNames(), "*RSS") >= 0)
                                        {
                                            NetworkAdapter["RSS"] = GetEnumInfo(adapterKey, "*RSS", "Receive Side Scaling", NetworkAdapter).ToValueString();
                                        }
                                        // Offloading
                                        foreach (string valueName in adapterKey.GetValueNames())
                                        {
                                            if (valueName.ToLower().Contains("offload") || valueName.ToLower().Contains("lsov") || valueName.ToLower().Contains("checksum"))
                                            {
                                                if (adapterKey.GetValue(valueName, "0").ToString() != "0")
                                                {
                                                    info = GetEnumInfo(adapterKey, valueName, "", NetworkAdapter);
                                                    NetworkAdapter.LogHeading($"Offloading: {info.ToString()}");
                                                }
                                            }
                                        }
                                        // warnings here - after offloading messages
                                        DateTime d;
                                        if (DateTime.TryParse(NetworkAdapter["DriverDate"].ToString(), out d))
                                        {
                                            if (d.Year < (DateTime.Now.Year - 2)) NetworkAdapter.LogWarning("Network driver may be out of date.");
                                        }
                                    }
                                    catch (Exception ex4)
                                    {
                                        NetworkAdapter.LogException("Exception enumerating adapter properties.", ex4);
                                    }  // no Finally block
                                }
                            }
                        }
                        catch (Exception ex3)
                        {
                            Computer.LogException($"Exception opening {adapterPath}.", ex3);
                        }
                        finally
                        {
                            if (adapterKey != null) adapterKey.Close();
                        }
                    }
                }
                catch (Exception ex2)
                {
                    Computer.LogException("Exception selecting from WIN32_NETWORKADAPTER to enumerate network adapter information.", ex2);
                }
                finally
                {
                    if (searcher != null) searcher.Dispose();
                }
            }
            catch (Exception ex)
            {
                Computer.LogException("Exception opening HKLM to enumerate network adapter information.", ex);
            }
            finally
            {
                if (hive != null) hive.Close();
            }
        }

        private static NICInfo GetEnumInfo(RegistryKey adapterKey, string enumName, string description, DataRow dr)
        {
            RegistryKey paramKey = null, enumKey = null;
            NICInfo info = new NICInfo();
            string enumValue = adapterKey.GetValue(enumName, "").ToString();
            info.effectiveValue = enumValue;
            info.paramDesc = description;
            info.valueName = enumName;
            try
            {
                paramKey = adapterKey.OpenSubKey($@"NDI\Params\{enumName}", RegistryKeyPermissionCheck.ReadSubTree,
                                                         System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                         System.Security.AccessControl.RegistryRights.ReadKey |
                                                         System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                         System.Security.AccessControl.RegistryRights.QueryValues);
                if (paramKey == null) return info;
                if (info.paramDesc == "") info.paramDesc = paramKey.GetValue("ParamDesc", "").ToString();
                if (info.effectiveValue == "") info.effectiveValue = paramKey.GetValue("default", "").ToString();
                try
                {
                    enumKey = paramKey.OpenSubKey("enum", RegistryKeyPermissionCheck.ReadSubTree,
                                                         System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                         System.Security.AccessControl.RegistryRights.ReadKey |
                                                         System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                         System.Security.AccessControl.RegistryRights.QueryValues);
                    if (enumKey == null)
                    {
                        paramKey.Close();
                        return info;
                    }
                    info.enumeration = enumKey.GetValue(info.effectiveValue, "").ToString();
                }
                catch (Exception ex2)
                {
                    dr.LogException($@"Exception opening 'NDI\Params\{enumName}\enum.", ex2);
                }
                finally
                {
                    if (enumKey != null) enumKey.Close();
                }
            }
            catch (Exception ex)
            {
                dr.LogException($@"Exception enumerating adapter parameter 'NDI\Params\{enumName}'.", ex);
            }
            finally
            {
                if (paramKey != null) paramKey.Close();
            }

            return info;
        }

        public static void CollectHostAlias(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];

            IPHostEntry HostEntry = Dns.GetHostEntry(Environment.MachineName);
            foreach (string Alias in HostEntry.Aliases)
            {
                DataRow HostAlias = ds.Tables["HostAlias"].NewRow();
                HostAlias["DNS_Alias"] = Alias;
                ds.Tables["HostAlias"].Rows.Add(HostAlias);
            }
        }

        public static void CollectIPAddress(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];

            IPHostEntry HostEntry = Dns.GetHostEntry(Environment.MachineName);
            foreach (IPAddress Addr in HostEntry.AddressList)
            {
                DataRow IPAddress = ds.Tables["IPAddress"].NewRow();
                IPAddress["AddressFamily"] = Addr.AddressFamily.ToString();
                IPAddress["Address"] = Addr.ToString();
                ds.Tables["IPAddress"].Rows.Add(IPAddress);
            }
        }

        public static void CollectDatabaseDriver(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            bool is64bit = Computer["CPU64Bit"].ToBoolean();
            string[] OLEDBProviders = DriverInfo.GetExtendedOLEDBNames();  // SQL and some non-SQL OLE DB Providers
            string[] ODBCDrivers = DriverInfo.GetODBCNames();
            DriverInfo info = null;
            FileVersionInfo versionInfo = null;
            string windowsVersion = Computer.GetString("WindowsVersion");
            string windowsReleaseID = Computer.GetString("WindowsReleaseID");

            foreach (string Provider in OLEDBProviders)
            {
                // info = DriverInfo.GetDriverInfo(Provider);
                object g = Registry.GetValue($@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\{Provider}\Clsid", "", "");
                string guid = g == null ? "" : g.ToString();
                if (guid != "")
                {
                    object ip = Registry.GetValue($@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{guid}\InProcServer32", "", "");
                    string inprocServer32 = ip == null ? "" : ip.ToString();
                    if (inprocServer32 != "")
                    {
                        DataRow DatabaseDriver = ds.Tables["DatabaseDriver"].NewRow();
                        ds.Tables["DatabaseDriver"].Rows.Add(DatabaseDriver);

                        DatabaseDriver["DriverName"] = Provider;
                        DatabaseDriver["DriverType"] = "OLE DB";
                        DatabaseDriver["Guid"] = guid;
                        DatabaseDriver["Path"] = inprocServer32;
                        versionInfo = FileVersionInfo.GetVersionInfo(inprocServer32);
                        info = DriverInfo.GetDriverInfo(Provider, versionInfo, windowsVersion, windowsReleaseID);
                        DatabaseDriver["Version"] = versionInfo.ProductVersion;
                        DatabaseDriver["TLS12"] = info == null ? "" : info.MinTLS12Version;
                        DatabaseDriver["TLS13"] = info == null ? "" : info.MinTLS13Version;
                        DatabaseDriver["ServerCompatibility"] = info == null ? "" : info.ServerCompatibility;
                        DatabaseDriver["Supported"] = info == null ? "" : info.Supported;
                        DatabaseDriver["MultiSubnetFailoverSupport"] = info == null ? "" : info.MultiSubnetFailover;
                    }
                    if (is64bit)
                    {
                        ip = Registry.GetValue($@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{guid}\InProcServer32", "", "");
                        inprocServer32 = ip == null ? "" : ip.ToString();
                        if (inprocServer32 != "")
                        {
                            inprocServer32 = SmartString.ReplaceBeginning(inprocServer32, Environment.GetEnvironmentVariable("ProgramFiles") + @"\", Environment.GetEnvironmentVariable("ProgramFiles(x86)") + @"\", true);
                            inprocServer32 = SmartString.ReplaceBeginning(inprocServer32, Environment.GetEnvironmentVariable("SystemRoot") + @"\System32\", Environment.GetEnvironmentVariable("SystemRoot") + @"\SysWOW64\", true);

                            DataRow DatabaseDriver = ds.Tables["DatabaseDriver"].NewRow();
                            ds.Tables["DatabaseDriver"].Rows.Add(DatabaseDriver);

                            DatabaseDriver["DriverName"] = Provider;
                            DatabaseDriver["DriverType"] = "OLE DB";
                            DatabaseDriver["Path"] = inprocServer32;
                            DatabaseDriver["Guid"] = guid;
                            versionInfo = FileVersionInfo.GetVersionInfo(inprocServer32);
                            info = DriverInfo.GetDriverInfo(Provider, versionInfo, windowsVersion, windowsReleaseID);
                            DatabaseDriver["Version"] = versionInfo.ProductVersion;
                            DatabaseDriver["TLS12"] = info == null ? "" : info.MinTLS12Version;
                            DatabaseDriver["TLS13"] = info == null ? "" : info.MinTLS13Version;
                            DatabaseDriver["ServerCompatibility"] = info == null ? "" : info.ServerCompatibility;
                            DatabaseDriver["Supported"] = info == null ? "" : info.Supported;
                            DatabaseDriver["MultiSubnetFailoverSupport"] = info == null ? "" : info.MultiSubnetFailover;
                        }
                    }
                }
            }

            // enumerate drivers in HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers

            RegistryKey hive = null, ODBCKey = null, driverKey = null;
            string ODBCPath = "", driverPath = "";
            try
            {
                ODBCPath = @"SOFTWARE\ODBC\ODBCINST.INI";
                hive = Registry.LocalMachine;
                ODBCKey = hive.OpenSubKey($@"{ODBCPath}\ODBC Drivers", RegistryKeyPermissionCheck.ReadSubTree,
                                            System.Security.AccessControl.RegistryRights.ReadPermissions |
                                            System.Security.AccessControl.RegistryRights.ReadKey |
                                            System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                            System.Security.AccessControl.RegistryRights.QueryValues);
                if (ODBCKey == null)
                {
                    Computer.LogCritical($@"Registry key should exist but does not: {ODBCKey}");
                }
                else
                {
                    string[] valueNames = ODBCKey.GetValueNames();
                    foreach (string valueName in valueNames)
                    {
                        if (valueName.Length > 0)
                        {
                            driverPath = $@"{ODBCPath}\{valueName}";
                            driverKey = hive.OpenSubKey(driverPath, RegistryKeyPermissionCheck.ReadSubTree,
                                                            System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                            System.Security.AccessControl.RegistryRights.ReadKey |
                                                            System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                            System.Security.AccessControl.RegistryRights.QueryValues);
                            if (driverKey == null)
                            {
                                Computer.LogCritical($@"Registry key should exist but does not: {driverKey}");
                            }
                            else
                            {
                                DataRow DatabaseDriver = ds.Tables["DatabaseDriver"].NewRow();
                                ds.Tables["DatabaseDriver"].Rows.Add(DatabaseDriver);

                                object d = driverKey.GetValue("Driver", "");
                                string path = d == null ? "" : d.ToString();

                                DatabaseDriver["DriverName"] = valueName;
                                DatabaseDriver["DriverType"] = "ODBC";
                                DatabaseDriver["Path"] = path;
                                DatabaseDriver["Guid"] = "";
                                versionInfo = FileVersionInfo.GetVersionInfo(path);
                                info = DriverInfo.GetDriverInfo(valueName, versionInfo, windowsVersion, windowsReleaseID);
                                DatabaseDriver["Version"] = versionInfo.ProductVersion;
                                DatabaseDriver["TLS12"] = info == null ? "" : info.MinTLS12Version;
                                DatabaseDriver["TLS13"] = info == null ? "" : info.MinTLS13Version;
                                DatabaseDriver["ServerCompatibility"] = info == null ? "" : info.ServerCompatibility;
                                DatabaseDriver["Supported"] = info == null ? "" : info.Supported;
                                DatabaseDriver["MultiSubnetFailoverSupport"] = info == null ? "" : info.MultiSubnetFailover;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Computer.LogException($@"There was a problem enumerating the ODBC drivers under {ODBCPath}.", ex);
            }
            finally
            {
                if (driverKey != null) driverKey.Close();
                if (ODBCKey != null) ODBCKey.Dispose();
                if (hive != null) hive.Dispose();
            }

            // enumerate 32-bit drivers on a 64-bit system in HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI\ODBC Drivers

            try
            {
                ODBCPath = @"SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI";
                hive = Registry.LocalMachine;
                ODBCKey = hive.OpenSubKey($@"{ODBCPath}\ODBC Drivers", RegistryKeyPermissionCheck.ReadSubTree,
                                            System.Security.AccessControl.RegistryRights.ReadPermissions |
                                            System.Security.AccessControl.RegistryRights.ReadKey |
                                            System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                            System.Security.AccessControl.RegistryRights.QueryValues);
                if (ODBCKey == null)
                {
                    Computer.LogCritical($@"Registry key should exist but does not: {ODBCKey}");
                }
                else
                {
                    string[] valueNames = ODBCKey.GetValueNames();
                    foreach (string valueName in valueNames)
                    {
                        if (valueName.Length > 0)
                        {
                            driverPath = $@"{ODBCPath}\{valueName}";
                            driverKey = hive.OpenSubKey(driverPath, RegistryKeyPermissionCheck.ReadSubTree,
                                                            System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                            System.Security.AccessControl.RegistryRights.ReadKey |
                                                            System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                            System.Security.AccessControl.RegistryRights.QueryValues);
                            if (driverKey == null)
                            {
                                Computer.LogCritical($@"Registry key should exist but does not: {driverKey}");
                            }
                            else
                            {
                                DataRow DatabaseDriver = ds.Tables["DatabaseDriver"].NewRow();
                                ds.Tables["DatabaseDriver"].Rows.Add(DatabaseDriver);

                                object d = driverKey.GetValue("Driver", "");
                                string path = d == null ? "" : d.ToString();

                                path = SmartString.ReplaceBeginning(path, Environment.GetEnvironmentVariable("ProgramFiles") + @"\", Environment.GetEnvironmentVariable("ProgramFiles(x86)") + @"\", true);
                                path = SmartString.ReplaceBeginning(path, Environment.GetEnvironmentVariable("SystemRoot") + @"\System32\", Environment.GetEnvironmentVariable("SystemRoot") + @"\SysWOW64\", true);


                                DatabaseDriver["DriverName"] = valueName;
                                DatabaseDriver["DriverType"] = "ODBC";
                                DatabaseDriver["Path"] = path;
                                DatabaseDriver["Guid"] = "";
                                versionInfo = FileVersionInfo.GetVersionInfo(path);
                                info = DriverInfo.GetDriverInfo(valueName, versionInfo, windowsVersion, windowsReleaseID);
                                DatabaseDriver["Version"] = versionInfo.ProductVersion;
                                DatabaseDriver["TLS12"] = info == null ? "" : info.MinTLS12Version;
                                DatabaseDriver["TLS13"] = info == null ? "" : info.MinTLS13Version;
                                DatabaseDriver["ServerCompatibility"] = info == null ? "" : info.ServerCompatibility;
                                DatabaseDriver["Supported"] = info == null ? "" : info.Supported;
                                DatabaseDriver["MultiSubnetFailoverSupport"] = info == null ? "" : info.MultiSubnetFailover;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Computer.LogException($@"There was a problem enumerating the ODBC drivers under {ODBCPath}.", ex);
            }
            finally
            {
                if (driverKey != null) driverKey.Close();
                if (ODBCKey != null) ODBCKey.Dispose();
                if (hive != null) hive.Dispose();
            }

        }

        public static void CollectSQLAlias(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataTable dtSQLAlias = ds.Tables["SQLAlias"];
            DataRow SQLAlias = null;
            RegistryKey hive = Registry.LocalMachine;
            RegistryKey aliasKey = null;
            string[] aliases = null, parts = null;
            bool is64bit = Computer["CPU64Bit"].ToBoolean();
            string[] regPath = new string[] { @"SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo", @"SOFTWARE\WOW6432Node\MSSQLServer\Client\ConnectTo" };
            int loopCount = is64bit ? 2 : 1; // only look to Wow64 registry path if on a 64-bit system
            string redirectsTo = "";

            for (int i = 0; i < loopCount; i++)
            {
                try
                {
                    aliasKey = hive.OpenSubKey(regPath[i], RegistryKeyPermissionCheck.ReadSubTree,
                                                           System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                           System.Security.AccessControl.RegistryRights.ReadKey |
                                                           System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                           System.Security.AccessControl.RegistryRights.QueryValues);
                    if (aliasKey == null) continue; // the key does not exist
                    aliases = aliasKey.GetValueNames();
                    foreach (string aliasName in aliases)
                    {
                        if (aliasName != "")
                        {
                            SQLAlias = dtSQLAlias.NewRow();
                            dtSQLAlias.Rows.Add(SQLAlias);
                            SQLAlias["64Bit"] = is64bit && (i == 0);  // on 64-bit machines, the second time round the loop is 32-bit
                            SQLAlias["AliasName"] = aliasName;
                            redirectsTo = aliasKey.GetValue(aliasName).ToString();
                            parts = redirectsTo.Split(',');
                            if (parts.Length > 1)
                            {
                                switch (parts[0])
                                {
                                    case "DBMSSOCN":
                                        SQLAlias["Protocol"] = "TCP";
                                        if (parts.Length == 3) SQLAlias["Port"] = parts[2];
                                        break;
                                    case "DBNMPNTW":
                                        SQLAlias["Protocol"] = "Named Pipes";
                                        break;
                                    default:
                                        SQLAlias["Protocol"] = parts[0];
                                        break;
                                }
                                SQLAlias["ServerName"] = parts[1];
                            }
                            SQLAlias = null;
                        }
                    }
                    aliasKey.Dispose();
                    aliasKey = null;
                }
                catch (Exception ex)
                {
                    if (SQLAlias != null) SQLAlias.LogException($"Problem parsing SQL Alias values under {regPath[i]}.", ex);
                    if (SQLAlias == null) Computer.LogException($"Problem opening registry key {regPath[i]} to parse SQL Aliases.", ex);
                }
                finally
                {
                    if (aliasKey != null) aliasKey.Dispose();
                    if (hive != null) hive.Dispose();
                }
            }
            hive.Dispose();
            hive = null;
        }

        public static void CollectClientSNI(DataSet ds)
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataTable dtClientSNI = ds.Tables["ClientSNI"];
            DataRow ClientSNI = null;

            bool is64bit = Computer["CPU64Bit"].ToBoolean();
            string[] regPath = new string[] { @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer", @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\MSSQLServer" };
            string[] SNINames = new string[] { "SNI9.0", "SNI10.0", "SNI11.0", "SNI18.0" };
            int loopCount = is64bit ? 2 : 1; // only look to Wow64 registry path if on a 64-bit system
            string propertyName = "";
            int propertyValue = 0;
            int flagCount = 0;
            object prot = null;

            for (int i = 0; i < loopCount; i++)
            {
                try
                {
                    //
                    // Process keys under each SNI name - TODO debug this on Windows 2016 VM - why does it fail but not generate a message??? Debug print messages with -1 argument?
                    //

                    foreach (string SNIName in SNINames)
                    {
                        if (Utility.CheckRegistryKeyExists($@"{regPath[i]}\Client\{SNIName}") == "1")  // not all SNI names exist on all machines
                        {
                            ClientSNI = dtClientSNI.NewRow();
                            dtClientSNI.Rows.Add(ClientSNI);
                            ClientSNI["Name"] = SNIName;
                            ClientSNI["64Bit"] = is64bit && (i == 0);
                            prot = Registry.GetValue($@"{regPath[i]}\Client\{SNIName}", "ProtocolOrder", "");
                            if (prot != null) ClientSNI["ProtocolOrder"] = string.Join(" ", (string[])prot);

                            // General flags
                            flagCount = Registry.GetValue($@"{regPath[i]}\Client\{SNIName}\GeneralFlags", "NumberOfFlags", 0).ToInt();
                            for (int k = 0; k < flagCount; k++)
                            {
                                propertyName = Registry.GetValue($@"{regPath[i]}\Client\{SNIName}\GeneralFlags\Flag{k + 1}", "Label", "").ToString();
                                propertyValue = Registry.GetValue($@"{regPath[i]}\Client\{SNIName}\GeneralFlags\Flag{k + 1}", "Value", 0).ToInt();
                                if (propertyName.Equals("Force protocol encryption", StringComparison.CurrentCultureIgnoreCase)) ClientSNI["ForceEncryption"] = propertyValue > 0;
                                if (propertyName.Equals("Trust Server Certificate", StringComparison.CurrentCultureIgnoreCase)) ClientSNI["TrustServerCertificate"] = propertyValue > 0;
                            }

                            // Tcp Settings
                            flagCount = Registry.GetValue($@"{regPath[i]}\Client\{SNIName}\tcp", "NumberOfProperties", 0).ToInt();
                            for (int k = 0; k < flagCount; k++)
                            {
                                propertyName = Registry.GetValue($@"{regPath[i]}\Client\{SNIName}\tcp\Property{k + 1}", "Name", "").ToString();
                                propertyValue = Registry.GetValue($@"{regPath[i]}\Client\{SNIName}\tcp\Property{k + 1}", "Value", 0).ToInt();
                                if (propertyName.Equals("Default Port", StringComparison.CurrentCultureIgnoreCase)) ClientSNI["TcpDefaultPort"] = propertyValue;
                                if (propertyName.Equals("KEEPALIVE (in milliseconds)", StringComparison.CurrentCultureIgnoreCase)) ClientSNI["TcpKeepAliveInterval"] = propertyValue;
                                if (propertyName.Equals("KEEPALIVEINTERVAL (in milliseconds)", StringComparison.CurrentCultureIgnoreCase)) ClientSNI["TcpKeepAliveRetryInterval"] = propertyValue;
                            }
                        }
                    }

                    //
                    // Process SuperSocketNetLib values
                    //

                    if (Utility.CheckRegistryKeyExists($@"{regPath[i]}") == "1")  // make sure SQL Server general registry key exists
                    {
                        ClientSNI = dtClientSNI.NewRow();
                        dtClientSNI.Rows.Add(ClientSNI);
                        ClientSNI["Name"] = "SuperSocketNetLib";
                        ClientSNI["64Bit"] = is64bit && (i == 0);
                        // protcol list
                        prot = Registry.GetValue($@"{regPath[i]}\MSSqlServer\SuperSocketNetLib", "ProtocolList", null);
                        if (prot != null) ClientSNI["ProtocolOrder"] = string.Join(" ", (string[])prot);
                        // force encryption
                        propertyValue = Registry.GetValue($@"{regPath[i]}\Client\SuperSocketNetLib", "Encrypt", 0).ToInt();
                        ClientSNI["ForceEncryption"] = propertyValue > 0;
                        // default port
                        propertyValue = Registry.GetValue($@"{regPath[i]}\MSSqlServer\SuperSocketNetLib\Tcp", "TcpPort", "").ToInt();   // this is a REG_SZ and not a REG_DWORD like above
                        ClientSNI["TcpDefaultPort"] = propertyValue;
                    }

                    //
                    // Clean up
                    //

                    ClientSNI = null;

                }
                catch (Exception ex)
                {
                    if (ClientSNI != null) ClientSNI.LogException($"There was a problem reading client driver {ClientSNI.GetString("Name")} properties.", ex);
                    if (ClientSNI == null) Computer.LogException($"There was a problem reading client driver {ClientSNI.GetString("Name")} properties.", ex);
                }
            }
        }

        public static void CollectService(DataSet ds)  // collects select services we are most interested in
        {
            string[] NamesOfInterest = { "IISADMIN", "MSDTC", "RpcSs", "termService", "W3SVC", "MsDtsServer", "MSSQL", "SQL", "ReportServer", "MSOLAP" };
            string serviceName = "";
            ManagementObjectSearcher searcher = null;

            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataRow Service = null;

            //
            // Enumerate Services
            //

            try
            {
                searcher = new ManagementObjectSearcher("Select * From Win32_Service");
                foreach (ManagementObject mo in searcher.Get())
                {
                    try
                    {
                        serviceName = mo.GetPropertyValue("Name").ToString();

                        foreach (string name in NamesOfInterest)
                        {
                            if (serviceName.StartsWith(name, StringComparison.CurrentCultureIgnoreCase))
                            {
                                Service = ds.Tables["Service"].NewRow();
                                ds.Tables["Service"].Rows.Add(Service);
                                string[] parts = serviceName.Split('$');
                                if (parts.Length == 1)
                                {
                                    Service["Name"] = parts[0];
                                    Service["Instance"] = "";
                                }
                                else
                                {
                                    Service["Name"] = parts[0];
                                    Service["Instance"] = parts[1];
                                }
                                if (parts[0].Equals("IISADMIN", StringComparison.CurrentCultureIgnoreCase) == true) Computer["IISRunning"] = true;
                                if (parts[0].Equals("W3SVC", StringComparison.CurrentCultureIgnoreCase) == true) Computer["IISRunning"] = true;
                                Service["PID"] = mo.GetPropertyValue("ProcessID").ToString();
                                string description = mo.GetPropertyValue("DisplayName").ToString();
                                Service["Description"] = description;
                                Service["Path"] = mo.GetPropertyValue("PathName").ToString();
                                Service["ServiceAccount"] = mo.GetPropertyValue("StartName").ToString();
                                Service["DomainAccount"] = Utility.TranslateServiceAccount(Service["ServiceAccount"].ToString(), Computer["NETBIOSName"].ToString());
                                string startMode = mo.GetPropertyValue("StartMode").ToString();
                                Service["StartMode"] = startMode;
                                bool started = mo.GetPropertyValue("Started").ToBoolean();
                                Service["Started"] = started;  // boolean
                                Service["Status"] = mo.GetPropertyValue("Status").ToString();

                                if (started == false)
                                {
                                    if (startMode.Equals("AUTO", StringComparison.CurrentCultureIgnoreCase))
                                    {
                                        Service.LogCritical($"{description} is set to automatically start but it is not running.");
                                    }
                                    else
                                    {
                                        Service.LogWarning($"{description} start mode is set to {startMode}.");
                                    }
                                }  // if started
                            }  // if serviceName
                        }  // foreach
                    }
                    catch (Exception ex2)
                    {
                        Computer.LogException("Exception enumerating service or enumerating service properties.", ex2);
                    }
                    finally
                    {
                        if (mo != null) mo.Dispose();
                    }
                }  // foreach mo
            }
            catch (Exception ex)
            {
                Computer.LogException("Exception accessing Management object for services: Win32_Service", ex);
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
            }

            //
            // Enumerate W3WP processes - TODO
            //

            object[] owner = new object[1];
            try
            {
                searcher = new ManagementObjectSearcher("Select * From Win32_Service WHERE Name='w3wp.exe'");
                foreach (ManagementObject mo in searcher.Get())
                {
                    Service = ds.Tables["Service"].NewRow();
                    ds.Tables["Service"].Rows.Add(Service);
                    Service["Name"] = mo.GetPropertyValue("Name").ToString();
                    Service["PID"] = mo.GetPropertyValue("ProcessID").ToString();
                    string description = mo.GetPropertyValue("Description").ToString();
                    Service["Description"] = description;
                    Service["Path"] = mo.GetPropertyValue("ExecutablePath").ToString();
                    mo.InvokeMethod("GetOwner", owner);
                    Service["ServiceAccount"] = $@"{owner[1]}\{owner[0]}";
                    Service["DomainAccount"] = Utility.TranslateServiceAccount(Service["ServiceAccount"].ToString(), Computer["NETBIOSName"].ToString());
                    Service["StartMode"] = "Manual";
                    Service["Started"] = true;  // boolean
                    Service["Status"] = "Running";
                    Computer["IISRunning"] = true;
                }
            }
            catch (Exception ex)
            {
                Service.LogException("Exception accessing Management object for w3wp.exe: Win32_Process", ex);
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
            }
        }

        public static void CollectSPNAccount(DataSet ds)
        {

            //
            // Collects both SPNAccount records and 0..n ConstrainedDelegationSPN records per SPNAccount record
            //

            int ACCOUNT_DISABLED = 2;                  //  0x00000002
            int ACCOUNT_LOCKED = 16;                   //  0x00000010
            int NORMAL_ACCOUNT = 512;                  //  0x00000200
            int WORKSTATION_TRUST_ACCOUNT = 4096;      //  0x00001000
            int SERVER_TRUST_ACCOUNT = 8192;           //  0x00002000
            int TRUSTED_FOR_DELEGATION = 524288;       //  0x00080000
            int NOT_DELEGATED = 1048576;               //  0x00100000
            int USE_DES_KEY_ONLY = 2097152;            //  0x00200000
            int PASSWORD_EXPIRED = 8388608;            //  0x00800000

            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataRow SPNAccount = null;

            if (Computer["ConnectedToDomain"].ToBoolean() == false) return;  // have to be joined to a domain for this collector to work

            //
            // Build list of unique DomainAccount values from the Service table
            //

            ArrayList serviceAccounts = new ArrayList();
            string acct = "";
            DataTable Service = ds.Tables["Service"];
            foreach (DataRow dr in Service.Rows)
            {
                acct = dr["DomainAccount"].ToString();
                if (serviceAccounts.Contains(acct) == false) serviceAccounts.Add(acct);
            }

            //
            // Add a record per unique account
            //

            string domain = "", tempAccount = "";
            int UAC = 0;
            SearchResultCollection results = null;
            DirectoryEntry entry = null;
            DirectorySearcher searcher = null;

            foreach (string account in serviceAccounts)
            {
                // split the account apart
                acct = account;
                domain = "";
                if (acct.Contains(@"\"))
                {
                    domain = SmartString.ChopWord(acct, ref acct, @"\");
                }
                else if (acct.Contains(@"@"))
                {
                    acct = SmartString.ChopWord(acct, ref domain, @"@");
                }
                else
                {
                    domain = Computer["ExpandedName"].ToString();
                }

                try
                {
                    // treat the account as a user account first
                    tempAccount = acct;
                    searcher = new DirectorySearcher(new DirectoryEntry($@"LDAP://{domain}"), $"samAccountName={tempAccount}", new string[] { "AdsPath", "cn" }, SearchScope.Subtree);
                    results = searcher.FindAll();
                    if (results.Count == 0)  // treat the account as the machine account if user account search fails
                    {
                        results = null;
                        searcher.Dispose();
                        tempAccount += "$";  // machine accounts have $ suffix for searching
                        searcher = new DirectorySearcher(new DirectoryEntry($@"LDAP://{domain}"), $"samAccountName={tempAccount}", new string[] { "AdsPath", "cn" }, SearchScope.Subtree);
                        results = searcher.FindAll();
                    }

                    // if not found log a message and continue around the loop - the foreach won't do anything in that case
                    if (results.Count == 0) Computer.LogCritical($"No accounts in domain '{domain}' have the samAccountName of '{acct}' or '{acct}$'.");

                    // process results
                    foreach (SearchResult result in results)
                    {
                        try
                        {
                            SPNAccount = ds.Tables["SPNAccount"].NewRow();
                            ds.Tables["SPNAccount"].Rows.Add(SPNAccount);
                            entry = result.GetDirectoryEntry();
                            SPNAccount["Account"] = tempAccount;
                            SPNAccount["Domain"] = domain;
                            SPNAccount["DistinguishedName"] = entry.Path;
                            UAC = entry.Properties["UserAccountControl"][0].ToInt();
                            SPNAccount["UserAccountControl"] = $"{UAC} (0x{UAC.ToString("X")})";
                            bool trusted = ((UAC & TRUSTED_FOR_DELEGATION) != 0);
                            SPNAccount["TrustedForDelegation"] = trusted.ToString();
                            if (trusted == false) SPNAccount.LogWarning($@"{tempAccount} must be trusted for delegation in order for Kerberos delegation to succeed.");
                            SPNAccount["Sensitive"] = ((UAC & NOT_DELEGATED) != 0).ToString();

                            // Assume 0 = RC4 if the property does not exist
                            PropertyValueCollection p = entry.Properties["msDS-SupportedEncryptionTypes"];
                            int ke = p.Count > 0 ? p[0].ToInt() : 0;
                            SPNAccount["KerberosEncryption"] = Utility.KerbEncryptNames(ke);

                            // account problems
                            if ((UAC & ACCOUNT_DISABLED) != 0) SPNAccount.LogCritical($@"{tempAccount} is disabled.");
                            if ((UAC & ACCOUNT_LOCKED) != 0) SPNAccount.LogCritical($@"{tempAccount} is locked.");
                            if ((UAC & USE_DES_KEY_ONLY) != 0) SPNAccount.LogWarning($@"{tempAccount} is set to use DES keys only.");
                            if ((UAC & PASSWORD_EXPIRED) != 0) SPNAccount.LogCritical($@"The password for {tempAccount} has expired.");

                            // account type
                            if ((UAC & NORMAL_ACCOUNT) != 0)
                            {
                                SPNAccount["AccountType"] = "User";
                            }
                            else if ((UAC & WORKSTATION_TRUST_ACCOUNT) != 0)
                            {
                                SPNAccount["AccountType"] = "Computer";
                            }
                            else if ((UAC & SERVER_TRUST_ACCOUNT) != 0)
                            {
                                SPNAccount["AccountType"] = "Domain Controller";
                            }
                            else
                            {
                                SPNAccount["AccountType"] = "Unknown";
                            }

                            // Get SPNs for this account
                            CollectSPN(ds, SPNAccount, entry.Path);

                            // Get constrained delegation SPNs for this account
                            bool constrained = entry.Properties["msDS-AllowedToDelegateTo"].Count > 0;
                            SPNAccount["ConstrainedDelegationEnabled"] = constrained;
                            if (constrained) // get SPNs for constrained delegation
                            {
                                try
                                {
                                    PropertyValueCollection props = entry.Properties["msDS-AllowedToDelegateTo"];
                                    foreach (object prop in props)
                                    {
                                        Console.WriteLine($"Constrained target SPN for {tempAccount}: {prop.ToString()}");
                                        // add constrained SPN records here
                                        DataRow ConstrainedDelegationSPN = ds.Tables["ConstrainedDelegationSPN"].NewRow();
                                        ds.Tables["ConstrainedDelegationSPN"].Rows.Add(ConstrainedDelegationSPN);
                                        ConstrainedDelegationSPN["ParentID"] = SPNAccount["ID"];
                                        ConstrainedDelegationSPN["ServiceAccount"] = account;
                                        ConstrainedDelegationSPN["SPN"] = prop.ToString();
                                    }
                                }
                                catch (Exception) { }  // ignore all errors
                            }

                            entry.Dispose();
                            entry = null;
                            if (results.Count > 1) SPNAccount.LogCritical($"Multiple accounts in domain '{domain}' have the samAccountName of '{acct}' or '{acct}$'.");
                        }
                        catch (Exception ex2)
                        {
                            SPNAccount.LogException($"An error occurred reading properties for account {SPNAccount.GetString("Account")}.", ex2);
                        }
                        finally
                        {
                            if (entry != null) entry.Dispose();
                        }
                    }
                    results.Dispose();
                    results = null;
                    searcher.Dispose();
                    searcher = null;
                }
                catch (Exception ex)
                {
                    Computer.LogException($"An error occurred searching for SPNs on account {tempAccount}.", ex);
                }
                finally
                {
                    if (results != null) results.Dispose();
                    if (searcher != null) searcher.Dispose();
                }
            }
        }

        public static void CollectSPN(DataSet ds, DataRow SPNAccount, string DistinguishedName)
        {
            DirectoryEntry entry = null, dupRoot = null, dupEntry = null;
            bool fDuplicate = false;
            PropertyValueCollection pvc = null;
            DirectorySearcher d = null;
            SearchResultCollection results = null;

            DataRow Computer = ds.Tables["Computer"].Rows[0];

            try
            {
                entry = new DirectoryEntry(DistinguishedName);
                pvc = entry.Properties["servicePrincipalName"];
                if (pvc.Count == 0)
                {
                    SPNAccount.LogWarning($"There are no Service Principle Names associated with {SPNAccount.GetString("Account")}.");
                }
                else
                {
                    foreach (string SPNName in pvc)
                    {
                        DataRow SPN = ds.Tables["SPN"].NewRow();
                        ds.Tables["SPN"].Rows.Add(SPN);
                        SPN["ParentID"] = SPNAccount["ID"];
                        SPN["ServiceAccount"] = SPNAccount["Account"];
                        SPN["SPN"] = SPNName;
                        SPN["HasDuplicates"] = false;
                        try
                        {
                            fDuplicate = false;
                            // search the computer's domain for duplicates
                            dupRoot = new DirectoryEntry($@"LDAP://{Computer["ExpandedName"].ToString()}");  // this is just the domain descriptor and not the computer name
                            d = new DirectorySearcher(dupRoot, $"servicePrincipalName={SPNName}", new String[] { "AdsPath", "cn"}, SearchScope.Subtree);
                            results = d.FindAll();
                            if (results.Count > 1)
                            {
                                fDuplicate = true;
                                SPN["HasDuplicates"] = true;
                                foreach (SearchResult result in results)
                                {
                                    dupEntry = result.GetDirectoryEntry();
                                    SPN.LogCritical($"Duplicate SPN {SPNName} on account {dupEntry.Properties["samAccountName"][0]}, {dupEntry.Properties["DistinguishedName"][0]}");
                                    dupEntry.Dispose();
                                }
                            }
                            results.Dispose();
                            d.Dispose();
                            dupRoot.Dispose();
                            if (fDuplicate == false) SPN.LogInfo("No duplicate SPNs found.");
                        }
                        catch (Exception)
                        {
                            // leave blank - no action on exception
                        }
                    }
                }
            }
            catch (Exception)
            {
                // do nothing - eat exceptions
            }
            finally
            {
                if (dupEntry != null) dupEntry.Dispose();
                if (results != null) results.Dispose();
                if (d != null) d.Dispose();
                if (dupRoot != null) dupRoot.Dispose();
                if (entry != null) entry.Dispose();
            }
        }

        public static void CollectSQLInstance(DataSet ds)  // ignoring SQL Server 2000 - due to different registry structure
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];

            EnumerateSQLServerInstances(ds, @"SOFTWARE\Microsoft", false);
            if (Computer["CPU64Bit"].ToBoolean()) EnumerateSQLServerInstances(ds, @"SOFTWARE\Wow6432Node\Microsoft", true);
        }

        public static void EnumerateSQLServerInstances(DataSet ds, string RegPath, bool Wow6432Node)
        {
            RegistryKey hive = null, sqlRootKey = null, instanceNames = null, instance = null;

            DataRow Computer = ds.Tables["Computer"].Rows[0];

            try
            {
                hive = Registry.LocalMachine;
                try
                {
                    sqlRootKey = hive.OpenSubKey($@"{RegPath}\Microsoft SQL Server", RegistryKeyPermissionCheck.ReadSubTree,
                                                    System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                    System.Security.AccessControl.RegistryRights.ReadKey |
                                                    System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                    System.Security.AccessControl.RegistryRights.QueryValues);
                    if (sqlRootKey != null)
                    {
                        try
                        {
                            instanceNames = sqlRootKey.OpenSubKey("Instance Names", RegistryKeyPermissionCheck.ReadSubTree,
                                                                   System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                                   System.Security.AccessControl.RegistryRights.ReadKey |
                                                                   System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                                   System.Security.AccessControl.RegistryRights.QueryValues);
                            if (instanceNames != null)
                            {
                                foreach (string typeName in instanceNames.GetSubKeyNames())  // RS, OLAP, SQL
                                {
                                    instance = instanceNames.OpenSubKey(typeName, RegistryKeyPermissionCheck.ReadSubTree,
                                                                         System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                                         System.Security.AccessControl.RegistryRights.ReadKey |
                                                                         System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                                         System.Security.AccessControl.RegistryRights.QueryValues);
                                    foreach (string instanceName in instance.GetValueNames())  // MSSQLSERVER, SQLPROD01, ...
                                    {
                                        if (instanceName != "")  // don't process the default value
                                        {
                                            DataRow SQLInstance = ds.Tables["SQLInstance"].NewRow();
                                            ds.Tables["SQLInstance"].Rows.Add(SQLInstance);
                                            SQLInstance["InstanceType"] = typeName;
                                            SQLInstance["InstanceName"] = instanceName;
                                            SQLInstance["InstanceFolder"] = instance.GetValue(instanceName);
                                            SQLInstance["Wow64Node"] = Wow6432Node;
                                        }
                                    }
                                    instance.Close();
                                }
                            }
                        }
                        catch (Exception ex3)
                        {
                            Computer.LogException($@"Exception opening {RegPath}\Microsoft SQL Server\Instance Names or a subkey.", ex3);
                        }
                        finally
                        {
                            if (instance != null) instance.Close();
                            if (instanceNames != null) instanceNames.Close();
                        }
                        sqlRootKey.Close();
                    }
                }
                catch (Exception ex2)
                {
                    Computer.LogException($@"Exception opening {RegPath}\Microsoft SQL Server or a subkey.", ex2);
                }
                finally
                {
                    if (sqlRootKey != null) sqlRootKey.Close();
                }

            }
            catch (Exception ex)
            {
                Computer.LogException("Error opening HKEY_LOCAL_MACHINE.", ex);
            }
            finally
            {
                if (hive != null) hive.Close();
            }
        }

        public static void CollectSQLServer(DataSet ds)  // ignoring SQL Server 2000 - due to different registry structure
        {
            DataTable SQLInstances = ds.Tables["SQLInstance"];

            foreach (DataRow SQLInstance in SQLInstances.Rows)
            {
                if (SQLInstance.GetString("InstanceType") == "SQL")
                {
                    if (SQLInstance.GetBoolean("Wow64Node") == true)
                    {
                        ProcessSQLInstance(ds, SQLInstance, $@"SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server\{SQLInstance.GetString("InstanceFolder")}");
                    }
                    else
                    {
                        ProcessSQLInstance(ds, SQLInstance, $@"SOFTWARE\Microsoft\Microsoft SQL Server\{SQLInstance.GetString("InstanceFolder")}");
                    }
                }
            }
        }

        public static void ProcessSQLInstance(DataSet ds, DataRow SQLInstance, string RegPath)
        {
            RegistryKey hive = null, MSSQLKey = null, setupKey = null, clusterStateKey = null, folderKey = null;

            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DataRow SQLServer = ds.Tables["SQLServer"].NewRow();
            SQLServer["ParentID"] = SQLInstance["ID"];
            ds.Tables["SQLServer"].Rows.Add(SQLServer);

            try
            {
                hive = Registry.LocalMachine;
                try
                {
                    folderKey = hive.OpenSubKey(RegPath, RegistryKeyPermissionCheck.ReadSubTree,
                                                 System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                 System.Security.AccessControl.RegistryRights.ReadKey |
                                                 System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                 System.Security.AccessControl.RegistryRights.QueryValues);
                    MSSQLKey = folderKey.OpenSubKey("MSSQLServer", RegistryKeyPermissionCheck.ReadSubTree,
                                                 System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                 System.Security.AccessControl.RegistryRights.ReadKey |
                                                 System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                 System.Security.AccessControl.RegistryRights.QueryValues);
                    ProcessMSSQLServer(SQLInstance, SQLServer, MSSQLKey);
                    MSSQLKey.Close();
                    MSSQLKey = null;
                    setupKey = folderKey.OpenSubKey("Setup", RegistryKeyPermissionCheck.ReadSubTree,
                                                 System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                 System.Security.AccessControl.RegistryRights.ReadKey |
                                                 System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                 System.Security.AccessControl.RegistryRights.QueryValues);
                    SQLServer["ServicePack"] = setupKey.GetValue("SP");
                    SQLServer["PatchLevel"] = setupKey.GetValue("PatchLevel");
                    SQLServer["Edition"] = setupKey.GetValue("Edition");
                    SQLServer["Path"] = setupKey.GetValue("SQLBinRoot");

                    //
                    // Check clustered state - and give warnings
                    //

                    string remainder = "";
                    int majorVersion = SmartString.ChopWord(SQLServer.GetString("Version"), ref remainder , ".").ToInt();
                    if (majorVersion < 10)  // SQL 2000 or 2005
                    {
                        SQLServer["Clustered"] = setupKey.GetValue("SqlCluster", 0).ToInt() == 1;
                    }
                    else  // SQL 2008 and later
                    {
                        SQLServer["Clustered"] = false;
                        clusterStateKey = folderKey.OpenSubKey("ClusterState", RegistryKeyPermissionCheck.ReadSubTree,
                                                 System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                 System.Security.AccessControl.RegistryRights.ReadKey |
                                                 System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                 System.Security.AccessControl.RegistryRights.QueryValues);
                        foreach(string clusterValueName in clusterStateKey.GetValueNames())
                        {
                            if (clusterValueName != "" && clusterStateKey.GetValue(clusterValueName, 0).ToInt() == 1) SQLServer["Clustered"] = true;
                        }
                        clusterStateKey.Close();
                        clusterStateKey = null;
                    }

                    if (Computer.GetBoolean("Clustered") == true && SQLServer.GetBoolean("Clustered") == false)
                    {
                        SQLServer.LogWarning("Computer is clustered. This instance is not.");
                    }
                    else if (Computer.GetBoolean("Clustered") == false && SQLServer.GetBoolean("Clustered") == true)
                    {
                        SQLServer.LogCritical("This instance's registry indicates it is clustered but the computer is not!");
                    }
                    setupKey.Close();
                    setupKey = null;
                    hive.Close();
                    hive = null;

                    ProcessSQLPathAndSPNs(ds, SQLInstance, SQLServer);
                }
                catch (Exception ex2)
                {
                    SQLServer.LogException($"Failed to open {RegPath} or a subfolder.", ex2);
                }
                finally
                {
                    if (clusterStateKey != null) clusterStateKey.Close();
                    if (setupKey != null) setupKey.Close();
                    if (MSSQLKey != null) MSSQLKey.Close();
                    if (folderKey != null) folderKey.Close();
                }
            }
            catch (Exception ex)
            {
                SQLServer.LogException($"Failed to open HKEY_LOCAL_MACHINE.", ex);
            }
            finally
            {
                if (hive != null) hive.Close();
            }
        }  // end CollectSQL

        public static void ProcessMSSQLServer(DataRow SQLInstance, DataRow SQLServer, RegistryKey MSSQLServer)
        {
            RegistryKey currentVersion = null, SSNetLib = null, protocol = null, IPKey = null, startupParameters = null;
            string IPAddress = "", stringData = "";
            bool IPEnabled = false;
            string[] extProtWord = new string[] { "Off", "Allowed", "Required" };

            //
            // Current version
            //

            try
            {
                currentVersion = MSSQLServer.OpenSubKey("CurrentVersion", RegistryKeyPermissionCheck.ReadSubTree,
                                                        System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                        System.Security.AccessControl.RegistryRights.ReadKey |
                                                        System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                        System.Security.AccessControl.RegistryRights.QueryValues);
                if (currentVersion != null)
                {
                    SQLServer["Version"] = currentVersion.GetValue("CurrentVersion", "").ToString();
                    currentVersion.Close();
                }
            }
            catch (Exception ex)
            {
                SQLServer.LogException("Failed to get the current version.", ex);
            }
            finally
            {
                if (currentVersion != null) currentVersion.Close();
            }

            //
            // ERRORLOG path
            //

            try
            {
                startupParameters = MSSQLServer.OpenSubKey("Parameters", RegistryKeyPermissionCheck.ReadSubTree,
                                                        System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                        System.Security.AccessControl.RegistryRights.ReadKey |
                                                        System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                        System.Security.AccessControl.RegistryRights.QueryValues);
                if (startupParameters != null)
                {
                    string[] valueNames = startupParameters.GetValueNames();
                    foreach (string valueName in valueNames)
                    {
                        if (valueName != "")
                        {
                            string value = startupParameters.GetValue(valueName, "").ToString();
                            if (value.StartsWith("-e")) SQLServer["ErrorLogPath"] = value.Substring(2);  // skip first two characters (the -e)
                        }
                    }
                    startupParameters.Close();
                }
            }
            catch (Exception ex)
            {
                SQLServer.LogException("Failed to get the ERRORLOG path. Admin permissions required.", ex);
            }
            finally
            {
                if (startupParameters != null) startupParameters.Close();
            }

            bool hadron = MSSQLServer.GetValue(@"HADR\HADR_Enabled", 0).ToInt() == 1;
            SQLServer["AlwaysOn"] = hadron;
            if (hadron == true) SQLServer.LogInfo("Please get always-on configuration information.");

            //
            // Protocol information - server network
            //

            try
            {
                SSNetLib = MSSQLServer.OpenSubKey("SuperSocketNetlib", RegistryKeyPermissionCheck.ReadSubTree,
                                                        System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                        System.Security.AccessControl.RegistryRights.ReadKey |
                                                        System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                        System.Security.AccessControl.RegistryRights.QueryValues);
                if (SSNetLib != null)
                {
                    string cert = SSNetLib.GetValue("Certificate", "").ToString();
                    if (cert == "")
                    {
                        // no thumbprint in the registry - read from the SQL ERRORLOG file
                        string path = SQLServer.GetString("ErrorLogPath");
                        if (path != "")
                        {
                            // A self-generated certificate was successfully loaded for encryption.
                            // The certificate [Cert Hash(sha1) "<Certificate Thumbprint>"] was successfully loaded for encryption.
                            string el = Utility.GetFileText(path);
                            string searchText = "was successfully loaded for encryption.";
                            string line = SmartString.GetStringLine(el, searchText, true);
                            if (line.Contains("self-generated"))
                            {
                                SQLServer["Certificate"] = "Self-generated certificate";
                            }
                            else if (line != "")
                            {
                                line = SmartString.GetBetween(line, @"[", @"]", false, true);  // auto trim the result
                                SQLServer["Certificate"] = line;
                            }
                        }
                    }
                    else
                    {
                        SQLServer["Certificate"] = cert; // use the thumbprint from the registry
                    }
                    SQLServer["ForceEncryption"] = (SSNetLib.GetValue("Encrypt", 0).ToInt() != 0 || SSNetLib.GetValue("ForceEncryption", 0).ToInt() != 0);
                    bool hidden = SSNetLib.GetValue("HideInstance", 0).ToInt() != 0;
                    SQLServer["Hidden"] = hidden;
                    if (hidden == true) SQLServer.LogWarning("This instance is hidden from showing in the SQL Browser.");
                    int exp = SSNetLib.GetValue("ExtendedProtection", 0).ToInt();
                    if (exp < 0 || exp > 2)
                    {
                        SQLServer.LogCritical($"Extended Protection value {exp} is outside the allowed range of 0..2.");
                        SQLServer["ExtendedProtection"] = exp.ToString();
                    }
                    else
                    {
                        SQLServer["ExtendedProtection"] = extProtWord[exp];
                        SQLServer["ExtProtSPNs"] = "";
                        if (exp > 0)
                        {
                            string[] acceptedSPNs = (string[])(SSNetLib.GetValue("AcceptedSPNs", null));
                            SQLServer["ExtProtSPNs"] = acceptedSPNs == null ? "" : string.Join(", ", acceptedSPNs);
                            SQLServer.LogWarning("JDBC Drivers do not currently support channel binding required by Extended Protection.");
                        }
                    }
                }

                //
                // Get protocol settings
                //

                foreach (string keyName in SSNetLib.GetSubKeyNames())
                {
                    try
                    {
                        protocol = SSNetLib.OpenSubKey(keyName, RegistryKeyPermissionCheck.ReadSubTree,
                                                        System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                        System.Security.AccessControl.RegistryRights.ReadKey |
                                                        System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                        System.Security.AccessControl.RegistryRights.QueryValues);
                        switch (keyName)
                        {
                            case "Np":
                                SQLServer["PipeName"] = protocol.GetValue("PipeName", "").ToString();
                                SQLServer["PipesEnabled"] = protocol.GetValue("Enabled", "").ToInt() == 1;
                                break;
                            case "Sm":
                                SQLServer["SharedMemoryEnabled"] = protocol.GetValue("Enabled", "").ToInt() == 1;
                                break;
                            case "Tcp":
                                IPEnabled = protocol.GetValue("Enabled", "").ToInt() == 1;
                                SQLServer["TCPEnabled"] = IPEnabled;
                                bool allIPs = protocol.GetValue("ListenOnAllIPs", "").ToInt() == 1;
                                SQLServer["ListenOnAllIPs"] = allIPs;
                                if (allIPs == false)
                                {
                                    SQLServer.LogWarning("TCP is not listening on all IP addresses.");
                                    SQLServer["TCPEnabled"] = false; // must check individual IP addresses for at least one enabled
                                    IPEnabled = false;
                                }
                                int keepAlive = protocol.GetValue("KeepAlive", -1).ToInt();
                                SQLServer["KeepAliveInterval"] = keepAlive == -1 ? "" : keepAlive.ToString();
                                foreach (string subkeyName in protocol.GetSubKeyNames())
                                {
                                    if ((allIPs == true && subkeyName.Equals("IPAll", StringComparison.CurrentCultureIgnoreCase) == true) ||
                                        (allIPs == false && subkeyName.Equals("IPAll", StringComparison.CurrentCultureIgnoreCase) == false))
                                    {
                                        try
                                        {
                                            IPKey = protocol.OpenSubKey(subkeyName, RegistryKeyPermissionCheck.ReadSubTree,
                                                                        System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                                        System.Security.AccessControl.RegistryRights.ReadKey |
                                                                        System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                                        System.Security.AccessControl.RegistryRights.QueryValues);
                                            IPAddress = "";
                                            if (allIPs == false)  // can we find an individual IP address that's enabled if IPALL is not set
                                            {
                                                IPAddress = IPKey.GetValue("IPAddress", "<missing>").ToString() + " (";
                                                if (IPKey.GetValue("Enabled", 0).ToInt() == 1) SQLServer["TcpEnabled"] = true;
                                            }
                                            if ((subkeyName.Equals("IPAll",StringComparison.CurrentCultureIgnoreCase) && SQLServer.GetBoolean("TcpEnabled")) || IPEnabled)
                                            {
                                                // fixed port
                                                stringData = IPKey.GetValue("TcpPort", "").ToString();
                                                if (stringData != "")
                                                {
                                                    // first part is if IPAll == true and else part is for individual IP addresses and IPAll == false
                                                    SQLServer["TcpPort"] = IPAddress == "" ? stringData : $"{SQLServer.GetString("TcpPort")} {IPAddress} {stringData})";
                                                }
                                                // dynamic port
                                                stringData = IPKey.GetValue("TcpDynamicPorts", "").ToString();  // !!! this value name is plural, the DataColumn name is not !!!
                                                if (stringData != "")
                                                {
                                                    // first part is if IPAll == true and else part is for individual IP addresses and IPAll == false
                                                    SQLServer["TcpDynamicPort"] = IPAddress == "" ? stringData : $"{SQLServer.GetString("TcpDynamicPort")} {IPAddress} {stringData})";
                                                }
                                            }
                                            if (SQLInstance.GetString("InstanceName") == "MSSQLServer" && (SQLServer.GetString("TcpPort") == "" || SQLServer.GetString("TcpDynamicPort") != ""))
                                            {
                                                SQLServer.LogWarning("Dynamic ports are not supported by the default instance of SQL Server.");
                                            }
                                            IPKey.Close();
                                            IPKey = null;
                                        }
                                        catch (Exception ex3)
                                        {
                                            SQLServer.LogException($@"Failed to open registry key: {keyName}\{subkeyName}", ex3);
                                        }
                                        finally
                                        {
                                            if (IPKey != null) IPKey.Close();
                                        }
                                    }
                                }
                                break;
                            case "Via":
                                // ignore this
                                break;
                            case "AdminConnection":
                                // ignore this
                                break;
                            default:
                                SQLServer.LogWarning($"Unexpected key: {keyName}");
                                break;
                        }
                        protocol.Close();
                        protocol = null;
                    }
                    catch (Exception ex2)
                    {
                        SQLServer.LogException($"Failed to open registry key {keyName}.", ex2);
                    }
                    finally
                    {
                        if (protocol != null) protocol.Close();
                    }
                }
                SSNetLib.Close();
                SSNetLib = null;
            }
            catch (Exception ex)
            {
                SQLServer.LogException("Failed to open the SuperSocketNetlib key.", ex);
            }
            finally
            {
                if (SSNetLib != null) SSNetLib.Close();
            }

        }  // end ProcessMSSQLServer

        public static void ProcessSQLPathAndSPNs(DataSet ds, DataRow SQLInstance, DataRow SQLServer)
        {
            DataRow dr = null, Computer = ds.Tables["Computer"].Rows[0];
            string account = "", suggestedSPN = "", instanceName = "", spnPrefixF = "", spnPrefixN = "";
            DataTable dtService = ds.Tables["Service"];
            DataTable dtSuggestedSPN = ds.Tables["SuggestedSPN"];
            DataRow SuggestedSPN = null;
            DataRow[] Rows = dtService.Select($"Path Like '*{SQLServer.GetString("Path")}*' AND (Name = 'MSSQL' OR Name ='MSSQLSERVER')");
            string SPNServiceAccount = "";

            if (Rows.Length == 0)
            {
                SQLServer.LogCritical("No service appears to be associated with this path.");
            }
            else if (Rows.Length > 1)
            {
                SQLServer.LogCritical("Multiple services appear to be associated with this path.");
            }
            else
            {
                dr = Rows[0];
                if (dr.GetBoolean("Started") == true)
                {
                    SQLServer["ProcessID"] = dr["PID"];
                }
                else
                {
                    SQLServer.LogWarning("Process is not running.");
                }
                account = dr.GetString("ServiceAccount");
                SQLServer["ServiceAccount"] = account;

                //
                // SPN stuff - must be joined to a domain
                //

                if (Computer.GetBoolean("JoinedToDomain") == true)
                {
                    account = dr.GetString("DomainAccount");
                    if (account.EndsWith("$")) account = account.Substring(0, account.Length - 1);
                    SQLServer["SPNServiceAccount"] = account;
                    SPNServiceAccount = account;
                    spnPrefixF = $"MSSQLSvc/{Computer.GetString("FQDN")}";
                    spnPrefixN = $"MSSQLSvc/{Computer.GetString("NETBIOSName")}";
                    // SPNs for TCP/IP
                    if (SQLServer.GetBoolean("TcpEnabled"))
                    {
                        if (SQLServer.GetString("TcpDynamicPort") != "") SQLServer.LogWarning("You should not use SPNs with dynamic ports.");
                        if (SQLServer.GetBoolean("ListenOnAllIPs"))
                        {
                            string[] ports = ($"{SQLServer.GetString("TcpPort")},{SQLServer.GetString("TcpDynamicPort")}").Split(',');
                            foreach (string portNumber in ports)
                            {
                                if (portNumber.IsInt())
                                {
                                    SuggestedSPN = dtSuggestedSPN.NewRow();
                                    dtSuggestedSPN.Rows.Add(SuggestedSPN);
                                    SuggestedSPN["ParentID"] = SQLServer["ID"];
                                    suggestedSPN = $@"{spnPrefixF}:{portNumber}";  // FQDN
                                    SuggestedSPN["SPNNAme"] = suggestedSPN;
                                    CheckSPN(ds, SQLServer, SuggestedSPN, suggestedSPN, SPNServiceAccount);

                                    SuggestedSPN = dtSuggestedSPN.NewRow();
                                    dtSuggestedSPN.Rows.Add(SuggestedSPN);
                                    SuggestedSPN["ParentID"] = SQLServer["ID"];
                                    suggestedSPN = $@"{spnPrefixN}:{portNumber}";  // NETBIOS name
                                    SuggestedSPN["SPNNAme"] = suggestedSPN;
                                    CheckSPN(ds, SQLServer, SuggestedSPN, suggestedSPN, SPNServiceAccount);
                                }
                            }
                        }
                        else  // don't suggest any for individual IP addresses
                        {
                            SQLServer.LogInfo("SQL Server is not listening on all IP addresses. Suggested SPNs not listed.");
                        }
                    }
                    // SPNs for Named Pipes
                    if (SQLServer.GetBoolean("PipesEnabled") || SQLServer.GetBoolean("SharedMemoryEnabled"))
                    {
                        instanceName = SQLInstance.GetString("InstanceName");
                        if (instanceName.Equals("MSSqlServer", StringComparison.CurrentCultureIgnoreCase))
                        {
                            SuggestedSPN = dtSuggestedSPN.NewRow();
                            dtSuggestedSPN.Rows.Add(SuggestedSPN);
                            SuggestedSPN["ParentID"] = SQLServer["ID"];
                            suggestedSPN = $@"{spnPrefixF}";  // FQDN
                            SuggestedSPN["SPNNAme"] = suggestedSPN;
                            CheckSPN(ds, SQLServer, SuggestedSPN, suggestedSPN, SPNServiceAccount);

                            SuggestedSPN = dtSuggestedSPN.NewRow();
                            dtSuggestedSPN.Rows.Add(SuggestedSPN);
                            SuggestedSPN["ParentID"] = SQLServer["ID"];
                            suggestedSPN = $@"{spnPrefixN}";  // NETBIOS name
                            SuggestedSPN["SPNNAme"] = suggestedSPN;
                            CheckSPN(ds, SQLServer, SuggestedSPN, suggestedSPN, SPNServiceAccount);
                        }
                        else
                        {
                            SuggestedSPN = dtSuggestedSPN.NewRow();
                            dtSuggestedSPN.Rows.Add(SuggestedSPN);
                            SuggestedSPN["ParentID"] = SQLServer["ID"];
                            suggestedSPN = $@"{spnPrefixF}:{instanceName}";  // FQDN
                            SuggestedSPN["SPNNAme"] = suggestedSPN;
                            CheckSPN(ds, SQLServer, SuggestedSPN, suggestedSPN, SPNServiceAccount);

                            SuggestedSPN = dtSuggestedSPN.NewRow();
                            dtSuggestedSPN.Rows.Add(SuggestedSPN);
                            SuggestedSPN["ParentID"] = SQLServer["ID"];
                            suggestedSPN = $@"{spnPrefixN}:{instanceName}";  // NETBIOS name
                            SuggestedSPN["SPNNAme"] = suggestedSPN;
                            CheckSPN(ds, SQLServer, SuggestedSPN, suggestedSPN, SPNServiceAccount);
                        }
                    }
                }
            }
        } // end ProcessSQLPathAndSPNs

        public static void CheckSPN(DataSet ds, DataRow SQLServer, DataRow SuggestedSPN, string SPNName, string accountName)  // check that the SPN is on the SQL account name and no other
        {
            DataRow Computer = ds.Tables["Computer"].Rows[0];
            DirectoryEntry dupRoot = null, entry = null;
            DirectorySearcher d = null;
            SearchResultCollection results = null;
            string message = "";

            //
            // Find if the SPN Exists, has duplicates, or is misplaced - could be duplicates that are all missplaced
            //

            try
            {
                // search the computer's domain for duplicates
                dupRoot = new DirectoryEntry($@"LDAP://{Computer["ExpandedName"].ToString()}");  // this is just the domain descriptor and not the computer name
                d = new DirectorySearcher(dupRoot, $"servicePrincipalName={SPNName}", new String[] { "AdsPath", "cn" }, SearchScope.Subtree);
                results = d.FindAll();

                // no results - the SPN does not exist
                if (results.Count == 0)
                {
                    SuggestedSPN["Exists"] = false;
                    SuggestedSPN["Message"] = "SPN does not exist.";
                }

                // one result - the SPN could be good or on the wrong account
                if (results.Count == 1)
                {
                    SearchResult result = results[0];
                    entry = result.GetDirectoryEntry();
                    if (CompareAccounts(entry.Properties["samAccountName"][0].ToString(), accountName) == true)
                    {
                        SuggestedSPN["Exists"] = true;
                        SuggestedSPN["Message"] = "Okay";
                    }
                    else
                    {
                        SuggestedSPN["Exists"] = false;
                        SuggestedSPN["Message"] = $"SPN is on the wrong account: {entry.Properties["samAccountName"][0]}, {entry.Properties["DistinguishedName"][0]}";
                    }
                    entry.Close();
                    entry = null;
                }

                // multiple results - the SPN may or may not exist and there is at least one duplicate
                if (results.Count > 1)
                {
                    message = "Duplicate SPN on account: ";
                    foreach (SearchResult result in results)
                    {
                        entry = result.GetDirectoryEntry();
                        if (CompareAccounts(entry.Properties["samAccountName"][0].ToString(), accountName) == true)
                        {
                            SuggestedSPN["Exists"] = true;
                        }
                        else
                        {
                            message += entry.Properties["samAccountName"][0] + ", ";
                        }
                        entry.Close();
                        entry = null;
                    }
                }
                results.Dispose();
                results = null;
                d.Dispose();
                d = null;
                dupRoot.Close();
                dupRoot = null;
            }
            catch (Exception ex)
            {
                SQLServer.LogException($"There was a problem searching LDAP for SPN {SPNName}.", ex);
            }
            finally
            {
                if (results != null) results.Dispose();
                if (d != null) d.Dispose();
                if (entry != null) entry.Close();
                if (dupRoot != null) dupRoot.Close();
            }
        }

        public static bool CompareAccounts(string account1, string account2)
        {
            string domain1 = "", domain2 = "";

            // trim trailing $ if present

            account1 = account1.EndsWith("$") ? account1.Substring(0, account1.Length -1) : account1;
            account2 = account2.EndsWith("$") ? account2.Substring(0, account2.Length - 1) : account2;

            //
            // Split account1 into a domain and account portions
            //

            if (account1.Contains(@"\") == true)
            {
                domain1 = SmartString.ChopWord(account1, ref account1, @"\");
            }
            else if (account1.Contains(@"@") == true)
            {
                account1 = SmartString.ChopWord(account1, ref domain1, @"\");
            }

            //
            // Split account2 into a domain and account portions
            //

            if (account2.Contains(@"\") == true)
            {
                domain2 = SmartString.ChopWord(account2, ref account2, @"\");
            }
            else if (account1.Contains(@"@") == true)
            {
                account2 = SmartString.ChopWord(account2, ref domain2, @"\");
            }

            //
            // Compare them -  TODO - there might be a better way to match them, maybe their distinguished names???
            //

            // full match
            if (account1.Equals(account2, StringComparison.CurrentCultureIgnoreCase) && domain1.Equals(domain2, StringComparison.CurrentCultureIgnoreCase)) return true;

            // partial match
            if (account1.Equals(account2, StringComparison.CurrentCultureIgnoreCase) && (domain1 =="" || domain2 == "")) return true;

            // no match
            return false;
        }
    }
}
