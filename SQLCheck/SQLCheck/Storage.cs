// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Data;

namespace SQLCheck
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //


    public static class Storage
    {
        /*----------------------------------------------------------------------------
         * DataTable Hierarchy
         * 
         * 
         -----------------------------------------------------------------------------*/
        public static DataSet CreateDataSet(String ComputerName)
        {
            DataSet ds = new DataSet(ComputerName);
            ds.ExtendedProperties.Add("SchemaVersion", Program.schemaVersion);
            DataTable dt = null;

            //
            // Messages
            //

            dt = new DataTable("Message");
            dt.AddColumn("TableName", "String");
            dt.AddColumn("TableRow", "Integer");
            dt.AddColumn("Severity", "Integer");
            dt.AddColumn("Message", "String");
            dt.AddColumn("ExceptionTypeName", "String");
            dt.AddColumn("ExMessage", "String");
            dt.AddColumn("ExSource", "String");
            dt.AddColumn("ExStackTrace", "String");
            ds.Tables.Add(dt);

            //
            // Domain
            //

            dt = new DataTable("Domain");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("DomainName", "String");
            dt.AddColumn("DomainShortName", "String");
            dt.AddColumn("DomainMode", "String");
            dt.AddColumn("ParentDomain", "String");
            dt.AddColumn("RootDomain", "String");
            dt.AddColumn("ForestName", "String");
            dt.AddColumn("ForestMode", "String");
            ds.Tables.Add(dt);

            //
            // Related Domain
            //

            dt = new DataTable("RelatedDomain");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("SourceDomain", "String");
            dt.AddColumn("TargetDomain", "String");
            dt.AddColumn("TrustType", "String");
            dt.AddColumn("TrustDirection", "String");
            dt.AddColumn("SelectiveAuthentication", "Boolean");
            dt.AddColumn("TrustAttributes", "String");
            dt.AddColumn("SupportedEncryptionTypes", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // Root Domain Related Domains - entries not having FOREST_TRANSITIVE flag set
            //

            dt = new DataTable("RootDomainRelatedDomain");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("SourceDomain", "String");
            dt.AddColumn("TargetDomain", "String");
            dt.AddColumn("TrustType", "String");
            dt.AddColumn("TrustDirection", "String");
            dt.AddColumn("SelectiveAuthentication", "Boolean");
            dt.AddColumn("TrustAttributes", "String");
            dt.AddColumn("SupportedEncryptionTypes", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // Forest Related Domains - entries having FOREST_TRANSITIVE flag set
            //

            dt = new DataTable("ForestRelatedDomain");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("SourceForest", "String");
            dt.AddColumn("TargetDomain", "String");
            dt.AddColumn("TrustType", "String");
            dt.AddColumn("TrustDirection", "String");
            dt.AddColumn("SelectiveAuthentication", "Boolean");
            dt.AddColumn("TrustAttributes", "String");
            dt.AddColumn("SupportedEncryptionTypes", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // Computer
            //

            dt = new DataTable("Computer");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("CurrentUser", "String");
            dt.AddColumn("NETBIOSName", "String");
            dt.AddColumn("FQDN", "String");
            dt.AddColumn("DNSSuffix", "String");
            dt.AddColumn("ExpandedName", "String");
            dt.AddColumn("CurrentDC", "String");
            dt.AddColumn("CPU64Bit", "Boolean");
            dt.AddColumn("ComputerRole", "String");
            dt.AddColumn("DomainOrWorkgroupName", "String");
            dt.AddColumn("JoinedToDomain", "Boolean");
            dt.AddColumn("ConnectedToDomain", "Boolean");
            dt.AddColumn("ProgramFilesFolder", "String");
            dt.AddColumn("ProgramFilesx86Folder", "String");
            dt.AddColumn("CommonFilesFolder", "String");
            dt.AddColumn("CommonFilesx86Folder", "String");
            dt.AddColumn("WindowsName", "String");
            dt.AddColumn("WindowsVersion", "String");
            dt.AddColumn("MajorVersion", "String");
            dt.AddColumn("MinorVersion", "String");
            dt.AddColumn("WindowsBuild", "String");
            dt.AddColumn("WindowsReleaseID", "String");
            dt.AddColumn("WindowsUBR", "String");
            dt.AddColumn("CLR4Version", "String");
            dt.AddColumn("CLR4StrongCrypto", "String");
            dt.AddColumn("CLR4StrongCryptoX86", "String");
            dt.AddColumn("CLR2Version", "String");
            dt.AddColumn("CLR2StrongCrypto", "String");
            dt.AddColumn("CLR2StrongCryptoX86", "String");
            dt.AddColumn("IISRunning", "Boolean");         // added when enumerating services
            dt.AddColumn("Clustered", "Boolean");
            dt.AddColumn("DiffieHellmanVersion", "String");
            dt.AddColumn("RebootNeeded", "Boolean");
            dt.AddColumn("LastSystemReboot", "DateTime");    // added to display last system reboot  clintonw 9/8/2022
            dt.AddColumn("CredentialGuard", "Boolean");
            dt.AddColumn("VNetFltExists", "Boolean");  // VMWare driver that may cause packet delays
            ds.Tables.Add(dt);

            //
            // Security
            //

            dt = new DataTable("Security");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("CrashOnAuditFail", "String", @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa!CrashOnAuditFail");
            dt.AddColumn("LanmanCompatibilityLevel", "String", @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa!LMCompatibilityLevel");
            dt.AddColumn("DisableLoopbackCheck", "String", @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa!DisableLoopbackCheck");
            dt.AddColumn("BackConnectionHostNames", "String", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0!BackConnectionHostNames");
            dt.AddColumn("MaxTokenSize", "String", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters!MaxTokenSize");
            dt.AddColumn("KerberosLogLevel", "String", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters!LogLevel");
            dt.AddColumn("KerberosLocalEncryption", "String", @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters!SupportedEncryptionTypes");
            dt.AddColumn("FIPSEnabled", "String", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy!Enabled");
            ds.Tables.Add(dt);

            //
            // TLS
            //

            dt = new DataTable("TLS");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("TLSVersion", "String");                // SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
            dt.AddColumn("ClientOrServer", "String");            // Client or Server
            dt.AddColumn("DefaultValue", "String");              // got from OS version mapping table: Not Supported, Disabled, Enabled
            dt.AddColumn("EnabledValue", "String");              // under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
            dt.AddColumn("DisabledByDefaultValue", "String");    // under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
            dt.AddColumn("EffectiveValue", "String");            // 
            ds.Tables.Add(dt);

            //
            // ProtocolOrder
            //

            dt = new DataTable("ProtocolOrder");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("RegistryList", "String");     // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 | Functions REG_MULTI_SZ
            dt.AddColumn("PolicyList", "String");       // HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002 ! Functions REG_SZ, comma-delimited
            ds.Tables.Add(dt);

            //
            // ODBC
            //

            dt = new DataTable("ODBC");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("ODBC_User_Trace", "String", @"HKEY_CURRENT_USER\Software\ODBC\ODBC.INI\ODBC!Trace");
            dt.AddColumn("ODBC_Machine_Trace", "String", @"HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBC.INI\ODBC!Trace");
            dt.AddColumn("ODBC_User_Trace_WOW", "String", @"HKEY_CURRENT_USER\Software\Wow6432Node\ODBC\ODBC.INI\ODBC!Trace");
            dt.AddColumn("ODBC_Machine_Trace_WOW", "String", @"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ODBC\ODBC.INI\ODBC!Trace");
            ds.Tables.Add(dt);

            //
            // Network - Global Network Settings - use NETSH where possible
            //

            dt = new DataTable("Network");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("TcpMaxDataRetransmissions", "String");
            dt.AddColumn("InitialRTO", "String");
            dt.AddColumn("MaxSYNRetransmissions", "String");
            dt.AddColumn("EnableTCPChimney", "String");
            dt.AddColumn("EnableRSS", "String");
            dt.AddColumn("EnableTCPA", "String");
            dt.AddColumn("MinUserPort", "String");
            dt.AddColumn("MaxUserPort", "String");
            dt.AddColumn("TcpTimedWaitDelay", "String");
            dt.AddColumn("SynAttackProtect", "String");
            ds.Tables.Add(dt);

            //
            // Network Adapter
            //

            dt = new DataTable("NetworkAdapter");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("Name", "String");
            dt.AddColumn("AdapterType", "String");
            dt.AddColumn("DriverDate", "String");
            dt.AddColumn("Speed", "String");
            dt.AddColumn("SpeedDuplex", "String", "Speed/Duplex");
            dt.AddColumn("FlowControl", "String", "Flow Control");
            dt.AddColumn("RSS", "String", "Receive Side Scaling");
            dt.AddColumn("JumboPacket", "String", "Jumbo Frames");
            dt.AddColumn("NICTeaming", "Boolean");
            dt.AddColumn("MACAddress", "String", "MAC Address");
            ds.Tables.Add(dt);

            //
            // FLTMC filters
            //

            dt = new DataTable("FLTMC");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("Name", "String");
            ds.Tables.Add(dt);

            //
            // Network Mini Driver
            //

            dt = new DataTable("NetworkMiniDriver");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("Service", "String", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}\*\Ndi!Service");
            dt.AddColumn("HelpText", "String", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}\*\Ndi!HelpText");
            dt.AddColumn("FilterMediaTypes", "String", @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}\*\Ndi\Interfaces!FilterMediaTypes");
            ds.Tables.Add(dt);

            //
            // Disk Drive
            //

            dt = new DataTable("DiskDrive");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("Drive", "String");
            dt.AddColumn("DriveType", "String");
            dt.AddColumn("DriveFormat", "String");
            dt.AddColumn("Capacity", "String");
            dt.AddColumn("BytesFree", "String");
            dt.AddColumn("PctFree", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // Host Alias - Aliases defined in the DNS database
            //

            dt = new DataTable("HostAlias");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("DNS_Alias", "String");
            ds.Tables.Add(dt);

            //
            // Hosts Entries - Aliases defined in the hosts file
            //

            dt = new DataTable("HostsEntries");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("HostsEntry", "String");
            ds.Tables.Add(dt);

            //
            // IP Address
            //

            dt = new DataTable("IPAddress");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("AddressFamily", "String");
            dt.AddColumn("Address", "String");
            ds.Tables.Add(dt);

            //
            // SQL Client Driver
            //

            dt = new DataTable("DatabaseDriver");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("DriverName", "String");
            dt.AddColumn("DriverType", "String");
            dt.AddColumn("Guid", "String");
            dt.AddColumn("Path", "String");
            dt.AddColumn("Version", "String");
            dt.AddColumn("TLS12", "String");
            dt.AddColumn("TLS13", "String");
            dt.AddColumn("ServerCompatibility", "String");
            dt.AddColumn("Supported", "String");
            dt.AddColumn("MultiSubnetFailoverSupport", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // ADAL DLLs
            //

            dt = new DataTable("ADALFile");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("FilePath", "String");
            dt.AddColumn("Version", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // ADAL Regsitry Keys
            //

            dt = new DataTable("ADALRegistry");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("RegPath", "String");
            dt.AddColumn("FilePath", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // Process with our drivers in them (and maybe some other drivers and DLLs)
            //

            dt = new DataTable("ProcessDrivers");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("ProcessName", "String");
            dt.AddColumn("ProcessID", "String");
            dt.AddColumn("DriverList", "String");
            ds.Tables.Add(dt);

            //
            // SQL Client SNI Settings
            //

            dt = new DataTable("ClientSNI");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("Name", "String");
            dt.AddColumn("64bit", "Boolean");
            dt.AddColumn("ProtocolOrder", "String");
            dt.AddColumn("ForceEncryption", "Boolean");
            dt.AddColumn("TrustServerCertificate", "Boolean");
            dt.AddColumn("TcpDefaultPort", "String");
            dt.AddColumn("TcpKeepAliveInterval", "String");
            dt.AddColumn("TcpKeepAliveRetryInterval", "String");
            ds.Tables.Add(dt);

            //
            // SQL Client Aliases
            //

            dt = new DataTable("SQLAlias");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("AliasName", "String");
            dt.AddColumn("Protocol", "String");
            dt.AddColumn("ServerName", "String");
            dt.AddColumn("Port", "String");
            dt.AddColumn("64bit", "Boolean");
            ds.Tables.Add(dt);

            //
            // Services
            //

            dt = new DataTable("Service");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("Name", "String");
            dt.AddColumn("Instance", "String");
            dt.AddColumn("PID", "String");
            dt.AddColumn("Description", "String");
            dt.AddColumn("Path", "String");
            dt.AddColumn("ServiceAccount", "String");
            dt.AddColumn("DomainAccount", "String");
            dt.AddColumn("StartMode", "String");
            dt.AddColumn("Started", "Boolean");
            dt.AddColumn("Status", "String");
            ds.Tables.Add(dt);

            //
            // SPN Account
            //
            // One entry per unique DomainAccount from the Service table
            //

            dt = new DataTable("SPNAccount");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("Account", "String");
            dt.AddColumn("Domain", "String");
            dt.AddColumn("DistinguishedName", "String");
            dt.AddColumn("AccountType", "String");
            dt.AddColumn("UserAccountControl", "String");
            dt.AddColumn("TrustedForDelegation", "Boolean");
            dt.AddColumn("KerberosEncryption", "String");
            dt.AddColumn("Sensitive", "Boolean");
            dt.AddColumn("ConstrainedDelegationEnabled", "Boolean");
            ds.Tables.Add(dt);

            //
            // Constrained Delegation SPN - target SPNs
            //

            dt = new DataTable("ConstrainedDelegationSPN");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("ServiceAccount", "String");
            dt.AddColumn("SPN", "String");
            ds.Tables.Add(dt);

            //
            // SPN - on the service account
            //

            dt = new DataTable("SPN");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("ServiceAccount", "String");
            dt.AddColumn("SPN", "String");
            dt.AddColumn("HasDuplicates", "Boolean");
            ds.Tables.Add(dt);

            //
            // SQL Instance
            //

            dt = new DataTable("SQLInstance");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("InstanceType", "String");
            dt.AddColumn("InstanceName", "String");
            dt.AddColumn("InstanceFolder", "String");
            dt.AddColumn("Wow64Node", "Boolean");
            ds.Tables.Add(dt);

            //
            // SQL Server - Child of SQL Instance
            //
            // Just for the database engine, not SSRS or OLAP
            // SQL 2005 and later - SQL 2000 not included
            //

            dt = new DataTable("SQLServer");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("InstanceName", "String");
            dt.AddColumn("Version", "String");
            dt.AddColumn("ServicePack", "String");
            dt.AddColumn("PatchLevel", "String");
            dt.AddColumn("Edition", "String");
            dt.AddColumn("Clustered", "Boolean");
            dt.AddColumn("AlwaysOn", "Boolean");                // new
            dt.AddColumn("AlwaysOnServers", "String");          // new
            dt.AddColumn("Listeners", "String");                // new
            dt.AddColumn("AvailabilityGroups", "String");       // new
            dt.AddColumn("ReplicationPorts", "String");         // new
            dt.AddColumn("AuthenticationMode", "String");       // new
            dt.AddColumn("Certificate", "String");
            dt.AddColumn("Hidden", "Boolean");
            dt.AddColumn("ExtendedProtection", "String");
            dt.AddColumn("ExtProtSPNs", "String");
            dt.AddColumn("ForceEncryption", "Boolean");
            dt.AddColumn("SharedMemoryEnabled", "Boolean");
            dt.AddColumn("PipesEnabled", "Boolean");
            dt.AddColumn("PipeName", "String");
            dt.AddColumn("TCPEnabled", "Boolean");
            dt.AddColumn("ListenOnAllIPs", "Boolean");
            dt.AddColumn("KeepAliveInterval", "String");
            dt.AddColumn("TCPPort", "String");
            dt.AddColumn("TCPDynamicPort", "String");
            dt.AddColumn("Path", "String");
            dt.AddColumn("ProcessID", "String");
            dt.AddColumn("ErrorLogPath", "String");
            dt.AddColumn("ServiceAccount", "String");
            dt.AddColumn("SPNServiceAccount", "String");
            ds.Tables.Add(dt);

            //
            // SuggestedSPN - Child of SQLServer
            //

            dt = new DataTable("SuggestedSPN");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("SPNName", "String");
            dt.AddColumn("Exists", "Boolean");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            //
            // Certificate
            //

            dt = new DataTable("Certificate");
            dt.AddColumn("ID", "Integer");
            dt.Columns["ID"].AutoIncrement = true;
            dt.AddColumn("ParentID", "Integer");
            dt.AddColumn("FriendlyName", "String");
            dt.AddColumn("Issuer", "String");
            dt.AddColumn("CommonName", "String");
            dt.AddColumn("SubjectAlternativeName", "String");
            dt.AddColumn("ThumbPrint", "String");
            dt.AddColumn("SignatureAlgorithm", "String");
            dt.AddColumn("KeySize", "String");
            dt.AddColumn("KeySpec", "String");
            dt.AddColumn("KeyUsage", "String");
            dt.AddColumn("ServerCert", "Boolean");
            dt.AddColumn("HasPrivateKey", "Boolean");
            dt.AddColumn("NotBefore", "String");
            dt.AddColumn("NotAfter", "String");
            dt.AddColumn("Message", "String");
            ds.Tables.Add(dt);

            return ds;
        }

        //public static void SaveDataSet(DataSet ds, string filePath)
        //{
        //    try
        //    {
        //        ds.WriteXml(filePath, XmlWriteMode.WriteSchema);
        //    }
        //    catch (Exception ex)
        //    {
        //        //DisplayException("There was an error saving the data.", ex);
        //    }
        //}

        //public static DataSet LoadDataSet(string filePath)
        //{
        //    DataSet ds = null;
        //    try
        //    {
        //        ds = new DataSet();
        //        ds.ReadXml(filePath);
        //        int dsSchemaVersion = 0;
        //        if (ds.ExtendedProperties.ContainsKey("SchemaVersion"))
        //        {
        //            try
        //            {
        //                dsSchemaVersion = (int)ds.ExtendedProperties["SchemaVersion"];
        //            }
        //            catch (Exception ex)
        //            {
        //                // TODO display message saying there was a problem determining the DataSet version
        //                return null;
        //            }
        //            if (dsSchemaVersion > Program.schemaVersion)
        //            {
        //                // TODO display message that the DataSet is newer than the app and to upgrade the application
        //                return null;
        //            }
        //        }
        //        else
        //        {
        //            // TODO display messgage that the DataSet is not versioned
        //            return null;
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        // TODO DisplayException("There was an error reading the data.", ex);
        //        return null;
        //    }
        //    return ds;
        //}

        //
        // Extension method for DataSet, DataTable, DataRow, including message logging
        //

        public enum SeverityLevel
        {
            Critical = 3,
            Exception = 4,
            Heading = 5,
            Info = 1,
            Verbose = 0,
            Warning = 2
        }

        public static void AddColumn(this DataTable dt, string ColumnName, string DataType, string Caption = "")
        {
            dt.Columns.Add(ColumnName, Type.GetType("System." + (DataType == "Integer" ? "Int32" : DataType))).Caption = Caption;
        }

        public static string GetString(this DataRow dr, string ColumnName)
        {
            if (dr.Table.Columns.Contains(ColumnName))
            {
                return dr[ColumnName].ToString();
            }
            return "<not collected>";  // If the column does not exist, return "<not collected>" - necessary when reading older files that may not have every field
        }

        public static string GetString(this DataRowView drv, string ColumnName)
        {
            if (drv.DataView.Table.Columns.Contains(ColumnName))
            {
                return drv[ColumnName].ToString();
            }
            return "<not collected>";  // If the column does not exist, return "<not collected>" - necessary when reading older files that may not have every field
        }

        public static bool GetBoolean(this DataRow dr, string ColumnName)  // returns false if any issues at all
        {
            if (dr.Table.Columns.Contains(ColumnName) && dr[ColumnName] != DBNull.Value)
            {
                return (bool)dr[ColumnName];
            }
            return false;
        }

        public static bool GetBoolean(this DataRowView drv, string ColumnName)  // returns false if any issues at all
        {
            if (drv.DataView.Table.Columns.Contains(ColumnName) && drv[ColumnName] != DBNull.Value)
            {
                return (bool)drv[ColumnName];
            }
            return false;
        }

        public static int GetInteger(this DataRow dr, string ColumnName)  // returns 0 if any issues at all
        {
            if (dr.Table.Columns.Contains(ColumnName) && dr[ColumnName] != DBNull.Value)
            {
                return (int)dr[ColumnName];
            }
            return 0;
        }

        public static int GetInteger(this DataRowView drv, string ColumnName)  // returns 0 if any issues at all
        {
            if (drv.DataView.Table.Columns.Contains(ColumnName) && drv[ColumnName] != DBNull.Value)
            {
                return (int)drv[ColumnName];
            }
            return 0;
        }

        public static void CheckRange(this DataRow dr, string RegName, object RegValue, int LowVal, int HighVal)
        {
            int value = 0;
            if (int.TryParse(RegValue.ToString(), out value))
            {
                if (value < LowVal || value > HighVal) dr.LogCritical($"Valid range for {RegName} is {LowVal}..{HighVal}.");
            }
        }

        public static void LogMessage(this DataRow dr, string message, SeverityLevel severity = SeverityLevel.Info, Exception exRecord = null)
        {
            DataTable dtMessage = dr.Table.DataSet.Tables["Message"];
            DataRow drMessage = dtMessage.NewRow();
            if (dr != null)
            {
                drMessage["TableName"] = dr.Table.TableName;
                drMessage["TableRow"] = dr["ID"];
            }

            drMessage["Severity"] = severity;
            drMessage["Message"] = message;

            if (exRecord != null)
            {
                drMessage["Severity"] = SeverityLevel.Exception;
                drMessage["ExMessage"] = exRecord.Message;
                drMessage["ExceptionTypeName"] = exRecord.GetType().Name;
                drMessage["ExSource"] = exRecord.Source;
                drMessage["ExStacktrace"] = exRecord.StackTrace;
            }
            dtMessage.Rows.Add(drMessage);
        }

        public static void LogMessage(this DataTable dt, string message, SeverityLevel severity = SeverityLevel.Info, Exception exRecord = null)
        {
            DataTable dtMessage = dt.DataSet.Tables["Message"];
            DataRow drMessage = dtMessage.NewRow();
            if (dt != null)
            {
                drMessage["TableName"] = dt.TableName;
            }

            drMessage["Severity"] = severity;
            drMessage["Message"] = message;

            if (exRecord != null)
            {
                drMessage["Severity"] = SeverityLevel.Exception;
                drMessage["ExMessage"] = exRecord.Message;
                drMessage["ExceptionTypeName"] = exRecord.GetType().Name;
                drMessage["ExSource"] = exRecord.Source;
                drMessage["ExStacktrace"] = exRecord.StackTrace;
            }
            dtMessage.Rows.Add(drMessage);
        }

        public static void LogVerbose(this DataRow dr, string message)
        {
            LogMessage(dr, message, SeverityLevel.Verbose);
        }

        public static void LogWarning(this DataRow dr, string message)
        {
            LogMessage(dr, message, SeverityLevel.Warning);
        }

        public static void LogCritical(this DataRow dr, string message)
        {
            LogMessage(dr, message, SeverityLevel.Critical);
        }

        public static void LogException(this DataRow dr, string message, Exception exRecord)
        {
            LogMessage(dr, message, SeverityLevel.Exception, exRecord);
        }
        public static void LogHeading(this DataRow dr, string message)
        {
            LogMessage(dr, message, SeverityLevel.Heading);
        }
        public static void LogInfo(this DataRow dr, string message)
        {
            LogMessage(dr, message, SeverityLevel.Info);
        }
    }
}
