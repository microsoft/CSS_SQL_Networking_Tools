// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Diagnostics;
using System.Data;
using System.Data.OleDb;
using Microsoft.Win32;

namespace SQLCheck
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    

    public class DriverInfo
    {
        public string DriverName = "";
        public string DriverType = "";
        public string MinTLS12Version = "";  // "Yes" means all versions support it, "No" means none, vresion # = the minimum version that does support it
        public string MinTLS13Version = "";
        public string ServerCompatibility = "";
        public string Supported = "";
        public string MultiSubnetFailover = "";

        public DriverInfo(string driverName, string driverType, string minTLS12Version, string minTLS13Version, string serverCompatibility, string supported, string multiSubnetFailover)
        {

            DriverName = driverName;
            DriverType = driverType;
            MinTLS12Version = minTLS12Version;
            MinTLS13Version = minTLS13Version;
            ServerCompatibility = serverCompatibility;
            Supported = supported;
            MultiSubnetFailover = multiSubnetFailover;
        }

        public static DriverInfo GetDriverInfo(string driverName, FileVersionInfo versionInfo, string WindowsVersion, string WindowsDisplayVersion)  // TODO - fix up MinTLSVersion and Server Support
        {
            string TLS12 = "No";
            string TLS13 = "No";

            // SQLOLEDB and SQL Server

            // A customer report:
            // OS version: Windows 10 Pro 10.0.18362 (Failed to connect to TLS 1.2 enabled server)
            // OS version: Windows 10 Pro 10.0.18363 (Able to connect using TLS 1.2)

            // Windows 10 December 2020 cumulative updates:

            // KB4593226(Build 14393.4104) for version 1607.
            // KB4592473(Build 15063.2584) for version 1703.
            // KB4592446(Build 17134.1902) for version 1803.
            // KB4592440(Build 17763.1637) for version 1809.  // my Windows Server is this
            // KB4592449(Build 18362.1256 and Build 18363.1256) for version 1903 and 1909.
            // KB4592438(Build 19041.685 and Build 19042.685) for version 2004 and 20H2.

            switch (driverName)
            {
                case "SQLOLEDB":
                case "SQL Server":
                    // switch (WindowsReleaseID.ToUpper())   // okay for pre-Win 11 or Win 2022
                    switch (WindowsDisplayVersion.ToUpper())
                    {
                        case "":            // Windows 8.1/2012 R2 and earlier - Won't fix these versions: Windows 2003, XP, 2008, 2008 R2, 2012
                                            // Windows 8.1 and Windows 2012 R2 = version 6.3.9600 - what build supports the updated DBNETLIB.DLL???
                            break;
                        case "1507":        // Windows 10       Threshold 1                        build 10240  July 29, 2015
                            TLS12 = "No";   // Won't fix
                            break;
                        case "1511":        // Windows 10       Threshold 2  November update       build 10586  November 10, 2015
                            TLS12 = "No";   // Won't fix
                            break;
                        case "1607":        // Windows 10/2016  Redstone 1   Anniversary Update    build 14393  August 2, 2016 - Windows 2016 release
                            TLS12 = "No";   // Won't fix
                            break;
                        case "1703":        // Windows 10/2016  Redstone 2   Creators Update       build 15063  April 5, 2017
                            TLS12 = "No";   // Won't fix
                            break;
                        case "1709":        // Windows 10/2016  Redstone 3   Fall Creators Update  build 16299  October 17, 2017
                            TLS12 = "No";   // Won't fix
                            break;
                        case "1803":        // Windows 10/2016  Redstone 4   April 2018 Update     build 17134  April 30, 2018
                            TLS12 = "No";   // Won't fix
                            break;
                        case "1809":        // Windows 10/2019  Redstone 5   October 2018 Update   build 17763  November 13, 2018 - Windows 2019 release
                                            // 17763.1554 has fix KBkb4580390 October 20, 2020
                            if (Utility.CompareVersion(WindowsVersion, "10.0.17763") == "=" && Utility.CompareVersion(WindowsVersion, "10.0.17763.1553") == ">") TLS12 = "Yes";
                            break;
                        case "1903":        // Windows 10/2019  19H1         May 2019 Update       build 18362  May 21, 2019
                                            // 18362.1171 has not -> 18362.1198 has the fix KB4580386 October 20, 2020
                            if (Utility.CompareVersion(WindowsVersion, "10.0.18362") == "=" && Utility.CompareVersion(WindowsVersion, "10.0.18362.1197") == ">") TLS12 = "Yes";
                            break;
                        case "1909":        // Windows 10/2019  19H2         November 2019 Update  build 18363  November 12, 2019
                                            // 18363.1171 has not -> 18363.1198 has the fix KB4580386 October 20, 2020
                            if (Utility.CompareVersion(WindowsVersion, "10.0.18363") == "=" && Utility.CompareVersion(WindowsVersion, "10.0.18363.1197") == ">") TLS12 = "Yes";
                            break;
                        case "2004":        // Windows 10/2019  20H1         May 2020 Update       build 19041  May 27, 2020
                                            // 19041.610 has the fix KB4580386 October 20, 2020
                            if (Utility.CompareVersion(WindowsVersion, "10.0.19041") == "=" && Utility.CompareVersion(WindowsVersion, "10.0.19041.609") == ">") TLS12 = "Yes";
                            break;
                        case "20H2":        // Windows 10/2019  20H2         October 2020 Update   build 19042  October 20, 2020
                                            // 19042.610 has the fix KB4580386 October 20, 2020
                            if (Utility.CompareVersion(WindowsVersion, "10.0.19042") == "=" && Utility.CompareVersion(WindowsVersion, "10.0.19042.609") == ">") TLS12 = "Yes";
                            break;
                        case "21H1":        // Windows 10/2019  21H1         ????                  build 19043  ????
                        case "IRON":        // more at https://microsoft.visualstudio.com/OS/_workitems/edit/27324781
                        case "21H2":
                        case "22H2":
                        case "23H2":
                        case "24H2":
                            TLS12 = "Yes";
                            break;
                        default:           // all versions of Winodws 11 or 2022 or greater support TLS 1.2
                            if (Utility.CompareVersion(WindowsVersion, "10.0.19999") == ">") TLS12 = "Yes";
                            break;
                    }
                    break;
                case "SQLNCLI10":
                case "SQL Server Native Client 10.0":
                    // SQLNCLI10 and SQL Server Native Client 10.0
                    if (versionInfo == null)
                    {
                        TLS12 = "Unknown";
                        break;
                    }
                    if (versionInfo.ProductMajorPart == 10 && versionInfo.ProductMinorPart ==  0 && versionInfo.ProductBuildPart >= 6543) TLS12 = "Yes";   // 10.0
                    if (versionInfo.ProductMajorPart == 10 && versionInfo.ProductMinorPart == 50 && versionInfo.ProductBuildPart >= 6537) TLS12 = "Yes";   // 10.50
                    if (versionInfo.ProductMajorPart == 10 && versionInfo.ProductMinorPart == 51 && versionInfo.ProductBuildPart >= 6537) TLS12 = "Yes";   // 10.51
                    break;
                case "SQLNCLI11":
                case "SQL Server Native Client 11.0":
                    // SQLNCLI11 and SQL Server Native Client 11.0
                    if (versionInfo == null)
                    {
                        TLS12 = "Unknown";
                        break;
                    }
                    if (versionInfo.ProductMajorPart == 11 && versionInfo.ProductMinorPart == 0 && versionInfo.ProductBuildPart >= 6538) TLS12 = "Yes";
                    break;
                case "ODBC Driver 11 for SQL Server":
                    // ODBC Driver 11 for SQL Server
                    if (versionInfo == null)
                    {
                        TLS12 = "Unknown";
                        break;
                    }
                    if (versionInfo.ProductMajorPart == 12 && versionInfo.ProductMinorPart == 0 && versionInfo.ProductBuildPart >= 4219) TLS12 = "Yes";
                    break;
                case "MSOLEDBSQL19":
                    // Which versions of Windows Support TLS 1.3 - if we fail this, return No
                    // https://docs.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-#tls-protocol-version-support
                    // Which versions of the driver support TLS 1.3 - if we fail this, return No
                    if (versionInfo == null)
                    {
                        TLS13 = "Unknown";
                        break;
                    }
                    TLS13 = "No"; // right now while we are in the initial release. Will be added, soon.
                    break;
                case "ODBC Driver 18 for SQL Server":
                    // Which versions of Windows Support TLS 1.3 - if we fail this, return No
                    // https://docs.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-#tls-protocol-version-support
                    // Which versions of the driver support TLS 1.3 - if we fail this, return No
                    if (versionInfo == null)
                    {
                        TLS13 = "Unknown";
                        break;
                    }
                    TLS13 = "No"; // right now while we are in the initial release. Will be added, soon.
                    break;
            }

            switch (driverName)
            {                                                        //      Name        Type      TLS12  TLS13    Server Support         Supported      MSF
                case "SQLOLEDB":                       return new DriverInfo(driverName, "OLE DB", TLS12, "No",    "SQL 7.0 - SQL 2019",  "Deprecated",  "No");
                case "SQLNCLI":                        return new DriverInfo(driverName, "OLE DB", "No",  "No",    "SQL 7.0 - SQL 2019",  "No",          "No");
                case "SQLNCLI10":                      return new DriverInfo(driverName, "OLE DB", TLS12, "No",    "SQL 7.0 - SQL 2019",  "No",          "No");
                case "SQLNCLI11":                      return new DriverInfo(driverName, "OLE DB", TLS12, "No",    "SQL 7.0 - SQL 2019",  "No",          "No");
                case "MSOLEDBSQL":                     return new DriverInfo(driverName, "OLE DB", "Yes", "No",    "SQL 2005 - SQL 2019", "Yes",         "Yes");
                case "MSOLEDBSQL19":                   return new DriverInfo(driverName, "OLE DB", "Yes", TLS13,   "SQL 2005 - SQL 2022", "Yes",         "Yes");
                case "SQL Server":                     return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "Deprecated",  "No");
                case "SQL Server Native Client 9.0":   return new DriverInfo(driverName, "ODBC",   "No",  "No",    "SQL 7.0 - SQL 2019",  "No",          "No");
                case "SQL Server Native Client 10.0":  return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "No",          "No");
                case "SQL Server Native Client 11.0":  return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "No",          "Yes");
                case "ODBC Driver 11 for SQL Server":  return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "Yes",         "Yes");
                case "ODBC Driver 13 for SQL Server":  return new DriverInfo(driverName, "ODBC",   "Yes", "No",    "SQL 7.0 - SQL 2019",  "Yes",         "Yes");
                case "ODBC Driver 17 for SQL Server":  return new DriverInfo(driverName, "ODBC",   "Yes", "No",    "SQL 2005 - SQL 2019", "Yes",         "Yes");
                case "ODBC Driver 18 for SQL Server":  return new DriverInfo(driverName, "ODBC",   "Yes", TLS13,   "SQL 2005 - SQL 2022", "Yes",         "Yes");
                default:
                    return null;
            }
        }

        public static string[] GetAllNames()
        {
            return new string[] {"SQLOLEDB",
                                 "SQLNCLI",
                                 "SQLNCLI10",
                                 "SQLNCLI11",
                                 "MSOLEDBSQL",
                                 "MSOLEDBSQL19",
                                  "SQL Server",
                                  "SQL Server Native Client 9.0",
                                  "SQL Server Native Client 10.0",
                                  "SQL Server Native Client 11.0",
                                  "ODBC Driver 11 for SQL Server",
                                  "ODBC Driver 13 for SQL Server",
                                  "ODBC Driver 17 for SQL Server",
                                  "ODBC Driver 18 for SQL Server"};
        }

        public static string[] GetOLEDBNames()
        {
            return new string[] {"SQLOLEDB",
                                 "SQLNCLI",
                                 "SQLNCLI10",
                                 "SQLNCLI11",
                                 "MSOLEDBSQL",
                                 "MSOLEDBSQL19"};
        }

        //public static string[] GetExtendedOLEDBNames()
        //{
        //    return new string[] {"SQLOLEDB",
        //                         "SQLNCLI",
        //                         "SQLNCLI10",
        //                         "SQLNCLI11",
        //                         "MSOLEDBSQL",
        //                         "MSOLEDBSQL19",
        //                         "Microsoft.ACE.OLEDB.10.0",   // supported by Office (Access)
        //                         "Microsoft.ACE.OLEDB.12.0",   // supported by Office (Access)
        //                         "Microsoft.ACE.OLEDB.16.0",   // supported by Office (Access)
        //                         "MSOLAP",                     // supported by Analysis Services (SSAS)
        //                         "ADSDSOObject",               // supported by Active Directory
        //                         "Sybase.ASEOLEDBProvider",    // supported by Sybase
        //                         "MySQLProv",                  // supported by MySQL
        //                         "Ifxoledbc",                  // supported by IBM/Informix
        //                         "IBMDA400",                   // supported by IBM AS/400 DB/2 database
        //                         "IBMDADB2",                   // supported by IBM DB/2 database
        //                         "DB2OLEDB",                   // supported by Microsoft Host Integration Services (HIS)
        //                         "OraOLEDB.Oracle"};           // supported by Oracle
        //}

        public static DataTable GetExtendedOLEDBNames(bool is64bit)
        {
            String[] MSFT_SQL_Providers = GetOLEDBNames();

            // fill the list with unordered provider information
            DataTable dtProviders = new DataTable("Unordered Providers");
            dtProviders = GetOLEDBProvidersTable();                                  // 32-bit or 64-bit registry scan depending on OS architecture
            if (is64bit) dtProviders.Merge(GetOLEDBProvidersTable(true));            // 32-bit registry scan

            DataTable dt = new DataTable("EnumeratedProviders");
            dt.AddColumn("ProgID", "String");
            dt.AddColumn("CLSID", "String");
            dt.AddColumn("Path", "String");
            dt.AddColumn("Description", "String");

            // Add the data for the Microsoft Providers for SQL Server

            DataView dv = new DataView(dtProviders);
            foreach (string ProgID in MSFT_SQL_Providers)
            {
                dv.RowFilter = $"ProgID='{ProgID}'";
                dv.Sort = "ProgID,Path";                                               // keep the 64-bit and 32-bit ProgIDs together
                foreach (DataRowView drv in dv)                                             // the providers in our list have only 1 version each as they are side-by-side with different PROGID names, unlike MSOLAP
                {
                    DataRow row = dt.NewRow();
                    row["ProgID"] = drv["ProgID"];
                    row["CLSID"] = drv["GUID"];
                    row["Path"] = drv["Path"];
                    row["Description"] = drv["Description"];
                    dt.Rows.Add(row);
                    dv[0].Row.Delete();                                            // removes the row from future consideration
                }
            }

            // add Providers that are not on the list in alphabetical order
            dv.RowFilter = "";
            dv.Sort = "ProgID,Path";
            foreach (DataRowView drv in dv)
            {
                DataRow row = dt.NewRow();
                row["ProgID"] = drv["ProgID"];
                row["CLSID"] = drv["GUID"];
                row["Path"] = drv["Path"];
                row["Description"] = drv["Description"];
                dt.Rows.Add(row);
            }

            return dt;
        }

        // this is based on they way MSDAENUM.GetRootEnumerator works
        public static DataTable GetOLEDBProvidersTable(bool WowMode = false)
        {
            DataTable dt = new DataTable();
            dt.AddColumn("ProgID", "String");
            dt.AddColumn("GUID", "String");
            dt.AddColumn("Path", "String");
            dt.AddColumn("Description", "String");

            RegistryKey hive = null;
            RegistryKey key = null;
            RegistryKey subKey = null;
            RegistryKey inProc32Key = null;
            RegistryKey OLEDBProviderKey = null;
            RegistryKey ProgIDKey = null;
            string RegistryPath = (WowMode ? @"WOW6432Node\CLSID" : "CLSID");

            try
            {
                // open the CLSID registry key for enumeration
                hive = Registry.ClassesRoot;
                key = hive.OpenSubKey(RegistryPath, RegistryKeyPermissionCheck.ReadSubTree,
                                                    System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                    System.Security.AccessControl.RegistryRights.ReadKey |
                                                    System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                    System.Security.AccessControl.RegistryRights.QueryValues);
                if (key is null) throw new InvalidOperationException($@"Registry key {RegistryPath} could not be opened.");

                // enumerate all the GUID sub keys
                string[] subKeyNames = key.GetSubKeyNames();
                foreach (string subKeyName in subKeyNames)
                {
                    try
                    {
                        subKey = key.OpenSubKey(subKeyName, RegistryKeyPermissionCheck.ReadSubTree,
                                                            System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                            System.Security.AccessControl.RegistryRights.ReadKey |
                                                            System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                            System.Security.AccessControl.RegistryRights.QueryValues);
                        if (subKey != null) // ignore keys we cannot open
                        {
                            inProc32Key = subKey.OpenSubKey("InprocServer32", RegistryKeyPermissionCheck.ReadSubTree,
                                                                              System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                                              System.Security.AccessControl.RegistryRights.ReadKey |
                                                                              System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                                              System.Security.AccessControl.RegistryRights.QueryValues);
                            if (inProc32Key == null) continue;

                            OLEDBProviderKey = subKey.OpenSubKey("OLE DB Provider", RegistryKeyPermissionCheck.ReadSubTree,
                                                                                    System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                                                    System.Security.AccessControl.RegistryRights.ReadKey |
                                                                                    System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                                                    System.Security.AccessControl.RegistryRights.QueryValues);
                            if (OLEDBProviderKey == null) continue;

                            ProgIDKey = subKey.OpenSubKey("ProgID", RegistryKeyPermissionCheck.ReadSubTree,
                                                                    System.Security.AccessControl.RegistryRights.ReadPermissions |
                                                                    System.Security.AccessControl.RegistryRights.ReadKey |
                                                                    System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                                                    System.Security.AccessControl.RegistryRights.QueryValues);
                            if (ProgIDKey == null) continue;

                            // all the subkeys exist - add values to the DataTable

                            string inProc32 = inProc32Key.GetValue(null, "").ToString(); // null -> default value
                            string description = OLEDBProviderKey.GetValue(null, "").ToString(); // null -> default value
                            string ProgID = ProgIDKey.GetValue(null, "").ToString(); // null -> default value

                            if (ProgID.EndsWith(".1")) ProgID = ProgID.Substring(0, ProgID.Length - 2);  // trim .1 but not other values; may have multiple drivers with the same ProgID

                            DataRow row = dt.NewRow();

                            row["ProgID"] = ProgID;
                            row["Description"] = description;
                            row["GUID"] = SmartString.GetBetween(subKey.Name, "{", "}"); // between { }
                            row["Path"] = inProc32;

                            dt.Rows.Add(row);
                        }
                    }
                    finally
                    {
                        if (inProc32Key != null) inProc32Key.Dispose();
                        if (OLEDBProviderKey != null) OLEDBProviderKey.Dispose();
                        if (ProgIDKey != null) ProgIDKey.Dispose();
                        if (subKey != null) subKey.Dispose();
                    }
                }

                key.Dispose();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"An exception happened opening a GUID subkey under {RegistryPath}. {ex.Message}");
            }
            finally
            {
                if (key != null) key.Dispose();
                if (hive != null) hive.Dispose();
            }

            return dt;
        }

        public static string[] GetODBCNames()
        {
            return new string[] { "SQL Server",
                                  "SQL Server Native Client 9.0",
                                  "SQL Server Native Client 10.0",
                                  "SQL Server Native Client 11.0",
                                  "ODBC Driver 11 for SQL Server",
                                  "ODBC Driver 13 for SQL Server",
                                  "ODBC Driver 17 for SQL Server",
                                  "ODBC Driver 18 for SQL Server"};
        }
    }
}