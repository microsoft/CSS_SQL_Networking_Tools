// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System.Diagnostics;
using System.Data;

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

        public static DriverInfo GetDriverInfo(string driverName, FileVersionInfo versionInfo, string WindowsVersion, string WindowsReleaseID)  // TODO - fix up MinTLSVersion and Server Support
        {
            string TLS12 = "No";

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
                    switch (WindowsReleaseID.ToUpper())
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
                            // TODO
                            break;
                        case "IRON":        // Windows 10/2019  Iron         ????                  build 20207????  ????   April 16, 2021????
                                            // more at https://microsoft.visualstudio.com/OS/_workitems/edit/27324781
                            // TODO
                            break;
                    }
                    break;
                case "SQLNCLI10":
                case "SQL Server Native Client 10.0":
                    // SQLNCLI10 and SQL Server Native Client 10.0
                    if (versionInfo.ProductMajorPart == 10 && versionInfo.ProductMinorPart ==  0 && versionInfo.ProductBuildPart >= 6543) TLS12 = "Yes";   // 10.0
                    if (versionInfo.ProductMajorPart == 10 && versionInfo.ProductMinorPart == 50 && versionInfo.ProductBuildPart >= 6537) TLS12 = "Yes";   // 10.50
                    if (versionInfo.ProductMajorPart == 10 && versionInfo.ProductMinorPart == 51 && versionInfo.ProductBuildPart >= 6537) TLS12 = "Yes";   // 10.51
                    break;
                case "SQLNCLI11":
                case "SQL Server Native Client 11.0":
                    // SQLNCLI11 and SQL Server Native Client 11.0
                    if (versionInfo.ProductMajorPart == 11 && versionInfo.ProductMinorPart == 0 && versionInfo.ProductBuildPart >= 6538) TLS12 = "Yes";
                    break;
                case "ODBC Driver 11 for SQL Server":
                    // ODBC Driver 11 for SQL Server
                    if (versionInfo.ProductMajorPart == 12 && versionInfo.ProductMinorPart == 0 && versionInfo.ProductBuildPart >= 4219) TLS12 = "Yes";
                    break;
            }

            switch (driverName)
            {                                                        //      Name        Type      TLS12  TLS13    Server Support         Supported      MSF
                case "SQLOLEDB":                       return new DriverInfo(driverName, "OLE DB", TLS12, "No",    "SQL 7.0 - SQL 2019",  "Deprecated",  "No");
                case "SQLNCLI":                        return new DriverInfo(driverName, "OLE DB", "No",  "No",    "SQL 7.0 - SQL 2019",  "No",          "No");
                case "SQLNCLI10":                      return new DriverInfo(driverName, "OLE DB", TLS12, "No",     "SQL 7.0 - SQL 2019",  "Yes",         "No");
                case "SQLNCLI11":                      return new DriverInfo(driverName, "OLE DB", TLS12, "No",    "SQL 7.0 - SQL 2019",  "Yes",         "No");
                case "MSOLEDBSQL":                     return new DriverInfo(driverName, "OLE DB", "Yes", "No",    "SQL 2005 - SQL 2019", "Yes",         "Yes");
                case "SQL Server":                     return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "Deprecated",  "No");
                case "SQL Server Native Client 9.0":   return new DriverInfo(driverName, "ODBC",   "No",  "No",    "SQL 7.0 - SQL 2019",  "No",          "No");
                case "SQL Server Native Client 10.0":  return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "Yes",         "No");
                case "SQL Server Native Client 11.0":  return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "Yes",         "Yes");
                case "ODBC Driver 11 for SQL Server":  return new DriverInfo(driverName, "ODBC",   TLS12, "No",    "SQL 7.0 - SQL 2019",  "Yes",         "Yes");
                case "ODBC Driver 13 for SQL Server":  return new DriverInfo(driverName, "ODBC",   "Yes", "No",    "SQL 7.0 - SQL 2019",  "Yes",         "Yes");
                case "ODBC Driver 17 for SQL Server":  return new DriverInfo(driverName, "ODBC",   "Yes", "No",    "SQL 2005 - SQL 2019", "Yes",         "Yes");
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
                                  "SQL Server",
                                  "SQL Server Native Client 9.0",
                                  "SQL Server Native Client 10.0",
                                  "SQL Server Native Client 11.0",
                                  "ODBC Driver 11 for SQL Server",
                                  "ODBC Driver 13 for SQL Server",
                                  "ODBC Driver 17 for SQL Server" };
        }

        public static string[] GetOLEDBNames()
        {
            return new string[] {"SQLOLEDB",
                                 "SQLNCLI",
                                 "SQLNCLI10",
                                 "SQLNCLI11",
                                 "MSOLEDBSQL" };
        }

        public static string[] GetExtendedOLEDBNames()
        {
            return new string[] {"SQLOLEDB",
                                 "SQLNCLI",
                                 "SQLNCLI10",
                                 "SQLNCLI11",
                                 "MSOLEDBSQL",
                                 "Microsoft.ACE.OLEDB.10.0",   // supported by Office (Access)
                                 "Microsoft.ACE.OLEDB.12.0",   // supported by Office (Access)
                                 "Microsoft.ACE.OLEDB.16.0",   // supported by Office (Access)
                                 "MSOLAP",                     // supported by Analysis Services (SSAS)
                                 "ADSDSOObject",               // supported by Active Directory
                                 "Sybase.ASEOLEDBProvider",    // supported by Sybase
                                 "MySQLProv",                  // supported by MySQL
                                 "Ifxoledbc",                  // supported by IBM/Informix
                                 "IBMDA400",                   // supported by IBM AS/400 DB/2 database
                                 "IBMDADB2",                   // supported by IBM DB/2 database
                                 "OraOLEDB.Oracle"};           // supported by Oracle
        }

        public static string[] GetODBCNames()
        {
            return new string[] { "SQL Server",
                                  "SQL Server Native Client 9.0",
                                  "SQL Server Native Client 10.0",
                                  "SQL Server Native Client 11.0",
                                  "ODBC Driver 11 for SQL Server",
                                  "ODBC Driver 13 for SQL Server",
                                  "ODBC Driver 17 for SQL Server" };
        }
    }
}
