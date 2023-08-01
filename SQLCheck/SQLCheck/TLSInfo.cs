using System;
using System.Data;

namespace SQLCheck
{
    class TLSInfo
    {
        public string SSL20c = "";   // client and server settings expire at different times
        public string SSL20s = "";   // client and server settings expire at different times
        public string SSL30 = "";
        public string TLS10 = "";
        public string TLS11 = "";
        public string TLS12 = "";
        public string TLS13 = "";

        public TLSInfo(string ssl20Client, string ssl20Server, string ssl30, string tls10, string tls11, string tls12, string tls13)
        {
            SSL20c = ssl20Client;
            SSL20s = ssl20Server;
            SSL30 = ssl30;
            TLS10 = tls10;
            TLS11 = tls11;
            TLS12 = tls12;
            TLS13 = tls13;
        }

        public string GetComputerDefault(string TLSVersion, string clientServer)
        {
            switch (TLSVersion)
            {
                case "SSL 2.0": return (clientServer == "Client") ? SSL20c : SSL20s;
                case "SSL 3.0": return SSL30;
                case "TLS 1.0": return TLS10;
                case "TLS 1.1": return TLS11;
                case "TLS 1.2": return TLS12;
                case "TLS 1.3": return TLS13;
                default: return $"Unknown TLS version: {TLSVersion}.";
            }
        }

        public static TLSInfo GetTLSInfo(DataRow Computer)
        {
            //
            // https://docs.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
            //
            // Confirmed with the SCHANNEL team that TLS 1.3 is not supported by any version of Windows 10 or 2019.
            // Some TLS 1.3 cipher suites may appear in the list on Windows 10 and 2019, but that was for TLS 1.3 proofing before releasing Windows 11 and 2022.
            // There is no actual support for TLS 1.3 before Windows 11 or 2022.
            //
            // Windows Version                                 Version #   Build #  SSL 2 Client  SSL 2 Server  SSL3        TLS 1.0     TLS 1.1     TLS 1.2     TLS 1.3
            // ----------------------------------------------  ----------  -------  ------------  ------------  ----------  ----------  ----------  ----------  ----------
            // Windows Vista / Windows Server 2008             NT 6.0        older  Disabled      Enabled       Enabled     Enabled     Not Supp    Not Supp    Not SUpp
            //
            // Windows Server 2008 with Service Pack 2(SP2)    NT 6.0         6002  Disabled      Enabled       Enabled     Enabled     Disabled    Disabled    Not Supp      Change
            // Windows 7 / Windows Server 2008 R2              NT 6.1               Disabled      Enabled       Enabled     Enabled     Disabled    Disabled    Not Supp
            //
            // Windows 8 / Windows Server 2012                 NT 6.2               Disabled      Disabled      Enabled     Enabled     Enabled     Enabled     Not Supp      Change
            // Windows 8.1 / Windows Server 2012 R2            NT 6.3               Disabled      Disabled      Enabled     Enabled     Enabled     Enabled     Not Supp
            // Windows 10, version 1507                        10.0          10240  Disabled      Disabled      Enabled     Enabled     Enabled     Enabled     Not Supp
            // Windows 10, version 1511                        10.0          10586  Disabled      Disabled      Enabled     Enabled     Enabled     Enabled     Not Supp
            //
            // Windows 10, version 1607 / Windows Server 2016  10.0          14393  Not Supp      Not Supp      Disabled    Enabled     Enabled     Enabled     Not Supp      Change
            // Windows 10, version 1809 / Windows Server 2019  10.0          17763  Not Supp      Not Supp      Disabled    Enabled     Enabled     Enabled     Not Supp
            // Windows 10, version 20H2 / Windows Server 2019  10.0          19042  Not Supp      Not Supp      Disabled    Enabled     Enabled     Enabled     Not Supp
            // Windows 10, version 21H1 / Windows Server 2019  10.0          19043  Not Supp      Not Supp      Disabled    Enabled     Enabled     Enabled     Not Supp
            //
            // Windows 11, version 21H2                        10.0          22000  Not Supp      Not Supp      Disabled    Enabled     Enabled     Enabled     Enabled       Change
            // Windows Server 2022, wersion 21H2               10.0          20348  Not Supp      Not Supp      Disabled    Enabled     Enabled     Enabled     Enabled


            string WindowsVersion = Computer.GetString("WindowsVersion");
            string WindowsReleaseID = Computer.GetString("WindowsReleaseID");
            string WindowsBuild = Computer.GetString("WindowsBuild");
            string WindowsName = Computer.GetString("WindowsName");

            // Windows 11, Windows 2022 and above
            if (Utility.CompareVersion(WindowsVersion, "10.0.20000") == ">") // Windows 11, Windows 2022, Windows 10/2019 versions 19042 and greater
            {
                return new TLSInfo("Not Supported", "Not Supported", "Disabled", "Enabled", "Enabled", "Enabled", "Enabled");
            }
            // Windows 2016, 2019 / Windows 10 Build 1607 and above
            else if (Utility.CompareVersion(WindowsVersion, "10.0.14392") == ">")  // starts with 10.0.14393
            {
                return new TLSInfo("Not Supported", "Not Supported", "Disabled", "Enabled", "Enabled", "Enabled", "Not Supported");
            }
            else if (Utility.CompareVersion(WindowsVersion, "10.0") == "=" ||   // Windows 10   and Windows 2016 and Windows 2019
                     WindowsVersion.Contains("NT 6.2.") ||                      // Windows 8    and Windows Server 2012
                     WindowsVersion.Contains("NT 6.3."))                        // Windows 8.1  and Windows Server 2012 R2
            {
                return new TLSInfo("Disabled", "Enabled", "Enabled", "Enabled", "Enabled", "Enabled", "Not Supported");
            }
            else if (WindowsVersion.Contains("NT 6.1.") ||                      // Windows 7 and Windows 2008 R2
                    (WindowsVersion.Contains("NT 6.0.") && WindowsBuild == "6002" && WindowsName.Contains("Server")))        // Windows Server 2008 SP2 (not Vista SP2)
            {
                // if version = Windows 2008 SP2, Windows 2008 R2, Windows 7
                return new TLSInfo("Enabled", "Enabled", "Disabled", "Disabled", "Disabled", "Disabled", "Not Supported");
            }
            else // anything older
            {
                return new TLSInfo("Enabled", "Enabled", "Not Supported", "Not Supported", "Not Supported", "Not Supported", "Not Supported");
            }
        }
    }
}
