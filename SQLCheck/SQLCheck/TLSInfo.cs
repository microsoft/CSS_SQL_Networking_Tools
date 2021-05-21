using System;
using System.Data;

namespace SQLCheck
{
    class TLSInfo
    {
        public string SSL20 = "";
        public string SSL30 = "";
        public string TLS10 = "";
        public string TLS11 = "";
        public string TLS12 = "";
        public string TLS13 = "";

        public TLSInfo(string ssl20, string ssl30, string tls10, string tls11, string tls12, string tls13)
        {
            SSL20 = ssl20;
            SSL30 = ssl30;
            TLS10 = tls10;
            TLS11 = tls11;
            TLS12 = tls12;
            TLS13 = tls13;
        }

        public string GetComputerDefault(string TLSVersion)
        {
            switch (TLSVersion)
            {
                case "SSL 2.0": return SSL20;
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
            string WindowsVersion = Computer.GetString("WindowsVersion");
            string WindowsReleaseID = Computer.GetString("WindowsReleaseID");
            string WindowsBuild = Computer.GetString("WindowsBuild");
            string WindowsName = Computer.GetString("WindowsName");

            if (Utility.CompareVersion(WindowsVersion, "10.0") == "=" && WindowsReleaseID.StartsWith("22"))  // Windows 22
            {
                return new TLSInfo("Enabled", "Enabled", "Enabled", "Enabled", "Enabled", "Enabled");
            }
            else if (Utility.CompareVersion(WindowsVersion, "10.0") == "=" ||   // Windows 10   and Windows 2016 and Windows 2019
                     WindowsVersion.Contains("NT 6.2.") ||                      // Windows 8    and Windows Server 2012
                     WindowsVersion.Contains("NT 6.3."))                        // Windows 8.1  and Windows Server 2012 R2
            {
                return new TLSInfo("Enabled", "Enabled", "Enabled", "Enabled", "Enabled", "Not Supported");
            }
            else if (WindowsVersion.Contains("NT 6.1.") ||                      // Windows 7 and Windows 2008 R2
                    (WindowsVersion.Contains("NT 6.0.") && WindowsBuild == "6002" && WindowsName.Contains("Server")))        // Windows Server 2008 SP2 (not Vista SP2)
            {
                // if version = Windows 2008 SP2, Windows 2008 R2, Windows 7
                return new TLSInfo("Enabled",  "Disabled", "Disabled", "Disabled", "Disabled", "Not Supported");
            }
            else // anything older
            {
                return new TLSInfo("Enabled", "Not Supported", "Not Supported", "Not Supported", "Not Supported", "Not Supported");
            }
        }
    }
}
