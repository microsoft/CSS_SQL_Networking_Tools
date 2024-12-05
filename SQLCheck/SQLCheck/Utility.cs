// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;
using System.Collections.Specialized;
using System.Management;
using System.DirectoryServices;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Data;

namespace SQLCheck
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Various methods that make other code easier to write
    //


    static class Utility
    {

        public static StreamWriter outLogFile;  // Clintonw-1017

        //
        // Wrapper for making a WMI call
        //

        public static StringDictionary ManagementHelper(string WMIClassName, params string[] ElementNames)
        {
            StringDictionary d = new StringDictionary();
            try
            {
                SelectQuery query = new SelectQuery(WMIClassName);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject current in searcher.Get())
                {
                    foreach (string ElementName in ElementNames)
                    {
                        d.Add(ElementName, current[ElementName].ToString());  // keyname, value
                    }
                }
            }
            catch (Exception)
            {
                //LogException(("Exception accessing Management object '" & Name & "'"), ex)
                return null;
            }
            return d;
        }

        //
        // DirectoryHelper
        //

        public static StringDictionary DirectoryHelper(string DirectoryEntryName, params string[] ElementNames)
        {
            StringDictionary d = new StringDictionary();
            try
            {
                DirectoryEntry entry = new DirectoryEntry(DirectoryEntryName);
                foreach (string ElementName in ElementNames)
                {
                    d.Add(ElementName, entry.Properties[ElementName][0].ToString());    // keyname, value
                }
            }
            catch (Exception)
            {
                //LogException(("Exception accessing Active Directory object '" & Name & "'"), ex)
                return null;
            }
            return d;
        }

        //
        // Registry Helper Methods
        //

        public static string CheckRegistryKeyExists(string path)
        {
            RegistryKey hive = null;
            RegistryKey key = null;
            try
            {
                path = path.Trim().ToUpper();
                if (path.StartsWith(@"HKEY_LOCAL_MACHINE\"))
                {
                    hive = Registry.LocalMachine;
                    path = path.Substring(19);
                }
                else if (path.StartsWith(@"HKLM\"))
                {
                    hive = Registry.LocalMachine;
                    path = path.Substring(5);
                }
                else if (path.StartsWith(@"HKEY_CURRENT_USER\"))
                {
                    hive = Registry.CurrentUser;
                    path = path.Substring(18);
                }
                else if (path.StartsWith(@"HKCU\"))
                {
                    hive = Registry.CurrentUser;
                    path = path.Substring(5);
                }
                else if (path.StartsWith(@"HKEY_CLASSES_ROOT\"))
                {
                    hive = Registry.ClassesRoot;
                    path = path.Substring(18);
                }
                else if (path.StartsWith(@"HKEY_CURRENT_CONFIG\"))
                {
                    hive = Registry.CurrentConfig;
                    path = path.Substring(20);
                }
                else if (path == "")
                {
                    return "Bad Rule: Unknown hive prefix or no subkey specified";
                }

                if (path == "") return "Bad Rule: No subkey specified.";

                key = hive.OpenSubKey(path, RegistryKeyPermissionCheck.ReadSubTree,
                                            System.Security.AccessControl.RegistryRights.ReadPermissions |
                                            System.Security.AccessControl.RegistryRights.ReadKey |
                                            System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                            System.Security.AccessControl.RegistryRights.QueryValues);
                return (key == null) ? "0" : "1";
            }
            finally
            {
                if (key != null) key.Close();
                if (hive != null) hive.Close();
            }
        }

        public static string GetRegistryValueAsString(string path, string valueName, RegistryValueKind typeName, object defaultValue)
        {
            RegistryKey hive = null;
            RegistryKey key = null;
            object value = null;
            try
            {
                path = path.Trim().ToUpper();
                if (path.StartsWith(@"HKEY_LOCAL_MACHINE\"))
                {
                    hive = Registry.LocalMachine;
                    path = path.Substring(19);
                }
                else if (path.StartsWith(@"HKLM\"))
                {
                    hive = Registry.LocalMachine;
                    path = path.Substring(5);
                }
                else if (path.StartsWith(@"HKEY_CURRENT_USER\"))
                {
                    hive = Registry.CurrentUser;
                    path = path.Substring(18);
                }
                else if (path.StartsWith(@"HKCU\"))
                {
                    hive = Registry.CurrentUser;
                    path = path.Substring(5);
                }
                else if (path.StartsWith(@"HKEY_CLASSES_ROOT\"))
                {
                    hive = Registry.ClassesRoot;
                    path = path.Substring(18);
                }
                else if (path.StartsWith(@"HKEY_CURRENT_CONFIG\"))
                {
                    hive = Registry.CurrentConfig;
                    path = path.Substring(20);
                }
                else if (path == "")
                {
                    return "Bad Rule: Unknown hive prefix or no subkey specified";
                }

                if (path == "") return "Bad Rule: No subkey specified.";

                key = hive.OpenSubKey(path, RegistryKeyPermissionCheck.ReadSubTree,
                                            System.Security.AccessControl.RegistryRights.ReadPermissions |
                                            System.Security.AccessControl.RegistryRights.ReadKey |
                                            System.Security.AccessControl.RegistryRights.EnumerateSubKeys |
                                            System.Security.AccessControl.RegistryRights.QueryValues);

                if (key == null) return defaultValue == null ? "" : defaultValue.ToString();

                value = key.GetValue(valueName);
                if (value == null) return defaultValue == null ? "" : defaultValue.ToString();

                if (key.GetValueKind(valueName) == typeName)
                {
                    if (typeName == RegistryValueKind.MultiString) return string.Join(", ", (string[])value);
                    return value.ToString();
                }
                else
                {
                    return $"{valueName} is of type {key.GetValueKind(valueName).ToString()} instead of type {typeName.ToString()}.";
                }
            }
            finally
            {
                if (key != null) key.Close();
                if (hive != null) hive.Close();
            }
        }

        public static string RegistryTryGetValue(string RegPath, string ValueName, string Default)
        {
            object oVal = Registry.GetValue(RegPath, ValueName, Default);
            if (oVal == null)
            {
                return "";
            }
            else
            {
                return oVal.ToString();
            }
        }

        public static int RegistryTryGetValue(string RegPath, string ValueName, int Default)
        {
            object oVal = Registry.GetValue(RegPath, ValueName, Default);
            if (oVal == null)
            {
                return 0;
            }
            else
            {
                return oVal.ToInt();
            }
        }

        //
        //  Gets Local computer name and creates local log output file      // Clintonw-1017
        // 
        public static StreamWriter openLogOutputFile()
        {
            string computerName = Environment.MachineName;   // won't crash
            computerName = $"SQLCheck.{computerName}.{ConvertCurrTimeToString()}.txt";
            outLogFile = new StreamWriter(computerName);
            Console.WriteLine("Generating SQLCheck log ...............");
            return outLogFile;
        }

        public static void WriteLine(string message)
        {
            if (outLogFile != null) outLogFile.WriteLine(message);
            Console.Write(".");
        }

        public static Boolean closeLogOutputFile()
        {
            outLogFile.Close();
            Console.WriteLine($"Output file was generated.");
            return true;
        }

        //
        // Runs a Console application and returns the STDOUT text back to the method.
        //
        // The overall program must be a Console app or there will be a flash of a Console Window while running
        //

        public static string GetExecutableSTDOUT(string exeName, string args)  
        {
            Process p = new Process();
            p.StartInfo.FileName = exeName;
            p.StartInfo.Arguments = args;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.Start();
            string result = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            return result;
        }

        //
        // Service Account Name Normalization
        //
        // Used to make all account names, including UPN account names, into the NT Account format
        // Convert local account names into domain account names ("domain\computer$")
        //

        public static string NormalizeNTAccount(string account, string domain = "")   // unsplit names just go in account and leave domain blank
        {
            try
            {
                System.Security.Principal.NTAccount nta = new System.Security.Principal.NTAccount(domain, account);
                System.Security.Principal.SecurityIdentifier si = (System.Security.Principal.SecurityIdentifier)nta.Translate(typeof(System.Security.Principal.SecurityIdentifier));
                System.Security.Principal.NTAccount ntaFull = (System.Security.Principal.NTAccount)si.Translate(typeof(System.Security.Principal.NTAccount));
                return $"{ntaFull.Value}";
            }
            catch (Exception ex)
            {
                if (domain == "") return account;
                return $@"{domain}\{account}";
            }
        }

        public static string ConvertLocalAccountToDomainAccount(string account, string ComputerName, string DomainName)
        {
            // string ComputerName = Computer.GetString("NETBIOSName");
            // string DomainName = Domain.GetString("DomainShortName");

            if (account.StartsWith(@"NT AUTHORITY\", StringComparison.InvariantCultureIgnoreCase) ||     // local built-in accounts             NT AUTHORITY\NETWORK SERVICE
                account.StartsWith(@"NT SERVICE\", StringComparison.InvariantCultureIgnoreCase) ||       // local virtual service accounts      NT SerVICE\MSSQLSERVICE
                account.StartsWith($@"{ComputerName}\", StringComparison.InvariantCultureIgnoreCase) ||  // local account                       SQLProd01\Administrator
                account.Contains(@"\") == false)
            {
                return $@"{DomainName}\{ComputerName}$";                                                 // output                              Contoso\SQLProd01$
            }
            return account;                                                                              // return domain account names unchanged
        }

        //
        // Reads a file into a string
        //
        // Mainly used to read the ERRORLOG file
        // It's a shared file, so we have to set the access mode and sharing mode
        //

        public static string GetFileText(string path)
        {
            string s = "";
            try
            {
                FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                TextReader r = new StreamReader(fs);
                s = r.ReadToEnd();
                r.Close();
                fs.Close();
            }
            catch (Exception)
            {
                // ignore all exceptions - but allow us to break and see what it is when testing
            }
            return s;
        }

        //
        // ArrayList string helper
        //

        public static void AddUnique(this ArrayList a, string value)   // case inseinsitive comparison
        {
            if (a == null || value == null || value.Trim() == "") return;
            foreach (string s in a) if (s.ToLower() == value.ToLower().Trim()) return;
            a.Add(value.Trim());
        }

        public static string Concatenate(this ArrayList a)
        {
            string s = "";
            if (a.Count == 0) return "";
            foreach (string element in a) s += $", {element}";
            return s.Substring(2);                               // remove leading comma and space
        }

        //
        // Data Type Conversion Methods
        //

        public static int ToInt(this string value)  // returns 0 if error
        {
            int val = 0;
            if (int.TryParse(value, out val)) return val;
            return 0;
        }

        public static int ToInt(this object value)  // returns 0 if error
        {
            int val = 0;
            if (value == null) return 0;
            if (value.GetType().Equals(typeof(int))) val = (int)value;
            if (value.GetType().Equals(typeof(uint))) val = (int)value;
            if (value.GetType().Equals(typeof(string))) val = ((string)value).ToInt();
            return val;
        }

        public static bool IsInt(this string value)
        {
            int x = 0;
            return int.TryParse(value, out x);
        }

        public static bool ToBoolean(this object value)  // returns false if error
        {
            bool val = false;
            if (value.GetType().Equals(typeof(Boolean))) val = (bool)value;
            return val;
        }

        public static bool In(this string value, params string[] values)
        {
            foreach (string val in values)
            {
                if (string.Compare(value, val, true) == 0) return true;
            }
            return false;
        }

        //
        // Trim a string after a certain place - case insensitve
        //

        public static string KeepBeforeIncluding(this string value, string delim)
        {
            int pos = value.IndexOf(delim, StringComparison.InvariantCultureIgnoreCase);
            return pos == -1 ? value.Trim() : value.Substring(0, pos + delim.Length).Trim();
        }

        //
        // Indexes a string with range checking - int index or numeric string index
        //

        public static string Translate(int index, params string[] Values)
        {
            if (index < 0 || index >= Values.Length) return $"Bad Translator index value {index}. Range 0..{Values.Length - 1}";
            if (Values[index] == null) return $"Bad Translator value at {index}.";
            return Values[index];
        }

        public static string Translate(string index, params string[] Values)
        {
            int i = 0;
            bool success = int.TryParse(index, out i);
            if (!success) return $"Non-numeric Translator index value '{index}'.";
            return Translate(i, Values);
        }

        //
        // Converts Lanman compatibility levels to string
        //

        public static string LanmanNames(string value)
        {
            switch (value)
            {
                case "0": return "Send LM & NTLM responses";
                case "1": return "Send LM & NTLM – use NTLMv2 session security if negotiated";
                case "2": return "Send NTLM response only";
                case "3": return "Send NTLMv2 response only";
                case "4": return "Send NTLMv2 response only. Refuse LM";
                case "5": return "Send NTLMv2 response only. Refuse LM & NTLM";
                default: return "";
            }
        }


        //
        // Converts a Kerberos encryption bitmask to string
        //

        public static string KerbEncryptNames(int bitmask)
        {
            string s = "";
            if (bitmask == 0) return "RC4_HMAC_MD5";
            if ((bitmask & 0x00000001) != 0) s += "DES_CBC_CRC";
            if ((bitmask & 0x00000002) != 0) s += "+DES_CBC_MD5";
            if ((bitmask & 0x00000004) != 0) s += "+RC4_HMAC_MD5";
            if ((bitmask & 0x00000008) != 0) s += "+AES128_HMAC_SHA1";
            if ((bitmask & 0x00000010) != 0) s += "+AES256_HMAC_SHA1";
            if (bitmask > 0x0000001F) s += "+Future";
            return (s.StartsWith("+") ? s.Substring(1) : s);
        }

        //
        // Converts a domain trust attribute bitmask to a string
        //

        public static string DomainTrustAttributeNames(int bitmask)
        {
            string s = "";
            if ((bitmask & 0x00000001) != 0) s += "NON_TRANSITIVE";
            if ((bitmask & 0x00000002) != 0) s += "|UPLEVEL_ONLY";
            if ((bitmask & 0x00000004) != 0) s += "|QUARANTINED_DOMAIN";
            if ((bitmask & 0x00000008) != 0) s += "|FOREST_TRANSITIVE";
            if ((bitmask & 0x00000010) != 0) s += "|CROSS_ORGANIZATION";
            if ((bitmask & 0x00000020) != 0) s += "|WITHIN_FOREST";
            if ((bitmask & 0x00000040) != 0) s += "|TREAT_AS_EXTERNAL";
            if ((bitmask & 0x00000080) != 0) s += "|USES_RC4_ENCRYPTION";
            if ((bitmask & 0x00000100) != 0) s += "|RESERVED_USES_AES_KEYS";  // RESERVED in MSFT documentation; USES_AES_KEYS in some 3rd-party dcumentation
            if ((bitmask & 0x00000200) != 0) s += "|CROSS_ORGANIZATION_NO_TGT_DELEGATION";
            if ((bitmask & 0x00000400) != 0) s += "|PIM_TRUST";
            if ((bitmask & 0x00000800) != 0) s += "|CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION";
            return (s.StartsWith("|") ? s.Substring(1) : s);
        }

        //
        // Translates common network transmission speed strings to a more compact form
        //

        public static string TranslateSpeed(string speed)
        {
            if (speed == null) return "";

            string weirdSpeed = ((ulong)(0x7FFFFFFFFFFFFFFF)).ToString();    // decimal: 9223372036854775807
            if (speed == weirdSpeed) return "";                              // found on Wifi and virtual adapters

            switch (speed)
            {
                case "10000000": return "10 MB/s";
                case "100000000": return "100 MB/s";
                case "1000000000": return "1 GB/s";
                case "10000000000": return "10 GB/s";
                case "100000000000": return "100 GB/s";
                default: return speed;
            }
        }

        //
        // Takes a service account name and determines whether it is a local account or a domain account
        // If it's a local account, returns the NETBIOS name of the computer - the account that's seen on the network
        //

        public static string TranslateServiceAccount(string Account, string NETBIOSName)
        {
            string acc = Account.ToUpper();
            string remainder = "";
            if (acc.StartsWith(@"NT AUTHORITY\") ||
                acc.StartsWith(@"NT SERVICE\") ||
                acc == @"LOCALSYSTEM" ||
                (acc.Contains(@"\") == false && acc.Contains("@") == false) ||  // old name format has domain\account and UPN format has account@domain.com
                SmartString.ChopWord(acc, ref remainder , @"\") == NETBIOSName.ToUpper())
            {
                Account = NETBIOSName;
            }
            return Account;
        }

        //
        // Takes a cipher suite name and annotes it with a suffix to indicate what versions of TLS it supports.
        // Adds the word 'weak' if not supported by the strong crypto flag.
        //
        // Ref: https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11-v22h2
        // and related pages
        public static string AnnotateCipherSuite(string name)
        {
            switch (name.ToUpper())
            {
                // TLS 1.3
                case "TLS_AES_256_GCM_SHA384": return $"{name} (TLS 1.3)";
                case "TLS_AES_128_GCM_SHA256": return $"{name} (TLS 1.3)";
                case "TLS_CHACHA20_POLY1305_SHA256": return $"{name} (TLS 1.3)";
                // TLS 1.2
                case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_RSA_WITH_AES_256_GCM_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_RSA_WITH_AES_128_GCM_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_RSA_WITH_AES_256_CBC_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_RSA_WITH_AES_128_CBC_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256": return $"{name} (TLS 1.2)";
                // TLS 1.2 - Pre Windows 10 cipher suites - same as the ones above without the _Pxxx suffix
                case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521": return $"{name} (TLS 1.2)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521": return $"{name} (TLS 1.2)";
                // TLS 1.2, weak
                case "TLS_RSA_WITH_NULL_SHA256": return $"{name} (TLS 1.2, weak)";
                // TLS 1.2, 1.1, 1.0
                case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_RSA_WITH_AES_256_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_RSA_WITH_AES_128_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": return $"{ name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": return $"{ name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_DHE_DSS_WITH_AES_256_CBC_SHA": return $"{ name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_DHE_DSS_WITH_AES_128_CBC_SHA": return $"{ name} (TLS 1.2, 1.1, 1.0)";
                // TLS 1.2, 1.1, 1.0 - Pre Windows 10 cipher suites - same as the ones above without the _Pxxx suffix
                case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521": return $"{name} (TLS 1.2, 1.1, 1.0)";
                case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521": return $"{name} (TLS 1.2, 1.1, 1.0)";
                // TLS 1.2, 1.1, 1.0, weak
                case "TLS_RSA_WITH_3DES_EDE_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, weak)";
                // TLS 1.2, 1.1, 1.0, SSL 3.0, weak
                case "TLS_RSA_WITH_NULL_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_RSA_WITH_RC4_128_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_RSA_WITH_RC4_128_MD5": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_RSA_WITH_DES_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_DHE_DSS_WITH_DES_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_RSA_WITH_NULL_MD5": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_RSA_EXPORT_WITH_RC4_40_MD5": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                case "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA": return $"{name} (TLS 1.2, 1.1, 1.0, SSL 3.0, weak)";
                // SSL 2.0
                case "SSL_CK_DES_192_EDE3_CBC_WITH_MD5": return $"{name} (SSL 2.0)";
                case "SSL_CK_DES_64_CBC_WITH_MD5": return $"{name} (SSL 2.0)";
                // SSL 2.0, weak
                case "SSL_CK_RC4_128_WITH_MD5": return $"{name} (SSL 2.0, weak)";
                case "SSL_CK_RC4_128_EXPORT40_WITH_MD5": return $"{name} (SSL 2.0, weak)";
                // PSK TLS 1.2
                case "TLS_PSK_WITH_AES_256_GCM_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_PSK_WITH_AES_128_GCM_SHA256": return $"{name} (TLS 1.2)";
                case "TLS_PSK_WITH_AES_256_CBC_SHA384": return $"{name} (TLS 1.2)";
                case "TLS_PSK_WITH_AES_128_CBC_SHA256": return $"{name} (TLS 1.2)";
                // PSK TLS 1.2, weak
                case "TLS_PSK_WITH_NULL_SHA384": return $"{name} (TLS 1.2, weak)";
                case "TLS_PSK_WITH_NULL_SHA256": return $"{name} (TLS 1.2, weak)";
                // anything else - return undecorated
                default: return name;
            }
        }

        //
        // Version Number Helper Methods
        //

        public static string GetFileVersion(string path, bool ShortVersion = false)
        {
            try
            {
                var versionInfo = FileVersionInfo.GetVersionInfo(path);
                string remainder = "";
                // returns only up to the first space when ShortVersion is true - what's after that is text and not version #
                return ShortVersion ? SmartString.ChopWord(versionInfo.FileVersion, ref remainder, " ", false, true) : versionInfo.FileVersion;
            }
            catch (Exception)
            {
                return "Not found";
            }
        }

        public static string GetProductVersion(string path)
        {
            try
            {
                var versionInfo = FileVersionInfo.GetVersionInfo(path);
                return versionInfo.ProductVersion;   // no need to chop this up
            }
            catch (Exception)
            {
                return "Not found";
            }
        }

        //
        // Compare two version number strings
        //
        // Split the string at the period ( . ) and convert each part to an INT for true numerical comparison.
        // If the two version numbers have a different number of parts, compare only what is common between them.
        // e.g. CompareVersion("1.2.345", "1.2.345.678") returns the same result as CompareVersion("1.2.345", "1.2.345")
        //
        // If you pass in non-numeric parts or really long numbers, we return an empty string - this should make the comparison false
        //

        public static string CompareVersion(string a, string b)
        {
            // input may be "10.0.1234.5"
            // input may be "Microsoft Windows NT 6.1.7601 Service Pack 1" - just compare the 6.1.7601 portion
            int aVal = 0, bVal = 0;
            string[] aParts = ExtractVersion(a).Split('.');
            string[] bParts = ExtractVersion(b).Split('.');
            int partLength = Math.Min(aParts.Length, bParts.Length);  // only compare the parts in common

            try
            {
                for (int i = 0; i < partLength; i++)  // throw an exception if the parts are not integer
                {
                    aVal = int.Parse(aParts[i]);
                    bVal = int.Parse(bParts[i]);
                    if (aVal < bVal) return "<";
                    if (aVal > bVal) return ">";
                }
                return "=";
            }
            catch (Exception ex)
            {
                Console.WriteLine($@"Utility.CompareVersion: Error comparing ""{a}"" -> ""{ExtractVersion(a)}"" and ""{b}"" -> {ExtractVersion(b)}.");
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
                return "";
            }
        }

        public static string ExtractVersion(string v)
        {
            // input may be 10.0.1234.5 - return unchanged
            // input may be Microsoft Windows NT 6.1.7601 Service Pack 1 - just return the 6.1.7601 portion
            if (v == null || v == "" || v.Substring(0, 1).IsInt()) return v;
            string[] words = v.Split(' ');
            foreach (string word in words)
            {
                if (word.Substring(0, 1).IsInt()) return word;
            }
            return v;
        }

        // Format Time for filename with leading zero
        public static string ConvertCurrTimeToString()
        {
            DateTime dt = DateTime.Now;
            string fmt = "00";
            return $"{dt.Year}{dt.Month.ToString(fmt)}{dt.Day.ToString(fmt)}{dt.Hour.ToString(fmt)}{dt.Minute.ToString(fmt)}{dt.Second.ToString(fmt)}";
        }

        // FormatInterval -TimeSpan to Days, Hours and Min as string
        public static string FormatInterval(TimeSpan ts)
        {
            return $"{ts.Days} Days, {ts.Hours} Hours, {ts.Minutes} Minutes";
        }

        public static string GetTimeZoneOffsetAndName(DateTime theDate)
        {
            TimeZoneInfo tz = TimeZoneInfo.Local;
            if (tz.SupportsDaylightSavingTime)
            {
                TimeSpan offset = tz.GetUtcOffset(theDate);
                string offsetText = "(UTC" + (offset.Hours < 0 ? "-" : "+") + offset.ToString(@"hh\:mm") + ")";
                return $"{offsetText} {(tz.IsDaylightSavingTime(theDate) ? tz.DaylightName : tz.StandardName)}";
            }
            return tz.DisplayName;
        }

    }

    public class StringIgnoreCaseComparer : System.Collections.Generic.IEqualityComparer<String>
    {
        public bool Equals(string a, string b)
        {
            return a.Equals(b, StringComparison.CurrentCultureIgnoreCase);
        }

        public int GetHashCode(string a)
        {
            return a.GetHashCode();
        }
    }
}
