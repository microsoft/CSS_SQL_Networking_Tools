// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Statically declared helper functions and global constants
    //

    public class ActivityTimer
    {
        private DateTime startTime;

        public void start(string Message)
        {
            startTime = DateTime.Now;
            Program.logDiagnosticNoReturn(Message + " ... ");
            Console.Write(Message + " ... ");
        }

        public void stop()
        {
            TimeSpan diff = DateTime.Now - startTime;
            Program.logDiagnostic("it took " + diff.TotalSeconds.ToString("0.000") + " seconds.");
            Console.WriteLine("it took " + diff.TotalSeconds.ToString("0.000") + " seconds.");
        }
    }

    class utility
    {

        public static string DATE_FORMAT = @"MM/dd/yyyy hh:mm:ss tt";     // 06/15/2014 09:03:55 PM
        public static string TIME_FORMAT = @"hh:mm:ss.fff tt";            // 03:22:12.549 AM
        public static double TICKS_PER_SECOND = 10000000.0;               // one tick = 100 nano seconds
        public static double TICKS_PER_MILLISECOND = utility.TICKS_PER_SECOND / 1000.0;

        //
        // Helper functions
        //

        public static bool ValidSSLVersion(ushort SSL)
        {
            if (SSL == 0x0200) return true;   // SSL 2.0
            if (SSL == 0x0300) return true;   // SSL 3.0
            if (SSL == 0x0301) return true;   // TLS 1.0
            if (SSL == 0x0302) return true;   // TLS 1.1
            if (SSL == 0x0303) return true;   // TLS 1.2
            if (SSL == 0x0304) return true;   // TLS 1.3
            return false;
        }

        public static bool ValidSSLVersion(byte sslMajor, byte sslMinor)
        {
            if (sslMajor == 2 && sslMinor == 0) return true;   // SSL 2.0
            if (sslMajor == 3 && sslMinor == 0) return true;   // SSL 3.0
            if (sslMajor == 3 && sslMinor == 1) return true;   // TLS 1.0
            if (sslMajor == 3 && sslMinor == 2) return true;   // TLS 1.1
            if (sslMajor == 3 && sslMinor == 3) return true;   // TLS 1.2
            if (sslMajor == 3 && sslMinor == 4) return true;   // TLS 1.3
            return false;
        }

        #region "String helpers"

        // Removes leading and trailing spaces and '\r' '\n' or '\0'.
        public static string CleanString(string s)
        {
            if (null == s) return s;
            s = s.Replace('\r', ' ');
            s = s.Replace('\n', ' ');
            s = s.Replace('\0', ' ');
            return s.Trim();
        }

        public static int FindASCIIString(byte[] b, int start, string s)
        {
            // convert string to character to byte array
            char[] c = s.ToCharArray();
            byte[] search = new byte[c.Length];
            for (int i = 0; i < c.Length; i++) search[i] = (byte)c[i];
            // search for
            for (int i = start; i < b.Length - search.Length + 1; i++)
            {
                bool found = true;
                for (int offset = 0; offset < search.Length; offset++)
                {
                    if (search[offset] != b[i])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return i;
            }
            return -1;  // not found
        }

        public static int FindUNICODEString(byte[] b, int start, string s)
        {
            // convert string to character to byte array
            char[] c = s.ToCharArray();
            byte[] search = new byte[c.Length * 2];
            for (int i = 0; i < c.Length; i++)
            {
                search[i * 2] = (byte)c[i];
                search[i * 2 + 1] = 0;
            }
            // search for the bytes in "search"
            for (int i = start; i < b.Length - search.Length + 1; i++)
            {
                bool found = true;
                for (int offset = 0; offset < search.Length; offset++)
                {
                    if (search[offset] != b[i + offset])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return i;
            }
            return -1;  // not found
        }

        public static string ReadAnsiString(byte[] b, int pos, int length)
        {
            string s;
            System.Text.ASCIIEncoding ansiEncoder = null;
            if (length <= 0) return "";
            if (length + pos > b.Length) return "";
            ansiEncoder = new System.Text.ASCIIEncoding();
            try
            {
                s = ansiEncoder.GetString(b, pos, length);
                s = s.Replace("\r", " ");
                s = s.Replace("\n", " ");
            }
            catch (Exception)
            {
                return "";
            }
            return s;
        }

        public static string ReadUnicodeString(byte[] b, int pos, int length)
        {
            string s;
            System.Text.UnicodeEncoding Encoder = null;
            if (length <= 0) return "";
            if (length * 2 + pos > b.Length) return "";
            Encoder = new System.Text.UnicodeEncoding();
            try
            {
                s = Encoder.GetString(b, pos, length * 2);
                s = s.Replace("\r", " ");
                s = s.Replace("\n", " ");
            }
            catch (Exception)
            {
                return "";
            }
            return s;
        }

        public static String FormatIPV4Address(uint IP)
        {
            string s = "";

            s = (IP & 0xff).ToString();
            IP >>= 8;
            s = (IP & 0xff).ToString() + "." + s;
            IP >>= 8;
            s = (IP & 0xff).ToString() + "." + s;
            IP >>= 8;
            s = (IP & 0xff).ToString() + "." + s;

            return s;
        }

        public static String FormatIPV6Address(ulong Hi, ulong Lo)
        {
            string sHi = "", sLo = "";

            sHi = (Hi & 0xffff).ToString("X");
            Hi >>= 16;
            sHi = (Hi & 0xffff).ToString("X") + ":" + sHi;
            Hi >>= 16;
            sHi = (Hi & 0xffff).ToString("X") + ":" + sHi;
            Hi >>= 16;
            sHi = (Hi & 0xffff).ToString("X") + ":" + sHi;

            sLo = (Lo & 0xffff).ToString("X");
            Lo >>= 16;
            sLo = (Lo & 0xffff).ToString("X") + ":" + sLo;
            Lo >>= 16;
            sLo = (Lo & 0xffff).ToString("X") + ":" + sLo;
            Lo >>= 16;
            sLo = (Lo & 0xffff).ToString("X") + ":" + sLo;

            return sHi + ":" + sLo;
        }

        public static void ParseIPPortString(string value, ref bool isIPV6, ref ushort port, ref uint ipv4, ref ulong ipv6hi, ref ulong ipv6lo)
        {
            isIPV6 = false; port = 0; ipv4 = 0; ipv6hi = 0; ipv6lo = 0;
            string[] words = value.Split(',');
            if (words.Length != 2) throw new ArgumentException("IP,Port string '" + value + "' does not have exactly 1 comma.");
            port = ushort.Parse(words[1]);
            System.Net.IPAddress addr=null;
            addr = System.Net.IPAddress.Parse(words[0]);
            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                isIPV6 = false;
                ipv4 = B2UInt32(addr.GetAddressBytes(),0);
            }
            else if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                isIPV6=true;
                ipv6hi=B2UInt64(addr.GetAddressBytes(),0);
                ipv6lo=B2UInt64(addr.GetAddressBytes(),8);
            }
            else
            {
                throw new ArgumentException("IP string '" + words[0] + "' is not a valid IPV4 or IPV6 address.");
            }
        }

        // Replace the file extension of the file spec with .LOG
        // If the filespec contains wild cards, truncate the naame at the first wild card and add .LOG to that
        // if the file spec ends with \*.* or \*.cap, make it use SQLNA.log
        public static string getLogFileName(string fileSpec)
        {
            int Pos = -1;

            // truncate at first * if any
            Pos = fileSpec.IndexOf("*");
            if (Pos >= 0) fileSpec = fileSpec.Substring(0, Pos);

            // if truncated string contains ? wildcards, truncate at first ?
            Pos = fileSpec.IndexOf("?");
            if (Pos >= 0) fileSpec = fileSpec.Substring(0, Pos);

            // find the last . and check it is after the last \ and then truncate there
            Pos = fileSpec.LastIndexOf(".");
            if (Pos >= 0 && Pos > fileSpec.LastIndexOf(@"\")) fileSpec = fileSpec.Substring(0, Pos);

            // check to make sure we have a partial file name ... otherwise, use SQLNA.log
            if (fileSpec.Length == 0 || fileSpec.EndsWith(@"\") || fileSpec.EndsWith(@":"))
            {
                fileSpec += "SQLNA";
            }

            // append .log to remaining file name
            return fileSpec + ".log";
        }

        public static string getDiagLogFileName(string LogName)
        {
            int PosDot = -1;
            int PosSlash = -1;

            // truncate at first * if any
            PosDot = LogName.LastIndexOf(".");
            if (PosDot >= 0)
            {
                PosSlash = LogName.LastIndexOf(@"\");
                if (PosDot < PosSlash)
                {
                    return LogName + ".diag.log";
                }
                else
                {
                    return LogName.Substring(0, PosDot) + ".diag" + LogName.Substring(PosDot);
                }
            }
            else
            {
                return LogName + ".diag.log";
            }
        }

        public static string getStatLogFileName(string LogName)
        {
            int PosDot = -1;
            int PosSlash = -1;

            // truncate at first * if any
            PosDot = LogName.LastIndexOf(".");
            if (PosDot >= 0)
            {
                PosSlash = LogName.LastIndexOf(@"\");
                if (PosDot < PosSlash)
                {
                    return LogName + ".stat.csv";
                }
                else
                {
                    return LogName.Substring(0, PosDot) + ".stat.csv";
                }
            }
            else
            {
                return LogName + ".stat.csv";
            }
        }

        #endregion

        #region "Byte to number helpers"

        // "Read" functions are little-endian (Intel normal), i.e. MSB is at the largest address and LSB is at the lowest address

        public static UInt64 ReadUInt64(byte[] b, int startOffset)
        {
            UInt64 v = 0;
            v = (UInt64)b[startOffset + 7];
            v <<= 8;
            v += (UInt64)b[startOffset + 6];
            v <<= 8;
            v += (UInt64)b[startOffset + 5];
            v <<= 8;
            v += (UInt64)b[startOffset + 4];
            v <<= 8;
            v += (UInt64)b[startOffset + 3];
            v <<= 8;
            v += (UInt64)b[startOffset + 2];
            v <<= 8;
            v += (UInt64)b[startOffset + 1];
            v <<= 8;
            v += (UInt64)b[startOffset + 0];
            return v;
        }

        // Converts bytes to UInt32 value.
        public static UInt32 ReadUInt32(byte[] tds, int pos)
        {
            UInt32 v;
            v = (UInt32)tds[pos + 3];
            v <<= 8;
            v += (UInt32)tds[pos + 2];
            v <<= 8;
            v += (UInt32)tds[pos + 1];
            v <<= 8;
            v += (UInt32)tds[pos + 0];
            return v;
        }

        public static UInt16 ReadUInt16(byte[] tds, int pos)
        {
            UInt16 v;
            v = (UInt16)tds[pos + 1];
            v <<= 8;
            v += (UInt16)tds[pos + 0];
            return v;
        }

        // "B" functions are big-endian, i.e. MSB is at the lowest address and MSB is at the lowest address

        public static UInt16 B2UInt16(byte[] b, int startOffset)
        {
            UInt16 v = 0;
            v = (UInt16)b[startOffset + 0];
            v <<= 8;
            v += (UInt16)b[startOffset + 1];
            return v;
        }

        // Helper function to convert bytes to UInt32 value.
        public static UInt32 B2UInt32(byte[] b, int startOffset)
        {
            UInt32 v = 0;
            v = (UInt32)b[startOffset + 0];
            v <<= 8;
            v += (UInt32)b[startOffset + 1];
            v <<= 8;
            v += (UInt32)b[startOffset + 2];
            v <<= 8;
            v += (UInt32)b[startOffset + 3];
            return v;
        }

        // Helper function to convert bytes to UInt48 value.
        public static UInt64 B2UInt48(byte[] b, int startOffset)
        {
            UInt64 v = 0;
            v = (UInt64)b[startOffset + 0];
            v <<= 8;
            v += (UInt64)b[startOffset + 1];
            v <<= 8;
            v += (UInt64)b[startOffset + 2];
            v <<= 8;
            v += (UInt64)b[startOffset + 3];
            v <<= 8;
            v += (UInt64)b[startOffset + 4];
            v <<= 8;
            v += (UInt64)b[startOffset + 5];
            return v;
        }

        // Helper function to convert bytes to UInt64 value.
        public static UInt64 B2UInt64(byte[] b, int startOffset)
        {
            UInt64 v = 0;
            v = (UInt64)b[startOffset + 0];
            v <<= 8;
            v += (UInt64)b[startOffset + 1];
            v <<= 8;
            v += (UInt64)b[startOffset + 2];
            v <<= 8;
            v += (UInt64)b[startOffset + 3];
            v <<= 8;
            v += (UInt64)b[startOffset + 4];
            v <<= 8;
            v += (UInt64)b[startOffset + 5];
            v <<= 8;
            v += (UInt64)b[startOffset + 6];
            v <<= 8;
            v += (UInt64)b[startOffset + 7];
            return v;
        }

        #endregion

        #region "Byte reversal helpers"

        public static Int16 ReverseInt16(Int16 data)
        {
            return (Int16)(((data & 0xFFU) << 8) | ((data & 0xFF00U) >> 8));
        }

        public static UInt16 ReverseUInt16(UInt16 data)
        {
            return (UInt16)(((data & 0xFFU) << 8) | ((data & 0xFF00U) >> 8));
        }

        public static Int32 ReverseUInt32(Int32 data)
        {
            return (Int32)((data & 0x000000FFU) << 24 | (data & 0x0000FF00U) << 8 | (data & 0x00FF0000U) >> 8 | (data & 0xFF000000U) >> 24);
        }

        public static UInt32 ReverseUInt32(UInt32 data)
        {
            return (data & 0x000000FFU) << 24 | (data & 0x0000FF00U) << 8 | (data & 0x00FF0000U) >> 8 | (data & 0xFF000000U) >> 24;
        }

        public static Int64 ReverseUInt64(Int64 data)
        {
            //
            // Need the unchecked keyword as the last constant interprets as UINT64 even though no U qualifer and will not cast to Int64
            //
            return (Int64)((data & 0x00000000000000FFL) << 56 | (data & 0x000000000000FF00L) << 40 | (data & 0x0000000000FF0000L) << 24 | (data & 0x00000000FF000000L) << 8 |
                       (data & 0x000000FF00000000L) >> 8 | (data & 0x0000FF0000000000L) >> 24 | (data & 0x00FF000000000000L) >> 40 | (data & unchecked((Int64)(0xFF00000000000000L))));
        }

        public static UInt64 ReverseUInt64(UInt64 data)
        {
            return (data & 0x00000000000000FFUL) << 56 | (data & 0x000000000000FF00UL) << 40 | (data & 0x0000000000FF0000UL) << 24 | (data & 0x00000000FF000000UL) << 8 |
                       (data & 0x000000FF00000000UL) >> 8 | (data & 0x0000FF0000000000UL) >> 24 | (data & 0x00FF000000000000UL) >> 40 | (data & 0xFF00000000000000UL) >> 56;
        }

        #endregion

    }

}
