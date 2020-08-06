// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;


namespace SQLNA
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Data that is stored per conversation
    // Helper methods for getting formatted data
    // Helper methods for dumping conversations for debugging purposes
    //

    public class ConversationData              //               - constructed in GetIPV4Conversation and GetIPV6Conversation
    {
        public ulong sourceMAC = 0;     // six bytes     - set in ParseEthernetFrame
        public uint sourceIP = 0;       // IPV4          - set in GetIPV4Conversation
        public ulong sourceIPHi = 0;    // IPV6          - set in GetIPV6Conversation
        public ulong sourceIPLo = 0;    // IPV6          - set in GetIPV6Conversation
        public ushort sourcePort = 0;   //               - set in GetIPV4Conversation and GetIPV6Conversation
        public ulong destMAC = 0;       // six bytes     - set in ParseEthernetFrame
        public uint destIP = 0;         // IPV4          - set in GetIPV4Conversation
        public ulong destIPHi = 0;      // IPV6          - set in GetIPV6Conversation
        public ulong destIPLo = 0;      // IPV6          - set in GetIPV6Conversation
        public ushort destPort = 0;     //               - set in GetIPV4Conversation and GetIPV6Conversation
        public bool isIPV6 = false;     //               - set in GetIPV6Conversation; GetIPV4Conversation leaves at default
        public bool isUDP = false;      //               - set in ParseUDPFrame; ParseTCPFrame leaves it at default
        public byte nextProtocol = 0;   //               - set in ParseIPV4Frame and ParseIPV6Frame (6 or 17)
        public ArrayList frames = new ArrayList();  //   - frame added in ParseIPV4Frame and ParseIPV6Frame
        // SQL-specific values
        public bool hasTDS = false;                 //   - set in ProcessTDS
        public bool isSQL = false;                  //   - set in ProcessTDS
        public bool isEncrypted = false;            //   - set in GetServerPreloginInfo
        public bool isMARSEnabled = false;          //   - set in ParseTCPFrame - when we detect SMP header
        public bool hasPrelogin = false;            //   - set in ProcessTDS
        public bool hasPreloginResponse = false;    //   - set in ProcessTDS
        public bool hasClientSSL = false;           //   - set in ProcessTDS
        public bool hasServerSSL = false;           //   - set in ProcessTDS
        public bool hasKeyExchange = false;         //   - set in ProcessTDS
        public bool hasCipherExchange = false;      //   - set in ProcessTDS
        public bool hasApplicationData = false;     //   - set in ProcessTDS   - this is the encrypted logon payload token
        public bool hasLogin7 = false;              //   - set in ProcessTDS   - this is the unencrypted login payload token - we should not see this unless SSL/TLS is disabled - very unsecure
        public bool hasNTLMChallenge = false;       //   - set in ProcessTDS
        public bool hasNTLMResponse = false;        //   - set in ProcessTDS
        public bool hasNullNTLMCreds = false;       //   - set in ProcessTDS
        public bool hasIntegratedSecurity = false;  //   - set in ProcessTDS
        public bool hasPostLoginResponse = false;   //   - set in ProcessTDS   - this contains the ENVCHANGE token - login was a success
        public int SPID = 0;
        public string clientVersion = null;         //   - set in GetClientPreloginInfo
        public string serverVersion = null;         //   - set in ProcessTDS
        public uint tdsVersionServer = 0;           //   - set in ProcessTDS
        public uint tdsVersionClient = 0;           //   - set in ProcessTDS
        public string tlsVersionClient = null;      //   - set in ProcessTDS
        public string tlsVersionServer = null;      //   - set in ProcessTDS
        public bool hasLowTLSVersion = false;       //   - set in ProcessTDS
        public string databaseName = null;          //   - set in ProcessTDS
        public string serverName = null;            //   - set in ProcessTDS
        public uint processID = 0;
        public uint threadID = 0;                   //   - set in GetClientPreloginInfo
        // Conversation statistics
        public int tdsFrames = 0;       //               - set in ProcessTDS
        public ulong totalBytes = 0;    //               - set in ParseEthernetFrame
        public long startTick = 0;      //               - set in ParseEthernetFrame
        public long endTick = 0;        //               - set in ParseEthernetFrame
        public int ackCount = 0;        //               - accumulated in ParsetTCPFrame
        public int pushCount = 0;       //               - accumulated in ParsetTCPFrame
        public int resetCount = 0;      //               - accumulated in ParsetTCPFrame
        public int synCount = 0;        //               - accumulated in ParsetTCPFrame
        public int finCount = 0;        //               - accumulated in ParsetTCPFrame
        public uint missingPackets = 0;
        public uint rawRetransmits = 0; //               - accumulated in FindRetransmits
        public uint sigRetransmits = 0; //               - accumulated in FindRetransmits
        public uint sourceFrames = 0;   //               - accumulated in ParseEthernetFrame
        public uint destFrames = 0;     //               - accumulated in ParseEthernetFrame
        public uint keepAliveCount = 0; //               - accumulated in ParseTCPFrame
        public uint truncatedFrameLength = 0; //         
        public uint truncationErrorCount = 0; //         
        public long LoginAckTime = 0;               //   - set in TDS Parser - so we can check whether LoginAck was sent after connection was closed
        public long FinTime = 0;                    //   - set in TCP Parser - so we can check whether LoginAck was sent after connection was closed
        public long ResetTime = 0;                  //   - set in TCP Parser - so we can check whether LoginAck was sent after connection was closed
        public long AttentionTime = 0;              //   - set in TDS Parser - so we can identify command timeouts

        public bool hasLateLoginAck  // added Dec 5, 2016
        {
            get
            {
                if (LoginAckTime == 0)
                {
                    return false;
                }
                else
                {
                    if (FinTime > 0 && LoginAckTime > FinTime) return true;
                    if (ResetTime > 0 && LoginAckTime > ResetTime) return true;
                    return false;
                }
            }
        }

        public bool hasLoginFailure     // TODO this needs work one of the OR-ed flags below is TRUE and it shouldn't be...
        {
            get
            {
                if (hasLateLoginAck) return true; // added Dec 5, 2016
                if (isEncrypted)
                {
                    if ((hasApplicationData == false) &&
                        ((resetCount > 0) || (finCount > 0)) &&
                        ((synCount > 0) || hasPrelogin || hasPreloginResponse || hasClientSSL || hasServerSSL ||
                          hasKeyExchange || hasCipherExchange || hasNTLMChallenge || hasNTLMResponse))
                    {
                        return true;
                    }
                }
                else if ((hasPostLoginResponse == false) &&
                        ((resetCount > 0) || (finCount > 0)) &&
                        ((synCount > 0) || hasPrelogin || hasPreloginResponse || hasClientSSL || hasServerSSL ||
                          hasKeyExchange || hasCipherExchange || hasNTLMChallenge || hasNTLMResponse || hasApplicationData))
                {
                    return true;
                }
                return false;
            }
        }

        public string FriendlyTDSVersionServer  // these are SERVER return codes, not client codes, which are different
        {
            get
            {
                switch (tdsVersionServer)
                {
                    case 0:
                        {
                            return isSQL ? "Unknown" : "";
                        }
                    case 0x07000000:
                        {
                            return "7.0 (SQL 7.0)";
                        }
                    case 0x07010000:
                        {
                            return "7.1 (SQL 2000)";
                        }
                    case 0x71000001:
                        {
                            return "7.1 (SQL 2000 SP1)";
                        }
                    case 0x72090002:
                        {
                            return "7.2 (SQL 2005)";
                        }
                    case 0x730A0003:
                        {
                            return "7.3 (SQL 2008)";
                        }
                    case 0x730B0003:
                        {
                            return "7.3 (SQL 2008 R2)";
                        }
                    case 0x74000004:
                        {
                            return "7.4 (SQL 2012+)";
                        }
                    default:
                        {
                            return tdsVersionServer.ToString("X8");
                        }
                }
            }
        }

        public string FriendlyTDSVersionClient  // these are SERVER return codes, not client codes, which are different
        {
            get
            {
                switch (tdsVersionClient)
                {
                    case 0:
                        {
                            return isSQL ? "Unknown" : "";
                        }
                    case 0x00000070:
                        {
                            return "7.0 (SQL 7.0)";
                        }
                    case 0x00000071:
                        {
                            return "7.1 (SQL 2000)";
                        }
                    case 0x01000071:
                        {
                            return "7.1 (SQL 2000 SP1)";
                        }
                    case 0x02000972:
                        {
                            return "7.2 (SQL 2005)";
                        }
                    case 0x03000A73:
                        {
                            return "7.3 (SQL 2008)";
                        }
                    case 0x03000B73:
                        {
                            return "7.3 (SQL 2008 R2)";
                        }
                    case 0x04000074:
                        {
                            return "7.4 (SQL 2012+)";
                        }
                    default:
                        {
                            return tdsVersionServer.ToString("X8");
                        }
                }
            }
        }

        public string loginFlags
        {
            get
            {
                string s = (synCount > 0 ? "S " : "  ") +
                           (hasPrelogin ? "PL " : "   ") +
                           (hasPreloginResponse ? "PR " : "   ") +
                           (hasClientSSL ? "CH " : "   ") +
                           (hasServerSSL ? "SH " : "   ") +
                           (hasKeyExchange ? "KE " : "   ") +
                           (hasCipherExchange ? "CE " : "   ") +
                           (hasApplicationData ? "AD " : "   ") +
                           (hasNTLMChallenge ? "NC " : "   ") +
                           (hasNTLMResponse ? "NR" : "  ");

                return s;
            }
        }

        public string ColumnHeader1()
        {
            string s = "";
            if (isIPV6)
            {
                s = "Source MAC   Dest MAC     Source IP Address                       SPort Destination IP Address                  DPort";
            }
            else
            {
                s = "Source MAC   Dest MAC     Source IP       SPort Destination IP  DPort";
            }
            if (isUDP)
            {
                return s + " Protocol StartTime              End Time               Duration (s) Frames   SFrames  DFrames";
            }
            else
            {
                return s +
                       " Protocol StartTime              " +
                       "End Time               Duration (s) Frames   SFrames  DFrames  ACK    PUSH   RESET  SYN FIN Missing Raw Retrans Sig Retrans SQL TDS Frames SPID";
            }
        }

        public string ColumnHeader2()
        {
            string s = "";

            if (isIPV6)
            {
                s = "------------ ------------ --------------------------------------- ----- --------------------------------------- -----";
            }
            else
            {
                s = "------------ ------------ --------------- ----- --------------- -----";
            }
            if (isUDP)
            {
                return s + " -------- ---------------------- ---------------------- ------------ -------- -------- --------";
            }
            else
            {
                return s +
                       " -------- ---------------------- " +
                       "---------------------- ------------ -------- -------- -------- ------ ------ ------ --- --- ------- ----------- ----------- --- ---------- -----";
            }
        }

        public string ColumnData()
        {
            if (isUDP)
            {
                return sourceMAC.ToString("X12") +
                       " " + destMAC.ToString("X12") +
                       (isIPV6 ? utility.FormatIPV6Address(sourceIPHi, sourceIPLo).PadLeft(40) : utility.FormatIPV4Address(sourceIP).PadLeft(16)) +
                       sourcePort.ToString().PadLeft(6) +
                       (isIPV6 ? utility.FormatIPV6Address(destIPHi, destIPLo).PadLeft(40) : utility.FormatIPV4Address(destIP).PadLeft(16)) +
                       destPort.ToString().PadLeft(6) +
                       (isUDP ? "      UDP" : "      TCP") +
                       " " + new DateTime(startTick).ToString(utility.DATE_FORMAT) +
                       " " + new DateTime(endTick).ToString(utility.DATE_FORMAT) +
                       ((double)(endTick - startTick) / 10000000).ToString("0.000000").PadLeft(13) +
                       frames.Count.ToString().PadLeft(9) +
                       sourceFrames.ToString().PadLeft(9) +
                       destFrames.ToString().PadLeft(9);
            }
            else
            {
                return sourceMAC.ToString("X12") +
                       " " + destMAC.ToString("X12") +
                       (isIPV6 ? utility.FormatIPV6Address(sourceIPHi, sourceIPLo).PadLeft(40) : utility.FormatIPV4Address(sourceIP).PadLeft(16)) +
                       sourcePort.ToString().PadLeft(6) +
                       (isIPV6 ? utility.FormatIPV6Address(destIPHi, destIPLo).PadLeft(40) : utility.FormatIPV4Address(destIP).PadLeft(16)) +
                       destPort.ToString().PadLeft(6) +
                       (isUDP ? "      UDP" : "      TCP") +
                       " " + new DateTime(startTick).ToString(utility.DATE_FORMAT) +
                       " " + new DateTime(endTick).ToString(utility.DATE_FORMAT) +
                       ((double)(endTick - startTick) / 10000000).ToString("0.000000").PadLeft(13) +
                       frames.Count.ToString().PadLeft(9) +
                       sourceFrames.ToString().PadLeft(9) +
                       destFrames.ToString().PadLeft(9) +
                       ackCount.ToString().PadLeft(7) +
                       pushCount.ToString().PadLeft(7) +
                       resetCount.ToString().PadLeft(7) +
                       synCount.ToString().PadLeft(4) +
                       finCount.ToString().PadLeft(4) +
                       missingPackets.ToString().PadLeft(8) +
                       rawRetransmits.ToString().PadLeft(12) +
                       sigRetransmits.ToString().PadLeft(12) +
                       (isSQL ? " YES" : "  No") +
                       tdsFrames.ToString().PadLeft(11) +
                       SPID.ToString().PadLeft(6);
            }
        }
    }
}