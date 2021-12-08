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
        public ArrayList packets = new ArrayList(); //   - packet added in CreatingPacketsFromFrames
        // SQL-specific values
        public bool hasTDS = false;                 //   - set in ProcessTDS
        public bool isSQL = false;                  //   - set in ProcessTDS
        public bool isEncrypted = false;            //   - set in GetServerPreloginInfo
        public bool isMARSEnabled = false;          //   - set in ProcessTDS - in PreLogin packet
        public bool hasPrelogin = false;            //   - set in ProcessTDS
        public bool hasPreloginResponse = false;    //   - set in ProcessTDS
        public bool hasClientSSL = false;           //   - set in ProcessTDS
        public bool hasServerSSL = false;           //   - set in ProcessTDS
        public bool hasKeyExchange = false;         //   - set in ProcessTDS
        public bool hasCipherExchange = false;      //   - set in ProcessTDS
        public bool hasApplicationData = false;     //   - set in ProcessTDS   - this is the encrypted logon payload token
        public bool hasLogin7 = false;              //   - set in ProcessTDS   - this is the unencrypted login payload token - we should not see this unless SSL/TLS is disabled - very unsecure
        public bool hasSSPI = false;                //   - set in ProcessTDS
        public bool hasNTLMChallenge = false;       //   - set in ProcessTDS
        public bool hasNTLMResponse = false;        //   - set in ProcessTDS
        public bool hasNullNTLMCreds = false;       //   - set in ProcessTDS
        public bool hasIntegratedSecurity = false;  //   - set in ProcessTDS
        public bool hasPostLoginResponse = false;   //   - set in ProcessTDS   - this contains the ENVCHANGE token - login was a success
        public bool hasDiffieHellman = false;       //   - set in ProcessTDS
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
        public ulong totalBytes = 0;    //               - set in ParseTCPFrame
        public ulong totalPayloadBytes = 0;         //   - set in ParseTCPFrame
        public long startTick = 0;      //               - set in ParseEthernetFrame
        public long endTick = 0;        //               - set in ParseEthernetFrame
        public int ackCount = 0;        //               - accumulated in ParseTCPFrame - can be in combination with other flags
        public int pushCount = 0;       //               - accumulated in ParseTCPFrame - can be in combination with other flags
        public int resetCount = 0;      //               - accumulated in ParseTCPFrame - can be in combination with other flags
        public int synCount = 0;        //               - accumulated in ParseTCPFrame - can be in combination with other flags
        public int finCount = 0;        //               - accumulated in ParseTCPFrame - can be in combination with other flags
        public int smpSynCount = 0;     //               - accumulated in ParseTCPFrame
        public int smpAckCount = 0;     //               - accumulated in ParseTCPFrame
        public int smpFinCount = 0;     //               - accumulated in ParseTCPFrame
        public int smpDataCount = 0;    //               - accumulated in ParseTCPFrame
        public int smpMaxSession = -1;  //               - accumulated in ParseTCPFrame
        public uint missingPackets = 0;
        public uint duplicateClientPackets = 0;     //   - accumulated in ParseIPV4Frame - unfortunately IPV6 does not have a packet identifier ****
        public uint duplicateServerPackets = 0;     //   - accumulated in ParseIPV4Frame - unfortunately IPV6 does not have a packet identifier ****
        public uint rawRetransmits = 0;             //   - accumulated in FindRetransmits
        public uint sigRetransmits = 0;             //   - accumulated in FindRetransmits
        public ushort maxRetransmitCount = 0;       //   - accumulated in FindRetransmits
        public uint sourceFrames = 0;               //   - accumulated in ParseEthernetFrame
        public uint destFrames = 0;                 //   - accumulated in ParseEthernetFrame
        public uint keepAliveCount = 0;             //   - accumulated in ParseTCPFrame
        public ushort maxKeepAliveRetransmits = 0;  //   - accoumulated in FindKeepAliveRetransmits
        public uint truncatedFrameLength = 0;       //         
        public uint truncationErrorCount = 0;       //         
        public int maxPayloadSize = 0;              //   - accumulated in ParseTCPFrame
        public bool maxPayloadLimit = false;        //   - accumulated in ParseTCPFrame
        public long synTime = 0;                    //
        public long ackSynTime = 0;                 //
        public long PreLoginTime = 0;               //   - set in TDS Parser - so we can time the PreLogin packet delay
        public long PreLoginResponseTime = 0;       //   - set in TDS Parser - so we can time the Prelogin packet response delay
        public long ClientHelloTime = 0;            //   - set in TDS Parser - so we can time the Client Hello packet delay
        public long ServerHelloTime = 0;            //   - set in TDS Parser - so we can time the Server Hello packet delay
        public long KeyExchangeTime = 0;            //   - set in TDS Parser - so we can time the Key Exchange packet delay
        public long CipherExchangeTime = 0;         //   - set in TDS Parser - so we can time the Cipher Exchange packet delay
        public long LoginTime = 0;                  //   - set in TDS Parser - so we can time the Login or Login7 packet delay
        public long SSPITime = 0;                   //   - set in TDS Parser - so we can time the SSPI packet delay
        public long NTLMChallengeTime = 0;          //   - set in TDS Parser - so we can time the NTLM Challenge packet delay
        public long NTLMResponseTime = 0;           //   - set in TDS Parser - so we can time the NTLM Response packet delay
        public long LoginAckTime = 0;               //   - set in TDS Parser - so we can time the LoginAck packet delay
        public long ErrorTime = 0;                  //   - set in TDS Parser - so we can time the Login Error packet delay
        public long FinTime = 0;                    //   - set in TCP Parser - so we can check whether LoginAck was sent after connection was closed
        public long ResetTime = 0;                  //   - set in TCP Parser - so we can check whether LoginAck was sent after connection was closed
        public long AttentionTime = 0;              //   - set in TDS Parser - so we can identify command timeouts
        public long smpFinTime = 0;                 //   - accumulated in ParseTCPFrame
        public uint Error = 0;
        public string ErrorMsg = "";
        public uint ErrorState = 0;
        public bool hasRedirectedConnection = false;
        public uint RedirectPort = 0;
        public string RedirectServer = "";
        public string PipeAdminName = "";              // - set in TCP Parser
        public ArrayList PipeNames = new ArrayList();  // - set in TCP Parser

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
                if (hasLateLoginAck || ErrorMsg != "") return true; // added Dec 5, 2016
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
                else
                {
                    if (hasApplicationData == true  && synCount == 0 && hasPrelogin == false && hasPreloginResponse == false &&
                        hasClientSSL == false && hasServerSSL == false && hasKeyExchange == false && hasCipherExchange == false &&
                        hasNTLMChallenge == false && hasNTLMResponse == false && frames.Count > (4 + 2 * keepAliveCount + rawRetransmits))
                    {
                        return false;
                    }
                    if ((hasPostLoginResponse == false) &&
                          ((resetCount > 0) || (finCount > 0)) &&
                          ((synCount > 0) || hasPrelogin || hasPreloginResponse || hasClientSSL || hasServerSSL ||
                            hasKeyExchange || hasCipherExchange || hasNTLMChallenge || hasNTLMResponse || hasApplicationData))
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        public long LoginDelay(string step, long firstFrameTick)   // times are in ticks, if prior packet time is unknown - timed to start of trace
        {
            long notPresent = (long)(-1 * utility.TICKS_PER_MILLISECOND);  // this value means a blank in the report instead of a 0.
            long priorTick = firstFrameTick;
            if (synTime != 0) priorTick = synTime;
            if (step == "AS") return ackSynTime == 0 ? notPresent : ackSynTime - priorTick;
            if (ackSynTime != 0) priorTick = ackSynTime;
            if (step == "PL") return PreLoginTime == 0 ? notPresent : PreLoginTime - priorTick;
            if (PreLoginTime != 0) priorTick = PreLoginTime;
            if (step == "PR") return PreLoginResponseTime == 0 ? notPresent : PreLoginResponseTime - priorTick;
            if (PreLoginResponseTime != 0) priorTick = PreLoginResponseTime;
            if (step == "CH") return ClientHelloTime == 0 ? notPresent : ClientHelloTime - priorTick;
            if (ClientHelloTime != 0) priorTick = ClientHelloTime;
            if (step == "SH") return ServerHelloTime == 0 ? notPresent : ServerHelloTime - priorTick;
            if (ServerHelloTime != 0) priorTick = ServerHelloTime;
            if (step == "KE") return KeyExchangeTime == 0 ? notPresent : KeyExchangeTime - priorTick;
            if (KeyExchangeTime != 0) priorTick = KeyExchangeTime;
            if (step == "CE") return CipherExchangeTime == 0 ? notPresent : CipherExchangeTime - priorTick;
            if (CipherExchangeTime != 0) priorTick = CipherExchangeTime;
            if (step == "AD") return LoginTime == 0 ? notPresent : LoginTime - priorTick;
            if (LoginTime != 0) priorTick = LoginTime;
            if (step == "SS") return SSPITime == 0 ? notPresent : SSPITime - priorTick;
            if (SSPITime != 0) priorTick = SSPITime;
            if (step == "NC") return NTLMChallengeTime == 0 ? notPresent : NTLMChallengeTime - priorTick;
            if (NTLMChallengeTime != 0) priorTick = NTLMChallengeTime;
            if (step == "NR") return NTLMResponseTime == 0 ? notPresent : NTLMResponseTime-priorTick;
            if (NTLMResponseTime != 0) priorTick = NTLMResponseTime;
            if (step == "LA") return LoginAckTime == 0 ? notPresent : LoginAckTime - priorTick;
            if (LoginAckTime != 0) priorTick = LoginAckTime;
            if (step == "ER") return ErrorTime == 0 ? notPresent : ErrorTime - priorTick;
            return notPresent;   // -1 means step not in the list above or step time is 0
        }

        public long LastPreloginTime()   // times are in ticks
        {
            if (ErrorTime > 0) return ErrorTime;
            if (LoginAckTime > 0) return LoginAckTime;
            if (NTLMResponseTime > 0) return NTLMResponseTime;
            if (NTLMChallengeTime > 0) return NTLMChallengeTime;
            if (SSPITime > 0) return SSPITime;
            if (CipherExchangeTime > 0) return CipherExchangeTime;
            if (KeyExchangeTime > 0) return KeyExchangeTime;
            if (ServerHelloTime > 0) return ServerHelloTime;
            if (ClientHelloTime > 0) return ClientHelloTime;
            if (PreLoginResponseTime > 0) return PreLoginResponseTime;
            if (PreLoginTime > 0) return PreLoginTime;
            return ackSynTime;
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
                           (hasNTLMResponse ? "NR " : "   ") +
                           (hasSSPI ? "SS " : "   ") +
                           (ErrorTime !=0 ? "ER" : "  ");

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