// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Data that is stored per frame
    // Helper methods for getting formatted data
    // Helper methods for dumping frames for debugging purposes
    //
    // Handling of PKTMON additional events. Should they be in-line with other frames in the conversation?
    // Probably not, since this would complicate all other analyses.
    // Should probably be in a side collection in each regular frame, so we do not bloat the conversation itself.
    //

    public enum FrameType
    {
        PreLogin = 1,                                     // set in ProcessTDS
        PreLoginResponse,                                 // set in ProcessTDS
        ClientHello,                                      // set in ProcessTDS
        ServerHello,                                      // set in ProcessTDS
        KeyExchange,                                      // set in ProcessTDS
        CipherChange,                                     // set in ProcessTDS
        ApplicationData,                                  // set in ProcessTDS
        Login7,                                           // set in ProcessTDS - we should never see this in the raw, should be ApplicationData instead
        SSPI,                                             // set in ProcessTDS
        NTLMChallenge,                                    // set in ProcessTDS
        NTLMResponse,                                     // set in ProcessTDS
        LoginAck,                                         // set in ProcessTDS
        LoginError,                                       // set in ProcessTDS
        Attention,                                        // set in ProcessTDS
        SQLBatch,                                         // set in ProcessTDS
        RPCRequest,                                       // set in ProcessTDS
        XactMgrRequest,                                   // set in ProcessTDS
        XActMgrReply,                                     // placeholder
        CommandError,                                     // set in ProcessTDS
        TabularResponse,                                  // set in ProcessTDS
        SMPAck,                                           // set in ParseTCPFrame
        SMPSyn,                                           // set in ParseTCPFrame
        SMPFin                                            // set in ParseTCPFrame
    }

    public class FrameData                                // constructed in ParseOneFile
    {
        public ConversationData conversation = null;      // set in ParseIPV4Frame and ParseIPV6Frame
        public FileData file = null;                      // set in ParseOneFile
        public PktmonData pktmon = null;                  // set in ParsePktmonFrame
        public ArrayList pktmonComponentFrames = null;    // set in Conversation.AddFrame, which replaces Conversation.frames.Add; this frame will also be first in the ArrayList
        public uint frameNo = 0;                          // set in ParseOneFile
        public long ticks = 0;                            // set in ParseOneFile
        public uint frameLength = 0;                      // set in ParseOneFile
        public uint capturedFrameLength = 0;              // set in ParseOneFile
        public bool isUDP = false;                        // set in ParseUDPFrame      
        public uint seqNo = 0;                            // set in ParseTCPFrame
        public uint ackNo = 0;                            // set in ParseTCPFrame
        public byte flags = 0;                            // set in ParseTCPFrame
        public ushort windowSize = 0;                     // set in ParseTCPFrame
        public ushort smpSession = 0;                     // set in ParseTCPFrame
        public byte smpType = 0;                          // set in ParseTCPFrame
        public byte[] payload = null;                     // set in ParseTCPFrame and ParseUDPFrame
        public FrameType frameType = 0;                   // set in ProcessTDS
        public bool isKeepAliveRetransmit = false;        // set in FindKeepAliveRetransmits
        public ushort kaRetransmitCount = 0;              // set in FindKeepAliveRetransmits
        public bool isRetransmit = false;                 // set in FindRetransmits
        public ushort retransmitCount = 0;                // set in FindRetransmits
        public FrameData originalFrame = null;            // set in FindRetransmits or FindKeepAliveRetransmits
        public bool isFromClient = false;                 // set in ParseIPV4Frame and ParseIPV6Frame
        public bool isContinuation = false;
        public ushort lastByteOffSet = 0;                 // set in ParseIPV4Frame and ParseIPV6Frame - offset of last byte in the IPV4 or IPV6 portion of the frame - should be the last byte of the payload
        public ushort packetID = 0;                       // set in ParseIPV4Frame (not available in IPV6)
        public byte[] reassembledPayLoad = null;

        public TDSHeader GetTDSHeader()
        {
            TDSHeader head = null;
            TDSReader r = null;                 // TDSReader does not need to be closed; GC is all it needs
            try
            {
                r = new TDSReader(payload, 0);  // header does not span packets, so we can read without aggregating
                head = TDSHeader.Read(r);
            }
            catch (Exception) { return null; }  // null if error
            return head;
        }

        public int payloadLength
        {
            get { return (payload == null) ? 0 : payload.Length; }
        }

        public int reassembledPayLoadLength
        {
            get { return (reassembledPayLoad == null) ? 0 : reassembledPayLoad.Length; }
        }

        public bool isKeepAlive
        {
            get
            {
                return ((payloadLength == 1) &&
                        (payload[0] == 0) &&
                        ((flags & (byte)TCPFlag.ACK) != 0) &&
                        ((flags & (byte)(TCPFlag.FIN | TCPFlag.FIN | TCPFlag.SYN | TCPFlag.RESET | TCPFlag.PUSH)) == 0));
            }
        }

        public bool hasFINFlag
        {
            get { return (flags & (byte)TCPFlag.FIN) != 0; }
        }

        public bool hasSYNFlag
        {
            get { return (flags & (byte)TCPFlag.SYN) != 0; }
        }

        public bool hasACKFlag
        {
            get { return (flags & (byte)TCPFlag.ACK) != 0; }
        }

        public bool hasPUSHFlag
        {
            get { return (flags & (byte)TCPFlag.PUSH) != 0; }
        }

        public bool hasRESETFlag
        {
            get { return (flags & (byte)TCPFlag.RESET) != 0; }
        }

        public string PacketType
        {
            get
            {
                switch (frameType)
                {
                    case FrameType.ApplicationData:      return "AD";
                    case FrameType.Attention:            return "ATTN";
                    case FrameType.CipherChange:         return "CE";
                    case FrameType.ClientHello:          return "CH";
                    case FrameType.CommandError:         return "ERR";
                    case FrameType.KeyExchange:          return "KE";
                    case FrameType.Login7:               return "L7";
                    case FrameType.LoginAck:             return "LA";
                    case FrameType.LoginError:           return "ER";
                    case FrameType.NTLMChallenge:        return "NC";
                    case FrameType.NTLMResponse:         return "NR";
                    case FrameType.PreLogin:             return "PL";
                    case FrameType.PreLoginResponse:     return "PR";
                    case FrameType.RPCRequest:           return "RPC";
                    case FrameType.ServerHello:          return "SH";
                    case FrameType.SMPAck:               return "SmpA";
                    case FrameType.SMPFin:               return "SmpF";
                    case FrameType.SMPSyn:               return "SmpS";
                    case FrameType.SQLBatch:             return "BAT";
                    case FrameType.SSPI:                 return "SS";
                    case FrameType.TabularResponse:      return "DATA";
                    case FrameType.XactMgrRequest:       return "TX";
                    default:
                        {
                            if (isKeepAlive) return "KA";
                            return FormatFlags("");
                        };
                }
            }
        }

        public string PacketTypeAndDirection
        {
            get
            {
                return (isFromClient ? ">" : "<") + PacketType;
            }
        }


        public string ColumnHeader1()
        {
            if (conversation.isUDP)
            {
                return "Frame     D FrLen  CapLen Time of Day            PLen  Payload Bytes - first 20                                    Payload Text";
            }
            else
            {
                return "Frame     D FrLen  CapLen Time of Day            Seq Number Ack Number Flags R C SMP   PLen  Payload Bytes - first 20                                    Payload Text";
            }
        }

        public string ColumnHeader2()
        {
            if (conversation.isUDP)
            {
                return "--------- - ------ ------ ---------------------- ----- ----------------------------------------------------------- --------------------";
            }
            else
            {
                return "--------- - ------ ------ ---------------------- ---------- ---------- ----- - - ----- ----- ----------------------------------------------------------- --------------------";
            }
        }

        public string ColumnData()
        {
            if (conversation.isUDP)
            {
                return frameNo.ToString().PadLeft(9) +
                       " " + ((isFromClient == true) ? "C" : "S") +
                       frameLength.ToString().PadLeft(7) +
                       capturedFrameLength.ToString().PadLeft(7) +
                       " " + new DateTime(ticks).ToString(utility.DATE_FORMAT) +
                       payloadLength.ToString().PadLeft(6) +
                       FormatPayload(20) +
                       " " + FormatPayloadChars(20);
            }
            else
            {
                return frameNo.ToString().PadLeft(9) +
                       " " + ((isFromClient == true) ? "C" : "S") +
                       frameLength.ToString().PadLeft(7) +
                       capturedFrameLength.ToString().PadLeft(7) +
                       " " + new DateTime(ticks).ToString(utility.DATE_FORMAT) +
                       seqNo.ToString().PadLeft(11) +
                       ackNo.ToString().PadLeft(11) +
                       " " + FormatFlags() +
                       " " + ((isRetransmit == true) ? "R" : " ") +
                       " " + ((isContinuation == true) ? "C" : " ") +
                       ((smpSession == 0) ? "      " : smpSession.ToString().PadLeft(6)) +
                       payloadLength.ToString().PadLeft(6) +
                       FormatPayload(20) +
                       " " + FormatPayloadChars(20);
            }
        }

        public string FormatFlags(string filler = ".")
        {
            string s = "";
            s += ((flags & (byte)TCPFlag.ACK) != 0) ? "A" : filler;
            s += ((flags & (byte)TCPFlag.PUSH) != 0) ? "P" : filler;
            s += ((flags & (byte)TCPFlag.RESET) != 0) ? "R" : filler;
            s += ((flags & (byte)TCPFlag.SYN) != 0) ? "S" : filler;
            s += ((flags & (byte)TCPFlag.FIN) != 0) ? "F" : filler;
            return s;
        }

        public string FormatPayload(int Length)
        {
            string s = "";
            if (payload != null)
            {
                for (int i = 0; i < ((payload.Length < Length) ? payload.Length : Length); i++)
                {
                    s += " " + payload[i].ToString("X2");
                }
            }
            return s.PadRight(Length * 3);
        }

        public string FormatPayloadChars(int Length)
        {
            string s = "";
            char c = '.';
            if (payload != null)
            {
                for (int i = 0; i < ((payload.Length < Length) ? payload.Length : Length); i++)
                {
                    c = (char)payload[i];
                    s += ((c < 32 || c > 126) ? "." : c.ToString());
                }
            }
            return s;
        }

    }


}