// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Varous small classes used by NetTrace or by reporting methods in OutputText.cs
    //

    enum FrameType
    {
        TCP = 0,
        UDP = 1
    }

   // enum TDSPacketType
   // {
   //     SQLBATCH           =  1,  //            from client only
   //     LOGIN              =  2,
   //     RPC                =  3,  //            from client only
   //     RESPONSE           =  4,  //            from server only
   //     ATTENTION          =  6,
   //     BULKLOAD           =  7,
   //     DTC                = 14,  // 0x0E
   //     //LOGIN7           = 16,  // 0x10       can be both - both what??? - why commented out???
   //     SSPI               = 17,  // 0x11
   //     PRELOGIN           = 18,  // 0x12       can come from either client or server
   //     APPDATA            = 23   // 0x17       can come from either client or server - TODO - clarify this
   // }

   // enum TDSTokenType
   // {
   //     PRELOGINRESPONSE    =   0, // byte 8 of RESPONSE packet
   //     OFFSET              = 120, // Used to inform the client where in the client's SQL text buffer a particular keyword occurs.
   //     RETURNSTATUS        = 121, //Used to send the status value of an RPC to the client. The server also uses this token to send the result status value of a T-SQL EXEC query.
   //     METADATA            = 136,
   //     TABNAME             = 164, // Used to send the table name to the client only when in browser mode or from sp_cursoropen.
   //     COLINFO             = 165,
   //     ORDER               = 169, //Used to inform the client by which columns the data is ordered
   //     ERROR               = 170,
   //     INFO                = 171, //S--->C
   //     RETURNVALUE         = 172, //Used to send the return value of an RPC to the client
   //     LOGINACK            = 173, //S--->C
   //     EXTACK              = 174, //FEATUREEXTACK, 
   //     NBCROW              = 210, //S--->C
   //     ROW                 = 211,
   //     ENVCHANGE           = 227,
   //     SESSIONSTATE        = 228, //Used to send session state data to the client. 
   //     SSPI                = 237, // 0xED
   //     DONE                = 253,
   //     DONEPROC            = 254,
   //     DONEINPROC          = 255,
   //}

    enum TCPFlag
    {
        FIN          =    1,
        SYN          =    2,
        RESET        =    4,
        PUSH         =    8,
        ACK          = 0x10,   // 16
        URGENT       = 0x20    // 32
    }

    

    class FileData                      //               - constructed in ParseFileSpec
    {
        public string filePath = null;  //               - set in ParseFileSpec
        public DateTime fileDate;       //               - set in ParseFileSpec
        public long fileSize = 0;       //               - set in ParseFileSpec
        public long startTick = 0;
        public long endTick = 0;
        public int frameCount = 0;
    }

    class SQLServer                                         // constructed in ProcessTDS
    {
        public uint sqlIP = 0;
        public ulong sqlIPHi = 0;
        public ulong sqlIPLo = 0;
        public ushort sqlPort = 0;
        public bool isIPV6 = false;
        public bool hasResets = false;                         // set in OutputText.DisplaySQLServerSummary
        public bool hasLoginFailures = false;                  // set in OutputText.DisplaySQLServerSummary
        public bool hasAttentions = false;                     // set in OutputText.DisplaySQLServerSummary
        public bool hasLowTLSVersion = false;                  // set in OutputText.DisplaySQLServerSummary
        public bool hasPostLogInResponse = false;
        public bool hasReadOnlyIntentConnections = false;
        public string serverVersion = "";
        public string instanceName = "";
        public string sqlHostName = "";
        public string namedPipe = "";
        public string isClustered = "";
        public ArrayList conversations = new ArrayList(1024);  // pre-size to moderate starting amount - SQL may have few or many conversations
    }

    public class ResetConnectionData
    {
        public string clientIP = null;
        public ushort sourcePort = 0;
        public bool isIPV6 = false;
        public int frames = 0;
        public uint ResetFrame = 0;
        public uint rawRetransmits = 0;
        public int firstFile = 0;
        public int lastFile = 0;
        public long startOffset = 0;
        public long endOffset = 0;
        public long endTicks = 0;
        public long duration = 0;
        public bool isClientReset = false;
        public string flags = null;
        public uint keepAliveCount = 0;
    }

    public class FailedConnectionData
    {
        public string clientIP = null;
        public ushort sourcePort = 0;
        public bool isIPV6 = false;
        public int frames = 0;
        public uint lastFrame = 0;
        public uint rawRetransmits = 0;
        public int firstFile = 0;
        public int lastFile = 0;
        public long startOffset = 0;
        public long endOffset = 0;
        public long endTicks = 0;
        public long duration = 0;
        public string loginProgress = null;
        public uint keepAliveCount = 0;
        public bool hasNullNTLMCreds = false;
        public bool LateLoginAck = false;
        public uint Error;
        public uint ErrorState;
        public string ErrorMsg;
    }

    public class ReadOnlyIntentConnectionData
    {
        public string clientIP = null;
        public ushort sourcePort = 0;
        public bool isIPV6 = false;
        public int frames = 0;
        public uint lastFrame = 0;
        public int firstFile = 0;
        public int lastFile = 0;
        public long startOffset = 0;
        public long endOffset = 0;
        public long endTicks = 0;
        public long duration = 0;
        public uint RedirectPort = 0;
        public string RedirectServer = "";
    }

    public class AttentionConnectionData
    {
        public string clientIP = null;
        public ushort sourcePort = 0;
        public bool isIPV6 = false;
        public int frames = 0;
        public uint AttentionFrame = 0;
        public int AttentionFile = 0;
        public long startOffset = 0;
        public long AttentionOffset = 0;
        public long AttentionTicks = 0;
    }

    public class LowTLSData
    {
        public string clientIP = null;
        public ushort sourcePort = 0;
        public bool isIPV6 = false;
        public long startOffset = 0;
        public int frames = 0;
        public int firstFile = 0;
        public int lastFile = 0;
        public bool hasClientHello = false;
        public string ClientTLSVersion = "";
        public bool hasServerHello = false;
        public string ServerTLSVersion = "";
        public bool hasLogin7 = false;
        public bool hasLogin = false;
    }

    public class SucessfulLoginData
    {
        public string clientIP = null;
        public ushort sourcePort = 0;
        public bool isIPV6 = false;
        public int StartFrame = 0;
        public uint firstFrame = 0;
        public uint lastFrame = 0;
        public int Connectionframe = 0;
        public int firstFile = 0;
        public int lastFile = 0;
        public long duration = 0;
        public long startOffset = 0;
        public long endOffset = 0;
        public long endTicks = 0;
        public int frames = 0;

    }

    //
    // Used for ephemaral ports report
    //

    public class IPRecord
    {
        public uint IP = 0;
        public ulong IPHi = 0;
        public ulong IPLo = 0;
        public int ExistingConnections = 0;
        public int NewConnections = 0;
        public int ExistingSQLConnections = 0;
        public int NewSQLConnections = 0;
        public int PeakConnectionsPerMinute = 0;
        public ushort LowPort = 65535;
        public ushort HighPort = 0;

        public bool isMatch(ConversationData c)
        {
            return ((IP == c.sourceIP && IPHi == c.sourceIPHi && IPLo == c.sourceIPLo) ||
                    (IP == c.destIP && IPHi == c.destIPHi && IPLo == c.destIPLo));
        }

        public bool isSource(ConversationData c)
        {
            return (IP == c.sourceIP && IPHi == c.sourceIPHi && IPLo == c.sourceIPLo);
        }
    }

}
