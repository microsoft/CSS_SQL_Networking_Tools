// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.using System;
using System;
using System.Collections;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Various TDS enums
    // Various readers
    //
    // TODO needs development - need to compare performance and ease of use of reader methods vs. current raw offset method
    //

    public enum TDSPacketType
    {
        SQLBATCH    =  1,    //            from client
        LOGIN       =  2,    //            from client          pre SQL Server 7.0 version of PRELOGIN packet
        RPC         =  3,    //            from client
        RESPONSE    =  4,    //            from server 
        ATTENTION   =  6,    //            from client
        BULKLOAD    =  7,    //            from client
        DTC         = 14,    // 0x0E       from client
        LOGIN7      = 16,    // 0x10       from client          part of the encrypted login sequence - cannot parse this packet type
        SSPI        = 17,    // 0x11
        PRELOGIN    = 18,    // 0x12       from client          for clients that support TDS 7.0 and above
        APPDATA     = 23,    // 0x17       can come from either client or server - TODO - clarify this
        INFO        = 171    // 0xAB       e.g. Change database context 
    }

    public enum TDSTokenType
    {
        PRELOGINRESPONSE    =    0,   // DONE - byte 8 of RESPONSE packet
        OFFSET              =  120,   //        Used to inform the client where in the client's SQL text buffer a particular keyword occurs.
        RETURNSTATUS        =  121,   // DONE   Used to send the status value of an RPC to the client. The server also uses this token to send the result status value of a T-SQL EXEC query.
        COLMETADATA         =  129,   //
        METADATA            =  136,   //
        TABNAME             =  164,   //        Used to send the table name to the client only when in browser mode or from sp_cursoropen.
        COLINFO             =  165,   //
        ORDER               =  169,   //        Used to inform the client by which columns the data is ordered
        ERROR               =  170,   // DONE
        INFO                =  171,   // DONE   S--->C
        RETURNVALUE         =  172,   //        Used to send the return value of an RPC to the client
        LOGINACK            =  173,   // DONE   S--->C
        EXTACK              =  174,   // DONE   FEATUREEXTACK, 
        NBCROW              =  210,   //        S--->C
        ROW                 =  211,   //
        ENVCHANGE           =  227,   // DONE
        SESSIONSTATE        =  228,   //        Used to send session state data to the client. 
        SSPI                =  237,   //        0xED
        DONE                =  253,   // DONE   Done status of SQL statement [within a batch, presumably]
        DONEPROC            =  254,   // DONE   Done status of a stored procedure
        DONEINPROC          =  255,   // DONE   Dome status of a SQL statement within a stored procedure
    }

    public enum TDSTokenColumnType
    {                               // Fixed + Len      Variable + Len + Scale + Precision + Collation [5 bytes]
        Null            =   0x1F,   //    F     1
        Image           =   0x22,   //                      V       4
        Text            =   0x23,   //                      V       4                         7.1 +
        GUID            =   0x24,   //                      V       1   (16 = not-null, 0 = null)
        VarBinary       =   0x25,   //                      V       1
        IntN            =   0x26,   //                      V       1   (1 = TinyInt, 2 = SmallInt, 4 = Int, 8 = BigInt)
        VarChar         =   0x27,   //                      V       1
        DateN           =   0x28,   //                      V       1   (3 = not null, 0 = null)
        TimeN           =   0x29,   //                      V       1+1 (Valid Length/Scale combinations: 3/1, 3/2, 4/3, 4/4, 5/5, 5/6, 5/7)
        DateTime2N      =   0x2A,   //                      V       1+1 (Valid Length/Scale combinations: 6/1, 6/2, 7/3, 7/4, 8/5, 8/6, 8/8)
        DateTimeOffsetN =   0x2B,   //                      V       1+1 (Valid Length/Scale combinations: 8/1, 8/2, 9/3, 9/4, 10/5, 10/6, 10/7)
        Binary          =   0x2D,   //                      V       1
        Char            =   0x2F,   //                      V       1
        TinyInt         =   0x30,   //    F      1
        Bit             =   0x32,   //    F      1
        SmallInt        =   0x34,   //    F      2
        Decimal         =   0x37,   //                      V       1 + 1 + 1   (Precision read before Scale)
        Int             =   0x38,   //    F      4
        SmallDateTime   =   0x3A,   //    F      4
        Real            =   0x3B,   //    F      4
        Money           =   0x3C,   //    F      8
        DateTime        =   0x3D,   //    F      8
        Float           =   0x3E,   //    F      8
        Numeric         =   0x3F,   //                      V       1 + 1 + 1   (Precision read before Scale)
        Variant         =   0x62,   //                      V       4
        NText           =   0x63,   //                      V       4
        BitN            =   0x68,   //                      V       1   (1 = not null, 0 = null)
        DecimalN        =   0x6A,   //                      V       1 + 1 + 1   (Precision read before Scale)
        NumericN        =   0x6C,   //                      V       1 + 1 + 1   (Precision read before Scale)
        FloatN          =   0x6D,   //                      V       1   (4 = Real, 8 = Float)
        MoneyN          =   0x6E,   //                      V       1   (4 = SmallMoney, 8 = Money)
        DateTimeN       =   0x6F,   //                      V       1   (4 = SmallDateTime, 8 = DateTime)
        SmallMoney      =   0x7A,   //   F      4
        BigInt          =   0x7B,   //   F      8
        LongVarBinary   =   0xA5,   //                      V      2
        LongVarChar     =   0xA7,   //                      V      2                         7.1 +
        LongBinary      =   0xAD,   //                      V      2
        LongChar        =   0xAF,   //                      V      2                         7.1 +
        NVarChar        =   0xE7,   //                      V      2                         7.1 +
        NChar           =   0xEF,   //                      V      2                         7.1 +
        UDT             =   0xF0,   //                      V      2 + 4 Unicode strings [DBName, SchemaName, TypeName, AssemblyName]
        XML             =   0xF1    //                      V      1 [SchemaPresent] if ==1, then read 3 Unicode strings [DBName, SchemaName, SchemaCollection]
    }                               // For 2 and 4 byte lengths, null = 0xFFFF and 0xFFFFFFFF respectively, 0 = empty, not null
                                    // See spec section 2.2.5.5 for partially specified lengths and chunking in up to 64KB blocks

    public enum TDSVersions  // from LOGINACK token
    {
        Unknown      =            0,
        SQL70        =   0x00000070,
        SQL2000      =   0x00000071,
        SQL200SP1    =   0x01000071,
        SQL2005      =   0x02000972,
        SQL2008      =   0x03000A73,
        SQL2008R2    =   0x03000B73,
        SQL2012      =   0x04000074,
        SQL2014      =   0x04000074
    }

    public enum TDSEnvChgTokens
    {
        Database            =   1,
        Language            =   2,
        CharSet             =   3,
        PacketSize          =   4,
        UnicodeSortLocale   =   5,
        UnicodeCompareFlags =   6,
        Collation           =   7,
        BeginTrans          =   8,
        CommitTrans         =   9,
        RollbackTrans       =  10,
        EnlistDTC           =  11,
        DefectTrans         =  12,
        MirrorPartner       =  13,
        PromoteTrans        =  15,
        TransMgrAddress     =  16,
        TransEnded          =  17,
        ResetCompletedAck   =  18,
        UserInfo            =  19,
        Routing             =  20
    }

    public class InvalidTDSException : Exception
    {
        public InvalidTDSException(string message) : base(message) { }
    }

    public class UnexpectedEndOfTDSException : Exception
    {
        public UnexpectedEndOfTDSException(string message) : base(message) { }
    }

    public class UnknownTDSVersionException : Exception
    {
        public UnknownTDSVersionException(string message) : base(message) { }
    }


    //
    // Header for every TDS message
    //

    public class TDSHeader
    {
        public byte PacketType;
        public byte Status;
        public ushort Length;  // length of current packet data (includes 8 bytes for the header)
        public ushort SPID;
        public byte PacketID;
        public byte Window;

        public void Read(TDSReader r)
        {
            PacketType = r.ReadByte();
            if (PacketType != (byte)TDSPacketType.SQLBATCH &&
                PacketType != (byte)TDSPacketType.LOGIN &&
                PacketType != (byte)TDSPacketType.RPC &&
                PacketType != (byte)TDSPacketType.RESPONSE &&
                PacketType != (byte)TDSPacketType.ATTENTION &&
                PacketType != (byte)TDSPacketType.BULKLOAD &&
                PacketType != (byte)TDSPacketType.DTC &&
                PacketType != (byte)TDSPacketType.LOGIN7 &&
                PacketType != (byte)TDSPacketType.SSPI &&
                PacketType != (byte)TDSPacketType.PRELOGIN &&
                PacketType != (byte)TDSPacketType.APPDATA) throw new InvalidTDSException("Unknown token type: " + PacketType);
            Status = r.ReadByte();
            if (Status > 31) throw new InvalidTDSException("Unknown Status value: " + Status);  // supposed to ignore other flag fields
            Length = r.ReadBigEndianUInt16();
            SPID = r.ReadBigEndianUInt16();
            PacketID = r.ReadByte();
            Window = r.ReadByte();
            if (Window != 0) throw new InvalidTDSException("Invalid TDS Window value: " + Window); // supposed to ignore
        }
    }

    //
    // Special header tokens that may appear at the beginning of certain TDS Packet Types
    //
    // TDSHeaderAll - may contain one or more of the below items
    //    [TDSHeaderQueryNotification]
    //    [TDSHeaderTransactionDescriptor]
    //    [TDSHeaderTraceActivity]
    //

    public class TDSHeaderQueryNotification
    {
        string NotifyID = null;
        string SSBDeployment = null;
        bool fHasTimeout = false;
        uint NotifyTimeout = 0;

        public void Read(TDSReader r, int headerLength)
        {
            int ReadLength = 4;
            ushort IDLength;
            ushort DeploymentLength;
            IDLength = r.ReadUInt16();
            NotifyID = r.ReadUnicodeString(IDLength / 2); // IDLength is supposed to be BYTEs rather than Characters - according to the spec
            DeploymentLength = r.ReadUInt16();
            SSBDeployment = r.ReadUnicodeString(DeploymentLength / 2); // spec section 2.2.5.3.1 (p33/195) says it is a count of bytes not chars
            ReadLength += 4 + IDLength + DeploymentLength; // multiply these guys by 2 if it turns out they a char counts - but spec says bytes
            if (ReadLength == headerLength - 4)
            {
                fHasTimeout = true;
                NotifyTimeout = r.ReadUInt32();
                ReadLength += 4;
            }
            if (ReadLength != headerLength) throw new InvalidTDSException("Query notification header length (" + headerLength + ") does not match bytes read (" + ReadLength + ").");
        }
    }

    public class TDSHeaderTransactionDescriptor
    {
        public UInt64 TransactionDescriptor;
        public UInt32 OutstandingRequestCount;

        public void Read(TDSReader r)
        {
            TransactionDescriptor = r.ReadUInt64();
            OutstandingRequestCount = r.ReadUInt32();
        }
    }

    public class TDSHeaderTraceActivity
    {
        byte[] ActivityID = null;

        public void Read(TDSReader r)
        {
            ActivityID = r.ReadBytes(20);
        }
    }

    public class TDSHeaderAll
    {
        public uint TotalLength;
        public TDSHeaderQueryNotification notification = null;
        public TDSHeaderTransactionDescriptor txd = null;
        public TDSHeaderTraceActivity trace = null;

        public void Read(TDSReader r)
        {
            uint ReadLength = 4;
            uint headerLength;
            ushort headerType;
            TotalLength = r.ReadUInt32();
            r.TokenStart((int)TotalLength - 4);    // TotalLength includes its own length (DWORD = 4 bytes)
            while (ReadLength < TotalLength)
            {
                headerLength = r.ReadUInt32();
                ReadLength += headerLength;
                headerType = r.ReadUInt16();
                switch (headerType)
                {
                    case 1:
                        {
                            notification = new TDSHeaderQueryNotification();
                            notification.Read(r, (int)headerLength);
                            break;
                        }
                    case 2:
                        {
                            txd = new TDSHeaderTransactionDescriptor();
                            txd.Read(r);
                            break;
                        }
                    case 3:
                        {
                            trace = new TDSHeaderTraceActivity();
                            trace.Read(r);
                            break;
                        }
                }
            }
            r.TokenDone();
            if (TotalLength != ReadLength) throw new InvalidTDSException("TDS HeaderAll TotalLength(" + TotalLength + ") does not equal ReadLength(" + ReadLength + ").");
        }
    }

    public abstract class TDSTokenBase
    {
        public byte TokenType;
    }

    public class TDSTokenPreloginResponse : TDSTokenBase // Token Type = 0 - does not call TDSReader .TokenStart or .DoneToken as there is no Length item
    {
        uint Version = 0;
        ushort SubBuild = 0;
        byte Encryption = 0;
        byte InstanceValidity = 0;
        uint ThreadID = 0;
        byte MarsData = 0;
        Guid TraceID = Guid.Empty;
        byte FedAuth = 0;
        byte[] Nonce = null;    // 32 bytes of data if FedAuth is non-zero

        public void Read(TDSReader r)
        {
            byte OptionToken = 0; ;
            int DataOffset;
            int DataLength;
            TDSReader offsetReader = null;

            OptionToken = r.ReadByte();

            while (OptionToken != (byte)TDSTokenType.DONEINPROC) // 255 or 0xFF
            {
                DataOffset = r.ReadBigEndianUInt16();
                DataLength = r.ReadBigEndianUInt16();
                offsetReader = r.OffsetReader(DataOffset);

                switch (OptionToken)
                {
                    case 0:          // version
                        {
                            if (DataLength > 0)
                            {
                                Version = offsetReader.ReadUInt32();
                                SubBuild = offsetReader.ReadUInt16();
                            }
                            break;
                        }
                    case 1:         // encryption
                        {
                            if (DataLength > 0) Encryption = offsetReader.ReadByte();
                            if (Encryption > 3) throw new InvalidTDSException("Invalid encryption option: " + Encryption);
                            break;
                        }
                    case 2:         // instanceValidity validity
                        {
                            if (DataLength > 0) InstanceValidity = offsetReader.ReadByte();
                            break;
                        }
                    case 3:         // thread ID
                        {
                            if (DataLength > 0) ThreadID = offsetReader.ReadUInt32();
                            break;
                        }
                    case 4:         // MARS
                        {
                            if (DataLength > 0) MarsData = offsetReader.ReadByte();
                            if (MarsData > 1) throw new InvalidTDSException("Invalid MARS option: " + MarsData);
                            break;
                        }
                    case 5:        // Trace ID
                        {
                            if (DataLength > 0) TraceID = new Guid(offsetReader.ReadBytes(16));
                            break;
                        }
                    case 6:        // Federated Auth Required
                        {
                            if (DataLength > 0) FedAuth = offsetReader.ReadByte();
                            break;
                        }
                    case 7:        // NONCE Option - 32 bytes of encrypted data
                        {
                            if (DataLength > 0) Nonce = offsetReader.ReadBytes(32);
                            break;
                        }
                }
            }
            r.DoneWithChildReaders();  // updates parent reader offset with child reader high offset - i.e.  causes the parent to jump past the referenced data
        }
    }

    public class TDSTokenReturnStatus : TDSTokenBase // Token Type = 121
    {
        public int Status;

        public void Read(TDSReader r)
        {
            Status = r.ReadInt32();
        }
    }

    public class TDSTokenColMetaData : TDSTokenBase // Token Type = 129
    {
        public ushort ColumnCount;
        public ArrayList ColumnData = null;

        public void Read(TDSReader r)
        {
            if (r.TDSVersion == (UInt32)TDSVersions.Unknown) throw new UnknownTDSVersionException("Column meta data needs to know the TDS version.");
            ColumnCount = r.ReadUInt16();
            if (ColumnCount == 0xFFFF) return;   // no metadata - the client specified to return none
            for (int i = 0; i < ColumnCount; i++)
            {
                TDSColumnMetaData cm = new TDSColumnMetaData();
                cm.Read(r);
                ColumnData.Add(cm);
            }
        }
    }

    public class TDSColumnMetaData  // helper class for the above
    {
        public UInt32 UserType;
        public UInt16 Flags;
        public TDSTokenColumnType Type;
        public string ColumnName = null;
        //
        // data-type-specific fields
        //
        public UInt32 Length;           // can be 1-byte, 2-byte, or 4-byte depending on the data type
        public byte[] Collation= null;  // 5 bytes - if TDS version >= 0x71
        public string TableName = null; // IMAGE, TEXT, and NTEXT columns only
        public byte Scale;
        public byte Precision;
        public string DBName = null;
        public string SchemaName = null;
        public string AssemblyName = null;
        public string TypeName = null;
        public string SchemaCollection = null;
        public byte XmlSchemaPresent;

        public void Read(TDSReader r)
        {
            byte TDSVer = (byte) (r.TDSVersion & 0x000000FF);
            UserType = (TDSVer < 0x72) ? r.ReadUInt16() : r.ReadUInt32();
            Flags = r.ReadUInt16();
            Type = (TDSTokenColumnType)(r.ReadByte());
            switch (Type)
            {
                //
                // no need to read anything else for fixed-length types
                //
                case TDSTokenColumnType.Null:
                case TDSTokenColumnType.TinyInt:
                case TDSTokenColumnType.Bit:
                case TDSTokenColumnType.SmallInt:
                case TDSTokenColumnType.Int:
                case TDSTokenColumnType.SmallDateTime:
                case TDSTokenColumnType.Real:
                case TDSTokenColumnType.Money:
                case TDSTokenColumnType.DateTime:
                case TDSTokenColumnType.Float:
                case TDSTokenColumnType.SmallMoney:
                case TDSTokenColumnType.BigInt:
                    {
                        break;
                    }
                //
                // data types that have a 1 byte length
                //
                case TDSTokenColumnType.GUID:
                case TDSTokenColumnType.VarBinary:
                case TDSTokenColumnType.IntN:
                case TDSTokenColumnType.VarChar:
                case TDSTokenColumnType.DateN:   // question about this type
                case TDSTokenColumnType.Binary:
                case TDSTokenColumnType.Char:
                case TDSTokenColumnType.BitN:
                case TDSTokenColumnType.FloatN:
                case TDSTokenColumnType.MoneyN:
                case TDSTokenColumnType.DateTimeN:
                    {
                        Length = r.ReadByte();
                        break;
                    }
                //
                // data types that have a 1 byte length and 1 byte scale
                //
                case TDSTokenColumnType.TimeN:
                case TDSTokenColumnType.DateTime2N:
                case TDSTokenColumnType.DateTimeOffsetN:
                    {
                        Length = r.ReadByte();
                        Scale = r.ReadByte();
                        break;
                    }
                //
                // data types that have a 1 byte length, 1 byte precision, and 1 byte scale
                //
                case TDSTokenColumnType.Decimal:
                case TDSTokenColumnType.Numeric:
                case TDSTokenColumnType.DecimalN:
                case TDSTokenColumnType.NumericN:
                    {
                        Length = r.ReadByte();
                        Precision = r.ReadByte();
                        Scale = r.ReadByte();
                        break;
                    }
                //
                // data types that have a 2 byte length
                //
                case TDSTokenColumnType.LongVarBinary:
                case TDSTokenColumnType.LongBinary:
                    {
                        Length = r.ReadUInt16();
                        break;
                    }
                //
                // data types that have a 2 byte length and an optional 5-byte collation
                //
                case TDSTokenColumnType.LongVarChar:
                case TDSTokenColumnType.LongChar:
                case TDSTokenColumnType.NVarChar:
                case TDSTokenColumnType.NChar:
                    {
                        Length = r.ReadUInt16();
                        if (TDSVer >= 0x71) Collation = r.ReadBytes(5);
                        break;
                    }
                //
                // data types that have a 4 byte length
                //
                case TDSTokenColumnType.Image:
                case TDSTokenColumnType.Variant:
                case TDSTokenColumnType.NText:
                    {
                        Length = r.ReadUInt32();
                        break;
                    }
                //
                // data types that have a 4 byte length and an optional 5-byte collation
                //
                case TDSTokenColumnType.Text:
                    {
                        Length = r.ReadUInt32();
                        if (TDSVer >= 0x71) Collation = r.ReadBytes(5);
                        break;
                    }
                //
                // CLR User-Defined Type
                //
                case TDSTokenColumnType.UDT:
                    {
                        Length = r.ReadUInt16();
                        DBName = r.ReadUnicodeString1();
                        SchemaName=r.ReadUnicodeString1();
                        TypeName=r.ReadUnicodeString1();
                        AssemblyName=r.ReadUnicodeString2();   // can be longer than 255 characters
                        break;
                    }
                //
                // XML
                //
                case TDSTokenColumnType.XML:
                    {
                        XmlSchemaPresent = r.ReadByte();
                        if (XmlSchemaPresent == 1)
                        {
                            DBName = r.ReadUnicodeString1();
                            SchemaName = r.ReadUnicodeString1();
                            SchemaCollection = r.ReadUnicodeString2();   // can be longer than 255 characters
                        }
                        break;
                    }
                default:
                    {
                        throw new InvalidTDSException("Unknown TDS data type: " + (byte)(Type) + ".");
                    }
            }
            ColumnName = r.ReadUnicodeString1();
        }
    }

    public class TDSTokenError : TDSTokenBase // Token Type = 170
    {
        public ushort Length;
        public uint Number;
        public byte State;
        public byte Class;
        public string Message = null;
        public string ServerName = null;
        public string ProcedureName = null;
        public uint LineNumber;

        public void Read(TDSReader r)
        {
            Length = r.ReadUInt16();
            r.TokenStart(Length);
            Number = r.ReadUInt32();
            State = r.ReadByte();
            Class = r.ReadByte();
            Message = r.ReadUnicodeString2();
            ServerName = r.ReadUnicodeString1();
            ProcedureName = r.ReadUnicodeString1();
            LineNumber = r.ReadUInt32();
            r.TokenDone();
        }
    }

    public class TDSTokenInfo : TDSTokenBase // Token Type = 171 - same structure as the ERROR token
    {
        public ushort Length;
        public uint Number;
        public byte State;
        public byte Class;
        public string Message = null;
        public string ServerName = null;
        public string ProcedureName = null;
        public uint LineNumber;

        public void Read(TDSReader r)
        {
            Length = r.ReadUInt16();
            r.TokenStart(Length);
            Number = r.ReadUInt32();
            State = r.ReadByte();
            Class = r.ReadByte();
            Message = r.ReadUnicodeString2();
            ServerName = r.ReadUnicodeString1();
            ProcedureName = r.ReadUnicodeString1();
            LineNumber = r.ReadUInt32();
            r.TokenDone();
        }
    }

    public class TDSTokenLoginAck : TDSTokenBase // Token Type = 173
    {
        public ushort Length;
        public byte Interface;
        public uint TDSVersion;
        public string ProgramName = null;
        public string ProgramVersion = null;

        public void Read(TDSReader r)
        {
            byte MajorVer;
            byte MinorVer;
            ushort Build;

            Length = r.ReadUInt16();
            r.TokenStart(Length);
            Interface = r.ReadByte();
            TDSVersion = r.ReadUInt32();
            r.TDSVersion = TDSVersion;
            ProgramName = r.ReadUnicodeString1();
            MajorVer = r.ReadByte();
            MinorVer = r.ReadByte();
            Build = r.ReadUInt16();
            ProgramVersion = MajorVer + "." + MinorVer + "." + Build;
            r.TokenDone();
        }
    }

    public class TDSTokenFeatureExtAck : TDSTokenBase // Token Type = 174
    {
        public ArrayList FeatureAckData = new ArrayList();

        public void Read(TDSReader r)
        {
            byte FeatureID = r.ReadByte();
            while (FeatureID != 0xFF)
            {
                FeatureExtAckData data = new FeatureExtAckData();
                data.FeatureID = FeatureID;
                data.FeatureData = r.ReadBytes4();
                FeatureID = r.ReadByte();
            }
        }
    }

    public class FeatureExtAckData
    {
        public byte FeatureID;
        public byte[] FeatureData = null;
    }

    public class TDSTokenEnvChange : TDSTokenBase // Token Type = 227
    {
        public ushort Length;
        public TDSEnvChgTokens EnvChangeType;
        public string NewValue = null;
        public string OldValue = null;
        public byte[] NewBytes = null;
        public byte[] OldBytes = null;
        // Routing properties - used when connecting to SQl Azure
        public byte Protocol;                   // 0 = TCP/IP - the only allowed value as of TDS 7.4
        public ushort ProtocolProperty;         // Port number for TCP/Ip protocol
        public string AlternateServer = null;   // server name to reroute the connection to

        public void Read(TDSReader r)
        {
            Length = r.ReadUInt16();
            r.TokenStart(Length);
            EnvChangeType = (TDSEnvChgTokens)r.ReadByte();
            if (EnvChangeType == TDSEnvChgTokens.PromoteTrans) r.TokenDone(); // Length always 1 for this token type
            switch (EnvChangeType)
            {
                case TDSEnvChgTokens.Database:               //   1  Database name
                case TDSEnvChgTokens.Language:               //   2  Language
                case TDSEnvChgTokens.CharSet:                //   3  Character set                         - TDS 7.0
                case TDSEnvChgTokens.PacketSize:             //   4  Packet Size
                case TDSEnvChgTokens.UnicodeSortLocale:      //   5  Unicode data sorting locale id        - TDS 7.0
                case TDSEnvChgTokens.UnicodeCompareFlags:    //   6  Unicode data sorting comparison flags - TDS 7.0
                case TDSEnvChgTokens.MirrorPartner:          //  13  Database mirroring partner
                case TDSEnvChgTokens.UserInfo:               //  19  User instance
                    {
                        NewValue = r.ReadUnicodeString1();   // returns "" if length argument is zero
                        OldValue = r.ReadUnicodeString1();
                        break;
                    }
                case TDSEnvChgTokens.Collation:              //   7  SQL collation - generally 5 bytes
                case TDSEnvChgTokens.BeginTrans:             //   8  Begin transaction          - old data is always 0x00 length
                case TDSEnvChgTokens.CommitTrans:            //   9  Commit transaction         - new data is always 0x00 length
                case TDSEnvChgTokens.RollbackTrans:          //  10  Rollback transaction       - new data is always 0x00 length
                case TDSEnvChgTokens.EnlistDTC:              //  11  Enlist TDS transaction     - new data is always 0x00 length
                case TDSEnvChgTokens.DefectTrans:            //  12  Defect transaction         - old data is always 0x00 length
                case TDSEnvChgTokens.TransMgrAddress:        //  16  Transaction Manager Address- old data is always 0x00 length - unused token
                case TDSEnvChgTokens.TransEnded:             //  17  Transaction Ended          - new data is always 0x00 length
                case TDSEnvChgTokens.ResetCompletedAck:      //  18  Reset achknowledgement     - new data and old data both 0x00 length
                    {
                        NewBytes = r.ReadBytes1();
                        OldBytes = r.ReadBytes1();
                        break;
                    }
                case TDSEnvChgTokens.PromoteTrans:           //  15  Promote transaction        - new data length is 4 bytes, old data is always 0x00 length  
                    {
                        NewBytes = r.ReadBytes4();
                        r.ReadByte();     // no real old data, just a 1 byte 0-length indicator
                        break;
                    }
                case TDSEnvChgTokens.Routing:                //  20  Routing                    - old data length is always 0x0000
                    {
                        // new value
                        ushort RoutingDataLength = r.ReadUInt16();   // may be sent if ReadOnlyIntent is true in TDS 7.1 - 7.3; could be sent in 7.4 even if the flag is false
                        if (RoutingDataLength > 0)
                        {
                            Protocol = r.ReadByte();
                            ProtocolProperty = r.ReadUInt16();
                            AlternateServer = r.ReadUnicodeString2();
                        }
                        // old value
                        r.ReadUInt16();
                        break;
                    }
            }
            if (EnvChangeType != TDSEnvChgTokens.PromoteTrans) r.TokenDone();  // Length for this token is always 1 even if there is more data; r.DoneToken(0 is called earlier for this token type
        }
    }

    public class TDSTokenDone : TDSTokenBase // Token Type = 253 - the completion of a SQL statement
    {
        public ushort Status;
        public ushort CurCmd;
        UInt64 DoneRowCount;               // read 4 bytes if TDS > 7.1, otherwise, read 2 bytes

        public void Read(TDSReader r)
        {
            if (r.TDSVersion == (UInt32)TDSVersions.Unknown) throw new UnknownTDSVersionException("Done token needs to know the TDS version.");
            Status = r.ReadUInt16();
            CurCmd = r.ReadUInt16();
            byte TDSVer = (byte)(r.TDSVersion & 0x000000FF);
            DoneRowCount = (TDSVer < 0x72) ? r.ReadUInt32() : r.ReadUInt64();
            r.TokenDone();
        }
    }

    public class TDSTokenDoneProc : TDSTokenBase // Token Type = 254 - The completion of a stored procedure - same structure as the Done token
    {
        public ushort Status;
        public ushort CurCmd;
        UInt64 DoneRowCount;               // read 4 bytes if TDS > 7.1, otherwise, read 2 bytes

        public void Read(TDSReader r)
        {
            if (r.TDSVersion == (UInt32)TDSVersions.Unknown) throw new UnknownTDSVersionException("Done token needs to know the TDS version.");
            Status = r.ReadUInt16();
            CurCmd = r.ReadUInt16();
            byte TDSVer = (byte)(r.TDSVersion & 0x000000FF);
            DoneRowCount = (TDSVer < 0x72) ? r.ReadUInt32() : r.ReadUInt64();
            r.TokenDone();
        }
    }

    public class TDSTokenDoneInProc : TDSTokenBase // Token Type = 255 - The completion of a SQL statement within a stored procedure - same structure as the Done token
    {
        public ushort Status;
        public ushort CurCmd;
        UInt64 DoneRowCount;               // read 4 bytes if TDS > 7.1, otherwise, read 2 bytes

        public void Read(TDSReader r)
        {
            if (r.TDSVersion == (UInt32)TDSVersions.Unknown) throw new UnknownTDSVersionException("Done token needs to know the TDS version.");
            Status = r.ReadUInt16();
            CurCmd = r.ReadUInt16();
            byte TDSVer = (byte)(r.TDSVersion & 0x000000FF);
            DoneRowCount = (TDSVer < 0x72) ? r.ReadUInt32() : r.ReadUInt64();
            r.TokenDone();
        }
    }

}
