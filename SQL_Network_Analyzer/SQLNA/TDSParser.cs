// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Parses frames to identify TDS traffic regardless of port
    //
    // Calling sequence:
    //
    // ProcessTDS                    - call once per NetworkTrace object - after parsing the file
    // FindStraySQLConversations     - call once per NetworkTrace object - after ProcessTDS
    //
    //
    //

    class TDSParser
    {
        // helper function
        // use this function to look for tokens in the SQL Prelogin Response
        private static int tokenOffset(byte[] tdsPayload, byte token, int offset = 8)  // 8 = the header length -- added for multiple tokens of the same type
        {
            ushort tokenLength = 0;

            // offset = 8; // removed due to optional parameter being added
            try
            {
                while (offset < (tdsPayload.Length - 2)) // if no room to read token + offset value (2 bytes), then exit loop
                {
                    if (tdsPayload[offset] == token)
                    {
                        return offset;
                    }
                    else if (tdsPayload[offset] == (byte)TDSTokenType.DONE)
                    {
                        return -1;
                    }
                    else
                    {
                        tokenLength = utility.ReadUInt16(tdsPayload, offset + 1);
                        offset += tokenLength + 3;
                    }
                }
            }
            catch (IndexOutOfRangeException)
            {
                return -1;
            }

            return -1;  // token not found
        }

        // helper function
        private static void GetClientPreloginInfo(byte[] tdsPayLoad, ConversationData conv)
        {
            UInt16 majorVersion, minorVersion, levelVersion;
            UInt16 offset, length;
            String clientInstance;

            try
            {
                //Skip first8 bytes of pre-login packet
                //Read options until we hit LASTOPT=0xFF token.Options are:
                //<Option1><Offset2><Length2>[<Option1><Offset2><Length2>]<LASTOPT>
                for (int i = 8; 0xFF != tdsPayLoad[i]; i += 5)
                {
                    // Get offset and length of prelogin option.
                    // Note the offset's and lengths are reverse byte order UInt16's.
                    offset = utility.B2UInt16(tdsPayLoad, i + 1);
                    length = utility.B2UInt16(tdsPayLoad, i + 3);

                    // Skip out now if offset is invalid.
                    if (8 + offset >= tdsPayLoad.Length)
                        return;

                    switch (tdsPayLoad[i])
                    {
                        case 0: // Client TDS Version; - needs work - TODO
                            majorVersion = utility.ReadUInt16(tdsPayLoad, 8 + offset);
                            minorVersion = utility.B2UInt16(tdsPayLoad, 8 + offset + 2);
                            levelVersion = utility.B2UInt16(tdsPayLoad, 8 + offset + 4);
                            conv.clientVersion = majorVersion.ToString() + "." + minorVersion.ToString() + "." + levelVersion.ToString();
                            break;
                        case 1: // encyption options. 
                            if (tdsPayLoad[8 + offset] == 1) conv.isEncrypted = true;
                            break;
                        case 2: // Client requested Instance
                            clientInstance = utility.CleanString(utility.ReadAnsiString(tdsPayLoad, 8 + offset, length));
                            break;
                        case 3: //Client TID.
                            if (4 == length)
                                conv.threadID = utility.ReadUInt32(tdsPayLoad, 8 + offset);
                            break;
                        case 4: // MARS options. 
                            if (tdsPayLoad[8 + offset] == 1) conv.isMARSEnabled = true;
                            break;
                        default:
                            break;
                    }
                }
            }
            catch (Exception)
            {
                //TODO:throw an exception. 

            };
        }

        // helper function
        private static void GetServerPreloginInfo(byte[] tdsPayLoad, ConversationData conv)
        {
            // UInt16 majorVersion, minorVersion, levelVersion;
            UInt16 offset, length;

            try
            {
                //Skip first8 bytes of pre-login packet
                //Read options until we hit LASTOPT=0xFF token.Options are:
                //<Option1><Offset2><Length2>[<Option1><Offset2><Length2>]<LASTOPT>
                for (int i = 8; 0xFF != tdsPayLoad[i]; i += 5)
                {
                    // Get offset and length of prelogin option.
                    // Note the offset's and lengths are reverse byte order UInt16's.
                    offset = utility.B2UInt16(tdsPayLoad, i + 1);
                    length = utility.B2UInt16(tdsPayLoad, i + 3);

                    if (8 + offset >= tdsPayLoad.Length) return;     // Skip out now if offset is invalid.
                    if (offset < 26) return;                         // TDS Continuation data may fake us out - will be better with message combining in v2.0

                    switch (tdsPayLoad[i])
                    {
                        case 0:
                            {
                                // Client TDS Version - getting this from LoginACK, now - obsolete code path
                                //majorVersion = utility.ReadUInt16(tdsPayLoad, 8 + offset);
                                //minorVersion = utility.B2UInt16(tdsPayLoad, 8 + offset + 2);
                                //levelVersion = utility.B2UInt16(tdsPayLoad, 8 + offset + 4);
                                //conv.serverVersion = majorVersion.ToString() + "." + minorVersion.ToString() + "." + levelVersion.ToString();
                                break;
                            }
                        case 1: // encyption options. 
                            {
                                byte encrypt = tdsPayLoad[8 + offset];
                                conv.isEncrypted = (encrypt == 1 || encrypt == 3) ? true : false;  // if the server says YES or NO, then that's that
                                conv.isEncRequired = (encrypt == 3);
                                break;
                            }
                        case 2:  // we don't care
                        case 3:  // we don't care
                            {
                                break;
                            }
                        case 4:
                            {
                                conv.isMARSEnabled = (tdsPayLoad[8 + offset] == 1) ? true : false;  // if the server says YES or NO, then that's that
                                break;
                            }
                        default:
                            break;
                    }
                }
            }
            catch (Exception)
            {
                //ToDO:throw an exception. 

            };
        }

        // post processing
        public static void ProcessTDS(NetworkTrace trace)
        {

            foreach (ConversationData c in trace.conversations)
            {
                long payLoadLength = 0;
                int tdsClientSource = 0;
                int tdsClientDest = 0;
                int tdsServerSource = 0;
                int tdsServerDest = 0;
                int tdsOtherFrames = 0;
                int switchClientServer = 0;   // 0 = do not switch; 1+ = switch - only increment if c.hasApplicationData and PostLoginResponse are false

                if (c.isUDP) continue;

                //if (c.sourcePort == 53388 || c.destPort == 53388)  // place to put breakpoint when trying to isolate a specifc conversation
                //    Console.WriteLine();

                // bypass client or server port < 500 - the well-known ports
                // SQL will not configure itself in this range with Dynamic Ports - uses a port from the ephemeral range
                //    Well Known Ports:      0 through   1023 
                //    Registered Ports:   1024 through  49151
                //    Dynamic/Private :  49152 through  65535
                // had some customer use ports 1021-1024 for SQL ports - lower limit to avoid common services: HTTP, HTTPS, Kerberos, SMB, etc., all below 500

                if ((c.sourcePort < 500) || (c.destPort < 500)) continue;  // to avoid confusing encrypted traffic on common services with SQL traffic. Override with /SQL command-line switch

                foreach (FrameData fd in c.frames)
                {
                    if (fd.pktmon != null && fd.pktmon.AppearanceCount > 1) continue; // don't parse pktmon tracepoints more than once
                    try
                    {
                        // weed out non-TDS packets
                        if (fd.payloadLength < 8) continue;  // ATTENTION payload is 8 bytes

                        // ignore continuation packets until we get a complete TDS message parser built
                        if (fd.isContinuation) continue;

                        // bypass HTTP
                        if ((utility.ReadAnsiString(fd.payload, 0, 3).ToUpper() == "GET") ||
                            (utility.ReadAnsiString(fd.payload, 0, 4).ToUpper() == "POST") ||
                            (utility.ReadAnsiString(fd.payload, 0, 4).ToUpper() == "HTTP"))   // other keywords much less common
                        {
                            break; // exit the entire conversation
                        }

                        int firstByte = fd.payload[0];

                        //if (c.destPort == 50422)  // debugging construct - more efficient than a conditional breakpoint
                        //{
                        //    if (fd.frameNo == 80723)
                        //        Console.WriteLine(fd.frameNo + "   " + firstByte + "   " + fd.FormatPayloadChars(30));
                        //}

                        // make sure we have a supported packet type
                        if ((firstByte != (int)TDSPacketType.SQLBATCH) &&   //    1
                            (firstByte != (int)TDSPacketType.LOGIN) &&      //    2
                            (firstByte != (int)TDSPacketType.RPC) &&        //    3
                            (firstByte != (int)TDSPacketType.RESPONSE) &&   //    4
                            (firstByte != (int)TDSPacketType.ATTENTION) &&  //    6
                            (firstByte != (int)TDSPacketType.BULKLOAD) &&   //    7
                            (firstByte != (int)TDSPacketType.DTC) &&        //   14   0x0E
                            (firstByte != (int)TDSPacketType.LOGIN7) &&     //   16   0x10
                            (firstByte != (int)TDSPacketType.SSPI) &&       //   17   0x11
                            (firstByte != (int)TDSPacketType.PRELOGIN) &&   //   18   0x12
                            (firstByte != (int)TDSPacketType.TDS8CCS) &&    //   20   0x14 - TDS 8.0 ? only if already marked by Client Hello or Server Hello, otherwise ignore
                            (firstByte != (int)TDSPacketType.TDS8TLS) &&    //   22   0x16 - TDS 8.0 ? if ALPN in Client Hello or Server Hello = tds/8.0; also for client-key exchange
                            (firstByte != (int)TDSPacketType.APPDATA))      //   23   0x17 - next 2 bytes give TLS version 0200, 0300 to 0303
                        {
                            continue;
                        }

                        // define TDS header fields
                        byte status = 0;
                        bool tdsEOM = false;
                        bool tdsResetConnection = false;
                        ushort tdsLength = 0;  // length of current packet data (includes 8 bytes for the header)
                        ushort SPID = 0;
                        byte PacketID = 0;
                        byte Window = 0;

                        // APPDATA and TDS8 TLS packets do not have a TDS payload, but a TLS payload, so skip these tests if APPDATA
                        if (firstByte == (int)TDSPacketType.APPDATA || firstByte == (int)TDSPacketType.TDS8TLS|| firstByte == (int)TDSPacketType.TDS8CCS)
                        {
                            // do nothing - ignore the TDS header that's in the else clause
                        }
                        else   // (firstByte != (int)TDSPacketType.APPDATA)
                        {
                            // get header values - except for Application Data, and TDS8 packet types
                            status = fd.payload[1];
                            tdsEOM = (status & 0x1) == 1;
                            tdsResetConnection = (status & 0x18) != 0;
                            tdsLength = utility.B2UInt16(fd.payload, 2);  // length of current packet data (includes 8 bytes for the header)
                            SPID = utility.B2UInt16(fd.payload, 4);
                            PacketID = fd.payload[6];
                            Window = fd.payload[7];

                            // TDS header Length argument needs to be non-zero and also >= payload length
                            if (tdsLength == 0 || tdsLength < fd.payloadLength) continue;

                            if (fd.payload[6] > 1) continue; // TDS Continuous Response packets can have greater values, but we are ignoring them right now

                            // TDS window needs to be 0   -- from TDSView -- TODO understand the reason for this - does MARS have non-Zero value?
                            if (fd.payload[7] != 0) continue;
                        }

                        switch (firstByte)
                        {
                            case (byte)TDSPacketType.TDS8TLS:
                                {
                                    TLS tls = TLS.Parse(fd.payload, 0);
                                    if (tls.handshake.hasClientHello)
                                    {
                                        // generic ClientHello stats, even for HTTPs, etc.
                                        ushort sslLevel = tls.handshake.clientHello.sslLevel;
                                        fd.frameType = FrameType.ClientHello;
                                        c.tlsVersionClient = translateSSLVersion(sslLevel);
                                        if (!fd.isFromClient) switchClientServer++;
                                        if (tls.hasTDS8)  // SQL-specific ClientHello stats
                                        {
                                            c.hasTDS8 = true;
                                            if (c.serverName == null || c.serverName == "") c.serverName = tls.handshake.clientHello.serverName;
                                            c.hasClientSSL = true;
                                            if (c.ClientHelloTime == 0) c.ClientHelloTime = fd.ticks;
                                            if (sslLevel < 0x0303) c.hasLowTLSVersion = true;  // mark anything less than TLS 1.2
                                            if (fd.isFromClient) { tdsClientSource++; } else { tdsClientDest++; };
                                        }
                                    }
                                    else if (tls.handshake.hasServerHello)
                                    {
                                        // generic ServerHello stats, even for HTTPS, etc.
                                        ushort sslLevel = tls.handshake.serverHello.sslLevel;
                                        fd.frameType = FrameType.ServerHello;
                                        if (fd.isFromClient) switchClientServer++;
                                        c.tlsVersionServer = translateSSLVersion(sslLevel);
                                        if (sslLevel < 0x0301)
                                        {
                                            if (translateSsl3CipherSuite(sslLevel).StartsWith("SSL_DHE")) c.hasDiffieHellman = true;
                                        }
                                        else   // TLS 1.0, 1.1, 1.2, 1.3  (Maj.Min = 3.1, 3.2, 3.3, 3.4)
                                        {
                                            if (translateTlsCipherSuite(sslLevel).StartsWith("TLS_DHE")) c.hasDiffieHellman = true;
                                        }

                                        if (tls.hasTDS8)  // SQL-specific ServerHello stats
                                        {
                                            c.hasTDS8 = true;
                                            c.hasServerSSL = true;
                                            if (c.ServerHelloTime == 0) c.ServerHelloTime = fd.ticks;
                                            if (sslLevel < 0x0303) c.hasLowTLSVersion = true;  // mark anything less than TLS 1.2
                                            if (fd.isFromClient) { tdsServerSource++; } else { tdsServerDest++; };
                                        }
                                    }
                                    else if (tls.handshake.hasClientKeyExchange)
                                    {
                                        fd.frameType = FrameType.KeyExchange;
                                        if (c.hasTDS8)
                                        {
                                            if (c.KeyExchangeTime == 0) c.KeyExchangeTime = fd.ticks;
                                            c.hasKeyExchange = true;
                                            if (fd.isFromClient) { tdsClientSource++; } else { tdsClientDest++; switchClientServer++; };
                                        }
                                    }
                                    payLoadLength += fd.payload.Length;
                                    break;
                                }
                            case (byte)TDSPacketType.TDS8CCS:
                                {
                                    fd.frameType = FrameType.CipherChange;
                                    if (c.hasTDS8)
                                    {
                                        c.hasCipherExchange = true;
                                        if (c.CipherExchangeTime == 0) c.CipherExchangeTime = fd.ticks;
                                        tdsOtherFrames++;  // since could be client or server
                                    }
                                    payLoadLength += fd.payload.Length;
                                    break;
                                }
                            case (byte)TDSPacketType.APPDATA:    // 0x17 = Application data
                                {
                                    byte sslMajor = fd.payload[1];
                                    byte sslMinor = fd.payload[2];
                                    if (utility.ValidSSLVersion(sslMajor, sslMinor))
                                    {
                                        c.hasApplicationData = true;
                                        fd.frameType = FrameType.ApplicationData;
                                        if (c.LoginTime == 0) c.LoginTime = fd.ticks;
                                        tdsOtherFrames++;  // since could be client or server
                                    }

                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;

                                    break;
                                }
                            case (byte)TDSPacketType.PRELOGIN: // can be client or server
                                {
                                    byte preloginType = fd.payload[8];  // first byte after TDS header = prelogin type
                                    byte handshakeType = 0;
                                    byte sslMajorVersion = 0;
                                    byte sslMinorVersion = 0;

                                    if (preloginType == 0)  // Prelogin packet
                                    {
                                        GetClientPreloginInfo(fd.payload, fd.conversation);
                                        c.hasPrelogin = true;
                                        fd.frameType = FrameType.PreLogin;
                                        if (c.PreLoginTime == 0) c.PreLoginTime = fd.ticks;
                                        if (fd.isFromClient)
                                        {
                                            tdsClientSource++;   // looks like SQL is on the destIP side - good
                                        }
                                        else
                                        {
                                            if (c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
                                            tdsClientDest++;     // looks like SQL is on the sourceIP side - need to switch later
                                        }
                                    }
                                    else if (preloginType == 0x16) // SSL handshake
                                    {
                                        sslMajorVersion = fd.payload[9]; // first byte after preLogintype
                                        sslMinorVersion = fd.payload[10]; // next byte
                                        handshakeType = fd.payload[13];   // first byte after SSL header = SSL handshake type
                                        if (handshakeType == 1 || handshakeType == 0x10) // Client Hello or Client Key Exchange
                                        {
                                            if (handshakeType == 1)
                                            {
                                                sslMajorVersion = fd.payload[17]; // we want the inner SSL version, 8 bytes further in
                                                sslMinorVersion = fd.payload[18]; // next byte
                                                c.hasClientSSL = true;
                                                fd.frameType = FrameType.ClientHello;
                                                if (c.ClientHelloTime == 0) c.ClientHelloTime = fd.ticks;
                                                c.tlsVersionClient = translateSSLVersion(sslMajorVersion, sslMinorVersion);
                                                if (sslMajorVersion != 3 || sslMinorVersion < 3) c.hasLowTLSVersion = true;  // mark anything less than TLS 1.2
                                            }
                                            if (handshakeType == 0x10)
                                            {
                                                if (c.KeyExchangeTime == 0) c.KeyExchangeTime = fd.ticks;
                                                c.hasKeyExchange = true;
                                                fd.frameType = FrameType.KeyExchange;
                                            }
                                            if (fd.isFromClient)
                                                tdsClientSource++;   // looks like SQL is on the destIP side - good
                                            else
                                            {
                                                if (c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
                                                tdsClientDest++;     // looks like SQL is on the sourceIP side - need to switch later
                                            }
                                        }
                                        else if (handshakeType == 2) // Server Hello -- do we sometimes hit here, or is it just in the TDS RESPONSE version of this logic
                                        {
                                            //Program.logDiagnostic($"TDS:Prelogin Server Hello packet seen at frame {fd.frameNo}.");
                                            sslMajorVersion = fd.payload[17]; // we want the inner SSL version, 8 bytes further in
                                            sslMinorVersion = fd.payload[18]; // next byte
                                            c.hasServerSSL = true;
                                            fd.frameType = FrameType.ServerHello;
                                            if (c.ServerHelloTime == 0) c.ServerHelloTime = fd.ticks;
                                            c.tlsVersionServer = translateSSLVersion(sslMajorVersion, sslMinorVersion);
                                            if (sslMajorVersion != 3 || sslMinorVersion != 3) c.hasLowTLSVersion = true;  // mark anything other than TLS 1.2
                                            byte skipLength = fd.payload[13 + 3 + 2 + 4 + 28 + 1];
                                            byte cipherHi = fd.payload[13 + 3 + 2 + 4 + 28 + 1 + skipLength + 1];
                                            byte cipherLo = fd.payload[13 + 3 + 2 + 4 + 28 + 1 + skipLength + 2];
                                            if (sslMajorVersion == 3 && sslMinorVersion == 0)  // SSL 3.0
                                            {
                                                if (translateSsl3CipherSuite(cipherHi, cipherLo).StartsWith("SSL_DHE")) c.hasDiffieHellman = true;
                                            }
                                            else if (sslMajorVersion == 3 && sslMinorVersion < 4)  // TLS 1.0, 1.1, 1.2  (Maj.Min = 3.1, 3.2, 3.3)
                                            {
                                                if (translateTlsCipherSuite(cipherHi, cipherLo).StartsWith("TLS_DHE")) c.hasDiffieHellman = true;
                                            }
                                            if (fd.isFromClient)
                                                tdsServerSource++;   // looks like SQL is on the sourceIP side - need to switch later
                                            else
                                                tdsServerDest++;     // looks like SQL is on the destIP side - good
                                        }
                                    }
                                    else if (preloginType == 0x14) // Cipher exchange - could be client or server
                                    {
                                        c.hasCipherExchange = true;
                                        fd.frameType = FrameType.CipherChange;
                                        if (c.CipherExchangeTime == 0) c.CipherExchangeTime = fd.ticks;
                                        tdsOtherFrames++;  // since could be client or server
                                    }

                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;

                                    break;
                                }
                            case (byte)TDSPacketType.LOGIN7:
                                {
                                    //accumulate the payload. *** normally, we should not see this packet unencrypted ***
                                    if (c.hasClientSSL == false && c.hasServerSSL == false &&
                                        c.hasKeyExchange == false && c.hasCipherExchange == false &&
                                        c.hasPostLoginResponse == false && c.Error == 0)
                                    {
                                        c.hasLogin7 = true;
                                        fd.frameType = FrameType.Login7;
                                        if (c.LoginTime == 0) c.LoginTime = fd.ticks;
                                    }
                                    payLoadLength += fd.payload.Length;

                                    // parse this better - JTDS and FreeTDS don't normally encrypt of do the driver prelogin packets TODO

                                    if (fd.isFromClient)
                                        tdsClientSource++;   // looks like SQL is on the destIP side - good
                                    else
                                        tdsClientDest++;     // looks like SQL is on the sourceIP side - need to switch later

                                    break;
                                }
                            case (byte)TDSPacketType.SSPI:
                                {
                                    c.hasIntegratedSecurity = true;  // kerberos or NTLM

                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;

                                    // Check for NTLM Response Message - if we don't find it, assume Kerberos
                                    if (fd.payloadLength > 16)
                                    {
                                        if ((utility.ReadAnsiString(fd.payload, 8, 7) == "NTLMSSP") &&   // NTLM signature
                                            (fd.payload[15] == 0) &&                                      // null terminated
                                            (fd.payload[16] == 3))                                       // Type = Authenticate Message
                                        {
                                            c.hasNTLMResponse = true;
                                            fd.frameType = FrameType.NTLMResponse;
                                            if (c.NTLMResponseTime == 0) c.NTLMResponseTime = fd.ticks;

                                            //Parse User name and domain name
                                            //check are they both 0 length? if yes, set a flag in conversation data that indicates null credentials 
                                            c.hasNullNTLMCreds = AreTheCredentialsNull(fd);

                                            if (fd.isFromClient == false && c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
                                        }
                                        else  // not NTLM, so Kerberos SSPI
                                        {
                                            c.hasSSPI = true;
                                            fd.frameType = FrameType.SSPI;
                                            if (c.SSPITime == 0) c.SSPITime = fd.ticks;
                                        }
                                    }

                                    if (fd.isFromClient)
                                        tdsClientSource++;   // looks like SQL is on the destIP side - good
                                    else
                                        tdsClientDest++;     // looks like SQL is on the sourceIP side - need to switch later

                                    break;
                                }
                            case (byte)TDSPacketType.RPC:
                            case (byte)TDSPacketType.SQLBATCH:
                            case (byte)TDSPacketType.DTC:
                                {
                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;
                                    c.hasPostLoginResponse = true; // if we're doing this, login has already succeeded
                                    switch (firstByte)
                                    {
                                        case (byte)TDSPacketType.RPC: { fd.frameType = FrameType.RPCRequest; break; }
                                        case (byte)TDSPacketType.SQLBATCH: { fd.frameType = FrameType.SQLBatch; break; }
                                        case (byte)TDSPacketType.DTC: { fd.frameType = FrameType.XactMgrRequest; break; }
                                    }
                                    // if (c.LoginAckTime == 0) c.LoginAckTime = fd.ticks;

                                    /*******
                                    if (firstByte == (int)TDSPacketType.SQLBATCH)
                                    {

                                        int Length = (int) utility.ReadUInt32(fd.payload, 2);

                                    }
                                    **************/

                                    if (fd.isFromClient)
                                        tdsClientSource++;   // looks like SQL is on the destIP side - good
                                    else
                                        tdsClientDest++;     // looks like SQL is on the sourceIP side - need to switch later

                                    break;
                                }
                            case (byte)TDSPacketType.ATTENTION:  // added Dec 5, 2016
                                {
                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;
                                    if (payLoadLength == 8) // has exactly 8-bytes of payload, just enough for the TDS header
                                    {
                                        c.hasPostLoginResponse = true; // if we're doing this, login has already succeeded
                                        fd.frameType = FrameType.Attention;
                                        if (c.AttentionTime == 0) c.AttentionTime = fd.ticks;

                                        if (fd.isFromClient)
                                            tdsClientSource++;   // looks like SQL is on the destIP side - good
                                        else
                                            tdsClientDest++;     // looks like SQL is on the sourceIP side - need to switch later
                                    }
                                    break;
                                }
                            case (byte)TDSPacketType.RESPONSE:  //0x4
                                {
                                    fd.frameType = FrameType.TabularResponse;  // generic response
                                    // process error responses
                                    if (fd.payload[8] == (byte)TDSTokenType.ERROR)
                                    {
                                        fd.frameType = FrameType.CommandError;
                                        if (c.Error == 0 && c.hasPostLoginResponse == false) // ignore command execute errors
                                        {
                                            fd.frameType = FrameType.LoginError;
                                            c.Error = utility.ReadUInt32(fd.payload, 11);
                                            c.ErrorState = fd.payload[15];
                                            int ErrorLen = (int)fd.payload[17];
                                            c.ErrorMsg = utility.ReadUnicodeString(fd.payload, 19, ErrorLen);
                                            c.ErrorTime = fd.ticks;
                                        }
                                    }
                                    //pre-login info from Server. 
                                    // if (tokenOffset(fd.payload, (byte)TDSTokenType.PRELOGINRESPONSE) > 7)  // response header is offset 0..7 - need to fix this routine
                                    else if (fd.payload[8] == (byte)TDSTokenType.PRELOGINRESPONSE) // only 1 token in the payload
                                    {
                                        GetServerPreloginInfo(fd.payload, fd.conversation);
                                        c.hasPreloginResponse = true;
                                        fd.frameType = FrameType.PreLoginResponse;
                                        if (c.PreLoginResponseTime == 0) c.PreLoginResponseTime = fd.ticks;
                                        if (fd.isFromClient && c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
                                    }
                                    else if (fd.payload[8] == 0x16 && fd.payloadLength > 10)  // SSL
                                    {
                                        byte preloginType = fd.payload[8];      // first byte after TDS header = prelogin type
                                        byte handshakeType = fd.payload[13];    // first byte after SSL header = SSL handshake type
                                        byte sslMajorVersion = fd.payload[9];   // first byte after preLogintype
                                        byte sslMinorVersion = fd.payload[10];  // next byte
                                        if (handshakeType == 2) // Server Hello
                                        {
                                            sslMajorVersion = fd.payload[17];   // we want the innter SSL version, not at the handshake level (that's 8 bytes further in)
                                            sslMinorVersion = fd.payload[18];  // next byte
                                            c.hasServerSSL = true;
                                            fd.frameType = FrameType.ServerHello;
                                            if (c.ServerHelloTime == 0) c.ServerHelloTime = fd.ticks;
                                            c.tlsVersionServer = translateSSLVersion(sslMajorVersion, sslMinorVersion);
                                            if (sslMajorVersion != 3 || sslMinorVersion != 3) c.hasLowTLSVersion = true;  // mark anything other than TLS 1.2
                                            byte skipLength = fd.payload[13 + 3 + 2 + 4 + 28 + 1];
                                            byte cipherHi = fd.payload[13 + 3 + 2 + 4 + 28 + 1 + skipLength + 1];
                                            byte cipherLo = fd.payload[13 + 3 + 2 + 4 + 28 + 1 + skipLength + 2];
                                            if (sslMajorVersion == 3 && sslMinorVersion == 0)  // SSL 3.0
                                            {
                                                if (translateSsl3CipherSuite(cipherHi, cipherLo).StartsWith("SSL_DHE")) c.hasDiffieHellman = true;
                                            }
                                            else if (sslMajorVersion == 3 && sslMinorVersion < 4)  // TLS 1.0, 1.1, 1.2  (Maj.Min = 3.1, 3.2, 3.3)
                                            {
                                                if (translateTlsCipherSuite(cipherHi, cipherLo).StartsWith("TLS_DHE")) c.hasDiffieHellman = true;
                                            }
                                            if (fd.isFromClient)
                                                tdsServerSource++;   // looks like SQL is on the sourceIP side - need to switch later
                                            else
                                                tdsServerDest++;     // looks like SQL is on the destIP side - good
                                        }
                                    }
                                    else if ((fd.payloadLength > 19) &&
                                                (fd.payload[8] == (byte)TDSTokenType.SSPI) &&                     // NTLM Challenge message
                                                (utility.ReadAnsiString(fd.payload, 11, 7) == "NTLMSSP") &&       // NTLM signature
                                                (fd.payload[18] == 0) &&                                          // null terminated
                                                (fd.payload[19] == 2))                                      // type = Challenge Message
                                    {
                                        c.hasNTLMChallenge = true;
                                        fd.frameType = FrameType.NTLMChallenge;
                                        if (c.NTLMChallengeTime == 0) c.NTLMChallengeTime = fd.ticks;
                                        if (fd.isFromClient == false && c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
                                    }
                                    else if ((fd.payloadLength > 19) && (fd.payload[8] == (byte)TDSTokenType.SSPI))      // Not NTLM, so Kerberos SSPI
                                    {
                                        c.hasSSPI = true;
                                        fd.frameType = FrameType.SSPI;
                                        if (c.SSPITime == 0) c.SSPITime = fd.ticks;
                                    }
                                    else if ((tokenOffset(fd.payload, (byte)TDSTokenType.ENVCHANGE) > 7) &&  // response header is offset 0..7 
                                                (tokenOffset(fd.payload, (byte)TDSTokenType.INFO) > 7) &&
                                                (tokenOffset(fd.payload, (byte)TDSTokenType.LOGINACK) > 7))
                                    {
                                        c.hasPostLoginResponse = true;
                                        fd.frameType = FrameType.LoginAck;
                                        if (c.LoginAckTime == 0) c.LoginAckTime = fd.ticks;

                                        try
                                        {
                                            // parse LoginAck packet
                                            int offset = tokenOffset(fd.payload, (byte)TDSTokenType.LOGINACK);
                                            c.tdsVersionServer = utility.B2UInt32(fd.payload, offset + 4);
                                            int nameLength = fd.payload[offset + 8] * 2; // unicode characters
                                            c.serverVersion = fd.payload[offset + nameLength + 9] + "." + fd.payload[offset + nameLength + 10] + "." +
                                                              fd.payload[offset + nameLength + 11] + "." + fd.payload[offset + nameLength + 12];
                                            // parse Info packet - any one, doesn't matter, all have the database name in them
                                            offset = tokenOffset(fd.payload, (byte)TDSTokenType.INFO);
                                            offset += utility.ReadUInt16(fd.payload, offset + 9) * 2; // unicode characters - and 2-byte length - skip this
                                            nameLength = fd.payload[offset + 11]; // unicode characters
                                            c.serverName = utility.ReadUnicodeString(fd.payload, offset + 12, nameLength);  // arg is chars not bytes
                                            // parse ENVCHANGE packet
                                            offset = tokenOffset(fd.payload, (byte)TDSTokenType.ENVCHANGE);
                                            int EnvChangeType = 0;
                                            int tokenLength = 0;
                                            while (offset != -1)
                                            {
                                                tokenLength = utility.ReadUInt16(fd.payload, offset + 1);
                                                EnvChangeType = fd.payload[offset + 3];
                                                if (EnvChangeType == 1)  // database name
                                                {
                                                    nameLength = fd.payload[offset + 4];
                                                    c.databaseName = utility.ReadUnicodeString(fd.payload, offset + 5, nameLength);
                                                }
                                                else if (EnvChangeType == 0x14)  // server redirection
                                                {
                                                    c.RedirectPort = utility.ReadUInt16(fd.payload, offset + 7);
                                                    int ServerLen = fd.payload[offset + 9];
                                                    c.RedirectServer = utility.ReadUnicodeString(fd.payload, offset + 11, ServerLen);
                                                    c.hasRedirectedConnection = true;
                                                }
                                                offset = tokenOffset(fd.payload, (byte)TDSTokenType.ENVCHANGE, offset + tokenLength + 3);
                                            }
                                        }
                                        catch (IndexOutOfRangeException)
                                        {
                                            Program.logDiagnostic("Index out of range exception in file " + trace.files.IndexOf(fd.file) + ", frame " + fd.frameNo + " parsing LoginAck token.");
                                            if (tdsEOM && tdsLength > fd.payloadLength) // truncated packet
                                            {
                                                Program.logDiagnostic("Payload length read = " + fd.payloadLength + ". TDS length = " + tdsLength);
                                            }
                                        }
                                        finally
                                        {
                                            if (fd.isFromClient == false && c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
                                        }
                                    }

                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;

                                    if (fd.isFromClient)
                                        tdsServerSource++;   // looks like SQL is on the sourceIP side - need to switch later
                                    else
                                        tdsServerDest++;     // looks like SQL is on the destIP side - good
                                    break;
                                }
                            case (byte)TDSPacketType.INFO:  //0xAB 
                                {

                                    break;
                                }
                        } // end switch
                    } // end try
                    catch (IndexOutOfRangeException)
                    {
                        Program.logDiagnostic("Index out of range exception in file " + trace.files.IndexOf(fd.file) + ", frame " + fd.frameNo + ".");
                    }
                    catch (Exception ex)
                    {
                        Program.logDiagnostic("Exception in file " + trace.files.IndexOf(fd.file) + ", frame " + fd.frameNo + ". \n\r" + ex.Message);
                    }

                } // end for each frame in conversation.frames

                //Enable hasTDS flag and isSQL flag - they are FALSE by default
                // Ignore tdsOtherFrames because pure SSL conversations will have 0x14 and 0x16 packet types and show as false positive
                // We may lose a couple of SQL Servers with one fragemented conversation, but they are not likely of interest

                int KeyFrameCount = (c.hasPrelogin ? 1 : 0)
                                  + (c.hasPreloginResponse ? 1 : 0)
                                  + (c.hasClientSSL ? 1 : 0)
                                  + (c.hasServerSSL ? 1 : 0)
                                  + (c.hasKeyExchange ? 1 : 0)
                                  + (c.hasCipherExchange ? 1 : 0)
                                  + (c.hasApplicationData ? 1 : 0)
                                  + (c.hasLogin7 ? 1 : 0)
                                  + (c.hasPostLoginResponse ? 1 : 0)
                                  + (c.hasLoginFailure ? 1 : 0);

                //
                // If we see the beginning of the conversation, but there are not enough key frames, then very strong % not SQL.
                // If the number of SQL packets is < 2% of the overall frame count, then not likely SQL. Can adjust this; 1% might be okay, too.
                // There is a possibility we're wrong, but other conversations should correct that.
                //

                if ((c.synCount > 0 && KeyFrameCount < 3) || ((tdsClientSource + tdsServerDest + tdsServerSource + tdsClientDest) * 50) < c.frames.Count)
                {
                    tdsClientSource = tdsServerDest = tdsServerSource = tdsClientDest = 0; // short-cut this option for determining if we have a SQL conversation
                }

                if (c.hasTDS8)   // we know from ClientHello ALPN it is definitely a SLQ conversation
                {
                    c.hasTDS = true;
                    c.isSQL = true;
                    c.tdsFrames = tdsClientSource + tdsServerSource + tdsClientDest + tdsServerDest + tdsOtherFrames;
                }
                else if (KeyFrameCount > 4)  // we're pretty sure this is a SQL Server -  JTDS just has Logon7 and hasPostLoginResponse special packets
                {
                    c.hasTDS = true;
                    c.isSQL = true;
                    c.tdsFrames = tdsClientSource + tdsServerSource + tdsClientDest + tdsServerDest + tdsOtherFrames;
                }
                else if (((tdsClientSource + tdsServerDest) > 0) && ((tdsServerSource + tdsClientDest) == 0) ||
                        ((tdsServerSource + tdsClientDest) > 0) && ((tdsClientSource + tdsServerDest) == 0))    // we're sort of sure
                {
                    c.hasTDS = true;
                    c.isSQL = true;
                    c.tdsFrames = tdsClientSource + tdsServerSource + tdsClientDest + tdsServerDest + tdsOtherFrames;
                }
                else
                {
                    c.hasTDS = false;
                    c.isSQL = false;
                }

                // based on the accumulated TDS flags, determine whether we need to switch client and server IP addresses and ports to make SQl on the destination side
                if (((tdsServerDest + tdsClientSource) > 0) && ((tdsClientDest + tdsServerSource) == 0))
                {
                    // SQL IP and port is the conversation destination IP and destination Port
                    // do nothing
                }
                else if (((tdsClientDest + tdsServerSource) > 0) && ((tdsServerDest + tdsClientSource) == 0))
                {
                    // SQL IP and port number are on the source side of the conversation
                    // Reverse everything so it goes on the destination side
                    reverseSourceDest(c);
                }
                else if (switchClientServer > 0)  // based on key frames we parse more completely
                {
                    reverseSourceDest(c);
                }
                else if (((tdsClientDest + tdsServerSource) > 0) && ((tdsServerDest + tdsClientSource) > 0))
                {
                    if (trace.FindSQLServer(c) != null)
                    {
                        c.hasTDS = true;
                        c.isSQL = true;
                        c.tdsFrames = tdsClientSource + tdsServerSource + tdsClientDest + tdsServerDest + tdsOtherFrames;
                    }
                    // this is a parsing issue - we should log regardless
                    Program.logDiagnostic("*** TDS conversation with SQL on the both sides. Look into this ***");
                    Program.logDiagnostic(c.ColumnData());
                    Program.logDiagnostic();
                    Program.logDiagnostic("CD: " + tdsClientDest.ToString() + "; SS:" + tdsServerSource.ToString() + "; SD:" + tdsServerDest.ToString() + "; CS:" + tdsClientSource.ToString());
                    Program.logDiagnostic();
                }

                // add the identified SQL Server to the collection and add the conversation to the server conversations
                if (c.isSQL)
                {
                    SQLServer Server = trace.GetSQLServer(c.destIP, c.destIPHi, c.destIPLo, c.destPort, c.isIPV6);
                    Server.AddConversation(c);
                }
            } // for each conversation
        }

        // post processing 
        public static void FindStraySQLConversations(NetworkTrace trace)
        {
            // go through all non-SQL conversations and see if they are on a port that SQL is using and set the flag, reverse source and dest if necessary, and add to SQLServers.conversations
            foreach (ConversationData c in trace.conversations)
            {
                if (c.isSQL == false)
                {
                    SQLServer server = trace.FindSQLServer(c);
                    if (server != null)
                    {
                        c.isSQL = true;
                        if (c.destIP != server.sqlIP || c.destIPHi != server.sqlIPHi || c.destIPLo != server.sqlIPLo || c.destPort != server.sqlPort)
                        {
                            reverseSourceDest(c);
                        }
                        server.AddConversation(c);
                    }
                }
            }
        }

        // post processing - added Dec 5, 2016
        public static void FindStraySQLServers(NetworkTrace trace)
        {
            // go through each SQL Server
            // if only 1 conversation, see if conversation client IP and port match another SQL Server's Server IP and port
            // if so, reverse the covnersation and add to the other SQl Server and get rid of this one
            foreach (SQLServer s in trace.sqlServers)
            {
                if (s.conversations.Count == 1)
                {
                    ConversationData c = (ConversationData)(s.conversations[0]);
                    SQLServer s2 = trace.FindSQLServer(c.sourceIP, c.sourceIPHi, c.sourceIPLo, c.sourcePort, c.isIPV6);  // normally we lookup by destination values
                    if (s2 != null)
                    {
                        reverseSourceDest(c);
                        s2.AddConversation(c);
                        s.conversations.Remove(c);
                        s.sqlIP = 0;
                        s.sqlIPHi = 0;
                        s.sqlIPLo = 0;
                        s.sqlPort = 0;
                    }
                }
            }
            // remove bad entries from the trace.sqlServers collection - iterate backwards because of RemoveAt method
            for (int i = trace.sqlServers.Count - 1; i > 0; i--)
            {
                SQLServer s = (SQLServer)(trace.sqlServers[i]);
                if (s.conversations.Count == 0 && s.sqlPort == 0 && s.sqlIP == 0 && s.sqlIPHi == 0 & s.sqlIPLo == 0) trace.sqlServers.RemoveAt(i);
            }
        }

        public static void CreatingPacketsFromFrames(NetworkTrace trace)
        {
            //
            // Go through each Conversation and look for SQL and Kerberos
            // These are the only ones where we may need to reassemble packets
            //
            // Use this to improve the parsers
            //

            PacketData clientPacket = new PacketData();   // may have overlapping packets. Not likely, but just in case.
            PacketData serverPacket = new PacketData();

            foreach (ConversationData c in trace.conversations)
            {
                if (c.isSQL || c.destPort == 88)  // do this for SQL and Kerberos both - may be able to remove code from Kerberos.cs
                {
                    foreach (FrameData frame in c.frames)
                    {
                        if ((frame.hasRESETFlag == false && frame.hasFINFlag == false && frame.hasSYNFlag == false &&
                             frame.hasACKFlag == true && frame.payloadLength > 1) || frame.hasPUSHFlag)
                        {
                            if (frame.isFromClient)
                            {
                                if (clientPacket.conversation == null)
                                {
                                    clientPacket.conversation = c;
                                    c.packets.Add(clientPacket);  // adds packet with empty frames collection
                                }
                                // if packet truncation, only add the first frame, otherwise it would be a disjoint buffer
                                // c.truncatedFrameLength is 0 if no truncation, or > 0 if truncation
                                if (c.truncatedFrameLength == 0 || clientPacket.frames.Count == 0) clientPacket.frames.Add(frame);
                                if (frame.hasPUSHFlag) clientPacket = new PacketData();
                            }
                            else
                            {
                                if (serverPacket.conversation == null)
                                {
                                    serverPacket.conversation = c;
                                    c.packets.Add(serverPacket);  // adds packet with empty frames collection
                                }
                                // if packet truncation, only add the first frame, otherwise it would be a disjoint buffer
                                // c.truncatedFrameLength is 0 if no truncation, or > 0 if truncation
                                if (c.truncatedFrameLength == 0 || serverPacket.frames.Count == 0) serverPacket.frames.Add(frame);
                                if (frame.hasPUSHFlag) serverPacket = new PacketData();
                            }
                        }
                    }
                }
            }
        }

        // helper function
        public static void reverseSourceDest(ConversationData c)
        {
            //Reverse isFromClient Flag in every frame.
            foreach (FrameData frameData in c.frames)
            {
                if (frameData.pktmon != null)
                {
                    foreach (FrameData fd in frameData.pktmonComponentFrames)
                    {
                        fd.isFromClient = !(fd.isFromClient);
                    }
                    // Reversing frameData.isFromClient, as in the else clause, is to be avoided as the main frame is the first element of the pktmonComponentFrames ArrayList.
                    // Reversing it there, reverses it in the main record. Do not want to do that twice or it would undo the change.
                }
                else
                {
                    frameData.isFromClient = !(frameData.isFromClient);
                }
            }

            // reverse client and dest fields so that SQL ends up on the destination side of things
            ulong temp = 0;

            temp = c.sourceMAC;
            c.sourceMAC = c.destMAC;
            c.destMAC = c.sourceMAC;

            temp = c.sourceIP;
            c.sourceIP = c.destIP;
            c.destIP = (uint)temp;

            temp = c.sourceIPHi;
            c.sourceIPHi = c.destIPHi;
            c.destIPHi = temp;

            temp = c.sourceIPLo;
            c.sourceIPLo = c.destIPLo;
            c.destIPLo = temp;

            temp = c.sourcePort;
            c.sourcePort = c.destPort;
            c.destPort = (ushort)temp;

            temp = c.sourceFrames;
            c.sourceFrames = c.destFrames;
            c.destFrames = (uint)temp;

            temp = c.TTLCountIn;
            c.TTLCountIn = c.TTLCountOut;
            c.TTLCountOut = (uint)temp;

            temp = c.TTLSumIn;
            c.TTLSumIn = c.TTLSumOut;
            c.TTLSumOut = (uint)temp;

            temp = c.minTTLHopsIn;
            c.minTTLHopsIn = c.minTTLHopsOut;
            c.minTTLHopsOut = (byte)temp;

            bool fTemp = false;
            fTemp = c.hasServerFin;
            c.hasServerFin = c.hasClientFin;
            c.hasClientFin = fTemp;
            if (c.hasClientFin && c.hasServerFin) c.hasServerFinFirst = !c.hasServerFinFirst; // only if both flags are set can we reverse this
            if (c.hasServerFin && !c.hasClientFin) c.hasServerFinFirst = true;
            if (!c.hasServerFin) c.hasServerFinFirst = false;
        }

        //Parse User name and domain name
        //check are they both 0 length? if yes, set a flag in conversation data that indicates null credentials 
        public static bool AreTheCredentialsNull(FrameData fd)
        {
            if (fd.payload == null) return false;

            // does not matter if the frame is fragmented. What we want - the length fields - are right near the beginning of the payload - just 36 bytes into it
            TDSReader ByteReader = new TDSReader(fd.payload, 0, -1, fd.payloadLength);
            ByteReader.ReadBytes(8);                // TDS header
            ByteReader.ReadBytes(8);                // Skip NTLMSSP string. 
            ByteReader.ReadBytes(4);                // Skip Message type
            ByteReader.ReadBytes(8);                // Skip LmChallengeResponseFields - 8 bytes expected
            ByteReader.ReadBytes(8);                // Skip NtChallengeResponseFields - 8 bytes expected
            short DomainNameLen = ByteReader.ReadInt16();                 // Read DomainNameFields->Length - 2 bytes
            ByteReader.ReadBytes(2);                // Skip DomainNameFields->MaximumLength - 2 bytes - to be ignored per the spec
            int DomainNameOffSet = ByteReader.ReadInt32();                // Read DomainNameFields->BufferOffset - 4 bytes
            short UserNameLen = ByteReader.ReadInt16();                   // Read UserNameFields-Length
            ByteReader.ReadBytes(2);                // Skip UserNameFields-MaximumLength  - 2 bytes - to be ignored per the spec
            int UserNameOffSet = (int)ByteReader.ReadInt16();             // Read UserNameFields-BufferOffset

            if (UserNameLen > 0 && DomainNameLen > 0) return false;

            return true; // user name or domain name are null
        }

        public static string translateSSLVersion(byte major, byte minor)
        {
            if (major == 0 && minor == 2) return "SSL 2.0";
            if (major == 3 && minor == 0) return "SSL 3.0";
            if (major == 3 && minor == 1) return "TLS 1.0";
            if (major == 3 && minor == 2) return "TLS 1.1";
            if (major == 3 && minor == 3) return "TLS 1.2";
            if (major == 3 && minor == 4) return "TLS 1.3";  // appears in a different token in the ClientHello packet
            return $"SSL {major}.{minor}";
        }

        public static string translateSSLVersion(ushort sslVersion)
        {
            return translateSSLVersion((byte)(sslVersion >> 8), (byte)(sslVersion & 0xFF));
        }

        public static string translateSsl3CipherSuite(byte cipherHi, byte cipherLo)
        {
            int code = (int)cipherHi * 256 + cipherLo;
            switch (code)
            {
                case 0x0000: return "SSL_NULL_WITH_NULL_NULL               { 0x00, 0x00 }";
                case 0x0001: return "SSL_RSA_WITH_NULL_MD5                 { 0x00, 0x01 }";
                case 0x0002: return "SSL_RSA_WITH_NULL_SHA                 { 0x00, 0x02 }";
                case 0x0003: return "SSL_RSA_EXPORT_WITH_RC4_40_MD5        { 0x00, 0x03 }";
                case 0x0004: return "SSL_RSA_WITH_RC4_128_MD5              { 0x00, 0x04 }";
                case 0x0005: return "SSL_RSA_WITH_RC4_128_SHA              { 0x00, 0x05 }";
                case 0x0006: return "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5    { 0x00, 0x06 }";
                case 0x0007: return "SSL_RSA_WITH_IDEA_CBC_SHA             { 0x00, 0x07 }";
                case 0x0008: return "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA     { 0x00, 0x08 }";
                case 0x0009: return "SSL_RSA_WITH_DES_CBC_SHA              { 0x00, 0x09 }";
                case 0x000A: return "SSL_RSA_WITH_3DES_EDE_CBC_SHA         { 0x00, 0x0A }";
                case 0x000B: return "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  { 0x00, 0x0B }";
                case 0x000C: return "SSL_DH_DSS_WITH_DES_CBC_SHA           { 0x00, 0x0C }";
                case 0x000D: return "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA      { 0x00, 0x0D }";
                case 0x000E: return "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  { 0x00, 0x0E }";
                case 0x000F: return "SSL_DH_RSA_WITH_DES_CBC_SHA           { 0x00, 0x0F }";
                case 0x0010: return "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA      { 0x00, 0x10 }";
                case 0x0011: return "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA { 0x00, 0x11 }";
                case 0x0012: return "SSL_DHE_DSS_WITH_DES_CBC_SHA          { 0x00, 0x12 }";
                case 0x0013: return "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA     { 0x00, 0x13 }";
                case 0x0014: return "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA { 0x00, 0x14 }";
                case 0x0015: return "SSL_DHE_RSA_WITH_DES_CBC_SHA          { 0x00, 0x15 }";
                case 0x0016: return "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA     { 0x00, 0x16 }";
                case 0x0017: return "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5    { 0x00, 0x17 }";
                case 0x0018: return "SSL_DH_anon_WITH_RC4_128_MD5          { 0x00, 0x18 }";
                case 0x0019: return "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA { 0x00, 0x19 }";
                case 0x001A: return "SSL_DH_anon_WITH_DES_CBC_SHA          { 0x00, 0x1A }";
                case 0x001B: return "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA     { 0x00, 0x1B }";
                case 0x001C: return "SSL_FORTEZZA_DMS_WITH_NULL_SHA        { 0X00, 0x1C }";
                case 0x001D: return "SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA{ 0x00, 0x1D }";
                case 0x001E: return "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA	   { 0x00, 0x1E }";
                case 0x00FF: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV     { 0x00, 0xFF }";    //RFC 5746 sec 3.3
            }
            // not in list
            return $"{cipherHi.ToString("X2")} {cipherLo.ToString("X2")}";
        }

        public static string translateSsl3CipherSuite(ushort sslVersion)
        {
            return translateSsl3CipherSuite((byte)(sslVersion >> 8), (byte)(sslVersion & 0xFF));
        }

        public static string translateTlsCipherSuite(byte cipherHi, byte cipherLo)
        {
            int code = (int)cipherHi * 256 + cipherLo;
            switch (code)
            {
                case 0x0000: return "TLS_NULL_WITH_NULL_NULL                 { 0x00, 0x00 }";
                case 0x0001: return "TLS_RSA_WITH_NULL_MD5                   { 0x00, 0x01 }";
                case 0x0002: return "TLS_RSA_WITH_NULL_SHA                   { 0x00, 0x02 }";
                case 0x0003: return "TLS_RSA_EXPORT_WITH_RC4_40_MD5          { 0x00, 0x03 }";
                case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5                { 0x00, 0x04 }";
                case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA                { 0x00, 0x05 }";
                case 0x0006: return "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5      { 0x00, 0x06 }";
                case 0x0007: return "TLS_RSA_WITH_IDEA_CBC_SHA               { 0x00, 0x07 }";
                case 0x0008: return "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA       { 0x00, 0x08 }";
                case 0x0009: return "TLS_RSA_WITH_DES_CBC_SHA                { 0x00, 0x09 }";
                case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA           { 0x00, 0x0A }";
                case 0x000B: return "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA    { 0x00, 0x0B }";
                case 0x000C: return "TLS_DH_DSS_WITH_DES_CBC_SHA             { 0x00, 0x0C }";
                case 0x000D: return "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA        { 0x00, 0x0D }";
                case 0x000E: return "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA    { 0x00, 0x0E }";
                case 0x000F: return "TLS_DH_RSA_WITH_DES_CBC_SHA             { 0x00, 0x0F }";
                case 0x0010: return "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA        { 0x00, 0x10 }";
                case 0x0011: return "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA   { 0x00, 0x11 }";
                case 0x0012: return "TLS_DHE_DSS_WITH_DES_CBC_SHA            { 0x00, 0x12 }";
                case 0x0013: return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA       { 0x00, 0x13 }";
                case 0x0014: return "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA   { 0x00, 0x14 }";
                case 0x0015: return "TLS_DHE_RSA_WITH_DES_CBC_SHA            { 0x00, 0x15 }";
                case 0x0016: return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA       { 0x00, 0x16 }";
                case 0x0017: return "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5      { 0x00, 0x17 }";
                case 0x0018: return "TLS_DH_anon_WITH_RC4_128_MD5            { 0x00, 0x18 }";
                case 0x0019: return "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA   { 0x00, 0x19 }";
                case 0x001A: return "TLS_DH_anon_WITH_DES_CBC_SHA            { 0x00, 0x1A }";
                case 0x001B: return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA       { 0x00, 0x1B }";
                case 0x001E: return "TLS_KRB5_WITH_DES_CBC_SHA               { 0x00, 0x1E }";
                case 0x001F: return "TLS_KRB5_WITH_3DES_EDE_CBC_SHA          { 0x00, 0x1F }";
                case 0x0020: return "TLS_KRB5_WITH_RC4_128_SHA               { 0x00, 0x20 }";
                case 0x0021: return "TLS_KRB5_WITH_IDEA_CBC_SHA              { 0x00, 0x21 }";
                case 0x0022: return "TLS_KRB5_WITH_DES_CBC_MD5               { 0x00, 0x22 }";
                case 0x0023: return "TLS_KRB5_WITH_3DES_EDE_CBC_MD5          { 0x00, 0x23 }";
                case 0x0024: return "TLS_KRB5_WITH_RC4_128_MD5               { 0x00, 0x24 }";
                case 0x0025: return "TLS_KRB5_WITH_IDEA_CBC_MD5              { 0x00, 0x25 }";
                case 0x0026: return "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA     { 0x00, 0x26 }";
                case 0x0027: return "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA     { 0x00, 0x27 }";
                case 0x0028: return "TLS_KRB5_EXPORT_WITH_RC4_40_SHA         { 0x00, 0x28 }";
                case 0x0029: return "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5     { 0x00, 0x29 }";
                case 0x002A: return "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5     { 0x00, 0x2A }";
                case 0x002B: return "TLS_KRB5_EXPORT_WITH_RC4_40_MD5         { 0x00, 0x2B }";
                case 0x002C: return "TLS_PSK_WITH_NULL_SHA                   { 0x00, 0x2C }";
                case 0x002D: return "TLS_DHE_PSK_WITH_NULL_SHA               { 0x00, 0x2D }";
                case 0x002E: return "TLS_RSA_PSK_WITH_NULL_SHA               { 0x00, 0x2E }";
                case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA            { 0x00, 0x2F }";
                case 0x0030: return "TLS_DH_DSS_WITH_AES_128_CBC_SHA         { 0x00, 0x30 }";
                case 0x0031: return "TLS_DH_RSA_WITH_AES_128_CBC_SHA         { 0x00, 0x31 }";
                case 0x0032: return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA        { 0x00, 0x32 }";
                case 0x0033: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA        { 0x00, 0x33 }";
                case 0x0034: return "TLS_DH_anon_WITH_AES_128_CBC_SHA        { 0x00, 0x34 }";
                case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA            { 0x00, 0x35 }";
                case 0x0036: return "TLS_DH_DSS_WITH_AES_256_CBC_SHA         { 0x00, 0x36 }";
                case 0x0037: return "TLS_DH_RSA_WITH_AES_256_CBC_SHA         { 0x00, 0x37 }";
                case 0x0038: return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA        { 0x00, 0x38 }";
                case 0x0039: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA        { 0x00, 0x39 }";
                case 0x003A: return "TLS_DH_anon_WITH_AES_256_CBC_SHA        { 0x00, 0x3A }";
                case 0x003B: return "TLS_RSA_WITH_NULL_SHA256                { 0x00, 0x3B }";
                case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256         { 0x00, 0x3C }";
                case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256         { 0x00, 0x3D }";
                case 0x003E: return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256      { 0x00, 0x3E }";
                case 0x003F: return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256      { 0x00, 0x3F }";
                case 0x0040: return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256     { 0x00, 0x40 }";
                case 0x0041: return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA       { 0x00, 0x41 }";
                case 0x0042: return "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA    { 0x00, 0x42 }";
                case 0x0043: return "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA    { 0x00, 0x43 }";
                case 0x0044: return "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA   { 0x00, 0x44 }";
                case 0x0045: return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA   { 0x00, 0x45 }";
                case 0x0046: return "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA   { 0x00, 0x46 }";
                case 0x0047: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA       { 0x00, 0x47 }";
                case 0x0048: return "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA    { 0x00, 0x48 }";
                case 0x0049: return "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA    { 0x00, 0x49 }";
                case 0x004A: return "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA   { 0x00, 0x4A }";
                case 0x004B: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA   { 0x00, 0x4B }";
                case 0x004C: return "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA   { 0x00, 0x4C }";
                case 0x0061: return "TLS_NTRU_NSS_WITH_RC4_128_SHA           { 0x00, 0x61 }";
                case 0x0062: return "TLS_NTRU_NSS_WITH_3DES_EDE_CBC_SHA      { 0x00, 0x62 }";
                case 0x0063: return "TLS_NTRU_NSS_WITH_AES_128_CBC_SHA       { 0x00, 0x63 }";
                case 0x0064: return "TLS_NTRU_NSS_WITH_AES_256_CBC_SHA       { 0x00, 0x64 }";
                case 0x0065: return "TLS_NTRU_RSA_WITH_RC4_128_SHA           { 0x00, 0x65 }";
                case 0x0066: return "TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA      { 0x00, 0x66 }";
                case 0x0067: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256     { 0x00, 0x67 }";
                case 0x0068: return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256      { 0x00, 0x68 }";
                case 0x0069: return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256      { 0x00, 0x69 }";
                case 0x006A: return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256     { 0x00, 0x6A }";
                case 0x006B: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256     { 0x00, 0x6B }";
                case 0x006C: return "TLS_DH_anon_WITH_AES_128_CBC_SHA256     { 0x00, 0x6C }";
                case 0x006D: return "TLS_DH_anon_WITH_AES_256_CBC_SHA256     { 0x00, 0x6D }";
                case 0x0084: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA       { 0x00, 0x84 }";
                case 0x0085: return "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA    { 0x00, 0x85 }";
                case 0x0086: return "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA    { 0x00, 0x86 }";
                case 0x0087: return "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA   { 0x00, 0x87 }";
                case 0x0088: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA   { 0x00, 0x88 }";
                case 0x0089: return "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA   { 0x00, 0x89 }";
                case 0x008A: return "TLS_PSK_WITH_RC4_128_SHA                { 0x00, 0x8A }";
                case 0x008B: return "TLS_PSK_WITH_3DES_EDE_CBC_SHA           { 0x00, 0x8B }";
                case 0x008C: return "TLS_PSK_WITH_AES_128_CBC_SHA            { 0x00, 0x8C }";
                case 0x008D: return "TLS_PSK_WITH_AES_256_CBC_SHA            { 0x00, 0x8D }";
                case 0x008E: return "TLS_DHE_PSK_WITH_RC4_128_SHA            { 0x00, 0x8E }";
                case 0x008F: return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA       { 0x00, 0x8F }";
                case 0x0090: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA        { 0x00, 0x90 }";
                case 0x0091: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA        { 0x00, 0x91 }";
                case 0x0092: return "TLS_RSA_PSK_WITH_RC4_128_SHA            { 0x00, 0x92 }";
                case 0x0093: return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA       { 0x00, 0x93 }";
                case 0x0094: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA        { 0x00, 0x94 }";
                case 0x0095: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA        { 0x00, 0x95 }";
                case 0x0096: return "TLS_RSA_WITH_SEED_CBC_SHA               { 0x00, 0x96 }";
                case 0x0097: return "TLS_DH_DSS_WITH_SEED_CBC_SHA            { 0x00, 0x97 }";
                case 0x0098: return "TLS_DH_RSA_WITH_SEED_CBC_SHA            { 0x00, 0x98 }";
                case 0x0099: return "TLS_DHE_DSS_WITH_SEED_CBC_SHA           { 0x00, 0x99 }";
                case 0x009A: return "TLS_DHE_RSA_WITH_SEED_CBC_SHA           { 0x00, 0x9A }";
                case 0x009B: return "TLS_DH_anon_WITH_SEED_CBC_SHA           { 0x00, 0x9B }";
                case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256         { 0x00, 0x9C }";
                case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384         { 0x00, 0x9D }";
                case 0x009E: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     { 0x00, 0x9E }";
                case 0x009F: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     { 0x00, 0x9F }";
                case 0x00A0: return "TLS_DH_RSA_WITH_AES_128_GCM_SHA256      { 0x00, 0xA0 }";
                case 0x00A1: return "TLS_DH_RSA_WITH_AES_256_GCM_SHA384      { 0x00, 0xA1 }";
                case 0x00A2: return "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256     { 0x00, 0xA2 }";
                case 0x00A3: return "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384     { 0x00, 0xA3 }";
                case 0x00A4: return "TLS_DH_DSS_WITH_AES_128_GCM_SHA256      { 0x00, 0xA4 }";
                case 0x00A5: return "TLS_DH_DSS_WITH_AES_256_GCM_SHA384      { 0x00, 0xA5 }";
                case 0x00A6: return "TLS_DH_anon_WITH_AES_128_GCM_SHA256     { 0x00, 0xA6 }";
                case 0x00A7: return "TLS_DH_anon_WITH_AES_256_GCM_SHA384     { 0x00, 0xA7 }";
                case 0x00A8: return "TLS_PSK_WITH_AES_128_GCM_SHA256         { 0x00, 0xA8 }";
                case 0x00A9: return "TLS_PSK_WITH_AES_256_GCM_SHA384         { 0x00, 0xA9 }";
                case 0x00AA: return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256     { 0x00, 0xAA }";
                case 0x00AB: return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384     { 0x00, 0xAB }";
                case 0x00AC: return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256     { 0x00, 0xAC }";
                case 0x00AD: return "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384     { 0x00, 0xAD }";
                case 0x00AE: return "TLS_PSK_WITH_AES_128_CBC_SHA256         { 0x00, 0xAE }";
                case 0x00AF: return "TLS_PSK_WITH_AES_256_CBC_SHA384         { 0x00, 0xAF }";
                case 0x00B0: return "TLS_PSK_WITH_NULL_SHA256                { 0x00, 0xB0 }";
                case 0x00B1: return "TLS_PSK_WITH_NULL_SHA384                { 0x00, 0xB1 }";
                case 0x00B2: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256     { 0x00, 0xB2 }";
                case 0x00B3: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384     { 0x00, 0xB3 }";
                case 0x00B4: return "TLS_DHE_PSK_WITH_NULL_SHA256            { 0x00, 0xB4 }";
                case 0x00B5: return "TLS_DHE_PSK_WITH_NULL_SHA384            { 0x00, 0xB5 }";
                case 0x00B6: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256     { 0x00, 0xB6 }";
                case 0x00B7: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384     { 0x00, 0xB7 }";
                case 0x00B8: return "TLS_RSA_PSK_WITH_NULL_SHA256            { 0x00, 0xB8 }";
                case 0x00B9: return "TLS_RSA_PSK_WITH_NULL_SHA384            { 0x00, 0xB9 }";
                case 0xC001: return "TLS_ECDH_ECDSA_WITH_NULL_SHA            { 0xC0, 0x01 }";
                case 0xC002: return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA         { 0xC0, 0x02 }";
                case 0xC003: return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA    { 0xC0, 0x03 }";
                case 0xC004: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA     { 0xC0, 0x04 }";
                case 0xC005: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA     { 0xC0, 0x05 }";
                case 0xC006: return "TLS_ECDHE_ECDSA_WITH_NULL_SHA           { 0xC0, 0x06 }";
                case 0xC007: return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        { 0xC0, 0x07 }";
                case 0xC008: return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA   { 0xC0, 0x08 }";
                case 0xC009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    { 0xC0, 0x09 }";
                case 0xC00A: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    { 0xC0, 0x0A }";
                case 0xC00B: return "TLS_ECDH_RSA_WITH_NULL_SHA              { 0xC0, 0x0B }";
                case 0xC00C: return "TLS_ECDH_RSA_WITH_RC4_128_SHA           { 0xC0, 0x0C }";
                case 0xC00D: return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA      { 0xC0, 0x0D }";
                case 0xC00E: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA       { 0xC0, 0x0E }";
                case 0xC00F: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA       { 0xC0, 0x0F }";
                case 0xC010: return "TLS_ECDHE_RSA_WITH_NULL_SHA             { 0xC0, 0x10 }";
                case 0xC011: return "TLS_ECDHE_RSA_WITH_RC4_128_SHA          { 0xC0, 0x11 }";
                case 0xC012: return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     { 0xC0, 0x12 }";
                case 0xC013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      { 0xC0, 0x13 }";
                case 0xC014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      { 0xC0, 0x14 }";
                case 0xC015: return "TLS_ECDH_anon_WITH_NULL_SHA             { 0xC0, 0x15 }";
                case 0xC016: return "TLS_ECDH_anon_WITH_RC4_128_SHA          { 0xC0, 0x16 }";
                case 0xC017: return "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA     { 0xC0, 0x17 }";
                case 0xC018: return "TLS_ECDH_anon_WITH_AES_128_CBC_SHA      { 0xC0, 0x18 }";
                case 0xC019: return "TLS_ECDH_anon_WITH_AES_256_CBC_SHA      { 0xC0, 0x19 }";
                case 0xC01A: return "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA       { 0xC0, 0x1A }";
                case 0xC01B: return "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA   { 0xC0, 0x1B }";
                case 0xC01C: return "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA   { 0xC0, 0x1C }";
                case 0xC01D: return "TLS_SRP_SHA_WITH_AES_128_CBC_SHA        { 0xC0, 0x1D }";
                case 0xC01E: return "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA    { 0xC0, 0x1E }";
                case 0xC01F: return "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA    { 0xC0, 0x1F }";
                case 0xC020: return "TLS_SRP_SHA_WITH_AES_256_CBC_SHA        { 0xC0, 0x20 }";
                case 0xC021: return "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA    { 0xC0, 0x21 }";
                case 0xC022: return "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA    { 0xC0, 0x22 }";
                case 0xC023: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 { 0xC0, 0x23 }";
                case 0xC024: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 { 0xC0, 0x24 }";
                case 0xC025: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  { 0xC0, 0x25 }";
                case 0xC026: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  { 0xC0, 0x26 }";
                case 0xC027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   { 0xC0, 0x27 }";
                case 0xC028: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   { 0xC0, 0x28 }";
                case 0xC029: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256    { 0xC0, 0x29 }";
                case 0xC02A: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384    { 0xC0, 0x2A }";
                case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 { 0xC0, 0x2B }";
                case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 { 0xC0, 0x2C }";
                case 0xC02D: return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256  { 0xC0, 0x2D }";
                case 0xC02E: return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384  { 0xC0, 0x2E }";
                case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   { 0xC0, 0x2F }";
                case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   { 0xC0, 0x30 }";
                case 0xC031: return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256    { 0xC0, 0x31 }";
                case 0xC032: return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384    { 0xC0, 0x32 }";
                case 0xC033: return "TLS_ECDHE_PSK_WITH_RC4_128_SHA          { 0xC0, 0x33 }";
                case 0xC034: return "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA     { 0xC0, 0x34 }";
                case 0xC035: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA      { 0xC0, 0x35 }";
                case 0xC036: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA      { 0xC0, 0x36 }";
                case 0xC037: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256   { 0xC0, 0x37 }";
                case 0xC038: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384   { 0xC0, 0x38 }";
                case 0xC039: return "TLS_ECDHE_PSK_WITH_NULL_SHA             { 0xC0, 0x39 }";
                case 0xC03A: return "TLS_ECDHE_PSK_WITH_NULL_SHA256          { 0xC0, 0x3A }";
                case 0xC03B: return "TLS_ECDHE_PSK_WITH_NULL_SHA384          { 0xC0, 0x3B }";
                case 0x00FF: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV       { 0x00, 0xFF }";
            }
            // not in list
            return $"{cipherHi.ToString("X2")} {cipherLo.ToString("X2")}";
        }

        public static string translateTlsCipherSuite(ushort sslVersion)
        {
            return translateTlsCipherSuite((byte)(sslVersion >> 8), (byte)(sslVersion & 0xFF));
        }
    }
}
