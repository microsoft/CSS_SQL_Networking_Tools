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
                for (int i = 8; 0xFF != tdsPayLoad[i]; i+=5 )
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
                        case 0: // Client TDS Version - getting this from LoginACK, now
                            //majorVersion = utility.ReadUInt16(tdsPayLoad, 8 + offset);
                            //minorVersion = utility.B2UInt16(tdsPayLoad, 8 + offset + 2);
                            //levelVersion = utility.B2UInt16(tdsPayLoad, 8 + offset + 4);
                            //conv.serverVersion = majorVersion.ToString() + "." + minorVersion.ToString() + "." + levelVersion.ToString();
                            //break;
                        case 1: // encyption options. 
                            byte encrypt = tdsPayLoad[8 + offset];
                            conv.isEncrypted = (encrypt == 1 || encrypt == 3) ? true : false;  // if the server says YES or NO, then that's that
                            break;
                        case 2:  // we don't care
                        case 3:  // we don't care
                            {
                                break;
                            }
                        case 4:
                            conv.isMARSEnabled = (tdsPayLoad[8 + offset] == 1) ? true : false;  // if the server says YES or NO, then that's that
                            break;
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
                    try
                    {
                        // increased < 7 to < 9. to fix exception in TCP ETW                     *** TODO TODO TODO
                        // weed out non-TDS packets
                        //if (fd.payloadLength < 7) continue;  // ATTENTION payload is 8 bytes   *** should we be < 8 instead ??? *** TODO TODO TODO
                        if (fd.payloadLength < 9 ) continue;  // ATTENTION payload is 8 bytes

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
                            (firstByte != (int)TDSPacketType.SSPI) &&       //   17   0x11
                            (firstByte != (int)TDSPacketType.PRELOGIN) &&   //   18   0x12
                            (firstByte != (int)TDSPacketType.APPDATA))      //   23   0x17
                        {
                            continue;
                        }

                        // read header parts that we are interested in
                        bool tdsEOM = (fd.payload[1] & 0x1) == 1;
                        ushort tdsLength = utility.B2UInt16(fd.payload, 2);

                        // APPDATA does not have a TDS payload, but a TLS payload, so skip these tests if APPDATA
                        if (firstByte != (int)TDSPacketType.APPDATA)
                        {
                            // TDS header Length argument needs to be non-zero and also >= payload length
                            if (tdsLength == 0 || tdsLength < fd.payloadLength) continue;

                            if (fd.payload[6] > 1) continue; // TDS Continuous Response packets can have greater values, but we are ignoring them right now

                            // TDS window needs to be 0   -- from TDSView -- TODO understand the reason for this - does MARS have non-Zero value?
                            if (fd.payload[7] != 0) continue;
                        }

                        switch (firstByte)
                        {
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
                                                c.hasClientSSL = true;
                                                c.tlsVersionClient = translateSSLVersion(sslMajorVersion, sslMinorVersion);
                                                if (sslMajorVersion != 3 || sslMinorVersion != 3) c.hasLowTLSVersion = true;  // mark anything other than TLS 1.2
                                            }
                                            if (handshakeType == 0x10) c.hasKeyExchange = true;
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
                                            Program.logDiagnostic($"TDS:Prelogin Server Hello packet seen at frame {fd.frameNo}.");
                                            c.hasServerSSL = true;
                                            c.tlsVersionServer = translateSSLVersion(sslMajorVersion, sslMinorVersion);
                                            if (sslMajorVersion != 3 || sslMinorVersion != 3) c.hasLowTLSVersion = true;  // mark anything other than TLS 1.2
                                            if (fd.isFromClient)
                                                tdsServerSource++;   // looks like SQL is on the sourceIP side - need to switch later
                                            else
                                                tdsServerDest++;     // looks like SQL is on the destIP side - good
                                        }
                                    }
                                    else if (preloginType == 0x14) // Cipher exchange - could be client or server
                                    {
                                        c.hasCipherExchange = true;
                                        tdsOtherFrames++;  // since could be client or server
                                    }

                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;

                                    break;
                                }
                            case (byte)TDSPacketType.APPDATA:    // 0x17 = Application data
                                {
                                    c.hasApplicationData = true;
                                    tdsOtherFrames++;  // since could be client or server

                                    //accumulate the payload. 
                                    payLoadLength += fd.payload.Length;

                                    break;
                                }
                            case (byte)TDSPacketType.LOGIN:
                                {
                                    //accumulate the payload. *** normally, we should not see this packet unencrypted ***
                                    c.hasLogin7 = true;
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

                                            //Parse User name and domain name
                                            //check are they both 0 length? if yes, set a flag in conversation data that indicates null credentials 
                                            c.hasNullNTLMCreds = AreTheCredentialsNull(fd);

                                            if (fd.isFromClient == false && c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
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
                                    c.hasPostLoginResponse = true; // if we're doing this, login has already succeeded
                                    c.AttentionTime = fd.ticks;

                                    if (fd.isFromClient)
                                        tdsClientSource++;   // looks like SQL is on the destIP side - good
                                    else
                                        tdsClientDest++;     // looks like SQL is on the sourceIP side - need to switch later

                                    break;
                                }
                            case (byte)TDSPacketType.RESPONSE:  //0x4
                                {
                                    // process error responses
                                    if (fd.payload[8] == (byte)TDSTokenType.ERROR)
                                    {
                                        c.Error = utility.ReadUInt32(fd.payload,11);
                                        c.ErrorState = fd.payload[15];
                                        int ErrorLen = (int)fd.payload[17];
                                        c.ErrorMsg = utility.ReadUnicodeString(fd.payload, 19, ErrorLen);
                                    }
                                    //pre-login info from Server. 
                                    // if (tokenOffset(fd.payload, (byte)TDSTokenType.PRELOGINRESPONSE) > 7)  // response header is offset 0..7 - need to fix this routine
                                    else if (fd.payload[8] == (byte)TDSTokenType.PRELOGINRESPONSE) // only 1 token in the payload
                                    {
                                        GetServerPreloginInfo(fd.payload, fd.conversation);
                                        c.hasPreloginResponse = true;
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
                                            c.hasServerSSL = true;
                                            c.tlsVersionServer = translateSSLVersion(sslMajorVersion, sslMinorVersion);
                                            if (sslMajorVersion != 3 || sslMinorVersion != 3) c.hasLowTLSVersion = true;  // mark anything other than TLS 1.2
                                            if (fd.isFromClient)
                                                tdsServerSource++;   // looks like SQL is on the sourceIP side - need to switch later
                                            else
                                                tdsServerDest++;     // looks like SQL is on the destIP side - good
                                        }
                                    }
                                    else if ((fd.payloadLength > 19) &&
                                                (fd.payload[8] == (byte)TDSTokenType.SSPI) &&                    // NTLM Challenge message
                                                (utility.ReadAnsiString(fd.payload, 11, 7) == "NTLMSSP") &&       // NTLM signature
                                                (fd.payload[18] == 0) &&                                         // null terminated
                                                (fd.payload[19] == 2))                                           // type = Challenge Message
                                    {
                                        c.hasNTLMChallenge = true;
                                        if (fd.isFromClient == false && c.hasApplicationData == false && c.hasPostLoginResponse == false) switchClientServer++;
                                    }
                                    else if ((tokenOffset(fd.payload, (byte)TDSTokenType.ENVCHANGE) > 7) &&  // response header is offset 0..7 
                                                (tokenOffset(fd.payload, (byte)TDSTokenType.INFO) > 7) &&
                                                (tokenOffset(fd.payload, (byte)TDSTokenType.LOGINACK) > 7))
                                    {
                                        c.hasPostLoginResponse = true;
                                        c.LoginAckTime = fd.ticks;
                                       
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
                                        catch (IndexOutOfRangeException ex)
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
                    catch (IndexOutOfRangeException ex)
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
                                  + (c.hasPostLoginResponse ? 1 : 0);

                //
                // If we see the beginning of the conversation, but there are not enough key frames, then very strong % not SQL.
                // If the number of SQL packets is < 2% of the overall frame count, then not likely SQL. Can adjust this; 1% might be okay, too.
                // There is a possibility we're wrong, but other conversations should correct that.
                //

                if ((c.synCount > 0 && KeyFrameCount < 3) || ((tdsClientSource + tdsServerDest+ tdsServerSource + tdsClientDest) * 50) < c.frames.Count)
                {
                    tdsClientSource = tdsServerDest = tdsServerSource = tdsClientDest = 0; // short-cut this option for determining if we have a SQL conversation
                }

                if (KeyFrameCount > 4)  // we're pretty sure this is a SQL Server -  JTDS just has Logon7 and hasPostLoginResponse special packets
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
                    Server.conversations.Add(c);
                    if (Server.serverVersion == "" && c.serverVersion != null) Server.serverVersion = c.serverVersion;
                    if (Server.sqlHostName == "" && c.serverName != null) Server.sqlHostName = c.serverName;
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
                        server.conversations.Add(c);
                        if (c.destIP != server.sqlIP || c.destIPHi != server.sqlIPHi || c.destIPLo != server.sqlIPLo || c.destPort != server.sqlPort)
                        {
                            reverseSourceDest(c);
                        }
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
                        s2.conversations.Add(c);
                        s.conversations.Remove(c);
                        s.sqlIP = 0;
                        s.sqlIPHi = 0;
                        s.sqlIPLo = 0;
                        s.sqlPort = 0;
                    }
                }
            }
            // remove bad entries from the trace.sqlServers collection - iterate backwards because of Remove method
            for (int i = trace.sqlServers.Count - 1; i > 0; i--)
            {
                SQLServer s = (SQLServer)(trace.sqlServers[i]);
                if (s.conversations.Count == 0 && s.sqlPort == 0 && s.sqlIP == 0 && s.sqlIPHi == 0 & s.sqlIPLo == 0) trace.sqlServers.RemoveAt(i);
            }
        }

        // helper function
        public static void reverseSourceDest(ConversationData c)
        {
                    //Reverse isFromClient Flag in every frame.
                    foreach (FrameData frameData in c.frames)
                        frameData.isFromClient = !(frameData.isFromClient);

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
            if (major == 3 && minor == 1) return "TLS 1.0";
            if (major == 3 && minor == 2) return "TLS 1.1";
            if (major == 3 && minor == 3) return "TLS 1.2";
            return $"SSL {major}.{minor}";
        }

    }
}
