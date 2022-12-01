// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Parses SSRP request and response
    // Built on UDP
    //

    class SSRPParser
    {


        public static string GetUDPToken(string[] Tokens, string name)
        {
            for (int i = 0; i < Tokens.Length; i++)
            {
                if (Tokens[i].ToLower() == name.ToLower()) return Tokens[i + 1];
            }
            return "";
        }

        public static void ParseSSRPResponse(String ssrpResponse, SSRPData SSRPRequest, NetworkTrace trace)
        {
            if (ssrpResponse.Length <= 0)
                return;

            //the client either (i) sends a single request to a specific machine and expects a single response, or 
            //(ii) broadcasts or multicasts a request to the network and expects zero or more responses from different 
            //discovery services on the network - Page# 30 in SSRP Specs.

            //Response can contain more than one server informaton.
            //Each server info separated by ;;
            String[] Servers = ssrpResponse.Split(new string[] { ";;" }, StringSplitOptions.None);

            foreach (var Server in Servers)
            {
                String[] Tokens = Server.Split(';');

                SSRPRequest.sqlHostName = GetUDPToken(Tokens, "ServerName");
                SSRPRequest.instanceName = GetUDPToken(Tokens, "InstanceName");
                SSRPRequest.isClustered = GetUDPToken(Tokens, "IsClustered");
                SSRPRequest.serverVersion = GetUDPToken(Tokens, "Version");
                SSRPRequest.namedPipe = GetUDPToken(Tokens, "np");
                string portString = GetUDPToken(Tokens, "tcp");

                SSRPRequest.sqlPort = portString.Length > 0 ? Convert.ToUInt16(portString) : (ushort)0;

                if (SSRPRequest.sqlPort != 0)
                {
                    SQLServer s = trace.GetSQLServer(SSRPRequest.sqlIP,
                                                     SSRPRequest.sqlIPHi,
                                                     SSRPRequest.sqlIPLo,
                                                     SSRPRequest.sqlPort,
                                                     SSRPRequest.isIPV6);
                    if (s != null)
                    {
                        if (s.sqlHostName == "")
                            s.sqlHostName = SSRPRequest.sqlHostName;
                        if (s.instanceName == "")
                            s.instanceName = SSRPRequest.instanceName;
                        if (s.isClustered == "")
                            s.isClustered = SSRPRequest.isClustered;
                        if (s.serverVersion == "")
                            s.serverVersion = SSRPRequest.serverVersion;
                        if (s.namedPipe == "")
                            s.namedPipe = SSRPRequest.namedPipe;
                    }
                }

            }
        }


        public static void ProcessUDP(NetworkTrace trace)
        {
            foreach (ConversationData c in trace.conversations)
            {
                if (c.isUDP && c.sourcePort == 1434)
                {
                    TDSParser.reverseSourceDest(c);
                }
                //parse only UDP conversations that are on port 1434
                if ((!c.isUDP) || ((c.isUDP) && (c.destPort != 1434)))
                    continue;


                SSRPData SSRPRequest = trace.GetSSRPRequest(c.destIP, c.destIPHi, c.destIPLo, c.isIPV6);

                if (!SSRPRequest.hasConversation(c))
                    SSRPRequest.conversations.Add(c);

                long requestTicks = 0;
                long responseTicks = 0;

                foreach (FrameData fd in c.frames)
                {
                    try
                    {
                        if ((byte)(fd.payload[0]) == (byte)3) // CLNT_UCAST_EX
                        {
                            SSRPRequest.hasResponse = false;
                        }

                        else if ((byte)(fd.payload[0]) == (byte)4) // Request for specific instance  (CLNT_UCAST_INST)
                        {
                            requestTicks = fd.ticks;
                            SSRPRequest.hasResponse = false;

                            if (c.frames.Count == 1)
                                SSRPRequest.hasNoResponse = true;

                            ushort Length = utility.ReadUInt16(fd.payload, 1);
                            SSRPRequest.instanceRequested = utility.ReadAnsiString(fd.payload, 3, Length);
                            //SSRPRequest.clientPort = c.sourcePort;
                            //SSRPRequest.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            SSRPRequest.sqlIP = c.destIP;
                            SSRPRequest.sqlIPHi = c.destIPHi;
                            SSRPRequest.sqlIPLo = c.destIPLo;
                        }
                        else if ((byte)(fd.payload[0]) == (byte)5) // Response of specific instance (SVR_RESP)
                        {
                            responseTicks = fd.ticks;
                            if (requestTicks > 0)   // ignore responses without requests
                            {
                                long deltaTicks = responseTicks - requestTicks;
                                long deltaTicksms = (long)(deltaTicks / utility.TICKS_PER_MILLISECOND);
                                if (deltaTicksms >= 990)
                                {
                                    SSRPRequest.hasSlowResponse = true;
                                }
                            }

                            SSRPRequest.hasResponse = true;
                            ushort Length = utility.ReadUInt16(fd.payload, 1);
                            String Response = utility.ReadAnsiString(fd.payload, 3, Length);
                            ParseSSRPResponse(Response, SSRPRequest, trace);
                            //if (SSRPRequest.sqlPort != 0)
                            //{
                            //    SQLServer s = trace.GetSQLServer(SSRPRequest.sqlIP, SSRPRequest.sqlIPHi, SSRPRequest.sqlIPLo, SSRPRequest.sqlPort, SSRPRequest.isIPV6);
                            //    if (s != null)
                            //    {
                            //        if (s.sqlHostName == "") s.sqlHostName = SSRPRequest.sqlHostName;
                            //        if (s.instanceName == "") s.instanceName = SSRPRequest.instanceName;
                            //        if (s.isClustered == "") s.isClustered = SSRPRequest.isClustered;
                            //        if (s.serverVersion == "") s.serverVersion = SSRPRequest.serverVersion;
                            //        if (s.namedPipe == "") s.namedPipe = SSRPRequest.namedPipe;
                            //    }
                        }
                    }
                    catch (Exception ex)
                    {
                        Program.logDiagnostic("SSRP Parser: Problem parsing frame " + fd.frameNo + " in file " + fd.file.filePath + ".");
                        Program.logDiagnostic(ex.Message);
                    }
                }
            }
        } // Process UDP

    } // end class

} // end namespace

