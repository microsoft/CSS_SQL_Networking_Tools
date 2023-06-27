// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Writes a text report containing several sections
    // Writes a csv file listing all conversations that can be sorted and filtered in Excel
    //

    class OutputText
    {
        public static void TextReport(NetworkTrace Trace)
        {
            DisplayHeader();
            DisplayFileStatistics(Trace);
            DisplayTrafficStatistics(Trace);
            DisplayDuplicatedPacketStatistics(Trace);
            DisplaySQLServerSummary(Trace);
            DisplayPossibleSQLServers(Trace);
            DisplayDomainControllerSummary(Trace);
            if (Program.outputConversationList) DisplaySucessfulLoginReport(Trace);  // optional section; must be explicitly requested
            DisplayResetConnections(Trace);
            DisplayServerClosedConnections(Trace);
            DisplayPktmonDrops(Trace);
            DisplayBadConnections(Trace);
            DisplayLoginErrors(Trace);
            DisplayDelayedLogins(Trace);
            DisplayDelayedPktmonEvents(Trace);
            DisplayDomainControllerLoginErrors(Trace);
            DisplayNamedPipesReport(Trace);
            DisplayAttentions(Trace);
            DisplayTLSIssues(Trace);
            DisplayRedirectedConnections(Trace);
            DisplayMTUReport(Trace);
            DisplayClientPortUsage(Trace);
            DisplaySSRPReport(Trace);
            DisplayKerberosResponseReport(Trace);
            DisplayDNSResponsesReport(Trace);
            OutputStats(Trace);
            DisplayFooter();
        }

        private static void DisplayHeader()
        {
            Program.logMessage("SQL Server Network Analyzer " + Program.VERSION_NUMBER + " Report");
            Program.logMessage("by the Microsoft CSS SQL Networking Team\r\n");
            Program.logMessage("Command line arguments:      " + Program.commandLine);
            Program.logMessage("Analysis run on:             " + DateTime.Now.ToString(utility.DATE_FORMAT) + "\r\n");
        }

        private static void DisplayFileStatistics(NetworkTrace Trace)
        {
            ReportFormatter rf = new ReportFormatter();
            rf.SetColumnNames("File#:R", "File Name:L", "Capture Start:R", "Capture End:R", "Frames:R", "Size (Bytes):R");
            rf.indent = 4;

            foreach (FileData f in Trace.files)
            {
                rf.SetcolumnData(Trace.files.IndexOf(f).ToString(),
                                 f.filePath,
                                 (new DateTime(f.startTick)).ToString(utility.DATE_FORMAT),
                                 (new DateTime(f.endTick)).ToString(utility.DATE_FORMAT),
                                 f.frameCount.ToString("#,##0"),
                                 f.fileSize.ToString("#,##0"));
            }

            Program.logMessage(rf.GetHeaderText());
            Program.logMessage(rf.GetSeparatorText());

            for (int i = 0; i < rf.GetRowCount(); i++)
            {
                Program.logMessage(rf.GetDataText(i));
            }

            Program.logMessage();

            // Report on PKTMON events

            if (Trace.hasPktmonRecords)
            {
                Program.logMessage("This trace contains repeated packets due to multiple PKTMON trace component events.");
                Program.logMessage("The total event count is reflected in the frame count above.");
                Program.logMessage("Most reports below only count the first frame in each packet group.");
                Program.logMessage();
                if (Trace.hasPktmonDropRecords)
                {
                    Program.logMessage("PKTMON events show that packets were dropped in the TCP or virtual network stack.");
                }
                else
                {
                    Program.logMessage("PKTMON events do not show dropped packets in the TCP or virtual network stack.");
                }
            }
            else
            {
                Program.logMessage("PKTMON events were not detected.");
            }
            Program.logMessage();
        }

        private static void DisplayTrafficStatistics(NetworkTrace Trace)
        {
            ulong tcpBytes = 0, tdsBytes = 0;
            ulong tcpPayloadBytes = 0, tdsPayloadBytes = 0;
            int tcpConversations = 0, tdsConversations = 0;
            int tcpFrames = 0, tdsFrames = 0;

            foreach (ConversationData c in Trace.conversations)
            {
                if (c.isUDP == false)
                {
                    tcpBytes += c.totalBytes;
                    tcpPayloadBytes += c.totalPayloadBytes;
                    tcpFrames += c.frames.Count;
                    tcpConversations++;
                    if (c.isSQL)
                    {
                        tdsBytes += c.totalBytes;
                        tdsPayloadBytes += c.totalPayloadBytes;
                        tdsFrames += c.frames.Count;
                        tdsConversations++;
                    }
                }
            }

            ReportFormatter rf = new ReportFormatter();
            rf.SetColumnNames("Statistic:L", "Packet Bytes:R", "Payload Bytes:R", "Frames:R", "Conversations:R");
            rf.indent = 4;
            rf.SetcolumnData("TCP Traffic", tcpBytes.ToString("#,##0"), tcpPayloadBytes.ToString("#,##0"), tcpFrames.ToString("#,##0"), tcpConversations.ToString("#,##0"));
            rf.SetcolumnData("SQL Traffic", tdsBytes.ToString("#,##0"), tdsPayloadBytes.ToString("#,##0"), tdsFrames.ToString("#,##0"), tdsConversations.ToString("#,##0"));

            Program.logMessage(rf.GetHeaderText());
            Program.logMessage(rf.GetSeparatorText());
            Program.logMessage(rf.GetDataText(0));
            Program.logMessage(rf.GetDataText(1));
            Program.logMessage();

            // Report on truncated packets

            uint truncationErrors = 0;
            uint truncationLength = 0;

            foreach (ConversationData c in Trace.conversations)
            {
                truncationErrors += c.truncationErrorCount;
                if (truncationLength == 0 && c.truncatedFrameLength != 0) truncationLength = c.truncatedFrameLength;
            }

            if (truncationLength != 0)
            {
                Program.logMessage("Frames were truncated to " + truncationLength + " bytes during capture.");
                if (truncationErrors != 0)
                    Program.logMessage("This resulted in " + truncationErrors + " frames that could not be parsed properly.");
                Program.logMessage();
            }

            // identify the IP address on which the network trace was captured
            if (Trace.BadChecksumFrames.Count > 0)  // if 0, then no bad checksums
            {
                ArrayList Addresses = new ArrayList();
                foreach (FrameData f in Trace.BadChecksumFrames)
                {
                    ConversationData c = f.conversation;
                    IPAddressMACAddress a = new IPAddressMACAddress();
                    if (f.isFromClient)
                    {
                        a.IPAddress = (c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP));
                        a.MACAddress = c.sourceMAC.ToString("X12");
                    }
                    else
                    {
                        a.IPAddress = (c.isIPV6 ? utility.FormatIPV6Address(c.destIPHi, c.destIPLo) : utility.FormatIPV4Address(c.destIP));
                        a.MACAddress = c.destMAC.ToString("X12");
                    }
                    Addresses.Add(a);
                }

                var GroupedRows = from row in (Addresses.ToArray())
                                  let row2 = (IPAddressMACAddress)row
                                  group row2 by row2.IPAddress into g
                                  orderby g.Count() descending
                                  select new { Address = g.Key, MAC = g.First().MACAddress, AddrCount = g.Count() };

                if (GroupedRows.Count() == 1)
                {
                    Program.logMessage($"Trace was probably taken on this IP address: {GroupedRows.First().Address}");
                }
                else
                {
                    foreach (var row in GroupedRows)
                    {
                        Program.logMessage($"Trace was probably taken on this IP address: {row.Address}, MAC Addr {row.MAC}, ({row.AddrCount * 10}%)");
                    }
                }

                Program.logMessage();
            }
        }

        private static void DisplayDuplicatedPacketStatistics(NetworkTrace Trace)
        {
            uint clientOnlyDupCount = 0, serverOnlyDupCount = 0, bidirectionalClientDupCount = 0, bidirectionalServerDupCount = 0;
            uint clientOnlyConvCount = 0, serverOnlyConvCount = 0, bidirectionalConvCount = 0;

            foreach (ConversationData c in Trace.conversations)
            {
                if (c.duplicateClientPackets > 0 && c.duplicateServerPackets > 0)
                {
                    bidirectionalConvCount++;
                    bidirectionalClientDupCount += c.duplicateClientPackets;
                    bidirectionalServerDupCount += c.duplicateServerPackets;
                }
                else if (c.duplicateClientPackets > 0 && c.duplicateServerPackets == 0)
                {
                    clientOnlyConvCount++;
                    clientOnlyDupCount += c.duplicateClientPackets;
                }
                else if (c.duplicateClientPackets == 0 && c.duplicateServerPackets > 0)
                {
                    serverOnlyConvCount++;
                    serverOnlyDupCount += c.duplicateServerPackets;
                }
            }

            if (clientOnlyConvCount > 0 || serverOnlyConvCount > 0 || bidirectionalConvCount > 0)
            {
                ReportFormatter rf = new ReportFormatter();
                rf.SetColumnNames("Duplicated IPV4 Packets:L", "Client Frames:R", "Server Frames:R", "Conversations:R");
                rf.indent = 4;
                rf.SetcolumnData("Client Only", clientOnlyDupCount.ToString("#,##0"), "", clientOnlyConvCount.ToString("#,##0"));
                rf.SetcolumnData("Server Only", "", serverOnlyDupCount.ToString("#,##0"), serverOnlyConvCount.ToString("#,##0"));
                rf.SetcolumnData("Bidirectional", bidirectionalClientDupCount.ToString("#,##0"), bidirectionalServerDupCount.ToString("#,##0"), bidirectionalConvCount.ToString("#,##0"));

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());
                Program.logMessage(rf.GetDataText(0));
                Program.logMessage(rf.GetDataText(1));
                Program.logMessage(rf.GetDataText(2));
                Program.logMessage();
                Program.logMessage("Duplicated packets are ignored in the network analysis.");
                Program.logMessage("For details on individual conversations, open the CSV file in Excel.");
                Program.logMessage();
            }
            else
            {
                Program.logMessage("There were no duplicated IPV4 packets detected in the network trace.");
                Program.logMessage();
            }
        }

        private static void DisplaySQLServerSummary(NetworkTrace Trace)
        {
            if (Trace.sqlServers != null && Trace.sqlServers.Count > 0)
            {
                Program.logMessage("The following SQL Servers were visible in the network trace:\r\n");

                ReportFormatter rf = new ReportFormatter();
                rf.SetColumnNames("IP Address:L",
                                   "HostName:L",
                                   "Port:R",
                                   "ServerPipe:L",
                                   "Version:L",
                                   "Files:R",
                                   "Clients:R",
                                   "Conversations:R",
                                   "Kerb Conv:R",
                                   "NTLM Conv:R",
                                   "MARS Conv:R",
                                   "Weak TLS Conv:R",   // TLS 1.1 and below
                                   "TDS8 Conv:R",
                                   "Redirected Conv:R",
                                   "Frames:R",
                                   "Bytes:R",
                                   "Resets:R",
                                   "Retransmits:R",
                                   "IsClustered:R");

                foreach (SQLServer s in Trace.sqlServers)
                {
                    ulong totalBytes = 0;
                    int totalFrames = 0, totalResets = 0, totalRetransmits = 0;
                    ArrayList clientIPs = new ArrayList();
                    string IPAddress = null;  // client IP address or Server IP address
                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);
                    int firstFile = 0;
                    if (s.conversations.Count > 0) firstFile = Trace.files.IndexOf(((FrameData)(((ConversationData)s.conversations[0]).frames[0])).file);
                    int lastFile = 0;
                    int integratedCount = 0;
                    int NTLMResponseCount = 0;
                    int MARSCount = 0;
                    int lowTLSVersionCount = 0;
                    int tds8Count = 0;

                    foreach (ConversationData c in s.conversations)
                    {
                        totalBytes += c.totalBytes;
                        totalFrames += c.frames.Count;
                        totalResets += c.resetCount;
                        totalRetransmits += (int)c.rawRetransmits;
                        if (c.hasServerFinFirst) s.hasServerClosedConnections = true;
                        if (c.hasSynFailure) s.hasSynFailure = true;
                        if (c.isIPV6)
                            IPAddress = utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo);
                        else
                            IPAddress = utility.FormatIPV4Address(c.sourceIP);
                        if (clientIPs.IndexOf(IPAddress) == -1) clientIPs.Add(IPAddress);
                        if (c.hasLoginFailure) s.hasLoginFailures = true;
                        if (c.hasRedirectedConnection) s.hasRedirectedConnections = true;
                        if (c.hasPostLoginResponse) s.hasPostLogInResponse = true;
                        if (c.AttentionTime > 0) s.hasAttentions = true;
                        // may see MARS enabled in PreLogin packet, or if that's missing, if the conversation has SMP packets
                        if (c.isMARSEnabled || (c.smpAckCount + c.smpDataCount + c.smpSynCount + c.smpFinCount > 0)) MARSCount++;
                        if (c.hasLowTLSVersion)
                        {
                            s.hasLowTLSVersion = true;
                            lowTLSVersionCount++;
                        }
                        int lastConvFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                        if (lastConvFile > lastFile) lastFile = lastConvFile;  // the last conversation may not end last, so we have to check
                        if (c.hasIntegratedSecurity) integratedCount++;
                        if (c.hasNTLMResponse == true) NTLMResponseCount++;
                        if (c.hasTDS8) tds8Count++;
                    }

                    if (totalResets > 0) s.hasResets = true;

                    if (s.isIPV6)
                        IPAddress = utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo);
                    else
                        IPAddress = utility.FormatIPV4Address(s.sqlIP);

                    rf.SetcolumnData(sqlIP,
                         s.sqlHostName,
                         s.sqlPort.ToString(),
                         s.namedPipe,
                         (s.serverVersion == null ? "" : s.serverVersion.ToString()),
                         (s.conversations.Count == 0 ? "NO TRAFFIC" : ((firstFile == lastFile) ? firstFile.ToString() : firstFile + "-" + lastFile)),
                         clientIPs.Count.ToString(),
                         s.conversations.Count.ToString(),
                         (integratedCount - NTLMResponseCount).ToString(),  // kerberos (maybe? Azure Active Directory?)
                         NTLMResponseCount.ToString(),
                         MARSCount.ToString(),
                         lowTLSVersionCount.ToString(),
                         tds8Count.ToString(),
                         (from ConversationData conv in s.conversations where conv.hasRedirectedConnection select conv).Count().ToString(),
                         totalFrames.ToString(),
                         totalBytes.ToString("#,##0"),
                         totalResets.ToString(),
                         totalRetransmits.ToString(),
                         s.isClustered);
                }

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

            }
            else // no SQL Servers found
            {
                Program.logMessage("There were no SQL Servers found in the network trace.");
            }

            Program.logMessage();
        }

        private static void DisplayPossibleSQLServers(NetworkTrace Trace)
        {
            if (Trace.possibleSqlServers != null && Trace.possibleSqlServers.Count > 0)
            {
                Program.logMessage("The following servers listening on port 1433 might be SQL Servers, but insufficient traffic was available to validate them.");
                Program.logMessage("If it is a valid SQL Server, copy the IP Address,Port into SQLNAUI and run the analysis again, or use /sql IP Address,Port in the SQLNA command-line if running directly.\r\n");

                ReportFormatter rf = new ReportFormatter();
                rf.SetColumnNames("IP Address,Port:L",
                                   "Files:R",
                                   "Clients:R",
                                   "Conversations:R",
                                   "Frames:R",
                                   "Bytes:R",
                                   "Resets:R",
                                   "Retransmits:R");

                foreach (SQLServer s in Trace.possibleSqlServers)
                {
                    ulong totalBytes = 0;
                    int totalFrames = 0, totalResets = 0, totalRetransmits = 0;
                    ArrayList clientIPs = new ArrayList();
                    string IPAddress = null;  // client IP address or Server IP address
                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);
                    int firstFile = 0;
                    if (s.conversations.Count > 0) firstFile = Trace.files.IndexOf(((FrameData)(((ConversationData)s.conversations[0]).frames[0])).file);
                    int lastFile = 0;

                    foreach (ConversationData c in s.conversations)
                    {
                        totalBytes += c.totalBytes;
                        totalFrames += c.frames.Count;
                        totalResets += c.resetCount;
                        totalRetransmits += (int)c.rawRetransmits;
                        if (c.isIPV6)
                            IPAddress = utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo);
                        else
                            IPAddress = utility.FormatIPV4Address(c.sourceIP);
                        if (clientIPs.IndexOf(IPAddress) == -1) clientIPs.Add(IPAddress);
                        int lastConvFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                        if (lastConvFile > lastFile) lastFile = lastConvFile;  // the last conversation may not end last, so we have to check
                    }

                    if (s.isIPV6)
                        IPAddress = utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo);
                    else
                        IPAddress = utility.FormatIPV4Address(s.sqlIP);

                    rf.SetcolumnData($"{sqlIP},{s.sqlPort.ToString()}",
                         (s.conversations.Count == 0 ? "NO TRAFFIC" : ((firstFile == lastFile) ? firstFile.ToString() : firstFile + "-" + lastFile)),
                         clientIPs.Count.ToString(),
                         s.conversations.Count.ToString(),
                         totalFrames.ToString(),
                         totalBytes.ToString("#,##0"),
                         totalResets.ToString(),
                         totalRetransmits.ToString());
                }

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

            }
            else // no other SQL Servers found
            {
                Program.logMessage("There were no other Servers listening on port 1433 found in the network trace.");
            }

            Program.logMessage();
        }

        private static void DisplayDomainControllerSummary(NetworkTrace Trace)
        {
            if (Trace.DomainControllers != null && Trace.DomainControllers.Count > 0)
            {
                Program.logMessage("The following Domain Controllers were visible in the network trace:\r\n");

                ReportFormatter rf = new ReportFormatter();
                rf.SetColumnNames("IP Address:L",
                                   "Files:R",
                                   "Clients:R",
                                   "Conversations:R",
                                   "Kerb Conv:R",
                                   "DNS Conv:R",
                                   "LDAP Conv:R",
                                   "MSRPC Conv:R",
                                   "MSRPC Port:R",
                                   "Frames:R",
                                   "Bytes:R");

                foreach (DomainController d in Trace.DomainControllers)
                {
                    ulong totalBytes = 0;
                    int totalFrames = 0;
                    ArrayList clientIPs = new ArrayList();
                    string IPAddress = null;  // client IP address
                    string IP = (d.isIPV6) ? utility.FormatIPV6Address(d.IPHi, d.IPLo) : utility.FormatIPV4Address(d.IP);
                    int firstFile = 0;
                    if (d.conversations.Count > 0) firstFile = Trace.files.IndexOf(((FrameData)(((ConversationData)d.conversations[0]).frames[0])).file);
                    int lastFile = 0;

                    foreach (ConversationData c in d.conversations)
                    {
                        totalBytes += c.totalBytes;
                        totalFrames += c.frames.Count;
                        if (c.isIPV6)
                            IPAddress = utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo);
                        else
                            IPAddress = utility.FormatIPV4Address(c.sourceIP);
                        if (clientIPs.IndexOf(IPAddress) == -1) clientIPs.Add(IPAddress);
                        int lastConvFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                        if (lastConvFile > lastFile) lastFile = lastConvFile;  // the last conversation may not end last, so we have to check
                    }

                    rf.SetcolumnData(IP,
                         (d.conversations.Count == 0 ? "NO TRAFFIC" : ((firstFile == lastFile) ? firstFile.ToString() : firstFile + "-" + lastFile)),
                         clientIPs.Count.ToString(),
                         d.conversations.Count.ToString(),
                         d.KerbPort88Count.ToString(),
                         d.DNSPort53Count.ToString(),
                         d.LDAPPort389Count.ToString(),
                         d.MSRPCPortCount.ToString(),
                         (d.hasMultipleMSRPCPorts ? "Multiple" : (d.MSRPCPort == 0 ? "None" : d.MSRPCPort.ToString())),
                         totalFrames.ToString(),
                         totalBytes.ToString("#,##0"));
                }

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

            }
            else // no Domain Controllers found
            {
                Program.logMessage("There were no Domain Controllers found in the network trace.");
            }

            Program.logMessage();
        }

        private static void DisplayResetConnections(NetworkTrace Trace)
        {
            bool hasError = false;

            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (SQLServer s in Trace.sqlServers)
            {
                int ignoredMARSConnections = 0;

                if (s.hasResets)
                {
                    hasError = true;
                    List<ResetConnectionData> ResetRecords = new List<ResetConnectionData>();

                    // initialize graph object
                    TextGraph g = new TextGraph();
                    g.startTime = new DateTime(firstTick);
                    g.endTime = new DateTime(lastTick);
                    g.SetGraphWidth(150);
                    g.fAbsoluteScale = true;
                    g.SetCutoffValues(1, 3, 9, 27, 81);

                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                    foreach (ConversationData c in s.conversations)
                    {
                        if (c.resetCount > 0)
                        {
                            //
                            // Ignore normal MARS shutdown sequence that always shows a RESET after SMP:FIN and ACK+FIN packets.
                            //
                            // We may not see the prelogin packets, so cannot rely on the isMARSEnabled flag being true.
                            //
                            // Encrypted MARS connections are going to show in the report as we have no way of knowing for sure whether
                            // the SMP:FIN packet was issued.
                            //
                            // Manual inspection of the CSV file or network trace may be needed.
                            //
                            if (c.smpFinCount > 0 && c.finCount > 0 && c.smpFinTime < c.ResetTime && c.FinTime < c.ResetTime)
                            {
                                ignoredMARSConnections++;
                                continue;
                            }

                            ResetConnectionData rd = new ResetConnectionData();

                            string clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);

                            bool traceOnServer = c.minTTLHopsOut != 0;
                            if (c.minTTLHopsIn != 0) Program.logDiagnostic($"Both client and server have non-zero TTL hops. IP: {clientIP}, Port: {c.sourcePort}.");
                            double avgTTL = -1.0;
                            byte TTL = 0;
                            byte minHops = 0;
                            if (traceOnServer)
                            {
                                if (c.TTLCountOut != 0)
                                {
                                    avgTTL = (1.0 * c.TTLSumOut) / c.TTLCountOut;
                                    TTL = (byte)(avgTTL + ((avgTTL == (byte)avgTTL) ? 0 : 1)); // round up if fractional
                                    minHops = c.minTTLHopsOut;
                                }
                            }
                            else
                            {
                                if (c.TTLCountIn != 0)
                                {
                                    avgTTL = (1.0 * c.TTLSumIn) / c.TTLCountIn;
                                    TTL = (byte)(avgTTL + ((avgTTL == (byte)avgTTL) ? 0 : 1)); // round up if fractional
                                    minHops = c.minTTLHopsIn;
                                }
                            }

                            rd.clientIP = clientIP;
                            rd.sourcePort = c.sourcePort;
                            rd.isIPV6 = c.isIPV6;
                            rd.frames = c.frames.Count;
                            rd.ResetFrame = 0;
                            rd.ResetFile = 0;
                            rd.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            rd.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                            rd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                            rd.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                            rd.endOffset = rd.endTicks - firstTick;
                            rd.duration = rd.endOffset - rd.startOffset;
                            rd.isClientReset = false;
                            rd.rawRetransmits = c.rawRetransmits;
                            rd.maxRetransmitsInARow = c.maxRetransmitCount;
                            rd.keepAliveCount = c.keepAliveCount;
                            rd.maxKeepAliveRetransmitsInARow = (ushort)(c.maxKeepAliveRetransmits == 0 ? 0 : c.maxKeepAliveRetransmits + 1);
                            rd.flags = null;
                            if (avgTTL != -1.0)  // count of outgoing packets must be > 0 - it's possible the conversation may be filtered to incoming packets or have just 1 packet total
                            {
                                rd.TTL = TTL;
                                rd.lowTTLHop = minHops;
                            }
                            rd.endFrames = c.GetLastPacketList(20);

                            //for (int i = c.frames.Count - 1; i >= 0; i--)
                            foreach (FrameData f in c.frames)   // search from beginning for first reset, not from end for last reset
                            {
                                //FrameData f = (FrameData)c.frames[i];
                                if ((f.flags & (byte)TCPFlag.RESET) > 0)
                                {
                                    rd.ResetFrame = f.frameNo;
                                    rd.ResetFile = Trace.files.IndexOf(f.file);
                                    rd.isClientReset = f.isFromClient;
                                    rd.flags = f.FormatFlags();
                                    g.AddData(new DateTime(f.ticks), 1.0); // for graphing
                                    break;
                                }
                            }

                            ResetRecords.Add(rd);
                        }
                    }

                    if (ResetRecords.Count > 0)
                    {
                        Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " were reset:\r\n");
                        ReportFormatter rf = new ReportFormatter();
                        switch (Program.filterFormat)
                        {
                            case "N":
                                {
                                    rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Reset File:R", "Reset Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Who Reset:L", "Flags:L", "TTL:R", "Hops:R", "Low TTL:R", "Keep-Alives:R", "KA Timeout:R", "Retransmits:R", "Max RT:R", "End Frames:L");
                                    break;
                                }
                            case "W":
                                {
                                    rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Reset File:R", "Reset Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Who Reset:L", "Flags:L", "TTL:R", "Hops:R", "Low TTL:R", "Keep-Alives:R", "KA Timeout:R", "Retransmits:R", "Max RT:R", "End Frames:L");
                                    break;
                                }
                            default:
                                {
                                    rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Reset File:R", "Reset Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Who Reset:L", "Flags:L", "TTL:R", "Hops:R", "Low TTL:R", "Keep-Alives:R", "KA Timeout:R", "Retransmits:R", "Max RT:R", "End Frames:L");
                                    break;
                                }
                        }

                        var OrderedRows = from row in ResetRecords orderby row.endOffset ascending select row;

                        foreach (var row in OrderedRows)
                        {
                            switch (Program.filterFormat)
                            {
                                case "N":  // list client IP and port as a NETMON filter string
                                    {
                                        rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                         (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                         row.ResetFile.ToString(),
                                                         row.ResetFrame.ToString(),
                                                         (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                         row.frames.ToString(),
                                                         (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.isClientReset ? "Client" : "Server"),
                                                         row.flags,
                                                         row.TTL == 0 ? "" : row.TTL.ToString(),
                                                         row.TTL == 0 ? "" : Parser.CalculateTTLHops(row.TTL).ToString(),
                                                         row.TTL == 0 ? "" : (Parser.CalculateTTLHops(row.TTL) != row.lowTTLHop ? row.lowTTLHop.ToString() : ""),
                                                         row.keepAliveCount.ToString(),
                                                         row.maxKeepAliveRetransmitsInARow.ToString(),
                                                         row.rawRetransmits.ToString(),
                                                         row.maxRetransmitsInARow.ToString(),
                                                         row.endFrames);
                                        break;
                                    }
                                case "W":  // list client IP and port as a WireShark filter string
                                    {
                                        rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                         (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                         row.ResetFile.ToString(),
                                                         row.ResetFrame.ToString(),
                                                         (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                         row.frames.ToString(),
                                                         (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.isClientReset ? "Client" : "Server"),
                                                         row.flags,
                                                         row.TTL == 0 ? "" : row.TTL.ToString(),
                                                         row.TTL == 0 ? "" : Parser.CalculateTTLHops(row.TTL).ToString(),
                                                         row.TTL == 0 ? "" : (Parser.CalculateTTLHops(row.TTL) != row.lowTTLHop ? row.lowTTLHop.ToString() : ""),
                                                         row.keepAliveCount.ToString(),
                                                         row.maxKeepAliveRetransmitsInARow.ToString(),
                                                         row.rawRetransmits.ToString(),
                                                         row.maxRetransmitsInARow.ToString(),
                                                         row.endFrames);
                                        break;
                                    }
                                default:  // list client IP and port as separate columns
                                    {
                                        rf.SetcolumnData(row.clientIP,
                                                         row.sourcePort.ToString(),
                                                         (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                         row.ResetFile.ToString(),
                                                         row.ResetFrame.ToString(),
                                                         (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                         row.frames.ToString(),
                                                         (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.isClientReset ? "Client" : "Server"),
                                                         row.flags,
                                                         row.TTL == 0 ? "" : row.TTL.ToString(),
                                                         row.TTL == 0 ? "" : Parser.CalculateTTLHops(row.TTL).ToString(),
                                                         row.TTL == 0 ? "" : (Parser.CalculateTTLHops(row.TTL) != row.lowTTLHop ? row.lowTTLHop.ToString() : ""),
                                                         row.keepAliveCount.ToString(),
                                                         row.maxKeepAliveRetransmitsInARow.ToString(),
                                                         row.rawRetransmits.ToString(),
                                                         row.maxRetransmitsInARow.ToString(),
                                                         row.endFrames);
                                        break;
                                    }
                            }
                        }

                        Program.logMessage(rf.GetHeaderText());
                        Program.logMessage(rf.GetSeparatorText());

                        for (int i = 0; i < rf.GetRowCount(); i++)
                        {
                            Program.logMessage(rf.GetDataText(i));
                        }

                        Program.logMessage();

                        //
                        // Display graph
                        //

                        Program.logMessage("    Distribution of RESET connections.");
                        Program.logMessage();
                        g.ProcessData();
                        Program.logMessage("    " + g.GetLine(0));
                        Program.logMessage("    " + g.GetLine(1));
                        Program.logMessage("    " + g.GetLine(2));
                        Program.logMessage("    " + g.GetLine(3));
                        Program.logMessage("    " + g.GetLine(4));
                        Program.logMessage("    " + g.GetLine(5));

                        Program.logMessage();

                        if (ignoredMARSConnections > 0)
                        {
                            Program.logMessage($"{ignoredMARSConnections} MARS connections were omitted from the report as being a false positive.");
                            Program.logMessage();
                        }
                    }
                    else // if (ResetRecords.Count > 0)
                    {
                        // all reset records were due to MARS connections
                        Program.logMessage($"All {ignoredMARSConnections} reset connections for SQL Server {sqlIP} on port {s.sqlPort} were due to the MARS connection closing sequence and were benign.");
                        Program.logMessage();
                    }

                }

            }

            if (hasError == false)
            {
                Program.logMessage("No reset connections were found.");
                Program.logMessage();
            }
        }

        private static void DisplayServerClosedConnections(NetworkTrace Trace)
        {
            bool hasError = false;

            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (SQLServer s in Trace.sqlServers)
            {
                if (s.hasServerClosedConnections)
                {
                    hasError = true;
                    List<ServerClosedConnectionData> ServerClosedRecords = new List<ServerClosedConnectionData>();

                    // initialize graph object
                    TextGraph g = new TextGraph();
                    g.startTime = new DateTime(firstTick);
                    g.endTime = new DateTime(lastTick);
                    g.SetGraphWidth(150);
                    g.fAbsoluteScale = true;
                    g.SetCutoffValues(1, 3, 9, 27, 81);

                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                    foreach (ConversationData c in s.conversations)
                    {
                        if (c.hasServerFinFirst)
                        {
                            ServerClosedConnectionData scd = new ServerClosedConnectionData();

                            scd.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            scd.sourcePort = c.sourcePort;
                            scd.isIPV6 = c.isIPV6;
                            scd.frames = c.frames.Count;
                            scd.closeFrame = 0;
                            scd.closeFile = 0;
                            scd.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            scd.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                            scd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                            scd.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                            scd.endOffset = scd.endTicks - firstTick;
                            scd.duration = scd.endOffset - scd.startOffset;
                            scd.flags = null;
                            scd.endFrames = c.GetLastPacketList(20);

                            //for (int i = c.frames.Count - 1; i >= 0; i--)
                            foreach (FrameData f in c.frames)   // search from beginning for first reset, not from end for last reset
                            {
                                if ((f.flags & (byte)TCPFlag.FIN) > 0)
                                {
                                    scd.closeFrame = f.frameNo;
                                    scd.closeFile = Trace.files.IndexOf(f.file);
                                    scd.flags = f.FormatFlags();
                                    g.AddData(new DateTime(f.ticks), 1.0); // for graphing
                                    break;
                                }
                            }

                            ServerClosedRecords.Add(scd);
                        }
                    }

                    if (ServerClosedRecords.Count > 0)
                    {
                        Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " were closed by the server:\r\n");
                        ReportFormatter rf = new ReportFormatter();
                        switch (Program.filterFormat)
                        {
                            case "N":
                                {
                                    rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Close File:R", "Close Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Flags:L", "End Frames:L");
                                    break;
                                }
                            case "W":
                                {
                                    rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Close File:R", "Close Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Flags:L", "End Frames:L");
                                    break;
                                }
                            default:
                                {
                                    rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Close File:R", "Close Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Flags:L", "End Frames:L");
                                    break;
                                }
                        }

                        var OrderedRows = from row in ServerClosedRecords orderby row.endOffset ascending select row;

                        foreach (var row in OrderedRows)
                        {
                            switch (Program.filterFormat)
                            {
                                case "N":  // list client IP and port as a NETMON filter string
                                    {
                                        rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                         (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                         row.closeFile.ToString(),
                                                         row.closeFrame.ToString(),
                                                         (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                         row.frames.ToString(),
                                                         (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         row.flags,
                                                         row.endFrames);
                                        break;
                                    }
                                case "W":  // list client IP and port as a WireShark filter string
                                    {
                                        rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                         (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                         row.closeFile.ToString(),
                                                         row.closeFrame.ToString(),
                                                         (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                         row.frames.ToString(),
                                                         (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         row.flags,
                                                         row.endFrames);
                                        break;
                                    }
                                default:  // list client IP and port as separate columns
                                    {
                                        rf.SetcolumnData(row.clientIP,
                                                         row.sourcePort.ToString(),
                                                         (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                         row.closeFile.ToString(),
                                                         row.closeFrame.ToString(),
                                                         (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                         row.frames.ToString(),
                                                         (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         row.flags,
                                                         row.endFrames);
                                        break;
                                    }
                            }
                        }

                        Program.logMessage(rf.GetHeaderText());
                        Program.logMessage(rf.GetSeparatorText());

                        for (int i = 0; i < rf.GetRowCount(); i++)
                        {
                            Program.logMessage(rf.GetDataText(i));
                        }

                        Program.logMessage();

                        //
                        // Display graph
                        //

                        Program.logMessage("    Distribution of Server-closed connections.");
                        Program.logMessage();
                        g.ProcessData();
                        Program.logMessage("    " + g.GetLine(0));
                        Program.logMessage("    " + g.GetLine(1));
                        Program.logMessage("    " + g.GetLine(2));
                        Program.logMessage("    " + g.GetLine(3));
                        Program.logMessage("    " + g.GetLine(4));
                        Program.logMessage("    " + g.GetLine(5));

                        Program.logMessage();
                    }
                }
            }

            if (hasError == false)
            {
                Program.logMessage("No server-closed connections were found.");
                Program.logMessage();
            }
        }


        private static void DisplayPktmonDrops(NetworkTrace Trace)
        {
            if (Trace.hasPktmonRecords == false)
            {
                Program.logMessage("No Pktmon trace events were found for drop reporting.");
                Program.logMessage();
            }
            else if (Trace.hasPktmonDropRecords == false)
            {
                Program.logMessage("The trace contains Pktmon events but no drop events were found.");
                Program.logMessage();
            }
            else  // pktmon with drop events
            {
                long firstTick = 0;
                long lastTick = 0;

                if (Trace.frames != null && Trace.frames.Count > 0)
                {
                    firstTick = ((FrameData)Trace.frames[0]).ticks;
                    lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
                }

                foreach (SQLServer s in Trace.sqlServers)
                {
                    if (s.hasPktmonDroppedEvent)
                    {
                        List<PktmonDropConnectionData> PktmonDropRecords = new List<PktmonDropConnectionData>();

                        // initialize graph object
                        TextGraph g = new TextGraph();
                        g.startTime = new DateTime(firstTick);
                        g.endTime = new DateTime(lastTick);
                        g.SetGraphWidth(150);
                        g.fAbsoluteScale = true;
                        g.SetCutoffValues(1, 3, 9, 27, 81);

                        string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                        foreach (ConversationData c in s.conversations)
                        {
                            if (c.hasPktmonDroppedEvent)
                            {
                                PktmonDropConnectionData pd = new PktmonDropConnectionData();

                                pd.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                                pd.sourcePort = c.sourcePort;
                                pd.isIPV6 = c.isIPV6;
                                pd.frames = c.frames.Count;
                                pd.dropFrame = 0;
                                pd.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                                pd.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                                pd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                                pd.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                                pd.endOffset = pd.endTicks - firstTick;
                                pd.duration = pd.endOffset - pd.startOffset;


                                foreach (FrameData f in c.frames)   // search from beginning for first drop record
                                {
                                    if (f.pktmonComponentFrames != null)
                                    {
                                        foreach (FrameData pktmonEvent in f.pktmonComponentFrames)
                                        {
                                            if (pktmonEvent.pktmon.eventID == 170)   // this is a drop frame
                                            {
                                                pd.dropFrame = pktmonEvent.frameNo;
                                                pd.dropComponent = pktmonEvent.pktmon.ComponentId;
                                                pd.dropReason = GetPktmonDropReasonText(pktmonEvent.pktmon.DropReason) + $" ({pktmonEvent.pktmon.DropReason})";
                                                g.AddData(new DateTime(f.ticks), 1.0); // for graphing
                                                break;
                                            }
                                        }
                                    }
                                }

                                PktmonDropRecords.Add(pd);
                            }
                        }
                        if (PktmonDropRecords.Count > 0)
                        {
                            Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " had Pktmon drop events in the TCP or virtual network stack:\r\n");
                            Program.logMessage("The drop events occurred on the machine on which the trace was collected.");
                            Program.logMessage();
                            ReportFormatter rf = new ReportFormatter();
                            switch (Program.filterFormat)
                            {
                                case "N":
                                    {
                                        rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Drop Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Drop Component:R", "Reason:L");
                                        break;
                                    }
                                case "W":
                                    {
                                        rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Drop Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Drop Component:R", "Reason:L");
                                        break;
                                    }
                                default:
                                    {
                                        rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Drop Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Drop Component:R", "Reason:L");
                                        break;
                                    }
                            }

                            var OrderedRows = from row in PktmonDropRecords orderby row.endOffset ascending select row;

                            foreach (var row in OrderedRows)
                            {
                                switch (Program.filterFormat)
                                {
                                    case "N":  // list client IP and port as a NETMON filter string
                                        {
                                            rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                             (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                             row.dropFrame.ToString(),
                                                             (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                             row.frames.ToString(),
                                                             (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             row.dropComponent.ToString(),
                                                             row.dropReason);
                                            break;
                                        }
                                    case "W":  // list client IP and port as a WireShark filter string
                                        {
                                            rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                             (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                             row.dropFrame.ToString(),
                                                             (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                             row.frames.ToString(),
                                                             (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             row.dropComponent.ToString(),
                                                             row.dropReason);
                                            break;
                                        }
                                    default:  // list client IP and port as separate columns
                                        {
                                            rf.SetcolumnData(row.clientIP,
                                                             row.sourcePort.ToString(),
                                                             (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                             row.dropFrame.ToString(),
                                                             (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                             row.frames.ToString(),
                                                             (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                             row.dropComponent.ToString(),
                                                             row.dropReason);
                                            break;
                                        }
                                }
                            }

                            Program.logMessage(rf.GetHeaderText());
                            Program.logMessage(rf.GetSeparatorText());

                            for (int i = 0; i < rf.GetRowCount(); i++)
                            {
                                Program.logMessage(rf.GetDataText(i));
                            }

                            Program.logMessage();

                            //
                            // Display graph
                            //

                            Program.logMessage("    Distribution of PKTMON drop events.");
                            Program.logMessage();
                            g.ProcessData();
                            Program.logMessage("    " + g.GetLine(0));
                            Program.logMessage("    " + g.GetLine(1));
                            Program.logMessage("    " + g.GetLine(2));
                            Program.logMessage("    " + g.GetLine(3));
                            Program.logMessage("    " + g.GetLine(4));
                            Program.logMessage("    " + g.GetLine(5));

                            Program.logMessage();
                        } // if (PktmonDropRecords.Count > 0)
                    } // if (s.hasPktmonDroppedEvent)
                } // foreach (SQLServer s in Trace.sqlServers)
            }  // else
        }  // private static void DisplayPktmonDrops

        private static void DisplayDelayedPktmonEvents(NetworkTrace Trace)
        {
            if (Trace.hasPktmonRecords == false)
            {
                Program.logMessage("No Pktmon trace events were found for delay reporting.");
                Program.logMessage();
            }
            else
            {
                long delayTicks = 2 * (long)utility.TICKS_PER_MILLISECOND; // any internal delay more than 2 milliseconds will be reported
                string delayWords = "2ms";                                 // sync with the line above

                long firstTick = 0;
                long lastTick = 0;

                if (Trace.frames != null && Trace.frames.Count > 0)
                {
                    firstTick = ((FrameData)Trace.frames[0]).ticks;
                    lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
                }

                List<PktmonDelayConnectionData> PktmonDelayRecords = new List<PktmonDelayConnectionData>();

                // initialize graph object
                TextGraph g = new TextGraph();
                g.startTime = new DateTime(firstTick);
                g.endTime = new DateTime(lastTick);
                g.SetGraphWidth(150);
                g.fAbsoluteScale = true;
                g.SetCutoffValues(1, 3, 9, 27, 81);

                foreach (ConversationData c in Trace.conversations)
                {
                    if (c.hasPktmonDroppedEvent) continue;   // this will appear in the DisplayPktmonDrops report

                    string clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                    string serverIP = (c.isIPV6) ? utility.FormatIPV6Address(c.destIPHi, c.destIPLo) : utility.FormatIPV4Address(c.destIP);
                    string protocolName = GetProtocolName(c);

                    foreach (FrameData f in c.frames)
                    {
                        if (f.pktmon != null && f.pktmonComponentFrames.Count > 1)
                        {
                            FrameData prevFrame = f;
                            long diffTick = 0;
                            for (int i = 1; i < f.pktmonComponentFrames.Count; i++)
                            {
                                FrameData nextFrame = (FrameData)f.pktmonComponentFrames[i];
                                diffTick = nextFrame.ticks - prevFrame.ticks;
                                if (diffTick > c.pktmonMaxDelay) c.pktmonMaxDelay = diffTick;
                                if (diffTick > delayTicks)
                                {
                                    PktmonDelayConnectionData pd = new PktmonDelayConnectionData();

                                    pd.sourceIP = clientIP;
                                    pd.sourcePort = c.sourcePort;
                                    pd.destIP = serverIP;
                                    pd.destPort = c.destPort;
                                    pd.isIPV6 = c.isIPV6;
                                    pd.delayFrame = prevFrame.frameNo;
                                    pd.delayTicks = prevFrame.ticks;
                                    pd.delayFile = Trace.files.IndexOf(prevFrame.file);
                                    pd.delayOffset = prevFrame.ticks - firstTick;
                                    pd.delayDuration = diffTick;
                                    pd.delayStartComponent = prevFrame.pktmon.ComponentId;
                                    pd.delayEndComponent = nextFrame.pktmon.ComponentId;
                                    pd.protocolName = protocolName;

                                    PktmonDelayRecords.Add(pd);
                                    g.AddData(new DateTime(prevFrame.ticks), 1.0);
                                }
                                prevFrame = nextFrame;
                            }
                        }
                    }
                }

                if (PktmonDelayRecords.Count > 0)
                {
                    Program.logMessage($"The following frames had Pktmon delays of greater than {delayWords} events in the TCP or virtual network stack:\r\n");
                    Program.logMessage("The delay occurred on the machine on which the trace was collected.");
                    Program.logMessage();
                    ReportFormatter rf = new ReportFormatter();
                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("Protocol:L", "NETMON Filter:L", "Delay Frame:R", "Delay File:R", "Delay Offset:R", "Delay Time:R", "Duration:R", "Delay Component 1:R", "Delay Component 2:R");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("Protocol:L", "WireShark Filter:L", "Delay Frame:R", "Delay File:R", "Delay Offset:R", "Delay Time:R", "Duration:R", "Delay Component 1:R", "Delay Component 2:R");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Protocol:L", "Client Address:L", "Port:R", "Server Address:L", "Port:R", "Delay Frame:R", "Delay File:R", "Delay Offset:R", "Delay Time:R", "Duration:R", "Delay Component 1:R", "Delay Component 2:R");
                                break;
                            }
                    }

                    var OrderedRows = from row in PktmonDelayRecords orderby row.delayOffset ascending select row;

                    foreach (var row in OrderedRows)
                    {
                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData(row.protocolName,
                                                     (row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.sourceIP + " and tcp.port==" + row.sourcePort.ToString() + " AND " + (row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.destIP + " and tcp.port==" + row.destPort.ToString(),
                                                     row.delayFrame.ToString(),
                                                     row.delayFile.ToString(),
                                                     (row.delayOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.delayTicks).ToString(utility.TIME_FORMAT),
                                                     row.delayDuration.ToString(),
                                                     row.delayStartComponent.ToString(),
                                                     row.delayStartComponent.ToString());
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData(row.protocolName, 
                                                     (row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.sourceIP + " and tcp.port==" + row.sourcePort.ToString() + " and " + (row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.destIP + " and tcp.port==" + row.destPort.ToString(),
                                                     row.delayFrame.ToString(),
                                                     row.delayFile.ToString(),
                                                     (row.delayOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.delayTicks).ToString(utility.TIME_FORMAT),
                                                     row.delayDuration.ToString(),
                                                     row.delayStartComponent.ToString(),
                                                     row.delayStartComponent.ToString());
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.sourceIP,
                                                     row.sourcePort.ToString(),
                                                     row.destIP,
                                                     row.destPort.ToString(),
                                                     row.delayFrame.ToString(),
                                                     row.delayFile.ToString(),
                                                     (row.delayOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.delayTicks).ToString(utility.TIME_FORMAT),
                                                     row.delayDuration.ToString(),
                                                     row.delayStartComponent.ToString(),
                                                     row.delayStartComponent.ToString());
                                    break;
                                }
                        }
                    } // foreach (var row in OrderedRows)

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();

                    //
                    // Display graph
                    //

                    Program.logMessage("    Distribution of PKTMON delay events.");
                    Program.logMessage();
                    g.ProcessData();
                    Program.logMessage("    " + g.GetLine(0));
                    Program.logMessage("    " + g.GetLine(1));
                    Program.logMessage("    " + g.GetLine(2));
                    Program.logMessage("    " + g.GetLine(3));
                    Program.logMessage("    " + g.GetLine(4));
                    Program.logMessage("    " + g.GetLine(5));

                    Program.logMessage();
                } // if (PktmonDropRecords.Count > 0)
                else
                {
                    Program.logMessage($"Pktmon events were found in the trace, but no events took more than {delayWords} to complete.");
                    Program.logMessage();
                }


            } // else
        } // DisplayDelayedPktmonEvents(NetworkTrace Trace)

        private static void DisplayBadConnections(NetworkTrace Trace)  // for non-SQL failures
        {
            long firstTick = 0;
            long lastTick = 0;

            List<BadConnectionData> BadConnectionRecords = new List<BadConnectionData>();

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            // initialize graph object
            TextGraph g = new TextGraph();
            g.startTime = new DateTime(firstTick);
            g.endTime = new DateTime(lastTick);
            g.SetGraphWidth(150);
            g.fAbsoluteScale = true;
            g.SetCutoffValues(1, 3, 9, 27, 81);

            foreach (ConversationData c in Trace.conversations)
            {
                if (c.hasSynFailure && c.isSQL == false)  // SQL failures will show in the Login failures report
                {
                    BadConnectionData td = new BadConnectionData();
                    td.serverIP = (c.isIPV6) ? utility.FormatIPV6Address(c.destIPHi, c.destIPLo) : utility.FormatIPV4Address(c.destIP);
                    td.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                    td.sourcePort = c.sourcePort;
                    td.destPort = c.destPort;
                    td.isIPV6 = c.isIPV6;
                    td.lastFrame = ((FrameData)c.frames[c.frames.Count - 1]).frameNo;
                    td.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                    td.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                    td.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                    td.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                    td.endOffset = td.endTicks - firstTick;
                    td.duration = td.endOffset - td.startOffset;
                    td.frames = c.frames.Count;
                    // td.loginProgress = c.loginFlags;
                    td.loginProgress = c.GetFirstPacketList(20);

                    BadConnectionRecords.Add(td);

                    g.AddData(new DateTime(td.endTicks), 1.0); // for graphing
                }
            }

            if (BadConnectionRecords.Count > 0)
            {
                Program.logMessage("The following conversations failed to connect to the server with a SYN failure or were probe connections:\r\n");
                ReportFormatter rf = new ReportFormatter();

                switch (Program.filterFormat)
                {
                    case "N":
                        {
                            rf.SetColumnNames("NETMON Filter (Server conv.):L", "(Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Packets:L");
                            break;
                        }
                    case "W":
                        {
                            rf.SetColumnNames("WireShark Filter (Server conv.):L", "(Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Packets:L");
                            break;
                        }
                    default:
                        {
                            rf.SetColumnNames("Server Address:L", "Port:R", "Client Address:L", "Port:R", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Packets:L");
                            break;
                        }
                }

                var OrderedRows = from row in BadConnectionRecords orderby row.endOffset ascending select row;

                foreach (var row in OrderedRows)
                {
                    switch (Program.filterFormat)
                    {
                        case "N":  // list client IP and port as a NETMON filter string
                            {
                                rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.serverIP + " and tcp.port==" + row.destPort.ToString(), 
                                                    (row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                    (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                    row.lastFrame.ToString(),
                                                    (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                    row.frames.ToString(),
                                                    (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    row.loginProgress);
                                break;
                            }
                        case "W":  // list client IP and port as a WireShark filter string
                            {
                                rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.serverIP + " and tcp.port==" + row.destPort.ToString(),
                                                    (row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                    (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                    row.lastFrame.ToString(),
                                                    (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                    row.frames.ToString(),
                                                    (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    row.loginProgress);
                                break;
                            }
                        default:  // list client IP and port as separate columns
                            {
                                rf.SetcolumnData(row.serverIP,
                                                    row.destPort.ToString(),
                                                    row.clientIP,
                                                    row.sourcePort.ToString(),
                                                    (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                    row.lastFrame.ToString(),
                                                    (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                    row.frames.ToString(),
                                                    (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                    row.loginProgress);
                                break;
                            }
                    }
                }

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

                Program.logMessage();

                //
                // Display graph
                //

                Program.logMessage("    Distribution of failed/probe connections.");
                Program.logMessage();
                g.ProcessData();
                Program.logMessage("    " + g.GetLine(0));
                Program.logMessage("    " + g.GetLine(1));
                Program.logMessage("    " + g.GetLine(2));
                Program.logMessage("    " + g.GetLine(3));
                Program.logMessage("    " + g.GetLine(4));
                Program.logMessage("    " + g.GetLine(5));

                Program.logMessage();
            }
            else
            {
                Program.logMessage("No SYN failures or probe connections found.");
                Program.logMessage();
            }
        }

        private static void DisplayDelayedLogins(NetworkTrace Trace)
        {
            bool hasDelay = false;
            
            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (SQLServer s in Trace.sqlServers)
            {
                List<LongConnectionData> DelayRecords = new List<LongConnectionData>();

                // initialize graph object
                TextGraph g = new TextGraph();
                g.startTime = new DateTime(firstTick);
                g.endTime = new DateTime(lastTick);
                g.SetGraphWidth(150);
                g.fAbsoluteScale = true;
                g.SetCutoffValues(1, 3, 9, 27, 81);

                string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                foreach (ConversationData c in s.conversations)
                {
                    // check whether the login sequence is visible; if not, skip this connection
                    string loginFlags = c.loginFlags.Trim();
                    bool hasLoginSequence = loginFlags != "AD" && loginFlags != "";  // if blank or only 'AD' then we are past the login phase
                    if (!hasLoginSequence) continue;   // try the next connection

                    // if we have login failures, was the total duration more than 2 seconds
                    long duration = ((FrameData)c.frames[c.frames.Count - 1]).ticks - ((FrameData)c.frames[0]).ticks;
                    if (c.hasLoginFailure && duration < 2 * utility.TICKS_PER_SECOND) continue;

                    // if we are encrypted, was the time up until the Login packet greater than 2 seconds?
                    // the packets after that are all encrypted, so we can't reliably time them
                    if (c.isEncrypted)
                    {
                        if (c.LoginTime != 0 && c.LoginDelay("AD", firstTick) < 2 * utility.TICKS_PER_SECOND) continue;
                    }

                    // check whether we completed the login
                    long cStart = ((FrameData)c.frames[0]).ticks;
                    if (c.LoginAckTime != 0 && c.LoginDelay("LA", firstTick) < 2 * utility.TICKS_PER_SECOND) continue;
                    if (c.ErrorTime != 0 && c.LoginDelay("ER", firstTick) < 2 * utility.TICKS_PER_SECOND) continue;

                    hasDelay = true;

                    LongConnectionData ld = new LongConnectionData();

                    ld.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                    ld.sourcePort = c.sourcePort;
                    ld.isIPV6 = c.isIPV6;
                    ld.frames = c.frames.Count;
                    ld.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                    ld.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                    ld.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                    ld.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                    ld.endOffset = ld.endTicks - firstTick;
                    ld.duration = ld.endOffset - ld.startOffset;
                    ld.rawRetransmits = c.rawRetransmits;
                    ld.keepAliveCount = c.keepAliveCount;
                    ld.ackSynInterval = (int)(c.LoginDelay("AS", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.preLoginInterval = (int)(c.LoginDelay("PL", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.preLoginResponseInterval = (int)(c.LoginDelay("PR", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.clientHelloInterval = (int)(c.LoginDelay("CH", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.serverHelloInterval = (int)(c.LoginDelay("SH", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.keyExchangeInterval = (int)(c.LoginDelay("KE", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.cipherExchangeInterval = (int)(c.LoginDelay("CE", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.loginInterval = (int)(c.LoginDelay("AD", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.sspiInterval = (int)(c.LoginDelay("SS", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.ntlmChallengeInterval = (int)(c.LoginDelay("NC", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.ntlmResponseInterval = (int)(c.LoginDelay("NR", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.loginAckInterval = (int)(c.LoginDelay("LA", firstTick) / utility.TICKS_PER_MILLISECOND);
                    ld.errorInterval = (int)(c.LoginDelay("ER", firstTick) / utility.TICKS_PER_MILLISECOND);

                    g.AddData(new DateTime(c.LastPreloginTime()), 1.0); // for graphing

                    DelayRecords.Add(ld);
                }

                if (DelayRecords.Count > 0)
                {
                    Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " took more than 2 seconds to login or error out:");
                    Program.logMessage("Login progress durations are in milliseconds.\r\n");
                    ReportFormatter rf = new ReportFormatter();
                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "AS:R", "PL:R", "PR:R", "CH:R", "SH:R", "KE:R", "CE:R", "AD:R", "SS:R", "NC:R", "NR:R", "LA:R", "ER:R", "Keep-Alives:R", "Retransmits:R");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "AS:R", "PL:R", "PR:R", "CH:R", "SH:R", "KE:R", "CE:R", "AD:R", "SS:R", "NC:R", "NR:R", "LA:R", "ER:R", "Keep-Alives:R",  "Retransmits:R");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "AS:R", "PL:R", "PR:R", "CH:R", "SH:R", "KE:R", "CE:R", "AD:R", "SS:R", "NC:R", "NR:R", "LA:R", "ER:R", "Keep-Alives:R", "Retransmits:R");
                                break;
                            }
                    }

                    var OrderedRows = from row in DelayRecords orderby row.endOffset ascending select row;

                    foreach (var row in OrderedRows)
                    {
                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                        (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                        (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                        row.frames.ToString(),
                                                        (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        row.ackSynInterval == -1 ? "" : $"{row.ackSynInterval}",
                                                        row.preLoginInterval == -1 ? "" : $"{row.preLoginInterval}",
                                                        row.preLoginResponseInterval == -1 ? "" : $"{row.preLoginResponseInterval}",
                                                        row.clientHelloInterval == -1 ? "" : $"{row.clientHelloInterval}",
                                                        row.serverHelloInterval == -1 ? "" : $"{row.serverHelloInterval}",
                                                        row.keyExchangeInterval == -1 ? "" : $"{row.keyExchangeInterval}",
                                                        row.cipherExchangeInterval == -1 ? "" : $"{row.cipherExchangeInterval}",
                                                        row.loginInterval == -1 ? "" : $"{row.loginInterval}",
                                                        row.sspiInterval == -1 ? "" : $"{row.sspiInterval}",
                                                        row.ntlmChallengeInterval == -1 ? "" : $"{row.ntlmChallengeInterval}",
                                                        row.ntlmResponseInterval == -1 ? "" : $"{row.ntlmResponseInterval}",
                                                        row.loginAckInterval == -1 ? "" : $"{row.loginAckInterval}",
                                                        row.errorInterval == -1 ? "" : $"{row.errorInterval}",
                                                        row.keepAliveCount.ToString(),
                                                        row.rawRetransmits.ToString());
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                        (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                        (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                        row.frames.ToString(),
                                                        (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        row.ackSynInterval == -1 ? "" : $"{row.ackSynInterval}",
                                                        row.preLoginInterval == -1 ? "" : $"{row.preLoginInterval}",
                                                        row.preLoginResponseInterval == -1 ? "" : $"{row.preLoginResponseInterval}",
                                                        row.clientHelloInterval == -1 ? "" : $"{row.clientHelloInterval}",
                                                        row.serverHelloInterval == -1 ? "" : $"{row.serverHelloInterval}",
                                                        row.keyExchangeInterval == -1 ? "" : $"{row.keyExchangeInterval}",
                                                        row.cipherExchangeInterval == -1 ? "" : $"{row.cipherExchangeInterval}",
                                                        row.loginInterval == -1 ? "" : $"{row.loginInterval}",
                                                        row.sspiInterval == -1 ? "" : $"{row.sspiInterval}",
                                                        row.ntlmChallengeInterval == -1 ? "" : $"{row.ntlmChallengeInterval}",
                                                        row.ntlmResponseInterval == -1 ? "" : $"{row.ntlmResponseInterval}",
                                                        row.loginAckInterval == -1 ? "" : $"{row.loginAckInterval}",
                                                        row.errorInterval == -1 ? "" : $"{row.errorInterval}",
                                                        row.keepAliveCount.ToString(),
                                                        row.rawRetransmits.ToString());
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.clientIP,
                                                        row.sourcePort.ToString(),
                                                        (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                        (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                        row.frames.ToString(),
                                                        (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        row.ackSynInterval == -1 ? "" : $"{row.ackSynInterval}",
                                                        row.preLoginInterval == -1 ? "" : $"{row.preLoginInterval}",
                                                        row.preLoginResponseInterval == -1 ? "" : $"{row.preLoginResponseInterval}",
                                                        row.clientHelloInterval == -1 ? "" : $"{row.clientHelloInterval}",
                                                        row.serverHelloInterval == -1 ? "" : $"{row.serverHelloInterval}",
                                                        row.keyExchangeInterval == -1 ? "" : $"{row.keyExchangeInterval}",
                                                        row.cipherExchangeInterval == -1 ? "" : $"{row.cipherExchangeInterval}",
                                                        row.loginInterval == -1 ? "" : $"{row.loginInterval}",
                                                        row.sspiInterval == -1 ? "" : $"{row.sspiInterval}",
                                                        row.ntlmChallengeInterval == -1 ? "" : $"{row.ntlmChallengeInterval}",
                                                        row.ntlmResponseInterval == -1 ? "" : $"{row.ntlmResponseInterval}",
                                                        row.loginAckInterval == -1 ? "" : $"{row.loginAckInterval}",
                                                        row.errorInterval == -1 ? "" : $"{row.errorInterval}",
                                                        row.keepAliveCount.ToString(),
                                                        row.rawRetransmits.ToString());
                                    break;
                                }
                        }
                    }

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();

                    //
                    // Display graph
                    //

                    Program.logMessage("    Distribution of slow connections.");
                    Program.logMessage();
                    g.ProcessData();
                    Program.logMessage("    " + g.GetLine(0));
                    Program.logMessage("    " + g.GetLine(1));
                    Program.logMessage("    " + g.GetLine(2));
                    Program.logMessage("    " + g.GetLine(3));
                    Program.logMessage("    " + g.GetLine(4));
                    Program.logMessage("    " + g.GetLine(5));

                    Program.logMessage();

                }
            }

            if (hasDelay == false)
            {
                Program.logMessage("No logins of over 2 seconds duration were found.");
                Program.logMessage();
            }
        }

        private static void DisplaySucessfulLoginReport(NetworkTrace Trace)
        {
            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            string sqlIP = null;

            foreach (SQLServer s in Trace.sqlServers)
            {
                List<SucessfulLoginData> SucessLogInRecords = new List<SucessfulLoginData>();

                sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);
                foreach (ConversationData c in s.conversations)
                {
                    if (c.hasPostLoginResponse)
                    {
                        SucessfulLoginData sd = new SucessfulLoginData();

                        sd.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                        sd.sourcePort = c.sourcePort;
                        sd.isIPV6 = c.isIPV6;
                        sd.lastFrame = ((FrameData)c.frames[c.frames.Count - 1]).frameNo;
                        sd.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                        sd.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                        sd.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                        sd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                        sd.endOffset = sd.endTicks - firstTick;
                        sd.duration = sd.endOffset - sd.startOffset;
                        sd.frames = c.frames.Count;
                        //sd.firstFrame = ((FrameData)c.frames[0]).frameNo;

                        SucessLogInRecords.Add(sd);

                    }
                }

                Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " connected & executing Queries or Stored Procedures:\r\n");
                ReportFormatter rf = new ReportFormatter();

                switch (Program.filterFormat)
                {
                    case "N":
                        {
                            rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Session Duration:R");
                            break;
                        }
                    case "W":
                        {
                            rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Session Duration:R");
                            break;
                        }
                    default:
                        {
                            rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Session Duration:R");
                            break;
                        }
                }

                var OrderedRows = from row in SucessLogInRecords orderby row.endOffset ascending select row;

                foreach (var row in OrderedRows)
                {
                    switch (Program.filterFormat)
                    {
                        case "N":  // list client IP and port as a NETMON filter string
                            {
                                rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                 (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                 row.lastFrame.ToString(),
                                                 (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                 (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                 new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                 row.frames.ToString(),
                                                 (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"));
                                break;
                            }
                        case "W":  // list client IP and port as a WireShark filter string
                            {
                                rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                 (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                 row.lastFrame.ToString(),
                                                 (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                 (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                 new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                 row.frames.ToString(),
                                                 (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"));
                                break;
                            }
                        default:  // list client IP and port as separate columns
                            {
                                rf.SetcolumnData(row.clientIP,
                                                 row.sourcePort.ToString(),
                                                 (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                 row.lastFrame.ToString(),
                                                 (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                 (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                 new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                 row.frames.ToString(),
                                                 (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"));

                                break;
                            }
                    }
                }

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

                Program.logMessage();
            }
            
        }

        private static void DisplayLoginErrors(NetworkTrace Trace)
        {
            bool hasError = false;
            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (SQLServer s in Trace.sqlServers)
            {
                if (s.hasLoginFailures)
                {
                    hasError = true;
                    List<FailedConnectionData> TimeoutRecords = new List<FailedConnectionData>();

                    // initialize graph object
                    TextGraph g = new TextGraph();
                    g.startTime = new DateTime(firstTick);
                    g.endTime = new DateTime(lastTick);
                    g.SetGraphWidth(150);
                    g.fAbsoluteScale = true;
                    g.SetCutoffValues(1, 3, 9, 27, 81);

                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                    foreach (ConversationData c in s.conversations)
                    {
                        if (c.hasLoginFailure)
                        {
                            FailedConnectionData td = new FailedConnectionData();

                            td.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            td.sourcePort = c.sourcePort;
                            td.isIPV6 = c.isIPV6;
                            td.lastFrame = ((FrameData)c.frames[c.frames.Count - 1]).frameNo;
                            td.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            td.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                            td.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                            td.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                            td.endOffset = td.endTicks - firstTick;
                            td.duration = td.endOffset - td.startOffset;
                            td.frames = c.frames.Count;
                            // td.loginProgress = c.loginFlags;
                            td.loginProgress = c.GetFirstPacketList(20);
                            td.rawRetransmits = c.rawRetransmits;
                            td.keepAliveCount = c.keepAliveCount;
                            td.hasDiffieHellman = c.hasDiffieHellman;
                            td.hasNullNTLMCreds = c.hasNullNTLMCreds;
                            td.LateLoginAck = c.hasLateLoginAck;
                            td.Error = c.Error;
                            td.ErrorState = c.ErrorState;
                            td.ErrorMsg = c.ErrorMsg;

                            TimeoutRecords.Add(td);

                            g.AddData(new DateTime(td.endTicks), 1.0); // for graphing
                        }
                    }

                    Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " timed out or were closed prior to completing the login process or had a login error:\r\n");
                    ReportFormatter rf = new ReportFormatter();

                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Login Progress:L", "Keep-Alives:R", "Retransmits:R", "DHE:R", "NullCreds:R", "LoginAck:L", "Error:L");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Login Progress:L", "Keep-Alives:R", "Retransmits:R", "DHE:R", "NullCreds:R", "LoginAck:L", "Error:L");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Login Progress:L", "Keep-Alives:R", "Retransmits:R", "NullCreds:R", "DHE:R", "LoginAck:L", "Error:L");
                                break;
                            }
                    }

                    var OrderedRows = from row in TimeoutRecords orderby row.endOffset ascending select row;

                    foreach (var row in OrderedRows)
                    {
                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.lastFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.loginProgress,
                                                     row.keepAliveCount.ToString(),
                                                     row.rawRetransmits.ToString(),
                                                     row.hasDiffieHellman ? "Yes" : "",
                                                     row.hasNullNTLMCreds ? "Yes" : "",
                                                     row.LateLoginAck ? "Late" : "",
                                                     row.Error == 0 ? "" : $"Error {row.Error}, State {row.ErrorState}: {row.ErrorMsg}");
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.lastFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.loginProgress,
                                                     row.keepAliveCount.ToString(),
                                                     row.rawRetransmits.ToString(),
                                                     row.hasDiffieHellman ? "Yes" : "",
                                                     row.hasNullNTLMCreds ? "Yes" : "",
                                                     row.LateLoginAck ? "Late" : "",
                                                     row.Error == 0 ? "" : $"Error {row.Error}, State {row.ErrorState}: {row.ErrorMsg}");
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.clientIP,
                                                     row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.lastFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.loginProgress,
                                                     row.keepAliveCount.ToString(),
                                                     row.rawRetransmits.ToString(),
                                                     row.hasDiffieHellman ? "Yes" : "",
                                                     row.hasNullNTLMCreds ? "Yes" : "",
                                                     row.LateLoginAck ? "Late" : "",
                                                     row.Error == 0 ? "" : $"Error {row.Error}, State {row.ErrorState}: {row.ErrorMsg}");
                                    break;
                                }
                        }
                    }

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();

                    //
                    // Display graph
                    //

                    Program.logMessage("    Distribution of timed-out/failed connections.");
                    Program.logMessage();
                    g.ProcessData();
                    Program.logMessage("    " + g.GetLine(0));
                    Program.logMessage("    " + g.GetLine(1));
                    Program.logMessage("    " + g.GetLine(2));
                    Program.logMessage("    " + g.GetLine(3));
                    Program.logMessage("    " + g.GetLine(4));
                    Program.logMessage("    " + g.GetLine(5));

                    Program.logMessage();
                }
            }

            if (hasError == false)
            {
                Program.logMessage("No login timeouts were found.");
                Program.logMessage();
            }
        }

        private static void DisplayDomainControllerLoginErrors(NetworkTrace Trace)
        {
            bool hasError = false;
            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (DomainController d in Trace.DomainControllers)
            {
                d.hasLoginFailures = false;

                List<FailedConnectionData> TimeoutRecords = new List<FailedConnectionData>();

                // initialize graph object
                TextGraph g = new TextGraph();
                g.startTime = new DateTime(firstTick);
                g.endTime = new DateTime(lastTick);
                g.SetGraphWidth(150);
                g.fAbsoluteScale = true;
                g.SetCutoffValues(1, 3, 9, 27, 81);

                string dcIP = (d.isIPV6) ? utility.FormatIPV6Address(d.IPHi, d.IPLo) : utility.FormatIPV4Address(d.IP);

                foreach (ConversationData c in d.conversations)
                {
                    if (c.isUDP == false)  // only check TCP conversations
                    {
                        bool hasLoginFailure = false;
                        // failure = all frames are SYN packets and no ACK+SYN 
                        if (c.synCount == c.frames.Count && c.ackCount == 0) hasLoginFailure = true;
                        // push flags, fin flags indicate success
                        //if (c.pushCount > 0 || c.finCount > 0) hasLoginFailures = false;

                        if (hasLoginFailure)
                        {
                            d.hasLoginFailures = true;
                            hasError = true;

                            FailedConnectionData td = new FailedConnectionData();

                            td.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            td.sourcePort = c.sourcePort;
                            td.destPort = c.destPort;
                            td.isIPV6 = c.isIPV6;
                            td.lastFrame = ((FrameData)c.frames[c.frames.Count - 1]).frameNo;
                            td.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            td.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                            td.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                            td.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                            td.endOffset = td.endTicks - firstTick;
                            td.duration = td.endOffset - td.startOffset;
                            td.frames = c.frames.Count;
                            td.loginProgress = c.GetFirstPacketList(20);

                            TimeoutRecords.Add(td);

                            g.AddData(new DateTime(td.endTicks), 1.0); // for graphing
                        }
                    }
                }

                if (d.hasLoginFailures)
                {

                    Program.logMessage("The following conversations with Domain Controller " + ((d.isIPV6) ? utility.FormatIPV6Address(d.IPHi, d.IPLo) : utility.FormatIPV4Address(d.IP)) + " failed to connect:\r\n");
                    ReportFormatter rf = new ReportFormatter();

                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("DC port:R", "NETMON Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Packets:L");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("DC port:R", "WireShark Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Packets:L");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("DC port:R", "Client Address:L", "Port:R", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Packets:L");
                                break;
                            }
                    }

                    var OrderedRows = from row in TimeoutRecords orderby row.endOffset ascending select row;

                    foreach (var row in OrderedRows)
                    {
                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData(row.destPort.ToString(),
                                                     (row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.lastFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.loginProgress);
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData(row.destPort.ToString(),
                                                     (row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.lastFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.loginProgress);
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.destPort.ToString(), 
                                                     row.clientIP,
                                                     row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.lastFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.loginProgress);
                                    break;
                                }
                        }
                    }

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();

                    //
                    // Display graph
                    //

                    Program.logMessage("    Distribution of failed Domain Controller connections.");
                    Program.logMessage();
                    g.ProcessData();
                    Program.logMessage("    " + g.GetLine(0));
                    Program.logMessage("    " + g.GetLine(1));
                    Program.logMessage("    " + g.GetLine(2));
                    Program.logMessage("    " + g.GetLine(3));
                    Program.logMessage("    " + g.GetLine(4));
                    Program.logMessage("    " + g.GetLine(5));

                    Program.logMessage();
                }
            }

            if (hasError == false)
            {
                Program.logMessage("No Domain Controller connection failures were found.");
                Program.logMessage();
            }
        }

        private static void DisplayAttentions(NetworkTrace Trace)
        {
            bool hasError = false;

            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (SQLServer s in Trace.sqlServers)
            {
                if (s.hasAttentions)
                {
                    hasError = true;
                    List<AttentionConnectionData> AttentionRecords = new List<AttentionConnectionData>();

                    // initialize graph object
                    TextGraph g = new TextGraph();
                    g.startTime = new DateTime(firstTick);
                    g.endTime = new DateTime(lastTick);
                    g.SetGraphWidth(150);
                    g.fAbsoluteScale = true;
                    g.SetCutoffValues(1, 3, 9, 27, 81);

                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                    foreach (ConversationData c in s.conversations)
                    {
                        if (c.AttentionTime > 0)
                        {
                            AttentionConnectionData rd = new AttentionConnectionData();

                            rd.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            rd.sourcePort = c.sourcePort;
                            rd.isIPV6 = c.isIPV6;
                            rd.frames = c.frames.Count;
                            rd.AttentionFrame = 0;
                            rd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;

                            //for (int i = c.frames.Count - 1; i >= 0; i--)
                            foreach (FrameData f in c.frames)   // search from beginning for first reset, not from end for last reset
                            {
                                //FrameData f = (FrameData)c.frames[i];
                                if (f.payloadLength > 0 && f.payload[0] == (int)TDSPacketType.ATTENTION)
                                {
                                    rd.AttentionFrame = f.frameNo;
                                    rd.AttentionFile = Trace.files.IndexOf(f.file);
                                    rd.AttentionTicks = f.ticks;
                                    rd.AttentionOffset = f.ticks - firstTick;
                                    g.AddData(new DateTime(f.ticks), 1.0); // for graphing
                                    break;
                                }
                            }

                            AttentionRecords.Add(rd);
                        }
                    }

                    Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " had a command timeout or Attention packet:\r\n");
                    ReportFormatter rf = new ReportFormatter();

                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Attn Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Attn Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Attn Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R");
                                break;
                            }
                    }

                    var OrderedRows = from row in AttentionRecords orderby row.AttentionOffset ascending select row;

                    foreach (var row in OrderedRows)
                    {
                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     row.AttentionFile.ToString(),
                                                     row.AttentionFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.AttentionOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.AttentionTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString());
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     row.AttentionFile.ToString(),
                                                     row.AttentionFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.AttentionOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.AttentionTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString());
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.clientIP,
                                                     row.sourcePort.ToString(),
                                                     row.AttentionFile.ToString(),
                                                     row.AttentionFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.AttentionOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.AttentionTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString());
                                    break;
                                }
                        }
                    }

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();

                    //
                    // Display graph
                    //

                    Program.logMessage("    Distribution of command timeouts/Attention packets.");
                    Program.logMessage();
                    g.ProcessData();
                    Program.logMessage("    " + g.GetLine(0));
                    Program.logMessage("    " + g.GetLine(1));
                    Program.logMessage("    " + g.GetLine(2));
                    Program.logMessage("    " + g.GetLine(3));
                    Program.logMessage("    " + g.GetLine(4));
                    Program.logMessage("    " + g.GetLine(5));

                    Program.logMessage();

                }
            }

            if (hasError == false)
            {
                Program.logMessage("No Attention packets were found.");
                Program.logMessage();
            }
        }


        private static void DisplayTLSIssues(NetworkTrace Trace)
        {
            bool hasError = false;

            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (SQLServer s in Trace.sqlServers)
            {
                if (s.hasLowTLSVersion)
                {
                    hasError = true;
                    List<LowTLSData> LowTLSRecords = new List<LowTLSData>();

                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                    foreach (ConversationData c in s.conversations)
                    {
                        if ((c.hasLogin7 && !c.hasClientSSL & !c.hasServerSSL) || c.hasLowTLSVersion)
                        {
                            LowTLSData rd = new LowTLSData();

                            rd.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            rd.sourcePort = c.sourcePort;
                            rd.isIPV6 = c.isIPV6;
                            rd.frames = c.frames.Count;
                            rd.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            rd.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                            rd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                            rd.hasLogin = c.hasApplicationData;
                            rd.hasLogin7 = c.hasLogin7;
                            rd.hasClientHello = c.hasClientSSL;
                            rd.ClientTLSVersion = c.tlsVersionClient;
                            rd.hasServerHello = c.hasServerSSL;
                            rd.ServerTLSVersion = c.tlsVersionServer;

                            LowTLSRecords.Add(rd);
                        }
                    }

                    Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " are not using TLS 1.2:\r\n");
                    ReportFormatter rf = new ReportFormatter();

                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Start Offset:R", "Frames:R", "Client TLS:L", "Server TLS:L", "Login Packet:L", "Login7 Packet:L");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Start Offset:R", "Frames:R", "Client TLS:L", "Server TLS:L", "Login Packet:L", "Login7 Packet:L");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Start Offset:R", "Frames:R", "Client TLS:L", "Server TLS:L", "Login Packet:L", "Login7 Packet:L");
                                break;
                            }
                    }

                    var OrderedRows = from row in LowTLSRecords orderby row.startOffset ascending select row;

                    foreach (var row in OrderedRows)
                    {
                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.frames.ToString(),
                                                     row.ClientTLSVersion,
                                                     row.ServerTLSVersion,
                                                     row.hasLogin.ToString(),
                                                     row.hasLogin7.ToString());

                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.frames.ToString(),
                                                   //  (row.hasClientHello) ? row.ClientTLSVersion : "None",
                                                   //  (row.hasServerHello) ? row.ServerTLSVersion : "None",
                                                     row.ClientTLSVersion,
                                                     row.ServerTLSVersion,
                                                     row.hasLogin.ToString(),
                                                     row.hasLogin7.ToString());
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.clientIP,
                                                     row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     row.frames.ToString(),
                                                     row.ClientTLSVersion,
                                                     row.ServerTLSVersion,
                                                     row.hasLogin.ToString(),
                                                     row.hasLogin7.ToString());
                                    break;
                                }
                        }
                    }

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();
                }
            }

            if (hasError == false)
            {
                Program.logMessage("All conversations were using TLS 1.2.");
                Program.logMessage();
            }
        }

        private static void DisplayNamedPipesReport(NetworkTrace Trace)
        {
            List<NamedPipeRecord> PipeRecords = new List<NamedPipeRecord>();

            long firstTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
            }

            foreach (ConversationData c in Trace.conversations)
            {
                if (c.PipeNames.Count > 0)
                {
                    // fix up the pipe prefix if captured
                    string adminName = c.PipeAdminName;
                    if (adminName == "")
                    {
                        adminName = @"\\unknown";
                    }
                    else
                    {
                        adminName = adminName.Replace("IPC$", "pipe");
                    }
                    foreach (PipeNameData pipeInfo in c.PipeNames)
                    {
                        NamedPipeRecord np = new NamedPipeRecord();
                        np.File = Trace.files.IndexOf(pipeInfo.frame.file);
                        np.FrameNumber = pipeInfo.frame.frameNo;
                        np.IsIPV6 = c.isIPV6;
                        np.TimeOffset = pipeInfo.frame.ticks - firstTick;
                        np.ticks = pipeInfo.frame.ticks;
                        if (c.destPort == 445)
                        {
                            np.ClientIPAddress = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            np.ClientPort = c.sourcePort;
                            np.ServerIPAddress = (c.isIPV6) ? utility.FormatIPV6Address(c.destIPHi, c.destIPLo) : utility.FormatIPV4Address(c.destIP);
                        }
                        else  // IP address and port #s need to be swapped from dest to source and vice versa
                        {
                            np.ClientIPAddress = (c.isIPV6) ? utility.FormatIPV6Address(c.destIPHi, c.destIPLo) : utility.FormatIPV4Address(c.destIP);
                            np.ClientPort = c.destPort;
                            np.ServerIPAddress = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                        }
                        np.PipeName = adminName + @"\" + pipeInfo.PipeName;
                        PipeRecords.Add(np);
                    }
                }
            }

            ReportFormatter rf = new ReportFormatter();

            // "Client Address:L", "Port:R", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Login Progress:L", "Keep-Alives:R", "Retransmits:R", "NullCreds:R", "DHE:R", "LoginAck:L", "Error:L");
            switch (Program.filterFormat)
            {
                case "N":
                    {
                        rf.SetColumnNames("Server Address:L", "Pipe Name:L", "NETMON Filter (Client conv.):L", "File:R", "Frame:R", "Offset:R", "Time:R");
                        break;
                    }
                case "W":
                    {
                        rf.SetColumnNames("Server Address:L", "Pipe Name:L", "WireShark Filter (Client conv.):L", "File:R", "Frame:R", "Offset:R", "Time:R");
                        break;
                    }
                default:
                    {
                        rf.SetColumnNames("Server Address:L", "Pipe Name:L", "Client Address:L", "Port:R", "File:R", "Frame:R", "Offset:R", "Time:R");
                        break;
                    }
            }

            var OrderedRows = from row in PipeRecords orderby row.ServerIPAddress, row.PipeName, row.TimeOffset ascending select row;

            foreach (var row in OrderedRows)
            {
                switch (Program.filterFormat)
                {
                    case "N":  // list client IP and port as a NETMON filter string
                        {
                            rf.SetcolumnData(row.ServerIPAddress,
                                             row.PipeName,
                                             (row.IsIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.ClientIPAddress + " and tcp.port==" + row.ClientPort.ToString(),
                                             row.File.ToString(),
                                             row.FrameNumber.ToString(),
                                             (row.TimeOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                             new DateTime(row.ticks).ToString(utility.TIME_FORMAT));
                            break;
                        }
                    case "W":  // list client IP and port as a WireShark filter string
                        {
                            rf.SetcolumnData(row.ServerIPAddress,
                                             row.PipeName,
                                             (row.IsIPV6 ? "ipv6" : "ip") + ".addr==" + row.ClientIPAddress + " and tcp.port==" + row.ClientPort.ToString(),
                                             row.File.ToString(),
                                             row.FrameNumber.ToString(),
                                             (row.TimeOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                             new DateTime(row.ticks).ToString(utility.TIME_FORMAT));
                            break;
                        }
                    default:  // list client IP and port as separate columns
                        {
                            rf.SetcolumnData(row.ServerIPAddress,
                                             row.PipeName,
                                             row.ClientIPAddress,
                                             row.ClientPort.ToString(),
                                             row.File.ToString(),
                                             row.FrameNumber.ToString(),
                                             (row.TimeOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                             new DateTime(row.ticks).ToString(utility.TIME_FORMAT));
                            break;
                        }
                }
            }

            if (PipeRecords.Count != 0)
            {
                Program.logMessage("The following Named Pipes conversations were detected in the network trace:\r\n");
                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

                Program.logMessage();
            }
            else
            {
                Program.logMessage("No Named Pipes conversations found.");
                Program.logMessage();
            }
        }

        private static void DisplaySSRPReport(NetworkTrace Trace)
        {
            long firstTick = 0;
            if (Trace.frames != null && Trace.frames.Count > 0) firstTick = ((FrameData)Trace.frames[0]).ticks;

            if (Trace.SSRPRequests.Count == 0)
            {
                Program.logMessage("No SSRP traffic was found in the network trace.");
                Program.logMessage();
            }

            foreach (SSRPData SSRPRequest in Trace.SSRPRequests)
            {
                string sqlIP = (SSRPRequest.isIPV6) ? utility.FormatIPV6Address(SSRPRequest.sqlIPHi, SSRPRequest.sqlIPLo) : utility.FormatIPV4Address(SSRPRequest.sqlIP);

                if (SSRPRequest.hasResponse == true && SSRPRequest.hasNoResponse == false)
                {
                    Program.logMessage("The SQL Browser for SQL Servers at IP Address " + sqlIP + " appears to be working. All requests were responded to.\r\n");
                }
                else if (SSRPRequest.hasResponse == false && SSRPRequest.hasNoResponse == true)
                {
                    Program.logMessage("The SQL Browser for SQL Servers at IP Address " + sqlIP + " appears to be turned off or blocked by firewall. No requests were responded to.\r\n");
                }
                else // some succeed and some fail
                {
                    Program.logMessage("The SQL Browser for SQL Servers at IP Address " + sqlIP + " appears to be working intermittently. Only some requests were responded to.\r\n");

                    if (SSRPRequest.hasResponse)
                    {
                        ReportFormatter rf = new ReportFormatter();

                        //string sqlIP = (SSRPRequest.isIPV6) ? utility.FormatIPV6Address(SSRPRequest.sqlIPHi, SSRPRequest.sqlIPLo) : utility.FormatIPV4Address(SSRPRequest.sqlIP);
                        Program.logMessage("The following SQL Browser requests were responded to:\r\n");

                        switch (Program.filterFormat)
                        {
                            case "N":
                                {
                                    rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "End Offset:R", "Instance:L");
                                    break;
                                }
                            case "W":
                                {
                                    rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "End Offset:R", "Instance:L");
                                    break;
                                }
                            default:
                                {
                                    rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "End Offset:R", "Instance:L");
                                    break;
                                }
                        }

                        foreach (ConversationData c in SSRPRequest.conversations)
                        {

                            FrameData f = (FrameData)c.frames[c.frames.Count - 1];

                            if (f.payload[0] != 5) continue;

                            ushort Length = utility.ReadUInt16(f.payload, 1);
                            String UDPResponse = utility.ReadAnsiString(f.payload, 3, Length);
                            SSRPParser.ParseSSRPResponse(UDPResponse, SSRPRequest, Trace);

                            long startOffset = ((FrameData)(c.frames[0])).ticks - firstTick;
                            long endOffset = f.ticks - firstTick;
                            long endTicks = f.ticks;

                            int firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            int lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);

                            switch (Program.filterFormat)
                            {
                                case "N":  // list client IP and port as a NETMON filter string
                                    {
                                        rf.SetcolumnData((c.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + (c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP)) + " AND udp.port==" + c.sourcePort.ToString(),
                                                         firstFile == lastFile ? firstFile.ToString() : firstFile + "-" + lastFile,
                                                         f.frameNo.ToString(),
                                                         new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                         (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         SSRPRequest.instanceName);
                                        break;
                                    }
                                case "W":  // list client IP and port as a WireShark filter string
                                    {
                                        rf.SetcolumnData((c.isIPV6 ? "ipv6" : "ip") + ".addr==" + (c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP)) + " and udp.port==" + c.sourcePort.ToString(),
                                                         firstFile == lastFile ? firstFile.ToString() : firstFile + "-" + lastFile,
                                                         f.frameNo.ToString(),
                                                         new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                         (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         SSRPRequest.instanceName);
                                        break;
                                    }
                                default:  // list client IP and port as separate columns
                                    {
                                        rf.SetcolumnData(c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP),
                                                         c.sourcePort.ToString(),
                                                         firstFile == lastFile ? firstFile.ToString() : firstFile + "-" + lastFile,
                                                         f.frameNo.ToString(),
                                                         new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                         (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         (endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         SSRPRequest.instanceName);
                                        break;
                                    }
                            }
                        }

                        Program.logMessage(rf.GetHeaderText());
                        Program.logMessage(rf.GetSeparatorText());

                        for (int i = 0; i < rf.GetRowCount(); i++)
                        {
                            Program.logMessage(rf.GetDataText(i));
                        }

                        Program.logMessage();

                    }

                    if (SSRPRequest.hasNoResponse)
                    {
                        ReportFormatter rf = new ReportFormatter();
                        //string sqlIP = (SSRPRequest.isIPV6) ? utility.FormatIPV6Address(SSRPRequest.sqlIPHi, SSRPRequest.sqlIPLo) : utility.FormatIPV4Address(SSRPRequest.sqlIP);
                        Program.logMessage("The following SQL Browser requests were not responded to:\r\n");

                        switch (Program.filterFormat)
                        {
                            case "N":
                                {
                                    rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "Requested Instance:L");
                                    break;
                                }
                            case "W":
                                {
                                    rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "Requested Instance:L");
                                    break;
                                }
                            default:
                                {
                                    rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "Requested Instance:L");
                                    break;
                                }
                        }

                        foreach (ConversationData c in SSRPRequest.conversations)
                        {
                            if (c.frames.Count != 1) continue;

                            FrameData f = (FrameData)c.frames[0];

                            if (f.payload[0] != 4) continue;

                            ushort Length = utility.ReadUInt16(f.payload, 1);
                            String requestedInstance = SSRPRequest.instanceRequested = utility.ReadAnsiString(f.payload, 3, Length);
                            SSRPRequest.instanceRequested = utility.ReadAnsiString(f.payload, 1, (f.payloadLength - 2));

                            long startOffset = f.ticks - firstTick;
                            long endTicks = f.ticks;

                            int firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);

                            switch (Program.filterFormat)
                            {
                                case "N":  // list client IP and port as a NETMON filter string
                                    {
                                        rf.SetcolumnData((c.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + (c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP)) + " AND udp.port==" + c.sourcePort.ToString(),
                                                         firstFile.ToString(),
                                                         f.frameNo.ToString(),
                                                         new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                         (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         SSRPRequest.instanceRequested);
                                        break;
                                    }
                                case "W":  // list client IP and port as a WireShark filter string
                                    {
                                        rf.SetcolumnData((c.isIPV6 ? "ipv6" : "ip") + ".addr==" + (c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP)) + " and udp.port==" + c.sourcePort.ToString(),
                                                         firstFile.ToString(),
                                                         f.frameNo.ToString(),
                                                         new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                         (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         SSRPRequest.instanceRequested);
                                        break;
                                    }
                                default:  // list client IP and port as separate columns
                                    {
                                        rf.SetcolumnData(c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP),
                                                         c.sourcePort.ToString(),
                                                         firstFile.ToString(),
                                                         f.frameNo.ToString(),
                                                         new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                         (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                         SSRPRequest.instanceRequested);
                                        break;
                                    }
                            }
                        }

                        Program.logMessage(rf.GetHeaderText());
                        Program.logMessage(rf.GetSeparatorText());

                        for (int i = 0; i < rf.GetRowCount(); i++)
                        {
                            Program.logMessage(rf.GetDataText(i));
                        }

                        Program.logMessage();

                    }
                }

                if (SSRPRequest.hasSlowResponse)
                {

                    ReportFormatter rf = new ReportFormatter();

                    Program.logMessage("The following SQL Browser requests may have timed out. Time delta >= 1 second; cutoff = 990ms:\r\n");

                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "End Offset:R", "Delay (ms):R", "Instance:L");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "End Offset:R", "Delay (ms):R", "Instance:L");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Frame:R", "DateTime:L", "Start Offset:R", "End Offset:R", "Delay (ms):R", "Instance:L");
                                break;
                            }
                    }

                    foreach (ConversationData c in SSRPRequest.conversations)
                    {

                        FrameData f = (FrameData)c.frames[c.frames.Count - 1];

                        if (f.payload[0] != 5) continue;

                        ushort Length = utility.ReadUInt16(f.payload, 1);
                        String UDPResponse = utility.ReadAnsiString(f.payload, 3, Length);
                        SSRPParser.ParseSSRPResponse(UDPResponse, SSRPRequest, Trace);

                        long startTicks = ((FrameData)(c.frames[0])).ticks;
                        long startOffset = startTicks - firstTick;
                        long endOffset = f.ticks - firstTick;
                        long endTicks = f.ticks;
                        long deltaTicks = endTicks - startTicks;
                        int deltaMS = (int)(deltaTicks / utility.TICKS_PER_MILLISECOND);

                        if (deltaMS < 990) continue;

                        int firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                        int lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);

                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData((c.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + (c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP)) + " AND udp.port==" + c.sourcePort.ToString(),
                                                     firstFile == lastFile ? firstFile.ToString() : firstFile + "-" + lastFile,
                                                     f.frameNo.ToString(),
                                                     new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                     (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     deltaMS.ToString(),
                                                     SSRPRequest.instanceName);
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData((c.isIPV6 ? "ipv6" : "ip") + ".addr==" + (c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP)) + " and udp.port==" + c.sourcePort.ToString(),
                                                     firstFile == lastFile ? firstFile.ToString() : firstFile + "-" + lastFile,
                                                     f.frameNo.ToString(),
                                                     new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                     (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     deltaMS.ToString(),
                                                     SSRPRequest.instanceName);
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(c.isIPV6 ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP),
                                                     c.sourcePort.ToString(),
                                                     firstFile == lastFile ? firstFile.ToString() : firstFile + "-" + lastFile,
                                                     f.frameNo.ToString(),
                                                     new DateTime(endTicks).ToString(utility.DATE_FORMAT),
                                                     (startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     deltaMS.ToString(),
                                                     SSRPRequest.instanceName);
                                    break;
                                }
                        }
                    }

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();
                }
            }
        }   

        private static void DisplayDNSResponsesReport(NetworkTrace Trace)
        {
            if (Trace.DNSRequestCount == 0)
            {
                Program.logMessage("No DNS traffic was found in the network trace.");
                Program.logMessage();
                return;
            }

            if (Trace.DNSResponses.Count == 0)
            {
                Program.logMessage("All " + Trace.DNSRequestCount + " DNS requests in the network trace were successful.");
                Program.logMessage();
            }
            else
            {
                Program.logMessage("The problematic DNS responses are:\r\n");

                ReportFormatter rf = new ReportFormatter();
                rf.SetColumnNames("Client Address:L",
                                  "Requested Name:L",
                                  "Error Message:L",
                                  "DateTime:L",
                                  "File#:R",
                                  "Frame#:R",
                                  "Client Port:R");

                foreach (DNS DNSResponse in Trace.DNSResponses)
                {
                    int firstFile = Trace.files.IndexOf(((FrameData)(DNSResponse.convData.frames[0])).file);

                    rf.SetcolumnData(DNSResponse.convData.isIPV6 ? utility.FormatIPV6Address(DNSResponse.convData.sourceIPHi, DNSResponse.convData.sourceIPLo) : utility.FormatIPV4Address(DNSResponse.convData.sourceIP),
                                     DNSResponse.nameReqested,
                                     DNSResponse.ErrorDesc,
                                     DNSResponse.TimeStamp,
                                     firstFile.ToString(),
                                     DNSResponse.frameNo.ToString(),
                                     DNSResponse.convData.sourcePort.ToString());



                }

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

                Program.logMessage();
            }

            if (Trace.DNSDelayedResponses.Count == 0)
            {
                Program.logMessage("All DNS requests completed in less than 2 seconds.");
                Program.logMessage();
            }
            else
            {
                Program.logMessage("The following DNS requests received a slow delay (2000ms or longer):\r\n");

                ReportFormatter rf = new ReportFormatter();
                rf.SetColumnNames("Client Address:L",
                                  "Requested Name:L",
                                  "Error Message:L",
                                  "DateTime:L",
                                  "Delay (ms):R",
                                  "File#:R",
                                  "Frame#:R",
                                  "Client Port:R");

                foreach (DNS DNSResponse in Trace.DNSResponses)
                {
                    int firstFile = Trace.files.IndexOf(((FrameData)(DNSResponse.convData.frames[0])).file);

                    rf.SetcolumnData(DNSResponse.convData.isIPV6 ? utility.FormatIPV6Address(DNSResponse.convData.sourceIPHi, DNSResponse.convData.sourceIPLo) : utility.FormatIPV4Address(DNSResponse.convData.sourceIP),
                                     DNSResponse.nameReqested,
                                     DNSResponse.ErrorDesc,
                                     DNSResponse.TimeStamp,
                                     DNSResponse.deltaMS.ToString(),
                                     firstFile.ToString(),
                                     DNSResponse.frameNo.ToString(),
                                     DNSResponse.convData.sourcePort.ToString());
                }

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }

                Program.logMessage();
            }
        }

        private static void DisplayKerberosResponseReport(NetworkTrace Trace)
        {

            if (Trace.KerbResponses.Count == 0)
            {
                Program.logMessage("No Kerberos TGS SPN traffic was found in the network trace.");
                Program.logMessage();
                return;
            }

            int RequestsWithNoResponse = 0;
            int ErrorResponses = 0;

            ReportFormatter rf = new ReportFormatter();
            rf.SetColumnNames("Client Address:L", "Port:R", "KDC Address:L", "File:R", "Frame:R", "Time:R", "SName Requested:L", "Wants Delegation:R", "Error Message:L");

            foreach (KerberosData KerbResponse in Trace.KerbResponses)
            {

                if (KerbResponse.ResponseType == MessageTypes.KRB_NONE) RequestsWithNoResponse++;
                
                if (KerbResponse.ResponseType == MessageTypes.KRB_ERROR)
                {
                    ErrorResponses++;

                    int firstFile = Trace.files.IndexOf(((FrameData)(KerbResponse.convData.frames[0])).file);

                    rf.SetcolumnData(KerbResponse.convData.isIPV6 ? utility.FormatIPV6Address(KerbResponse.convData.sourceIPHi, KerbResponse.convData.sourceIPLo) : utility.FormatIPV4Address(KerbResponse.convData.sourceIP),
                                     KerbResponse.convData.sourcePort.ToString(),
                                     KerbResponse.convData.isIPV6 ? utility.FormatIPV6Address(KerbResponse.convData.destIPHi, KerbResponse.convData.destIPLo) : utility.FormatIPV4Address(KerbResponse.convData.destIP),
                                     firstFile.ToString(),
                                     KerbResponse.frameNo.ToString(),
                                     KerbResponse.TimeStamp,
                                     KerbResponse.SPNRequested,
                                     (KerbResponse.IsForwardable ? "Yes" : "No"),
                                     KerbResponse.ErrorDesc);
                }
            }

            if (RequestsWithNoResponse > 0)
            {
                Program.logMessage("There were " + RequestsWithNoResponse + " Kerberos TGS requests that were not responded to. They may have happened after the trace ended.");
                Program.logMessage();
            }

            if (ErrorResponses == 0)
            {
                Program.logMessage("There were no Kerberos TGS requests that resulted in an error response.");
            }
            else
            {
                Program.logMessage("Kerberos TGS SPN traffic that resulted in an error response:\r\n");

                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                }
            }

            Program.logMessage();
        }

        private static void DisplayClientPortUsage(NetworkTrace Trace)
        {
            //
            // find all IP addresses that have connected to a SQL Server - we'll ignore those that do not connect
            //

            ArrayList IPAddresses = new ArrayList();
            ArrayList UniqueIPAddresses = new ArrayList();

            foreach (SQLServer s in Trace.sqlServers)
            {
                foreach (ConversationData c in s.conversations)
                {
                    IPRecord addr = new IPRecord();
                    addr.IP = c.sourceIP;
                    addr.IPHi = c.sourceIPHi;
                    addr.IPLo = c.sourceIPLo;
                    IPAddresses.Add(addr);
                }
            }

            var q = (from IPRecord addr in IPAddresses select new { addr.IP, addr.IPHi, addr.IPLo }).Distinct();

            foreach (var rec in q)  // validated that even though IPRecord is a class, it returns distinct based on field values and not IP address
            {
                IPRecord addr = new IPRecord();
                addr.IP = rec.IP;
                addr.IPHi = rec.IPHi;
                addr.IPLo = rec.IPLo;
                UniqueIPAddresses.Add(addr);
                // Program.logMessage(utility.FormatIPV4Address(addr.IP) + "     " + utility.FormatIPV6Address(addr.IPHi,addr.IPLo));
            }

            IPAddresses = null;

            //
            // Compile running statistics for each unique IP address
            //

            foreach (IPRecord rec in UniqueIPAddresses)
            {
                ConversationData Tail = null;
                int TailIndex = 0;
                int ConnectionsPerMinute = 0;

                foreach (ConversationData c in Trace.conversations) // these will be in ascending order based on parsing algorithm
                {
                    if (rec.isMatch(c))
                    {
                        if (c.sourcePort < rec.LowPort) rec.LowPort = c.sourcePort;   // set for existing or new connections
                        if (c.sourcePort > rec.HighPort) rec.HighPort = c.sourcePort; // set for existing or new connections

                        if (c.synCount > 0)
                        {
                            if (rec.isSource(c))
                            {
                                rec.NewConnections++;
                                if (c.isSQL) rec.NewSQLConnections++;
                                ConnectionsPerMinute++;
                                if (ConnectionsPerMinute > rec.PeakConnectionsPerMinute) rec.PeakConnectionsPerMinute = ConnectionsPerMinute;

                                //
                                // bring up the tail end and decrement ConnectionsPerMinute if we find old ones.
                                //

                                Tail = (ConversationData)(Trace.conversations[TailIndex]);

                                while (true)
                                {
                                    if (rec.isSource(Tail))
                                    {
                                        if ((c.startTick - Tail.startTick) > (60 * utility.TICKS_PER_SECOND))
                                        {
                                            if (Tail.synCount > 0) ConnectionsPerMinute--;
                                        }
                                        else break;
                                    }
                                    TailIndex++;
                                    Tail = (ConversationData)(Trace.conversations[TailIndex]);
                                }
                            }
                        } // if c.syncount
                        else
                        {
                            rec.ExistingConnections++;
                            if (c.isSQL) rec.ExistingSQLConnections++;
                        }
                    }
                } // if ismatch
            }

            //
            // Get top 10 that where the peak connections / minute is > 1000
            //

            var q2 = (from IPRecord rec in UniqueIPAddresses orderby rec.PeakConnectionsPerMinute descending select rec).Take(10);

            ReportFormatter rf = new ReportFormatter();
            rf.SetColumnNames("Client IP Address:L", "Existing Conn:R", "New Conn:R", "Existing SQL Conn:R", "New SQL Conn:R", "Low Port:R", "High Port:R", "Peak Connections/min:R");

            int TopPeakValue = 0;

            foreach (IPRecord rec in q2)
            {
                rf.SetcolumnData(rec.IP == 0 ? utility.FormatIPV6Address(rec.IPHi, rec.IPLo) : utility.FormatIPV4Address(rec.IP),
                                 rec.ExistingConnections.ToString(),
                                 rec.NewConnections.ToString(),
                                 rec.ExistingSQLConnections.ToString(),
                                 rec.NewSQLConnections.ToString(),
                                 rec.LowPort.ToString(),
                                 rec.HighPort.ToString(),
                                 rec.PeakConnectionsPerMinute.ToString());

                // relies on sort order of "var q2" query being descending; gets value of first record, which should be the busiest
                if (TopPeakValue == 0) TopPeakValue = rec.PeakConnectionsPerMinute;
            }

            if (TopPeakValue < 1000)
            {
                Program.logMessage("No clients appear to be running out of ephemeral ports.");
            }
            else
            { 
                Program.logMessage("High Ephemeral Port Usage (Top 10)");
                Program.logMessage();
                Program.logMessage(rf.GetHeaderText());
                Program.logMessage(rf.GetSeparatorText());

                for (int i = 0; i < rf.GetRowCount(); i++)
                {
                    Program.logMessage(rf.GetDataText(i));
                } 
            }

            Program.logMessage();
        }

        private static void DisplayMTUReport(NetworkTrace Trace)
        {
            ArrayList MTUSizes = new ArrayList();
            int maxPayloadSize = 0;

            // gather unique max payload sizes
            foreach (ConversationData c in Trace.conversations)
            {
                if (c.maxPayloadSize > maxPayloadSize) maxPayloadSize = c.maxPayloadSize;
                if (c.maxPayloadLimit && MTUSizes.IndexOf(c.maxPayloadSize) < 0) MTUSizes.Add(c.maxPayloadSize);
            }

            Program.logMessage($"The maximum payload size observed was {maxPayloadSize}.");

            // how many did we find?
            if (MTUSizes.Count == 1)
            {
                Program.logMessage($"The MTU maximum payload size observed was {(int)MTUSizes[0]}.");
            }
            else if (MTUSizes.Count > 0)
            {
                string rowList = "";
                var OrderedRows = from row in MTUSizes.ToArray() orderby (int)row ascending select row;
                foreach (var row in OrderedRows) rowList += ", " + row.ToString();
                rowList = rowList.Substring(2);  // get rid of leading ", "
                Program.logMessage($"Multiple MTU maximum payload sizes were observed: {rowList}");
                
            }
            else
            {
                Program.logMessage("MTU maximum payload size was not determined.");
            }

            Program.logMessage();
        }

        private static void DisplayRedirectedConnections(NetworkTrace Trace)
        {
            //
            // Connections can be redirected when connecting to Windows Azure SQL Database
            // Connections can be redirected when connecting to Always-On with ApplicationIntent=readOnly
            //

            bool hasRedirectedConnection = false;
            long firstTick = 0;
            long lastTick = 0;

            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                firstTick = ((FrameData)Trace.frames[0]).ticks;
                lastTick = ((FrameData)Trace.frames[Trace.frames.Count - 1]).ticks;
            }

            foreach (SQLServer s in Trace.sqlServers)
            {
                if (s.hasRedirectedConnections)
                {
                    hasRedirectedConnection = true;
                    List<RedirectedConnectionData> ReadOnlyRecords = new List<RedirectedConnectionData>();

                    // initialize graph object
                    TextGraph g = new TextGraph();
                    g.startTime = new DateTime(firstTick);
                    g.endTime = new DateTime(lastTick);
                    g.SetGraphWidth(150);
                    g.fAbsoluteScale = true;
                    g.SetCutoffValues(1, 3, 9, 27, 81);

                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);

                    foreach (ConversationData c in s.conversations)
                    {
                        if (c.hasRedirectedConnection)
                        {
                            RedirectedConnectionData rocd = new RedirectedConnectionData();

                            rocd.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            rocd.sourcePort = c.sourcePort;
                            rocd.isIPV6 = c.isIPV6;
                            rocd.lastFrame = ((FrameData)c.frames[c.frames.Count - 1]).frameNo;
                            rocd.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            rocd.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                            rocd.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                            rocd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                            rocd.endOffset = rocd.endTicks - firstTick;
                            rocd.duration = rocd.endOffset - rocd.startOffset;
                            rocd.frames = c.frames.Count;
                            rocd.RedirectPort = c.RedirectPort;
                            rocd.RedirectServer = c.RedirectServer;

                            ReadOnlyRecords.Add(rocd);

                            g.AddData(new DateTime(rocd.endTicks), 1.0); // for graphing
                        }
                    }

                    Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " were redirected to server.\r\n");
                    Program.logMessage("This could be due to Application Intent = ReadOnly or SQL Azure Gateway redirection.\r\n");
                    ReportFormatter rf = new ReportFormatter();

                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Redir Srv:R", "Redir Port:R");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Redir Srv:R", "Redir Port:R");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Redir Srv:R", "Redir Port:R");
                                break;
                            }
                    }

                    var OrderedRows = from row in ReadOnlyRecords orderby row.endOffset ascending select row;

                    foreach (var row in OrderedRows)
                    {
                        switch (Program.filterFormat)
                        {
                            case "N":  // list client IP and port as a NETMON filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                        (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                        row.lastFrame.ToString(),
                                                        (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                        row.frames.ToString(),
                                                        (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        row.RedirectServer,
                                                        row.RedirectPort.ToString());
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                        (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                        row.lastFrame.ToString(),
                                                        (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                        row.frames.ToString(),
                                                        (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        row.RedirectServer,
                                                        row.RedirectPort.ToString());
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.clientIP,
                                                        row.sourcePort.ToString(),
                                                        (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                        row.lastFrame.ToString(),
                                                        (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                        row.frames.ToString(),
                                                        (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                        row.RedirectServer,
                                                        row.RedirectPort.ToString());
                                    break;
                                }
                        }
                    }

                    Program.logMessage(rf.GetHeaderText());
                    Program.logMessage(rf.GetSeparatorText());

                    for (int i = 0; i < rf.GetRowCount(); i++)
                    {
                        Program.logMessage(rf.GetDataText(i));
                    }

                    Program.logMessage();

                    //
                    // Display graph
                    //

                    Program.logMessage("    Distribution of redirected connections.");
                    Program.logMessage();
                    g.ProcessData();
                    Program.logMessage("    " + g.GetLine(0));
                    Program.logMessage("    " + g.GetLine(1));
                    Program.logMessage("    " + g.GetLine(2));
                    Program.logMessage("    " + g.GetLine(3));
                    Program.logMessage("    " + g.GetLine(4));
                    Program.logMessage("    " + g.GetLine(5));

                    Program.logMessage();
                }
            }
            if (!hasRedirectedConnection)
            {
                Program.logMessage("No redirected connections were found.");
                Program.logMessage();
            }
        }

        private static void DisplayFooter()
        {
            Program.logMessage("End of Report");
            Program.logMessage();
            Program.logMessage("Please send your feedback to our Wiki at https://github.com/microsoft/CSS_SQL_Networking_Tools/wiki.");

            if (DateTime.Now > DateTime.Parse(Program.UPDATE_DATE))
            {
                Program.logMessage();
                Program.logMessage("This version of SQL Network Analyzer is likely not current. Please check if there is an updated version available.");
            }
        }

        private static void OutputStats(NetworkTrace Trace)
        {
            Program.logStat(@"SourceIP,SourcePort,DestIP,DestPort,IPVersion,Protocol,Syn,Fin,Reset,AckSynDelayms,Retransmit,ClientDup,ServerDup,KeepAlive,Integrated Login,NTLM,Login7,Encrypted,Mars,PacketVisualization,Pktmon,MaxPktmonDelay,PktmonDrop,PktmonDropReason,MaxPayloadSize,PayloadSizeLimit,Frames,Bytes,SentBytes,ReceivedBytes,Bytes/Sec,StartFile,EndFile,StartTime,EndTime,Duration,ClientTTL,ClientLowHops,ServerTTL,ServerLowHops,ServerName,ServerVersion,DatabaseName,ServerTDSVersion,ClientTDSVersion,ServerTLSVersion,ClientTLSVersion,RedirSrv,RedirPort,Error,ErrorState,ErrorMessage,");

            long traceFirstTick = 0;
            if (Trace.frames != null && Trace.frames.Count > 0)
            {
                traceFirstTick = ((FrameData)Trace.frames[0]).ticks;
            }

            foreach (ConversationData c in Trace.conversations)
            {
                int firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                int lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                long firstTick = ((FrameData)c.frames[0]).ticks;
                long endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                long duration = endTicks - firstTick;
                string ServerName = "";
                string ServerVersion = "";

                SQLServer s = Trace.FindSQLServer(c.destIP, c.destIPHi, c.destIPLo, c.destPort, c.isIPV6);
                if (s != null)
                {
                    ServerName = s.sqlHostName;
                    ServerVersion = s.serverVersion;
                }

                Program.logStat(((c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP)) + "," +
                                c.sourcePort + "," +
                                ((c.isIPV6) ? utility.FormatIPV6Address(c.destIPHi, c.destIPLo) : utility.FormatIPV4Address(c.destIP)) + "," +
                                c.destPort + "," +
                                ((c.isIPV6) ? "IPV6" : "IPV4") + "," +
                                GetProtocolName(c) + "," +
                                c.synCount + "," +
                                c.finCount + "," +
                                c.resetCount + "," +
                                (c.isUDP || c.ackSynTime == 0 ? "" : ((int)(c.LoginDelay("AS", firstTick) / utility.TICKS_PER_MILLISECOND)).ToString()) + "," +
                                c.rawRetransmits + "," +
                                c.duplicateClientPackets + "," +
                                c.duplicateServerPackets + "," +
                                c.keepAliveCount + "," +
                                (c.hasIntegratedSecurity ? "Y" : "") + "," +
                                (c.hasNTLMChallenge || c.hasNTLMResponse ? "Y" : "") + "," +
                                (c.hasLogin7 ? "Y" : "") + "," +
                                (c.isEncrypted ? (c.isEncRequired ? "R" : "Y") : "") + "," +
                                (c.isSQL && (c.isMARSEnabled || (c.smpAckCount + c.smpSynCount + c.smpFinCount + c.smpDataCount) > 0) ? "Y" : "") + "," +
                                (c.isUDP ? "" : c.frames.Count <= 40 ? c.GetPacketList(0, c.frames.Count) : c.GetFirstPacketList(20) + " ... " + c.GetLastPacketList(20)) + "," +
                                // Pktmon,MaxPktmonDelay,PktmonDrop,PktmonDropReason
                                (Trace.hasPktmonRecords ? "Y" : "") + "," +
                                (Trace.hasPktmonRecords ? $"{(c.pktmonMaxDelay / utility.TICKS_PER_SECOND).ToString("0.000000")}" : "") + "," +
                                (Trace.hasPktmonRecords && c.hasPktmonDroppedEvent ? $"Y" : "") + "," +
                                (Trace.hasPktmonRecords && c.hasPktmonDroppedEvent ? GetPktmonDropReasonText(c.pktmonDropReason) : "") + "," +
                                c.maxPayloadSize + "," +
                                (c.maxPayloadLimit ? "Y": "") + "," +
                                c.frames.Count + "," +
                                c.totalBytes + "," +
                                "," +   // do not have a separate counter for sent bytes      TODO ? do we really need it?
                                "," +   // do not have a separate counter for received bytes  TODO ? do we really need it?
                                (c.frames.Count > 1 ? (c.totalBytes * 1.0 / duration * utility.TICKS_PER_SECOND).ToString("0") : "") + "," +
                                firstFile + "," +
                                lastFile + "," +
                                new DateTime(firstTick).ToString(utility.TIME_FORMAT) + "," +
                                new DateTime(endTicks).ToString(utility.TIME_FORMAT) + "," +
                                (duration / utility.TICKS_PER_SECOND).ToString("0.000000") + "," +
                                (c.TTLCountOut == 0 ? "" : (c.TTLSumOut / c.TTLCountOut).ToString()) + "," +
                                (c.TTLCountOut == 0 ? "" : c.minTTLHopsOut.ToString()) + "," +
                                (c.TTLCountIn == 0 ? "" : (c.TTLSumIn / c.TTLCountIn).ToString()) + "," +
                                (c.TTLCountIn == 0 ? "" : c.minTTLHopsIn.ToString()) + "," +
                                ServerName + "," +
                                ServerVersion + "," +
                                ((c.databaseName == null) ? "" : c.databaseName) + "," +
                                c.FriendlyTDSVersionServer + "," +
                                c.FriendlyTDSVersionClient + "," + 
                                ((c.tlsVersionServer == null) ? "" : c.tlsVersionServer) + "," +
                                ((c.tlsVersionClient == null) ? "" : c.tlsVersionClient) + "," +
                                c.RedirectServer.Replace(",", "<") + "," +
                                (c.RedirectPort == 0 ? "" : c.RedirectPort.ToString()) + "," +
                                (c.Error == 0 ? "" : c.Error.ToString()) + "," +
                                (c.ErrorState == 0 ? "" : c.ErrorState.ToString()) + "," +
                                c.ErrorMsg.Replace(",", "."));  // replace comma with period, otherwise this MUST be the last column
            }
        }

        private static string GetProtocolName(ConversationData c)
        {
            if (c.isSQL) return "SQL";
            if (c.destPort == 88) return "Kerb";
            if (c.destPort == 53) return "DNS";
            if (c.isUDP)
            {
                if (c.destPort==1434) return "SSRP";
                return "UDP";
            }
            return "TCP";
        }

        private static string GetPktmonDropReasonText(uint value)
        {
            switch (value)
            {
                case 0: return "Unspecified";
                case 1: return "Invalid Data";
                case 2: return "Invalid Packet";
                case 3: return "Insufficient resources";
                case 4: return "Adapter not ready";
                case 5: return "Media Disconnected";
                case 6: return "Not accepted";
                case 7: return "Device busy";
                case 8: return "Filtered";
                case 9: return "Filtered VLAN";
                case 10: return "Unauthorized VLAN";
                case 11: return "Unauthorized MAC";
                case 12: return "Failed security policy";
                case 13: return "Failed pVlan setting";
                case 14: return "QoS drop";
                case 15: return "IPSec drop";
                case 16: return "Spoofed MAC address is not allowed";
                case 17: return "Failed DHCP guard";
                case 18: return "Failed Router Guard";
                case 19: return "Bridge is not allowed inside VM";
                case 20: return "Virtual Subnet ID does not match";
                case 21: return "Required vSwitch extension is missing";
                case 22: return "Creating vSwitch over another vSwitch is not allowed";
                case 23: return "MTU mismatch";
                case 24: return "Native forwarding required";
                case 25: return "Invalid VLAN format";
                case 26: return "Invalid destination MAC";
                case 27: return "Invalid source MAC";
                case 28: return "First NB too small";
                case 29: return "Windows Network Virtualization error";
                case 30: return "Storm limit exceeded";
                case 31: return "ICMP request injected by switch";
                case 32: return "Failed to update destination list";
                case 33: return "Destination NIC is disabled";
                case 34: return "Packet does not match destination NIC packet filter";
                case 35: return "vSwitch data flow is disabled";
                case 36: return "Port isolation setting does not allow untagged traffic";
                case 37: return "Invalid PD queue";
                case 38: return "Adapter is in low power state";
                case 101: return "Adapter paused";
                case 102: return "Adapter reset in progress";
                case 103: return "Send aborted";
                case 104: return "Unsupported EtherType";
                case 201: return "Microport error";
                case 202: return "VF not ready";
                case 203: return "Microport not ready";
                case 204: return "VMBus error";
                default: return $"Unknown value: {value}";
            }
        } // end of GetPktMonDropReason

    }
}
