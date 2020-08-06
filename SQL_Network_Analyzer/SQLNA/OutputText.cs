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
            DisplaySQLServerSummary(Trace);
            if (Program.outputConversationList) DisplaySucessfullLoginReport(Trace);  // optional section; must be explicitly requested
            DisplayResetConnections(Trace);
            DisplayLoginTimeouts(Trace);
            DisplayAttentions(Trace);
            DisplayTLSIssues(Trace);
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
                                 (new DateTime(f.endTick)).ToString(utility.TIME_FORMAT),
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
        }

        private static void DisplayTrafficStatistics(NetworkTrace Trace)
        {
            ulong tcpBytes = 0, tdsBytes = 0;
            int tcpConversations = 0, tdsConversations = 0;
            int tcpFrames = 0, tdsFrames = 0;

            foreach (ConversationData c in Trace.conversations)
            {
                if (c.isUDP == false)
                {
                    tcpBytes += c.totalBytes;
                    tcpFrames += c.frames.Count;
                    tcpConversations++;
                    if (c.isSQL)
                    {
                        tdsBytes += c.totalBytes;
                        tdsFrames += c.frames.Count;
                        tdsConversations++;
                     }
                }
            }

            ReportFormatter rf = new ReportFormatter();
            rf.SetColumnNames("Statistic:L", "Bytes:R", "Frames:R", "Conversations:R");
            rf.indent = 4;
            rf.SetcolumnData("TCP Traffic", tcpBytes.ToString("#,##0"), tcpFrames.ToString("#,##0"), tcpConversations.ToString("#,##0"));
            rf.SetcolumnData("SQL Traffic", tdsBytes.ToString("#,##0"), tdsFrames.ToString("#,##0"), tdsConversations.ToString("#,##0"));

            Program.logMessage(rf.GetHeaderText());
            Program.logMessage(rf.GetSeparatorText());
            Program.logMessage(rf.GetDataText(0));
            Program.logMessage(rf.GetDataText(1));
            Program.logMessage();

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
                                   "NTLM Conv:R",
                                   "non-TLS 1.2 Conv:R",
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
                    string IPAddress = null;  // client IP address
                    string sqlIP = (s.isIPV6) ? utility.FormatIPV6Address(s.sqlIPHi, s.sqlIPLo) : utility.FormatIPV4Address(s.sqlIP);
                    int firstFile = 0;
                    if (s.conversations.Count > 0) Trace.files.IndexOf(((FrameData)(((ConversationData)s.conversations[0]).frames[0])).file);
                    int lastFile = 0;
                    int NTLMResponseCount = 0;
                    int lowTLSVersionCount = 0;

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
                        if (c.hasLoginFailure) s.hasLoginFailures = true;
                        if (c.hasPostLoginResponse) s.hasPostLogInResponse = true;
                        if (c.AttentionTime > 0) s.hasAttentions = true;
                        if (c.hasLowTLSVersion)
                        {
                            s.hasLowTLSVersion = true;
                            lowTLSVersionCount++;
                        }
                        int lastConvFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                        if (lastConvFile > lastFile) lastFile = lastConvFile;
                        if (c.hasNTLMResponse == true) NTLMResponseCount += 1;
                    }

                    if (totalResets > 0) s.hasResets = true;

                    rf.SetcolumnData(sqlIP,
                         s.sqlHostName,
                         s.sqlPort.ToString(),
                         s.namedPipe,
                         (s.serverVersion == null ? "" : s.serverVersion.ToString()),
                         (s.conversations.Count == 0 ? "NO TRAFFIC" : ((firstFile == lastFile) ? firstFile.ToString() : firstFile + "-" + lastFile)),
                         clientIPs.Count.ToString(),
                         s.conversations.Count.ToString(),
                         NTLMResponseCount.ToString(),
                         lowTLSVersionCount.ToString(),
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
                            ResetConnectionData rd = new ResetConnectionData();

                            rd.clientIP = (c.isIPV6) ? utility.FormatIPV6Address(c.sourceIPHi, c.sourceIPLo) : utility.FormatIPV4Address(c.sourceIP);
                            rd.sourcePort = c.sourcePort;
                            rd.isIPV6 = c.isIPV6;
                            rd.frames = c.frames.Count;
                            rd.ResetFrame = 0;
                            rd.firstFile = Trace.files.IndexOf(((FrameData)(c.frames[0])).file);
                            rd.lastFile = Trace.files.IndexOf(((FrameData)(c.frames[c.frames.Count - 1])).file);
                            rd.startOffset = ((FrameData)c.frames[0]).ticks - firstTick;
                            rd.endTicks = ((FrameData)c.frames[c.frames.Count - 1]).ticks;
                            rd.endOffset = rd.endTicks - firstTick;
                            rd.duration = rd.endOffset - rd.startOffset;
                            rd.isClientReset = false;
                            rd.rawRetransmits = c.rawRetransmits;
                            rd.keepAliveCount = c.keepAliveCount;
                            rd.flags = null;

                            //for (int i = c.frames.Count - 1; i >= 0; i--)
                            foreach (FrameData f in c.frames)   // search from beginning for first reset, not from end for last reset
                            {
                                //FrameData f = (FrameData)c.frames[i];
                                if ((f.flags & (byte)TCPFlag.RESET) > 0)
                                {
                                    rd.ResetFrame = f.frameNo;
                                    rd.isClientReset = f.isFromClient;
                                    rd.flags = f.FormatFlags();
                                    g.AddData(new DateTime(f.ticks), 1.0); // for graphing
                                    break;
                                }
                            }

                            ResetRecords.Add(rd);
                        }
                    }

                    Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " were reset:\r\n");
                    ReportFormatter rf = new ReportFormatter();
                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Reset Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Who Reset:L", "Flags:L", "Keep-Alives:R", "Retransmits:R");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Reset Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Who Reset:L", "Flags:L", "Keep-Alives:R", "Retransmits:R");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Reset Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Who Reset:L", "Flags:L", "Keep-Alives:R", "Retransmits:R");
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
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " AND tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.ResetFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.isClientReset ? "Client" : "Server"),
                                                     row.flags,
                                                     row.keepAliveCount.ToString(),
                                                     row.rawRetransmits.ToString());
                                    break;
                                }
                            case "W":  // list client IP and port as a WireShark filter string
                                {
                                    rf.SetcolumnData((row.isIPV6 ? "ipv6" : "ip") + ".addr==" + row.clientIP + " and tcp.port==" + row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.ResetFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.isClientReset ? "Client" : "Server"),
                                                     row.flags,
                                                     row.keepAliveCount.ToString(),
                                                     row.rawRetransmits.ToString());
                                    break;
                                }
                            default:  // list client IP and port as separate columns
                                {
                                    rf.SetcolumnData(row.clientIP,
                                                     row.sourcePort.ToString(),
                                                     (row.firstFile == row.lastFile) ? row.firstFile.ToString() : row.firstFile + "-" + row.lastFile,
                                                     row.ResetFrame.ToString(),
                                                     (row.startOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.endOffset / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     new DateTime(row.endTicks).ToString(utility.TIME_FORMAT),
                                                     row.frames.ToString(),
                                                     (row.duration / utility.TICKS_PER_SECOND).ToString("0.000000"),
                                                     (row.isClientReset ? "Client" : "Server"),
                                                     row.flags,
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
                    
                }
            }

            if (hasError == false)
            {
                Program.logMessage("No reset connections were found.");
                Program.logMessage();
            }
        }


        private static void DisplaySucessfullLoginReport(NetworkTrace Trace)
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
                                rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " AND tcp.port==" + row.sourcePort.ToString(),
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

        private static void DisplayLoginTimeouts(NetworkTrace Trace)
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
                    List<TimeoutConnectionData> TimeoutRecords = new List<TimeoutConnectionData>();

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
                            TimeoutConnectionData td = new TimeoutConnectionData();

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
                            td.loginProgress = c.loginFlags;
                            td.rawRetransmits = c.rawRetransmits;
                            td.keepAliveCount = c.keepAliveCount;
                            td.hasNullNTLMCreds = c.hasNullNTLMCreds;
                            td.LateLoginAck = c.hasLateLoginAck;

                            TimeoutRecords.Add(td);

                            g.AddData(new DateTime(td.endTicks), 1.0); // for graphing
                        }
                    }

                    Program.logMessage("The following conversations with SQL Server " + sqlIP + " on port " + s.sqlPort + " timed out or were closed prior to completing the login process:\r\n");
                    ReportFormatter rf = new ReportFormatter();

                    switch (Program.filterFormat)
                    {
                        case "N":
                            {
                                rf.SetColumnNames("NETMON Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Login Progress:L", "Keep-Alives:R", "Retransmits:R", "NullCreds:R", "LoginAck:L");
                                break;
                            }
                        case "W":
                            {
                                rf.SetColumnNames("WireShark Filter (Client conv.):L", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Login Progress:L", "Keep-Alives:R", "Retransmits:R", "NullCreds:R", "LoginAck:L");
                                break;
                            }
                        default:
                            {
                                rf.SetColumnNames("Client Address:L", "Port:R", "Files:R", "Last Frame:R", "Start Offset:R", "End Offset:R", "End Time:R", "Frames:R", "Duration:R", "Login Progress:L", "Keep-Alives:R", "Retransmits:R", "NullCreds:R", "LoginAck:L");
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
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " AND tcp.port==" + row.sourcePort.ToString(),
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
                                                     row.hasNullNTLMCreds ? "Yes" : "",
                                                     row.LateLoginAck ? "Late" : "");
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
                                                     row.hasNullNTLMCreds ? "Yes" : "",
                                                     row.LateLoginAck ? "Late" : "");
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
                                                     row.hasNullNTLMCreds ? "Yes" : "",
                                                     row.LateLoginAck ? "Late" : "");
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

                    Program.logMessage("    Distribution of timed-out connections.");
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
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " AND tcp.port==" + row.sourcePort.ToString(),
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
                                    rf.SetcolumnData((row.isIPV6 ? "IPV6" : "IPV4") + ".Address==" + row.clientIP + " AND tcp.port==" + row.sourcePort.ToString(),
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
            }
        }

     

         private static void DisplayDNSResponsesReport(NetworkTrace Trace)
        {
            if (Trace.DNSRequestCount == 0)
            {
                Program.logMessage("No DNS traffic was found in the network trace..");
                Program.logMessage();
                return;
            }

            if (Trace.DNSResponses.Count == 0)
            {
                Program.logMessage("All " + Trace.DNSRequestCount + " DNS requests in the network trace were successful.");
                Program.logMessage();
                return;
            }

                Program.logMessage("The problematic DNS responses are :\r\n");

                ReportFormatter rf = new ReportFormatter();
                rf.SetColumnNames("Client Address:L",
                                  "Rquested Name:L",
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
                Program.logMessage("There were " + RequestsWithNoResponse + " Kerberos TGS requests that were not responed to. They may have happened after the trace ended.");
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

                foreach (ConversationData c in Trace.conversations) // these will be in ascenading order based on parsing algorithm
                {
                    if (rec.isMatch(c))
                    {
                        if (c.synCount > 0)
                        {
                            if (rec.isSource(c))
                            {
                                rec.NewConnections++;
                                if (c.isSQL) rec.NewSQLConnections++;
                                ConnectionsPerMinute++;
                                if (ConnectionsPerMinute > rec.PeakConnectionsPerMinute) rec.PeakConnectionsPerMinute = ConnectionsPerMinute;
                                if (c.sourcePort < rec.LowPort) rec.LowPort = c.sourcePort;
                                if (c.sourcePort > rec.HighPort) rec.HighPort = c.sourcePort;

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
                if (TopPeakValue == 0) TopPeakValue = rec.PeakConnectionsPerMinute;
            }

            Program.logMessage("High Ephemeral Port Usage (Top 10)");
            Program.logMessage();
            Program.logMessage(rf.GetHeaderText());
            Program.logMessage(rf.GetSeparatorText());

            for (int i = 0; i < rf.GetRowCount(); i++)
            {
                Program.logMessage(rf.GetDataText(i));
            }

            if (TopPeakValue < 1000)
            {
                Program.logMessage();
                Program.logMessage("No clients appear to be running out of ephemeral ports.");
            }

            Program.logMessage();
        }

        private static void DisplayFooter()
        {
            Program.logMessage("End of Report");
            Program.logMessage();
            Program.logMessage("Please send your feedback to our Wiki.");

            //if (DateTime.Now > DateTime.Parse(Program.UPDATE_DATE))
            //{
            //    Program.logMessage();
            //    Program.logMessage("This version of SQL Network Analyzer is likely not current. Please check if there is an updated version available.");
            //}
        }

        private static void OutputStats(NetworkTrace Trace)
        {
            Program.logStat(@"SourceIP,SourcePort,DestIP,DestPort,IPVersion,Protocol,Syn,Fin,Reset,Retransmit,KeepAlive,Integrated Login,NTLM,Login7,Encrypted,Mars,Frames,Bytes,SentBytes,ReceivedBytes,Bytes/Sec,StartFile,EndFile,StartTime,EndTime,Duration,ServerName,ServerVersion,DatabaseName,ServerTDSVersion,ClientTDSVersion,ServerTLSVersion,ClientTLSVersion");
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
                                c.rawRetransmits + "," +
                                c.keepAliveCount + "," +
                                (c.hasIntegratedSecurity ? "Y" : "") + "," +
                                (c.hasNTLMChallenge || c.hasNTLMResponse ? "Y" : "") + "," +
                                (c.hasLogin7 ? "Y" : "") + "," +
                                (c.isEncrypted ? "Y" : "") + "," +
                                (c.isMARSEnabled ? "Y" : "") + "," +
                                c.frames.Count + "," +
                                c.totalBytes + "," +
                                "," +
                                "," +
                                (c.frames.Count > 1 ? (c.totalBytes * 1.0 / duration * utility.TICKS_PER_SECOND).ToString("0") : "") + "," +
                                firstFile + "," +
                                lastFile + "," +
                                new DateTime(firstTick).ToString(utility.TIME_FORMAT) + "," +
                                new DateTime(endTicks).ToString(utility.TIME_FORMAT) + "," +
                                (duration / utility.TICKS_PER_SECOND).ToString("0.000000") + "," +
                                ServerName + "," +
                                ServerVersion + "," +
                                ((c.databaseName == null) ? "" : c.databaseName) + "," +
                                c.FriendlyTDSVersionServer + "," +
                                c.FriendlyTDSVersionClient + "," + 
                                ((c.tlsVersionServer == null) ? "" : c.tlsVersionServer) + "," +
                                ((c.tlsVersionClient == null) ? "" : c.tlsVersionClient));
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

    }
}
