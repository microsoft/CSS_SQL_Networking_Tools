// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;
using System.IO;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Reads a network trace and produces a report and a csv file to give an overview of the trace and potential issues
    // Produces a diagnostic log file to record any exceptions or other issues
    //
    // Usage: SQLNA captureFile [/output outputFile] [[/sql ipaddress,port]...] [/convList] [/filterFmt NETMON|WireShark]
    //

    class Program
    {
        static StreamWriter logFile = null;
        static StreamWriter diagFile = null;
        static StreamWriter statFile = null;
        static string CurrentActivity = "";
        public static bool dumpConversations = false;        // diagnostic flag; must uncomment code, as well
        public static string commandLine = null;
        public static string outFile = null;
        public static string diagOutFile = null;
        public static bool outputConversationList = false;   // enables a section in the main report that is normally suppressed
        public static string filterFormat = "";              // blank | N | W   if N or W, replaces the Client IP and Port in reports with a filter string in either NETMON or WireShark format

        public const string VERSION_NUMBER = "1.5.1600.6";
        public const string UPDATE_DATE = "2021/01/31"; 

        static void Main(string[] args)
        {
            string fileSpec = null;
            string outFile = null;
            string diagOutFile = null;
            string statOutFile = null;
            
            ArrayList sqlHints = new ArrayList();

            ActivityTimer T = new ActivityTimer();

            //
            // Set command-line rules and parse the command-line
            //

            CommandLineParser cp = new CommandLineParser(); 
            cp.AddRule(new ArgRule("", true, false, true, true));                 // file name is required
            cp.AddRule(new ArgRule("output", true, false, true, false));          // -output filename is optional and case-insensitive, one time only
            cp.AddRule(new ArgRule("sql", true, true, false, false));             // -sql 10:10:10:10,1433 -sql 10.10.10.11,1433 ... -sql ip,port     0..n times   (ipv4 or ipv6)
            cp.AddRule(new ArgRule("convList", false, false, true, false));       // -convList     outputs a rather lengthy report segment that is normally not required
            cp.AddRule(new ArgRule("filterFmt", true, false, true, false));       // -filterFmt NETMON|WireShark   replaces the Client IP address and port columns with a filter string, instead
            string ruleViolation = cp.Parse(args);

            if (ruleViolation != "")
            {
                Console.WriteLine("Bad arguments: " + ruleViolation);
                displayUsage();
                return;           // exit the application
            }
            else  // for case-insensitive argument names, use lower-case to match
            {
                ArrayList values = null;
                //
                // set filename -> fileSpec
                //
                values = cp.GetArgs("");
                fileSpec = ((CommandLineArgs)values[0]).value;  // required, so it's here or we'd get a ruleViolation earlier
                //
                // set outputFile -> outFile
                //
                values = cp.GetArgs("output");
                if (values.Count != 0)  // argument supplied
                {
                    outFile = ((CommandLineArgs)values[0]).value;
                }
                else // argument omitted
                {
                    outFile = utility.getLogFileName(fileSpec);
                }
                diagOutFile = utility.getDiagLogFileName(outFile);
                statOutFile = utility.getStatLogFileName(outFile);
                //
                // set sqlHints
                //
                values = cp.GetArgs("sql");
                if (values.Count != 0) // argument supplied
                {
                    foreach (CommandLineArgs value in values) sqlHints.Add(value.value);
                }
                //
                // set outputConversationList
                //
                values = cp.GetArgs("convlist");
                if (values.Count != 0)
                {
                    outputConversationList = true;
                }
                //
                // set filterFormat
                //
                values = cp.GetArgs("filterfmt");
                if (values.Count != 0)
                {
                    string value = ((CommandLineArgs)values[0]).value.ToUpper();
                    switch (value)
                    {
                        case "NETMON":
                            {
                                filterFormat = "N";
                                break;
                            }
                        case "WIRESHARK":
                            {
                                filterFormat = "W";
                                break;
                            }
                        default:
                            {
                                Console.WriteLine("Bad arguments: filterFmt");
                                displayUsage();
                                return;           // exit the application
                            }
                    }
                }
            }

            commandLine = string.Join(" ", args);

            try
            {
                diagFile = new StreamWriter(diagOutFile);

                // output diagnostic header
                logDiagnostic("SQL Server Network Analyzer " + VERSION_NUMBER);
                logDiagnostic("Command line arguments:      " + string.Join(" ", args));
                logDiagnostic("Analysis run on:             " + DateTime.Now.ToString(utility.DATE_FORMAT));
                    
                // open log file
                CurrentActivity = "opening log file: " + outFile;
                logFile = new StreamWriter(outFile);

                NetworkTrace Trace = new NetworkTrace();

                // add SQL hints
                foreach (string value in sqlHints)
                {
                    bool isIPV6 = false;
                    ushort port = 0;
                    uint ipv4 = 0;
                    ulong ipv6hi = 0, ipv6lo = 0;
                    utility.ParseIPPortString(value, ref isIPV6, ref port, ref ipv4, ref ipv6hi, ref ipv6lo);
                    Trace.GetSQLServer(ipv4, ipv6hi, ipv6lo, port, isIPV6); // creates an entry in the SQl Server table if not one already - allows for duplicate -sql command-line arguments
                }

                // read files and parse into memory structures
                CurrentActivity = "parsing input file(s) from the folder.";
                Parser.ParseFileSpec(fileSpec, Trace);

                //Post Processing
                CurrentActivity = "processing data.";

                T.start("\nReversing backward conversations");
                Parser.ReverseBackwardConversations(Trace);
                T.stop();

                T.start("Finding retransmitted packets");
                Parser.FindRetransmits(Trace);
                T.stop();

                T.start("Finding continuation packets");
                Parser.FindContinuationFrames(Trace);
                T.stop();
               
                T.start("Parsing TDS frames");
                TDSParser.ProcessTDS(Trace);
                T.stop();

                T.start("Finding stray SQL conversations");
                TDSParser.FindStraySQLConversations(Trace);
                T.stop();

                T.start("Finding stray SQL Servers");
                TDSParser.FindStraySQLServers(Trace);
                T.stop();

                T.start("Parsing UDP frames");
                SSRPParser.ProcessUDP(Trace);
                T.stop();

                T.start("Parsing DNS frames");
                NameResolutionParser.ProcessUDP(Trace);
                T.stop();

                T.start("Parsing Kerberos frames");
                //CurrentActivity = "analyzing data.";
                KerberosParser.Process(Trace);
                T.stop();

                //Analysis

                CurrentActivity = "writing report.";
                statFile = new StreamWriter(statOutFile);
                OutputText.TextReport(Trace);
                statFile.Close();
                statFile = null;

                // dump conversations to console window
                //if (dumpConversations)
                //{
                //    foreach (ConversationData c in Trace.conversations)
                //    {
                //        if (c.sourcePort != 62729) continue;
                //        Console.WriteLine();
                //        Console.WriteLine(c.ColumnHeader1());
                //        Console.WriteLine(c.ColumnHeader2());
                //        Console.WriteLine(c.ColumnData());
                //        Console.WriteLine();
                //        Console.WriteLine(((FrameData)(c.frames[0])).ColumnHeader1());
                //        Console.WriteLine(((FrameData)(c.frames[0])).ColumnHeader2());

                //        foreach (FrameData f in c.frames)
                //        {
                //            Console.WriteLine(f.ColumnData());
                //        }
                //    }
                //    Console.ReadLine();
                //}
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while " + CurrentActivity + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
                logDiagnostic("An error occurred while " + CurrentActivity + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
            }
            finally
            {
                if (logFile != null) logFile.Close();
                if (diagFile != null) diagFile.Close();
                if (statFile != null) statFile.Close();
            }
        }

        static public void displayUsage()
        {
            Console.WriteLine(@"SQL Network Analyzer - Invalid command line arguments");
            Console.WriteLine();
            Console.WriteLine(@"USAGE:");
            Console.WriteLine();
            Console.WriteLine(@"     SQLNA captureFile [/output outputFile] [[/sql ipaddress,port]...] [/convList] [/filterFmt NETMON|WireShark]");
            Console.WriteLine();
            Console.WriteLine(@"EXAMPLES:");
            Console.WriteLine();
            Console.WriteLine(@"     SQLNA c:\temp\mytrace.cap         ... writes to c:\temp\mytrace.log");
            Console.WriteLine(@"     SQLNA c:\temp\mytrace.pcap        ... writes to c:\temp\mytrace.log");
            Console.WriteLine(@"     SQLNA c:\temp\mytrace.pcapng      ... writes to c:\temp\mytrace.log");
            Console.WriteLine();
            Console.WriteLine(@"     SQLNA c:\temp\mytrace*.cap /output c:\temp\trace.log");
            Console.WriteLine();
            Console.WriteLine(@"     SQLNA c:\temp\mytrace.cap /sql 10.0.0.2,1433     ... hints at SQL Server");
            Console.WriteLine();
            Console.WriteLine(@"Supported file formats:  NETMON 2.x, PCAP, PCAPNG, ETL.");
            Console.WriteLine(@"Supported link types:    Ethernet");
            Console.WriteLine();
        }

        static public void logMessage(string Message)
        {
            if (logFile != null) logFile.WriteLine(Message);
        }

        static public void logMessage()
        {
            if (logFile != null) logFile.WriteLine();
        }

        static public void logDiagnostic(string Message)
        {
            if (diagFile != null) diagFile.WriteLine(Message);
        }

        static public void logDiagnostic()
        {
            if (diagFile != null) diagFile.WriteLine();
        }

        static public void logDiagnosticNoReturn(string Message)
        {
            if (diagFile != null) diagFile.Write(Message);
        }

        static public void logStat(string Message)
        {
            if (statFile != null) statFile.WriteLine(Message);
        }
    }
}
