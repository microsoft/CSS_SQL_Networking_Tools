// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Data;
using System.Reflection;

namespace SQLCheck
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //


    public static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>

        public static readonly string version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
        public static readonly int schemaVersion = 1;  // increment whenever the DataSet schema changes, not for every code fix
        static bool TraceOn = false;

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0].ToUpper() == "T") TraceOn = true;
            DataSet ds = Storage.CreateDataSet("Test");
            Collectors.Collect(ds);

            // Clintonw-Oct17
            // Create file
            Console.WriteLine("Writing SQLCheck Log ....");
            TextReport.Report(ds, Utility.openLogOutputFile());
            Utility.closeLogOutputFile();
        }

        public static void Trace(string Message)
        {
            if (TraceOn) Console.WriteLine(Message);
        }
    }
}
