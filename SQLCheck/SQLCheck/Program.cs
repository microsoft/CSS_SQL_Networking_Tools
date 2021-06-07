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


    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>

        public static readonly string version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
        public static readonly int schemaVersion = 1;  // increment whenever the DataSet schema changes, not for every code fix

        [STAThread]
        static void Main()
        {
            DataSet ds = Storage.CreateDataSet("Test");
            Collectors.Collect(ds);
            TextReport.Report(ds, Console.Out);
        }
    }
}
