// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace SQLNAUI
{
    internal static class Program
    {

        internal static string RegPath = @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\SQL Network Analyzer";
        internal static string convListValueName = "ShowSuccessfulConversationReport";
        internal static string addrFormatValueName = "AddressFormat";
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new FrmSQLNAUI());
        }
    }
}
