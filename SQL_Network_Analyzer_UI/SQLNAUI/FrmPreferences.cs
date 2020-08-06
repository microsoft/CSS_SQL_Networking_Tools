// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using Microsoft.Win32;
using System.Windows.Forms;

namespace SQLNAUI
{
    public partial class FrmPreferences : Form
    {

        public FrmPreferences()
        {
            InitializeComponent();
        }

        private void FrmPreferences_Load(object sender, EventArgs e)
        {
            //
            // Nonexistant values may come back null, so the ? : operators are used.
            // Make sure the conditional logic returns the default option in the case of an empty string.
            //

            object regValue = null;
            string value = "";

            // Conversation List
            regValue = Registry.GetValue(Program.RegPath, Program.convListValueName, "False");
            value = regValue == null ? "" : ((string)regValue).ToUpper();
            ChkShowConv.Checked = value == "TRUE" ? true : false;

            // Address Format
            regValue = Registry.GetValue(Program.RegPath, Program.addrFormatValueName, "Default");
            value = regValue == null ? "" : ((string)regValue).ToUpper();
            switch (value)
            {
                case "NETMON":
                    {
                        CboAddressFormat.Text = "NETMON Filter String";
                        break;
                    }
                case "WIRESHARK":
                    {
                        CboAddressFormat.Text = "WireShark Filter String";
                        break;
                    }
                default:
                    {
                        CboAddressFormat.Text = "Default";
                        break;
                    }
            }
        }

        private void BtnOkay_Click(object sender, EventArgs e)
        {
            string value = "";

            // Conversation List
            value = ChkShowConv.Checked ? "True" : "False";
            Registry.SetValue(Program.RegPath, Program.convListValueName, value);

            // Address Format
            switch (CboAddressFormat.Text.ToUpper())
            {
                case "NETMON FILTER STRING":
                    {
                        Registry.SetValue(Program.RegPath, Program.addrFormatValueName, "NETMON");
                        break;
                    }
                case "WIRESHARK FILTER STRING":
                    {
                        Registry.SetValue(Program.RegPath, Program.addrFormatValueName, "WireShark");
                        break;
                    }
                default:
                    {
                        Registry.SetValue(Program.RegPath, Program.addrFormatValueName, "Default");
                        break;
                    }
            }
            this.Close();
        }

        private void BtnCancel_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
