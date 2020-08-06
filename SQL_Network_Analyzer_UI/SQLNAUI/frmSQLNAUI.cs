// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SQLNAUI
{
    public partial class FrmSQLNAUI : Form
    {
        bool convList = false;
        string addrFormat = "Default";

        public FrmSQLNAUI()
        {
            InitializeComponent();
        }

        private void FrmSQLNAUI_Load(object sender, EventArgs e)
        {
            GetRegistryDefaults();
        }

        private void MnuFileOpen_Click(object sender, EventArgs e)
        {
            DialogResult result;
            this.OpenFileDialog1.Multiselect = false;
            // this.OpenFileDialog1.ValidateNames = true;
            this.OpenFileDialog1.Title = "Open Files to Analyze";
            this.OpenFileDialog1.SupportMultiDottedExtensions = true;
            this.OpenFileDialog1.CheckPathExists = true;
            this.OpenFileDialog1.Filter = @"Capture Files (*.cap;*.etl;*.pcap;*.pcapng)|*.cap;*.etl;*.pcap;*.pcapng|All Files (*.*)|*.*";
            result = this.OpenFileDialog1.ShowDialog(this.Owner);
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                TxtFileSpec.Text = this.OpenFileDialog1.FileName;
            }

            UpdateCommand();
        }

        private void MnuFilePreferences_Click(object sender, EventArgs e)
        {
            Form Pref = new FrmPreferences();
            Pref.ShowDialog();
            GetRegistryDefaults();
            UpdateCommand();
        }

        private void MnuFileExit_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void UpdateCommand()
        {
            TxtCommand.Text = "SQLNA";
            if (TxtFileSpec.Text.Trim() != "") TxtCommand.Text += @" """ + TxtFileSpec.Text.Trim() + @"""";
            if (TxtLogFile.Text.Trim() != "") TxtCommand.Text += @" /output """ + TxtLogFile.Text.Trim() + @"""";
            if (TxtSQLHint.Text.Trim() != "") TxtCommand.Text += @" /sql " + TxtSQLHint.Text.Trim().Replace(" ", " /sql ");
            if (convList) TxtCommand.Text += @" /convList";
            if (addrFormat != "Default") TxtCommand.Text += addrFormat == "NETMON Filter String" ? @" /filterFmt NETMON" : @" /filterFmt WireShark";
        }

        private void GetRegistryDefaults()
        {
            //
            // Nonexistant values may come back null, so the ToString() will convert it to an empty string.
            // Make sure the conditional logic returns the default option in the case of an empty string.
            //

            object regValue = null;
            string value = "";

            // Conversation List
            regValue = Registry.GetValue(Program.RegPath, Program.convListValueName, "False");
            value = regValue == null ? "" : ((string)regValue).ToUpper();
            convList = value == "TRUE" ? true : false;

            // Address Format
            regValue = Registry.GetValue(Program.RegPath, Program.addrFormatValueName, "Default");
            value = regValue == null ? "" : ((string)regValue).ToUpper();
            switch (value)
            {
                case "NETMON":
                    {
                        addrFormat = "NETMON Filter String";
                        break;
                    }
                case "WIRESHARK":
                    {
                        addrFormat = "WireShark Filter String";
                        break;
                    }
                default:
                    {
                        addrFormat = "Default";
                        break;
                    }
            }
        }

        private void TxtLogFile_TextChanged(object sender, EventArgs e)
        {
            UpdateCommand();
        }

        private void TxtFileSpec_TextChanged(object sender, EventArgs e)
        {
            UpdateCommand();
        }

        private void TxtSQLHint_TextChanged(object sender, EventArgs e)
        {
            UpdateCommand();
        }

        private void BtnParse_Click(object sender, EventArgs e)
        {
            if (TxtCommand.Text != "SQLNA")
            {
                System.Diagnostics.Process.Start(System.Environment.GetEnvironmentVariable("ComSpec"), @" /K " + TxtCommand.Text);
            }
        }
    }
}
