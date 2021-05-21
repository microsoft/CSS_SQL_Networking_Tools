namespace SQLNAUI
{
    partial class FrmPreferences
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.BtnOkay = new System.Windows.Forms.Button();
            this.BtnCancel = new System.Windows.Forms.Button();
            this.Label1 = new System.Windows.Forms.Label();
            this.ChkShowConv = new System.Windows.Forms.CheckBox();
            this.Label2 = new System.Windows.Forms.Label();
            this.CboAddressFormat = new System.Windows.Forms.ComboBox();
            this.TextBox1 = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // BtnOkay
            // 
            this.BtnOkay.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.BtnOkay.Location = new System.Drawing.Point(451, 250);
            this.BtnOkay.Name = "BtnOkay";
            this.BtnOkay.Size = new System.Drawing.Size(75, 35);
            this.BtnOkay.TabIndex = 0;
            this.BtnOkay.Text = "OK";
            this.BtnOkay.UseVisualStyleBackColor = true;
            this.BtnOkay.Click += new System.EventHandler(this.BtnOkay_Click);
            // 
            // BtnCancel
            // 
            this.BtnCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.BtnCancel.Location = new System.Drawing.Point(370, 250);
            this.BtnCancel.Name = "BtnCancel";
            this.BtnCancel.Size = new System.Drawing.Size(75, 35);
            this.BtnCancel.TabIndex = 1;
            this.BtnCancel.Text = "Cancel";
            this.BtnCancel.UseVisualStyleBackColor = true;
            this.BtnCancel.Click += new System.EventHandler(this.BtnCancel_Click);
            // 
            // Label1
            // 
            this.Label1.AutoSize = true;
            this.Label1.Location = new System.Drawing.Point(18, 19);
            this.Label1.Name = "Label1";
            this.Label1.Size = new System.Drawing.Size(199, 13);
            this.Label1.TabIndex = 2;
            this.Label1.Text = "Show \"Successful Conversation\" Report";
            // 
            // ChkShowConv
            // 
            this.ChkShowConv.AutoSize = true;
            this.ChkShowConv.Location = new System.Drawing.Point(274, 20);
            this.ChkShowConv.Name = "ChkShowConv";
            this.ChkShowConv.Size = new System.Drawing.Size(15, 14);
            this.ChkShowConv.TabIndex = 3;
            this.ChkShowConv.UseVisualStyleBackColor = true;
            // 
            // Label2
            // 
            this.Label2.AutoSize = true;
            this.Label2.Location = new System.Drawing.Point(18, 53);
            this.Label2.Name = "Label2";
            this.Label2.Size = new System.Drawing.Size(137, 13);
            this.Label2.TabIndex = 4;
            this.Label2.Text = "Address Display Preference";
            // 
            // CboAddressFormat
            // 
            this.CboAddressFormat.FormattingEnabled = true;
            this.CboAddressFormat.Items.AddRange(new object[] {
            "Default",
            "NETMON Filter String",
            "WireShark Filter String",
            "Auto"});
            this.CboAddressFormat.Location = new System.Drawing.Point(274, 50);
            this.CboAddressFormat.Name = "CboAddressFormat";
            this.CboAddressFormat.Size = new System.Drawing.Size(230, 21);
            this.CboAddressFormat.TabIndex = 5;
            this.CboAddressFormat.Text = "Auto";
            // 
            // TextBox1
            // 
            this.TextBox1.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.TextBox1.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.TextBox1.Enabled = false;
            this.TextBox1.Location = new System.Drawing.Point(21, 232);
            this.TextBox1.Multiline = true;
            this.TextBox1.Name = "TextBox1";
            this.TextBox1.ReadOnly = true;
            this.TextBox1.Size = new System.Drawing.Size(303, 53);
            this.TextBox1.TabIndex = 6;
            this.TextBox1.Text = "SQL Network Analyzer User Interface\r\nMicrosoft CSS SQL Server Networking Team\r\nCo" +
    "pyright 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021";
            // 
            // FrmPreferences
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(538, 297);
            this.Controls.Add(this.TextBox1);
            this.Controls.Add(this.CboAddressFormat);
            this.Controls.Add(this.Label2);
            this.Controls.Add(this.ChkShowConv);
            this.Controls.Add(this.Label1);
            this.Controls.Add(this.BtnCancel);
            this.Controls.Add(this.BtnOkay);
            this.Name = "FrmPreferences";
            this.Text = "Preferences";
            this.Load += new System.EventHandler(this.FrmPreferences_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button BtnOkay;
        private System.Windows.Forms.Button BtnCancel;
        private System.Windows.Forms.Label Label1;
        private System.Windows.Forms.CheckBox ChkShowConv;
        private System.Windows.Forms.Label Label2;
        private System.Windows.Forms.ComboBox CboAddressFormat;
        private System.Windows.Forms.TextBox TextBox1;
    }
}