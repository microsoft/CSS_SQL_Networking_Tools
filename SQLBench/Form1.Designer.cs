// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
namespace SQLBench
{
    partial class Form1
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
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.editToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.copyCToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.clearStatusToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exportResultsToTxtFileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.runToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.gridToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.viewToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.clearToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.TabControl = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.label4 = new System.Windows.Forms.Label();
            this.numericUpDown1 = new System.Windows.Forms.NumericUpDown();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.DBTests = new System.Windows.Forms.CheckBox();
            this.FileTests = new System.Windows.Forms.CheckBox();
            this.CPUMem = new System.Windows.Forms.CheckBox();
            this.ConnStrings = new System.Windows.Forms.TextBox();
            this.Folders = new System.Windows.Forms.TextBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.txtResult = new System.Windows.Forms.RichTextBox();
            this.menuStrip1.SuspendLayout();
            this.TabControl.SuspendLayout();
            this.tabPage1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDown1)).BeginInit();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // menuStrip1
            // 
            this.menuStrip1.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.editToolStripMenuItem,
            this.runToolStripMenuItem,
            this.gridToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Padding = new System.Windows.Forms.Padding(4, 2, 0, 2);
            this.menuStrip1.Size = new System.Drawing.Size(602, 24);
            this.menuStrip1.TabIndex = 0;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.exitToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(37, 20);
            this.fileToolStripMenuItem.Text = "&File";
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(92, 22);
            this.exitToolStripMenuItem.Text = "&Exit";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
            // 
            // editToolStripMenuItem
            // 
            this.editToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.copyCToolStripMenuItem,
            this.clearStatusToolStripMenuItem,
            this.exportResultsToTxtFileToolStripMenuItem});
            this.editToolStripMenuItem.Name = "editToolStripMenuItem";
            this.editToolStripMenuItem.Size = new System.Drawing.Size(39, 20);
            this.editToolStripMenuItem.Text = "&Edit";
            // 
            // copyCToolStripMenuItem
            // 
            this.copyCToolStripMenuItem.Name = "copyCToolStripMenuItem";
            this.copyCToolStripMenuItem.Size = new System.Drawing.Size(196, 22);
            this.copyCToolStripMenuItem.Text = "Copy Ctrl+C";
            this.copyCToolStripMenuItem.Click += new System.EventHandler(this.copyCToolStripMenuItem_Click);
            // 
            // clearStatusToolStripMenuItem
            // 
            this.clearStatusToolStripMenuItem.Name = "clearStatusToolStripMenuItem";
            this.clearStatusToolStripMenuItem.Size = new System.Drawing.Size(196, 22);
            this.clearStatusToolStripMenuItem.Text = "Clear Status";
            this.clearStatusToolStripMenuItem.Click += new System.EventHandler(this.clearStatusToolStripMenuItem_Click);
            // 
            // exportResultsToTxtFileToolStripMenuItem
            // 
            this.exportResultsToTxtFileToolStripMenuItem.Name = "exportResultsToTxtFileToolStripMenuItem";
            this.exportResultsToTxtFileToolStripMenuItem.Size = new System.Drawing.Size(196, 22);
            this.exportResultsToTxtFileToolStripMenuItem.Text = "Export Results to txt file";
            this.exportResultsToTxtFileToolStripMenuItem.Click += new System.EventHandler(this.exportResultsToTxtFileToolStripMenuItem_Click);
            // 
            // runToolStripMenuItem
            // 
            this.runToolStripMenuItem.Name = "runToolStripMenuItem";
            this.runToolStripMenuItem.Size = new System.Drawing.Size(40, 20);
            this.runToolStripMenuItem.Text = "&Run";
            this.runToolStripMenuItem.Click += new System.EventHandler(this.runToolStripMenuItem_Click);
            // 
            // gridToolStripMenuItem
            // 
            this.gridToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.viewToolStripMenuItem,
            this.clearToolStripMenuItem});
            this.gridToolStripMenuItem.Name = "gridToolStripMenuItem";
            this.gridToolStripMenuItem.Size = new System.Drawing.Size(41, 20);
            this.gridToolStripMenuItem.Text = "&Grid";
            // 
            // viewToolStripMenuItem
            // 
            this.viewToolStripMenuItem.Name = "viewToolStripMenuItem";
            this.viewToolStripMenuItem.Size = new System.Drawing.Size(101, 22);
            this.viewToolStripMenuItem.Text = "View";
            this.viewToolStripMenuItem.Click += new System.EventHandler(this.viewToolStripMenuItem_Click);
            // 
            // clearToolStripMenuItem
            // 
            this.clearToolStripMenuItem.Name = "clearToolStripMenuItem";
            this.clearToolStripMenuItem.Size = new System.Drawing.Size(101, 22);
            this.clearToolStripMenuItem.Text = "Clear";
            this.clearToolStripMenuItem.Click += new System.EventHandler(this.clearToolStripMenuItem_Click);
            // 
            // TabControl
            // 
            this.TabControl.Controls.Add(this.tabPage1);
            this.TabControl.Controls.Add(this.tabPage2);
            this.TabControl.Location = new System.Drawing.Point(9, 25);
            this.TabControl.Margin = new System.Windows.Forms.Padding(2);
            this.TabControl.Name = "TabControl";
            this.TabControl.SelectedIndex = 0;
            this.TabControl.Size = new System.Drawing.Size(582, 331);
            this.TabControl.TabIndex = 1;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.label4);
            this.tabPage1.Controls.Add(this.numericUpDown1);
            this.tabPage1.Controls.Add(this.label3);
            this.tabPage1.Controls.Add(this.label2);
            this.tabPage1.Controls.Add(this.label1);
            this.tabPage1.Controls.Add(this.DBTests);
            this.tabPage1.Controls.Add(this.FileTests);
            this.tabPage1.Controls.Add(this.CPUMem);
            this.tabPage1.Controls.Add(this.ConnStrings);
            this.tabPage1.Controls.Add(this.Folders);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Margin = new System.Windows.Forms.Padding(2);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(2);
            this.tabPage1.Size = new System.Drawing.Size(574, 305);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Settings";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(8, 15);
            this.label4.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(62, 13);
            this.label4.TabIndex = 32;
            this.label4.Text = "No of Tests";
            // 
            // numericUpDown1
            // 
            this.numericUpDown1.Location = new System.Drawing.Point(75, 15);
            this.numericUpDown1.Margin = new System.Windows.Forms.Padding(2);
            this.numericUpDown1.Minimum = new decimal(new int[] {
            1,
            0,
            0,
            0});
            this.numericUpDown1.Name = "numericUpDown1";
            this.numericUpDown1.Size = new System.Drawing.Size(38, 20);
            this.numericUpDown1.TabIndex = 31;
            this.numericUpDown1.Value = new decimal(new int[] {
            1,
            0,
            0,
            0});
            this.numericUpDown1.ValueChanged += new System.EventHandler(this.numericUpDown1_ValueChanged);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(227, 93);
            this.label3.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(96, 13);
            this.label3.TabIndex = 30;
            this.label3.Text = "Connection Strings";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(230, 15);
            this.label2.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(72, 13);
            this.label2.TabIndex = 29;
            this.label2.Text = "Folder Names";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 7F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(16, 279);
            this.label1.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(248, 13);
            this.label1.TabIndex = 28;
            this.label1.Text = "Press enter after Folder Names, Connection Strings.";
            // 
            // DBTests
            // 
            this.DBTests.AutoSize = true;
            this.DBTests.Checked = true;
            this.DBTests.CheckState = System.Windows.Forms.CheckState.Checked;
            this.DBTests.Location = new System.Drawing.Point(4, 81);
            this.DBTests.Margin = new System.Windows.Forms.Padding(2);
            this.DBTests.Name = "DBTests";
            this.DBTests.Size = new System.Drawing.Size(101, 17);
            this.DBTests.TabIndex = 22;
            this.DBTests.Text = "Database Tests";
            this.DBTests.UseVisualStyleBackColor = true;
            // 
            // FileTests
            // 
            this.FileTests.AutoSize = true;
            this.FileTests.Checked = true;
            this.FileTests.CheckState = System.Windows.Forms.CheckState.Checked;
            this.FileTests.Location = new System.Drawing.Point(4, 59);
            this.FileTests.Margin = new System.Windows.Forms.Padding(2);
            this.FileTests.Name = "FileTests";
            this.FileTests.Size = new System.Drawing.Size(71, 17);
            this.FileTests.TabIndex = 21;
            this.FileTests.Text = "File Tests";
            this.FileTests.UseVisualStyleBackColor = true;
            // 
            // CPUMem
            // 
            this.CPUMem.AutoSize = true;
            this.CPUMem.Checked = true;
            this.CPUMem.CheckState = System.Windows.Forms.CheckState.Checked;
            this.CPUMem.Location = new System.Drawing.Point(4, 37);
            this.CPUMem.Margin = new System.Windows.Forms.Padding(2);
            this.CPUMem.Name = "CPUMem";
            this.CPUMem.Size = new System.Drawing.Size(119, 17);
            this.CPUMem.TabIndex = 20;
            this.CPUMem.Text = "CPU/Memory Tests";
            this.CPUMem.UseVisualStyleBackColor = true;
            // 
            // ConnStrings
            // 
            this.ConnStrings.Location = new System.Drawing.Point(230, 114);
            this.ConnStrings.Margin = new System.Windows.Forms.Padding(2);
            this.ConnStrings.Multiline = true;
            this.ConnStrings.Name = "ConnStrings";
            this.ConnStrings.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.ConnStrings.Size = new System.Drawing.Size(329, 54);
            this.ConnStrings.TabIndex = 18;
            // 
            // Folders
            // 
            this.Folders.Location = new System.Drawing.Point(230, 34);
            this.Folders.Margin = new System.Windows.Forms.Padding(2);
            this.Folders.Multiline = true;
            this.Folders.Name = "Folders";
            this.Folders.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.Folders.Size = new System.Drawing.Size(329, 54);
            this.Folders.TabIndex = 17;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.txtResult);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Margin = new System.Windows.Forms.Padding(2);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(2);
            this.tabPage2.Size = new System.Drawing.Size(574, 305);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Results";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // txtResult
            // 
            this.txtResult.Location = new System.Drawing.Point(4, 5);
            this.txtResult.Margin = new System.Windows.Forms.Padding(2);
            this.txtResult.Name = "txtResult";
            this.txtResult.Size = new System.Drawing.Size(568, 301);
            this.txtResult.TabIndex = 0;
            this.txtResult.Text = "";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(602, 372);
            this.Controls.Add(this.TabControl);
            this.Controls.Add(this.menuStrip1);
            this.MainMenuStrip = this.menuStrip1;
            this.Margin = new System.Windows.Forms.Padding(2);
            this.MinimumSize = new System.Drawing.Size(618, 411);
            this.Name = "Form1";
            this.RightToLeftLayout = true;
            this.Text = "SQL Benchmark Tool";
            this.KeyDown += new System.Windows.Forms.KeyEventHandler(this.Form1_KeyDown);
            this.Resize += new System.EventHandler(this.Form1_Resize);
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.TabControl.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDown1)).EndInit();
            this.tabPage2.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem editToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem runToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem gridToolStripMenuItem;
        private System.Windows.Forms.TabControl TabControl;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.CheckBox DBTests;
        private System.Windows.Forms.CheckBox FileTests;
        private System.Windows.Forms.CheckBox CPUMem;
        private System.Windows.Forms.TextBox ConnStrings;
        private System.Windows.Forms.TextBox Folders;
        private System.Windows.Forms.RichTextBox txtResult;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem copyCToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem clearStatusToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem viewToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem clearToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem exportResultsToTxtFileToolStripMenuItem;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.NumericUpDown numericUpDown1;
    }
}

