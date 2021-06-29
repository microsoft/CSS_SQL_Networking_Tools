// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Data;
using System.Drawing;
using System.Windows.Forms;

namespace SQLBench
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    public partial class GridView : Form
    {
        public DataSet F2dsStats;
        BindingSource myMemory = new BindingSource();
        BindingSource myFiles = new BindingSource();
        BindingSource myDBTests = new BindingSource();
        //int originalX;
       // int originalY;
        public GridView()
        {
            InitializeComponent();
            //sets objests for scalabiltity
            tabControl1.Size = new Size(this.Size.Width - 35, this.Size.Height - 104);
            dataGridView1.Size = new Size(tabControl1.Width - 6, tabControl1.Height - 22);
            dataGridView2.Size = new Size(tabControl1.Width - 6, tabControl1.Height - 22);
            dataGridView3.Size = new Size(tabControl1.Width - 6, tabControl1.Height - 22);
            label1.Location = new Point(15, this.Size.Height - 67);
            this.Refresh();
        }

        private void GridView_Load(object sender, EventArgs e)
        {
            //set the Datasourse for each datagrid based on the Dataset tables
            myMemory.DataSource = F2dsStats.Tables[0];
            myFiles.DataSource = F2dsStats.Tables[1];
            myDBTests.DataSource = F2dsStats.Tables[2];
            dataGridView1.DataSource = myMemory;
            dataGridView2.DataSource = myFiles;
            dataGridView3.DataSource = myDBTests;
            dataGridView1.Refresh();
            dataGridView2.Refresh();
            dataGridView3.Refresh();
            //modify column headers per grid
            SetMemoryColumnHeader();
            SetFileColumnHeader();
            SetDBColumnHeader();
        }
      
        private void SetMemoryColumnHeader()
        {
            //Rewrites the datagridview1 Header text file for a better layout.
            //Sets teh column widths 
            dataGridView1.Columns[6].Width = 110;
            dataGridView1.Columns[7].Width = 110;
            dataGridView1.Columns[8].Width = 110;
            //sets the display format
            foreach (DataGridViewColumn col in dataGridView1.Columns)
            {
                col.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleCenter;
                col.DefaultCellStyle.Format = "#,##0.00";
            }
            //Changed header text
            dataGridView1.Columns[1].HeaderText = "Integer Math (ops/sec)";
            dataGridView1.Columns[2].HeaderText = "Floating Point (ops/sec)";
            dataGridView1.Columns[3].HeaderText = "Decimal Math (ops/sec)";
            dataGridView1.Columns[4].HeaderText = "String Concat. (ops/sec)";
            dataGridView1.Columns[5].HeaderText = "Tree Creation (ops/sec)";
            dataGridView1.Columns[6].HeaderText = "Tree TransversalIn Order (ops/sec)";
            dataGridView1.Columns[7].HeaderText = "Tree Transversal Pre Order (ops/sec)";
            dataGridView1.Columns[8].HeaderText = "Tree Transversal Post Order (ops/sec)";
        }
        private void SetFileColumnHeader()
        {
            //Rewrites the datagridview2 Header text file for a better layout.
            //sets the display format
            foreach (DataGridViewColumn col in dataGridView2.Columns)
            {
                col.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleCenter;
                col.DefaultCellStyle.Format = "#,##0.00";
            }
            //Changed header text
            dataGridView2.Columns[1].HeaderText = "File Path";
            dataGridView2.Columns[2].HeaderText = "Create Time (ms)";
            dataGridView2.Columns[3].HeaderText = "Sequence Read (rows/sec)";
            dataGridView2.Columns[4].HeaderText = "Sequence Write (rows/sec)";
            dataGridView2.Columns[5].HeaderText = "Random Seek/Read (ops/sec)";
            dataGridView2.Columns[6].HeaderText = "Random Seek/Writes (ops/sec)";
            dataGridView2.Columns[7].HeaderText = "Test Duration(sec)";
        }
        private void SetDBColumnHeader()
        {
            //Rewrites the datagridview3 Header text file for a better layout.
            //sets the display format
            foreach (DataGridViewColumn col in dataGridView3.Columns)
            {
                col.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleCenter;
                col.DefaultCellStyle.Format = "#,##0.00";
            }
            //Changed header text
            dataGridView3.Columns[1].HeaderText = "Connection String";
            dataGridView3.Columns[2].HeaderText = "Open (ops/ms)";
            dataGridView3.Columns[3].HeaderText = "Close (ops/sec)";
            dataGridView3.Columns[4].HeaderText = "Insert (rows/sec)";
            dataGridView3.Columns[5].HeaderText = "Read (ops/sec)";
            dataGridView3.Columns[6].HeaderText = "BLOB Reads (ops/sec)";
            dataGridView3.Columns[7].HeaderText = "BLOB Writes (ops/sec)";
            dataGridView3.Columns[8].HeaderText = "Test Duration(sec)";
        }
        
        private void copyToClipboarcToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //Copes the endire active tab grid to the clip board memory space.
            if (tabControl1.SelectedTab == tabControl1.TabPages["Memory"])
            {
                dataGridView1.MultiSelect = true;
                dataGridView1.SelectAll();
                dataGridView1.ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText;
                DataObject dataObj = dataGridView1.GetClipboardContent();
                if (dataObj != null)
                    Clipboard.SetDataObject(dataObj);
            }
            if (tabControl1.SelectedTab == tabControl1.TabPages["File"])
            {
                dataGridView2.MultiSelect = true;
                dataGridView2.SelectAll();
                dataGridView2.ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText;
                DataObject dataObj = dataGridView2.GetClipboardContent();
                if (dataObj != null)
                    Clipboard.SetDataObject(dataObj);
            }
            if (tabControl1.SelectedTab == tabControl1.TabPages["Database"])
            {
                dataGridView3.MultiSelect = true;
                dataGridView3.SelectAll();
                dataGridView3.ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText;
                DataObject dataObj = dataGridView3.GetClipboardContent();
                if (dataObj != null)
                    Clipboard.SetDataObject(dataObj);
            }
        }
        
        private void exportCurrentGridToCVSFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //Creates a CSV file in the directory of the executable 
            //Copyes and writes the entire grid information to the csv file.
            label1.Text = "File was saved to: ";
            if (tabControl1.SelectedTab == tabControl1.TabPages["Memory"])
            {
                string Memorypath = Environment.CurrentDirectory + "\\Memory.csv";
                label1.Text += Memorypath;
                dataGridView1.MultiSelect = true;
                dataGridView1.SelectAll();
                dataGridView1.ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText;
                DataObject dataObj = dataGridView1.GetClipboardContent();
                if (dataObj != null)
                    System.IO.File.WriteAllText(Memorypath, dataObj.GetText(TextDataFormat.CommaSeparatedValue));
            }
            if (tabControl1.SelectedTab == tabControl1.TabPages["File"])
            {
                string Memorypath = Environment.CurrentDirectory + "\\File.csv";
                label1.Text += Memorypath;
                dataGridView2.MultiSelect = true;
                dataGridView2.SelectAll();
                dataGridView2.ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText;
                DataObject dataObj = dataGridView2.GetClipboardContent();
                if (dataObj != null)
                    System.IO.File.WriteAllText(Memorypath, dataObj.GetText(TextDataFormat.CommaSeparatedValue));
            }
            if (tabControl1.SelectedTab == tabControl1.TabPages["Database"])
            {
                string Memorypath = Environment.CurrentDirectory + "\\Database.csv";
                label1.Text += Memorypath;
                dataGridView3.MultiSelect = true;
                dataGridView3.SelectAll();
                dataGridView3.ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText;
                DataObject dataObj = dataGridView3.GetClipboardContent();
                if (dataObj != null)
                    System.IO.File.WriteAllText(Memorypath, dataObj.GetText(TextDataFormat.CommaSeparatedValue));
            }
            label1.Visible = true;
        }

        private void exitToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            //Close current form
            this.Close();
        }

        private void Deletedaddedrows()
        { 
            //Cleanup the dataset so if you add more test samples it will recalculate and display properly
            // Deletes the static rows added when the form is loaded.
            int memeoryrows = F2dsStats.Tables[0].Rows.Count;
            int fileRows = F2dsStats.Tables[1].Rows.Count;
            int databaserows = F2dsStats.Tables[2].Rows.Count;
            for (int a = memeoryrows-1; a >= (memeoryrows-5);a--)
            {
                DataRow row = F2dsStats.Tables[0].Rows[a];
                F2dsStats.Tables[0].Rows.Remove(row);
            }
            for (int a = fileRows-1; a >= (fileRows - 6); a--)
            {
                DataRow row = F2dsStats.Tables[1].Rows[a];
                F2dsStats.Tables[1].Rows.Remove(row);
            }
            for (int a = databaserows-1; a >= (databaserows - 6); a--)
            {
                DataRow row = F2dsStats.Tables[2].Rows[a];
                F2dsStats.Tables[2].Rows.Remove(row);
            }
        }

        private void GridView_Resize(object sender, EventArgs e)
        {
            //resizes the form's objects when the main form gets resized.
            tabControl1.Size = new Size(this.Size.Width - 35, this.Size.Height - 104);
            dataGridView1.Size = new Size(tabControl1.Width - 6, tabControl1.Height - 22);
            dataGridView2.Size = new Size(tabControl1.Width - 6, tabControl1.Height - 22);
            dataGridView3.Size = new Size(tabControl1.Width - 6, tabControl1.Height - 22);
            label1.Location = new Point(15, this.Size.Height-67);
            this.Refresh();
        }
    }
}
