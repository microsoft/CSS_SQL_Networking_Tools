// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Data;
using System.Drawing;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace SQLBench
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    public partial class Form1 : Form
    {
        public DataSet dsStats;
        GenerateDataSet newdsStats;
        bool Testwarning = false;
        Random myrnd = new Random();
        Tree mytree = new Tree();
        LogMessage myLog;
        public Form1()
        {
            InitializeComponent();
            TabControl.Size = new Size(this.Size.Width - 42, this.Size.Height - 88);
            txtResult.Size = new Size(TabControl.Size.Width - 20, TabControl.Size.Height - 38);
            //set folders Text box 
            Folders.Text = Environment.GetEnvironmentVariable("Temp");
            //set inital connection strings
            ConnStrings.Text = "server=(local);database=Tempdb;Integrated Security=SSPI";
            //create the dataset inorder to store tests sample data
            //CreateDataSet();
            myLog = new LogMessage("myGUI");
            //newdsStats = new GenerateDataSet();
            this.Text = $"SQL Benchmark Tool - Version {Program.VERSION_NUMBER}";
        }
       
        private void LogMessage()
        {
            //Get the last Massage from the LogMessages object
            txtResult.Text += myLog.GetMessage()+"\n";
            txtResult.SelectionStart = txtResult.Text.Length;
            this.txtResult.ScrollToCaret();
            this.txtResult.Refresh();
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //Close the application
            try
            {
                this.Close();
            }
            catch (System.Exception ex)
            {
                Exception myexception = ex;
                MessageBox.Show(myexception.ToString());
            }
        }
        private void MyCopy()
        {
            //copy Result text box to clipboard memory
            Clipboard.SetDataObject((Object)this.txtResult.Text, true);
        }
        private void copyCToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //call my copy function
            MyCopy();
        }

        private void Form1_KeyDown(object sender, KeyEventArgs e)
        {
            //allows you to use control c to copy result test box
            if (e.Control && e.KeyCode == Keys.C)
            {
                MyCopy();
            }
        }

        private void clearStatusToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //Clears result text box contents
            txtResult.Clear();
        }

        private void runToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //sets tab control to 1(result text box) and starts processing the tests.
            TabControl.SelectedIndex = 1;
            ProcessTests();
        }

        private void ProcessTests()
        {
            newdsStats = new GenerateDataSet();
            newdsStats.mathtest = CPUMem.Checked;
            newdsStats.filetest = FileTests.Checked;
            newdsStats.dbtest = DBTests.Checked;
            // GenerateDataSet MyTestDb = new GenerateDataSet();
            //capture system information and add it to the result text box
            myLog.RecordMessage($"SQL Benchmark Tool - Version {Program.VERSION_NUMBER}");
            LogMessage();
            myLog.RecordMessage($"Copyright (c) Microsoft Corporation.");
            LogMessage();
            myLog.RecordMessage($"Licensed under the MIT license.");
            LogMessage();
            myLog.RecordMessage($"Written by the CSS SQL Networking Team.");
            LogMessage();
            myLog.RecordMessage("");
            LogMessage();
            myLog.RecordMessage("Machine Name: " + Environment.MachineName);
            LogMessage();
            myLog.RecordMessage("Processors: " + Environment.ProcessorCount.ToString());
            LogMessage();
            myLog.RecordMessage("OS Version: " + Environment.OSVersion.Version.ToString());
            LogMessage();
            myLog.RecordMessage("Version: " + Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", string.Empty).ToString());
            LogMessage();
            myLog.RecordMessage(".NET Version: " + Environment.Version.ToString());
            LogMessage();
            myLog.RecordMessage("User Name: " + Environment.UserDomainName + "\\" + Environment.UserName);
            LogMessage();
            myLog.RecordMessage("Current Directory: " + Environment.CurrentDirectory);
            LogMessage();
            myLog.RecordMessage("");
            LogMessage();
            for (int a = 1; a <= numericUpDown1.Value; a++)
            {
                if (this.CPUMem.Checked)
                {
                    //if CPUMem check box is checked call the following functions
                    myLog.RecordMessage("");
                    LogMessage();
                    //create data row
                    DataRow dataRow = newdsStats.dsStats.Tables["Memory"].NewRow();
                    CPU_Integer_UpDownTest(dataRow);
                    CPU_Float_UpDownTest(dataRow);
                    CPU_Decimal_UpDownTest(dataRow);
                    CPU_String_ConcatenationTest(dataRow);
                    CPU_TreeTest(dataRow);
                    CPU_TreeTransversalInOrder(dataRow);
                    CPU_TreeTransversalPreOrder(dataRow);
                    CPU_TreeTransversalPostOrder(dataRow);
                    GC.Collect();
                    newdsStats.dsStats.Tables["Memory"].Rows.Add(dataRow);
                }
                if (this.FileTests.Checked)
                {
                    //IF file test check box is checked
                    // create stop watch timer
                    Stopwatch mywatch = new Stopwatch();
                    mywatch.Start(); // start stop watch
                    string[] strArray = this.Folders.Text.Split('\r'); //create string array
                    int index = 0;
                    while (index < strArray.Length)
                    {
                        //loop through array until index is greater than or equal to string array length
                        string str = strArray[index].Trim();
                        if (str != "")
                        {
                            myLog.RecordMessage("");
                            LogMessage();
                            //create data row
                            DataRow dataRow = newdsStats.dsStats.Tables["File"].NewRow();
                            dataRow["Path"] = (object)str;
                            this.File_Test(str, dataRow);//run file test passing the string from the array and the data row
                            mywatch.Stop(); //stop timer
                            myLog.RecordMessage("File Test duration: " + mywatch.Elapsed.TotalMilliseconds.ToString("#,##0") + " ms."); //pass resault to log to add it to the Result Text box
                            LogMessage();
                            dataRow["Total"] = (object)mywatch.Elapsed.TotalMilliseconds; //add to data row the total time the test took
                            newdsStats.dsStats.Tables["File"].Rows.Add(dataRow); //add row to dataset table 
                        }
                        checked { ++index; }
                    }
                }
                if (this.DBTests.Checked)
                {
                    DataRow mydataRow = newdsStats.dsStats.Tables["Database"].NewRow();
                    Database_Test(mydataRow, myLog);

                }
            }
            myLog.RecordMessage("End of Tests!\n"); // let the user know the tests are over.
            LogMessage();
            //newdsStats.GenerateStaticSGridView((int)numericUpDown1.Value);
            newdsStats.GenerateCSVFile((int)numericUpDown1.Value);
        }

        private void CPU_Integer_UpDownTest(DataRow dr)
        {
            double mytime = 0.0;
            try
            {
                MathTest Int_Test = new MathTest();
                mytime += Convert.ToDouble(Int_Test.CPU_Integer_Addition());
                mytime += Convert.ToDouble(Int_Test.CPU_Integer_Subtraction());
                mytime += Convert.ToDouble(Int_Test.CPU_Integer_Multiplication());
                mytime += Convert.ToDouble(Int_Test.CPU_Integer_Division());
                mytime = mytime / 4;
                myLog.RecordMessage("Integer Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second."); //add time results to Result text box
                LogMessage();
                DataRow dataRow = dr; //crate data ra
                dataRow["IMath"] = (mytime * 1000.0);
            }
            catch (Exception exception)
            { 
                myLog.RecordMessage("Exception performing Integer Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }
        private void CPU_Float_UpDownTest(DataRow dr)
        {
            //test floating point math
            double mytime = 0.0;
            try
            {
                MathTest Float_Test = new MathTest();
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Addition());
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Subtraction());
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Multiplication());
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Division());
                mytime = mytime / 4;
                myLog.RecordMessage("Floating Point Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second."); //add time results to Result text box
                LogMessage();
                dr["FMath"] = (mytime * 1000.0);
            }
            catch (Exception exception) 
            { 
                myLog.RecordMessage("Exception performing Floating Point Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }
        private void CPU_Decimal_UpDownTest(DataRow dr)
        {
            double mytime = 0.0;
            try
            {
                MathTest Dec_Test = new MathTest();
                mytime += Convert.ToDouble(Dec_Test.CPU_Decimal_Addition());
                mytime += Convert.ToDouble(Dec_Test.CPU_Decimal_Subtraction());
                mytime += Convert.ToDouble(Dec_Test.CPU_Decimal_Multiplication());
                mytime += Convert.ToDouble(Dec_Test.CPU_Decimal_Division());
                mytime = mytime / 4;
                myLog.RecordMessage("Decimal Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second."); //add time results to Result text box
                LogMessage();
                dr["DMath"] = (mytime * 1000.0);
            }
            catch (Exception exception) 
            { 
                myLog.RecordMessage("Exception performing Decimal Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }
        private void CPU_String_ConcatenationTest(DataRow dr)
        {
            //preform string concatenation tests
            double mytime = 0.0;
            try
            {
                myStringConcat str = new myStringConcat();
                mytime += Convert.ToDouble(str.MyConcatination());
                myLog.RecordMessage("String Concatenation: " + (mytime * 1000.0).ToString("#,##0") + " operations per second.");//add timer to result text box
                LogMessage();
                DataRow dataRow = dr;//creat row
                // ISSUE: variable of a boxed type
                dataRow["SCat"] = (mytime * 1000);//add to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing String Concatenation test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }
        private void CPU_TreeTest(DataRow dr)
        {
            Stopwatch mywatch = new Stopwatch();//create timer
           // DateTime curtimestart = DateTime.Now;
            //TimeSpan myspan; 
            mywatch.Start();
            try
            {
                Random myrnd = new System.Random();//create randome number
                long Createednodes = 0; //create node with 0
                //double createtime = 0;                           
                for (int a = 0; a < 1000; a++)
                {   //create 1000 nodes
                    mytree.AddNode(myrnd.Next());
                    Createednodes++;
                }
                //DateTime stoptime = DateTime.Now;
               // myspan = stoptime - curtimestart;
                mywatch.Stop();//stop timmer
                myLog.RecordMessage("Create Tree: " + (1000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0).ToString("#,##0") + " operations per second.");//add timer to result text box
                LogMessage();
                dr["TreeCreate"] = (object)(10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing Tree Node test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }

        private void CPU_TreeTransversalInOrder(DataRow dr)
        {
            Stopwatch mywatch = new Stopwatch();//create timer
            mywatch.Start();//start timer
            try
            {
              //  DateTime Starttime = DateTime.Now;
                mytree.Inorder(mytree.ReturnRoot());//get in order tree serchar
               // DateTime stoptime = DateTime.Now;
               // TimeSpan timespan = stoptime - Starttime;
                mywatch.Stop();//stop timer
                myLog.RecordMessage("Tree Span in order: " + (10000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0).ToString("#,##0") + " operations per second.");//add timer to result text box
                LogMessage();
                dr["TraverseInOrder"] = (object)(10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch(Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing tree transveral in order test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }
        private void CPU_TreeTransversalPreOrder(DataRow dr)
        {
            Stopwatch mywatch = new Stopwatch();//create timer
            mywatch.Start();//timer start
            try
            {
               // DateTime Starttime = DateTime.Now;
                mytree.Preorder(mytree.ReturnRoot());//transvers pre order tree
               // DateTime stoptime = DateTime.Now;
               // TimeSpan timespan = stoptime - Starttime;
                mywatch.Stop();//stop timer
                myLog.RecordMessage("Tree Span Pre order: " + (10000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0).ToString("#,##0") + " operations per second.");//add timer to result text box
                LogMessage();
                dr["TraversePreOrder"] = (object)(10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing tree transveral in order test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }
        private void CPU_TreeTransversalPostOrder(DataRow dr)
        {
            Stopwatch mywatch = new Stopwatch();//create timer
            mywatch.Start();//start timer
            try
            {
               // DateTime Starttime = DateTime.Now;
                mytree.Postorder(mytree.ReturnRoot());//transvers tree post order
               // DateTime stoptime = DateTime.Now;
              //  TimeSpan timespan = stoptime - Starttime;
                mywatch.Stop();//stop timer
                myLog.RecordMessage("Tree Span Post order: " + (10000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0).ToString("#,##0") + " operations per second.");//add timer to result text box
                LogMessage();
                dr["TraversePostOrder"] = (object)(10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing tree transveral in order test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
                LogMessage();
            }
        }
        private void File_Test(string FolderPath, DataRow dr)
        {
            FileTests myFTest = new FileTests();
            //Console.WriteLine(myFTest.);
            if (FolderPath != "")
                myFTest.path = FolderPath+ "\\test123.bin";
            string CFile = myFTest.createFile();
            string RFile = myFTest.readFile();
            string SeqFile = myFTest.SequenceWrite();
            string RndRFile = myFTest.randomRead();
            string RndWFile = myFTest.randomWrite();
            myLog.RecordMessage("File Creation (" + 100000.ToString("#,##0") + " * " + Convert.ToString(512) + "-byte records): " + CFile + " milli-seconds.");
            LogMessage();
            dr["Create"] = Convert.ToDouble(CFile);
            myLog.RecordMessage("File Sequential Read: " + RFile + " operations per second.");
            LogMessage();
            dr["SRead"] = Convert.ToDouble(RFile);
            myLog.RecordMessage("File Sequential Write: " + SeqFile + " operations per second.");
            LogMessage();
            dr["SWrite"] = Convert.ToDouble(SeqFile);
            myLog.RecordMessage("File Random Read: " + RndRFile + " operations per second.");
            LogMessage();
            dr["RRead"] = Convert.ToDouble(RndRFile);
            myLog.RecordMessage("File Random Write: " + RndWFile + " operations per second.");
            LogMessage();
            dr["RWrite"] = Convert.ToDouble(RndWFile);
        }
        private void Database_Test(DataRow dr, LogMessage myLog)
        {         
            string[] ConnectionStrings = ConnStrings.Text.Split(new string[] {"\r\n"}, StringSplitOptions.RemoveEmptyEntries);
            foreach (string connStr in ConnectionStrings)
            {
                DBTests myTest = new DBTests(connStr);
                Stopwatch TotalRunTime = new Stopwatch();
                DataRow mydataRow = newdsStats.dsStats.Tables["Database"].NewRow();
                double opentotal = 0.0;
                double closetotal = 0.0;
                double myInsert = 0.0;
                double myBlobWrite = 0.0;
                double TotalReadRec = 0.0;
                double TotalReadBlob = 0.0;

                TotalRunTime.Start();
                dr["Conn"] = connStr;
                myLog.RecordMessage("Database Test: " + connStr);
                LogMessage();
                myLog.RecordMessage("BLOB size: " + Convert.ToString(16384) + " bytes.");
                LogMessage();
                myLog.RecordMessage("Database Test: " + connStr);
                myTest.ConnTest(out opentotal, out closetotal);
                myLog.RecordMessage("Connection Open: " + opentotal.ToString("#,##0") + " operations per second.");
                LogMessage();
                dr["Open"] = opentotal;
                myLog.RecordMessage("Connection Close: " + closetotal.ToString("#,##0") + " operations per second.");
                LogMessage();
                dr["Close"] = closetotal;
                myTest.InsertRow(out myInsert);
                myLog.RecordMessage("Insert Row: " + myInsert.ToString("#,##0") + " operations per second.");
                LogMessage();
                dr["Insert"] = myInsert;
                myTest.WriteBlobTest(out myBlobWrite);
                myLog.RecordMessage("Write BLOB: " + myBlobWrite.ToString("#,##0") + " operations per second.");
                LogMessage();
                dr["WriteBlob"] = myBlobWrite;
                myTest.ReadRowsTest(out TotalReadRec);
                myLog.RecordMessage("Read Rows: " + TotalReadRec.ToString("#,##0") + " operations per second.");
                LogMessage();
                dr["ReadRows"] = TotalReadRec;
                myTest.ReadBlobTest(out TotalReadBlob);
                myLog.RecordMessage("Read BLOB: " + TotalReadBlob.ToString("#,##0") + " operations per second.");
                LogMessage();
                dr["ReadBlob"] = TotalReadBlob;
                TotalRunTime.Stop();
                myLog.RecordMessage("Database Test duration: " + TotalRunTime.Elapsed.TotalMilliseconds.ToString("#,##0") + " ms."); // add results to Result test box
                LogMessage();
                dr["Total"] = TotalRunTime.Elapsed.TotalMilliseconds; //add total to data row
                newdsStats.dsStats.Tables["Database"].Rows.Add(dr);
                myTest.Cleanup();
            }
        }

        private void viewToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //create new Gridview form object. 
            //set the dataset in GridView = to that of Form1 
            //Display the form object.
            try
            {
                GridView myView = new GridView();
                myView.F2dsStats = newdsStats.dsStats;
                myView.Show();
            }
            catch (Exception message) { MessageBox.Show(message.Message); }
        }

        private void clearToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //Over write dataset to clear out the data
            try
            {
                newdsStats = new GenerateDataSet();
            }
            catch (Exception message) { MessageBox.Show(message.Message); }
        }

        private void exportResultsToTxtFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //Create a file in the location of the executal directory and name it Result.txt
            try
            {
                string myfile = Environment.CurrentDirectory + "\\Result.txt";
                File.WriteAllText(myfile, txtResult.Text);
                MessageBox.Show("File Saved to: " + myfile);
            }
            catch (Exception message) { MessageBox.Show(message.Message); }
        }

        private void Form1_Resize(object sender, EventArgs e)
        {
            TabControl.Size = new Size(this.Size.Width-42, this.Size.Height -90);
            txtResult.Size = new Size(TabControl.Size.Width-20,TabControl.Size.Height-38);
        }

        private void numericUpDown1_ValueChanged(object sender, EventArgs e)
        {
            if(numericUpDown1.Value >10 && Testwarning==false)
            {
                DialogResult mydialog = MessageBox.Show("Selected number of tests might slow the performance of your machine.  Would you like to continue anyway?","Warning", MessageBoxButtons.OKCancel);
                switch(mydialog)
                {
                    case DialogResult.OK:
                        Testwarning = true;
                        break;
                    case DialogResult.Cancel:
                        numericUpDown1.Value = 10;
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
