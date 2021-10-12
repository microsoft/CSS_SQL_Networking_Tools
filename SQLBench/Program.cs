// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Windows.Forms;
using System.Collections;
using System.Data;
using Microsoft.Win32;
using System.Diagnostics;
using System.Reflection;

namespace SQLBench
{
    class Program
    {
        /// <summary>
        /// The main entry point for the application.
        ///    
        /// Written by the Microsoft CSS SQL Networking Team
        /// 
        /// Performs a single-threaded benchmark on CPU, Memory, the file system, and SQL Server
        /// Can run as either a command-line tool or a Windowed tool.
        /// 
        /// </summary>
        /// 

        public static string VERSION_NUMBER = Assembly.GetExecutingAssembly().GetName().Version.ToString();

        [STAThread]
        static void Main(string[] args)
        {
            bool mathTests = false;
            bool fileTests = false;
            bool databaseTests = false;
            // bool ClustedIndex = false;
            ArrayList FolderPaths = new ArrayList();
            ArrayList ConnectionStrings = new ArrayList();
            // string dbtesttype = "VARBINARY";
            int looptest = 1;
            string outFile = "";
            // string Connfile = "";

            CommandLineParser cp = new CommandLineParser();

            cp.AddRule(new ArgRule("n", true, false, true, false));           // -n loopcount
            cp.AddRule(new ArgRule("cpu", false, false, true, false));        // -cpu
            cp.AddRule(new ArgRule("file", true, true, true, false));         // -file filepath without file name
            cp.AddRule(new ArgRule("sql", true, true, true, false));          // -sql connectionstr
            cp.AddRule(new ArgRule("output", true, false, true, false));      // -output filepath\filename

            //
            // Are we going to run as a GUI or a command-line application?
            //

            // GUI - no arguments
            if (args.Length == 0)
            {
                displayUsage();
            }
            else  // command-line - interpret the arguments
            {
                string ruleViolation = cp.Parse(args);
                if (ruleViolation != "")
                {
                    Console.WriteLine("Bad argument: " + ruleViolation);
                    displayUsage();
                    return;
                }
                else
                {
                    ArrayList values = null;

                    //
                    // How many tests to perform
                    //

                    values = cp.GetArgs("n");
                    if (values.Count != 0) looptest = Convert.ToInt32(((CommandLineArgs)values[0]).value);

                    //
                    // Do we perform the CPU test?
                    //

                    values = cp.GetArgs("cpu");
                    if (values.Count > 0) mathTests = true;

                    //
                    // Do we perform the file tests
                    //

                    values = cp.GetArgs("file");
                    foreach (CommandLineArgs value in values)
                    {
                        FolderPaths.Add(value.value);
                        fileTests = true;
                    }

                    //
                    // Do we perform database tests
                    //

                    values = cp.GetArgs("sql");
                    foreach (CommandLineArgs value in values)
                    {
                        ConnectionStrings.Add(value.value);
                        databaseTests = true;
                    }

                    //
                    // Where do we log the data
                    //

                    values = cp.GetArgs("output");
                    if (values.Count != 0)
                    {
                        outFile = ((CommandLineArgs)values[0]).value;
                    }
                    else
                    {
                        outFile = Environment.CurrentDirectory;
                    }

                    StartTests(looptest, mathTests, fileTests, databaseTests, outFile, ConnectionStrings, FolderPaths);
                }
            }
        }
        static public void StartTests(int looptest, bool mathtest, bool filetest, bool dbtest, string output, ArrayList ConnectionStrings, ArrayList FolderPaths)
        {
            GenerateDataSet MyTestDb = new GenerateDataSet();
            MyTestDb.mathtest = mathtest;
            MyTestDb.filetest = filetest;
            MyTestDb.dbtest = dbtest;
            LogMessage myLog = new LogMessage("MyConsole");
            Tree mytree = new Tree();
            //capture system information and add it to the result text box
            myLog.RecordMessage($"SQL Benchmark Tool - Version {Program.VERSION_NUMBER}");
            myLog.RecordMessage($"Copyright (c) Microsoft Corporation.");
            myLog.RecordMessage($"Licensed under the MIT license.");
            myLog.RecordMessage($"Written by the CSS SQL Networking Team.");
            myLog.RecordMessage("");
            myLog.RecordMessage($"Machine Name: {Environment.MachineName}");
            myLog.RecordMessage("Processors: " + Environment.ProcessorCount.ToString());
            myLog.RecordMessage("OS Version: " + Environment.OSVersion.Version.ToString());
            myLog.RecordMessage("Version: " + Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", string.Empty).ToString());
            myLog.RecordMessage(".NET Version: " + Environment.Version.ToString());
            myLog.RecordMessage("User Name: " + Environment.UserDomainName + "\\" + Environment.UserName);
            myLog.RecordMessage("Current Directory: " + Environment.CurrentDirectory);
            myLog.RecordMessage("");
            for (int a = 0; a < looptest; a++)
            {
                if (mathtest == true)
                {
                    //if CPUMem check box is checked call the following functions
                    //this.LogMessage("");
                    //create data row
                    DataRow dataRow = MyTestDb.dsStats.Tables["Memory"].NewRow();
                    CPU_Integer_UpDownTest(dataRow, myLog);
                    CPU_Float_UpDownTest(dataRow, myLog);
                    CPU_Decimal_UpDownTest(dataRow, myLog);
                    CPU_String_ConcatenationTest(dataRow, myLog);
                    CPU_TreeTest(dataRow, myLog, mytree);
                    CPU_TreeTransversalInOrder(dataRow, myLog, mytree);
                    CPU_TreeTransversalPreOrder(dataRow, myLog, mytree);
                    CPU_TreeTransversalPostOrder(dataRow, myLog, mytree);
                    //GC.Collect();
                    MyTestDb.dsStats.Tables["Memory"].Rows.Add(dataRow);
                    myLog.RecordMessage("");
                }
                if (filetest == true)
                {
                    foreach (string fileDir in FolderPaths)
                    {
                        DataRow dataRow = MyTestDb.dsStats.Tables["File"].NewRow();
                        Stopwatch total = new Stopwatch();
                        total.Start();
                        FileTest(dataRow, myLog, fileDir);
                        total.Stop();
                        dataRow["Total"] = total.Elapsed.TotalMilliseconds;
                        MyTestDb.dsStats.Tables["File"].Rows.Add(dataRow);
                    }
                }
                if (dbtest == true)
                {
                    foreach (string connStr in ConnectionStrings)
                    {
                        DataRow dataRow = MyTestDb.dsStats.Tables["Database"].NewRow();
                        DatabaseTest(dataRow, myLog, connStr);
                        MyTestDb.dsStats.Tables["Database"].Rows.Add(dataRow);
                    }
                }
            }   
            
            myLog.RecordMessage("End of Tests.");
            myLog.SaveLog(output);
            MyTestDb.GenerateCSVFile(looptest);
            MyTestDb.DataOutput(output);
        }
   
        static private void CPU_Integer_UpDownTest(DataRow dr, LogMessage mylog)
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
                // LogMessage("Integer Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second."); //add time results to Result text box
                mylog.RecordMessage("Integer Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second.");
                //Console.WriteLine("Integer Math: {0}" + (mytime * 1000.0).ToString("#,##0") + " operations per second.");
                DataRow dataRow = dr; //crate data ra
                dataRow["IMath"] = (mytime * 1000.0);

            }
            catch (Exception exception) 
            {
                //LogMessage("Exception performing Integer Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace); 
                mylog.RecordMessage("Exception performing Integer Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }
        static private void CPU_Float_UpDownTest(DataRow dr, LogMessage mylog)
        {
            double mytime = 0.0;
            try
            {
                MathTest Float_Test = new MathTest();
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Addition());
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Subtraction());
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Multiplication());
                mytime += Convert.ToDouble(Float_Test.CPU_Float_Division());
                mytime = mytime / 4;
                // LogMessage("Integer Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second."); //add time results to Result text box
                mylog.RecordMessage("Float Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second.");
                //Console.WriteLine("Integer Math: {0}" + (mytime * 1000.0).ToString("#,##0") + " operations per second.");
                DataRow dataRow = dr; //crate data ra
                dataRow["FMath"] = (mytime * 1000.0);

            }
            catch (Exception exception)
            {
                //LogMessage("Exception performing Integer Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace); 
                mylog.RecordMessage("Exception performing Integer Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }
        static private void CPU_Decimal_UpDownTest(DataRow dr, LogMessage mylog)
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
                // LogMessage("Integer Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second."); //add time results to Result text box
                mylog.RecordMessage("Decimal Math: " + (mytime * 1000.0).ToString("#,##0") + " operations per second.");
                //Console.WriteLine("Integer Math: {0}" + (mytime * 1000.0).ToString("#,##0") + " operations per second.");
                DataRow dataRow = dr; //crate data row
                dataRow["DMath"] = (mytime * 1000.0);

            }
            catch (Exception exception)
            {
                //LogMessage("Exception performing Integer Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace); 
                mylog.RecordMessage("Exception performing Integer Math test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }

        static private void CPU_String_ConcatenationTest(DataRow dr,LogMessage mylog)
        {
            //preform string concatenation tests
            double mytime = 0.0;
            try
            {
                myStringConcat str = new myStringConcat();
                mytime += Convert.ToDouble(str.MyConcatination());
                mylog.RecordMessage("String Concatenation: " + (mytime * 1000.0).ToString("#,##0") + " operations per second.");//add timer to result text box
                DataRow dataRow = dr;//creat row
                // ISSUE: variable of a boxed type
                dataRow["SCat"] = (mytime*1000);//add to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                mylog.RecordMessage("Exception performing String Concatenation test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }
        static private void CPU_TreeTest(DataRow dr, LogMessage mylog, Tree mytree)
        {
            Stopwatch mywatch = new Stopwatch();//create timer
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
                mylog.RecordMessage("Create Tree: " + (1000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0).ToString("#,##0") + " operations per second.");//add timer to result text box
                dr["TreeCreate"] = (10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                mylog.RecordMessage("Exception performing Tree Node test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }
        static private void CPU_TreeTransversalInOrder(DataRow dr, LogMessage myLog, Tree mytree)
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
                dr["TraverseInOrder"] = (object)(10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing tree transveral in order test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }
        static private void CPU_TreeTransversalPreOrder(DataRow dr, LogMessage myLog, Tree mytree)
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
                dr["TraversePreOrder"] = (object)(10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing tree transveral in order test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }
        static private void CPU_TreeTransversalPostOrder(DataRow dr, LogMessage myLog, Tree mytree)
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
                dr["TraversePostOrder"] = (object)(10000000.0 / mywatch.Elapsed.TotalMilliseconds * 1000.0);//add timer to data row
            }
            catch (Exception ex)
            {
                Exception exception = ex;
                myLog.RecordMessage("Exception performing tree transveral in order test.\r\n" + exception.Message + "\r\n" + exception.StackTrace);
            }
        }
        static private void FileTest(DataRow dr, LogMessage mylog, string fileDir)
        {
            FileTests myFTest = new FileTests();
            //Console.WriteLine(myFTest.);
            if (fileDir != "")
                myFTest.path = fileDir + @"\test123.bin";
            string CFile = myFTest.createFile();
            string RFile = myFTest.readFile();
            string SeqFile = myFTest.SequenceWrite();
            string RndRFile = myFTest.randomRead();
            string RndWFile = myFTest.randomWrite();
            mylog.RecordMessage($"File Test: {myFTest.path}");
            dr["Path"] = myFTest.path;
            mylog.RecordMessage("File Creation (" + 100000.ToString("#,##0") + " * " + Convert.ToString(512) + "-byte records): " + CFile + " milli-seconds.");
            dr["Create"] = Convert.ToDouble(CFile);
            mylog.RecordMessage("File Sequential Read: " + RFile + " operations per second.");
            dr["SRead"] = Convert.ToDouble(RFile);
            mylog.RecordMessage("File Sequential Write: " + SeqFile + " operations per second.");
            dr["SWrite"] = Convert.ToDouble(SeqFile);
            mylog.RecordMessage("File Random Read: " + RndRFile + " operations per second.");
            dr["RRead"] = Convert.ToDouble(RndRFile);
            mylog.RecordMessage("File Random Write: " +RndWFile + " operations per second.");
            dr["RWrite"] = Convert.ToDouble(RndWFile);
            mylog.RecordMessage("");  // blank line after the test
        }
        static void DatabaseTest(DataRow dr, LogMessage myLog, string connStr)
        {
            DBTests myTest = new DBTests(connStr);
            Stopwatch TotalRunTime = new Stopwatch();
            double opentotal = 0.0;
            double closetotal = 0.0;
            double myInsert = 0.0;
            double myBlobWrite = 0.0;
            double TotalReadRec= 0.0;
            double TotalReadBlob = 0.0;
       
            TotalRunTime.Start();
            myLog.RecordMessage("Database Test: " + connStr);
            dr["Conn"] = connStr;
            myTest.ConnTest(out opentotal, out closetotal);
            myLog.RecordMessage("Connection Open: " + opentotal.ToString("#,##0") + " operations per second.");
            dr["Open"] = opentotal;
            myLog.RecordMessage("Connection Close: " + closetotal.ToString("#,##0") + " operations per second.");
            dr["Close"] = closetotal;
            myTest.InsertRow(out myInsert);
            myLog.RecordMessage("Insert Row: " + myInsert.ToString("#,##0") + " operations per second.");
            dr["Insert"] = myInsert;
            myTest.WriteBlobTest(out myBlobWrite);
            myLog.RecordMessage("Write BLOB: " + myBlobWrite.ToString("#,##0") + " operations per second.");
            dr["WriteBlob"] = myBlobWrite;
            myTest.ReadRowsTest(out TotalReadRec);
            myLog.RecordMessage("Read Rows: " + TotalReadRec.ToString("#,##0") + " operations per second.");
            dr["ReadRows"] = TotalReadRec;
            myTest.ReadBlobTest(out TotalReadBlob);
            myLog.RecordMessage("Read BLOB: " + TotalReadBlob.ToString("#,##0") + " operations per second.");
            dr["ReadBlob"] = TotalReadBlob;
            TotalRunTime.Stop();
            dr["Total"]= TotalRunTime.Elapsed.TotalMilliseconds;
            myTest.Cleanup();
            myLog.RecordMessage("Database Test duration: " + TotalRunTime.Elapsed.TotalMilliseconds.ToString("#,##0") + " ms."); // add results to Result test box
            dr["Total"] = TotalRunTime.Elapsed.TotalMilliseconds; //add total to data row
            myLog.RecordMessage("");
        }

        static public void displayUsage()
        {
            Console.WriteLine(@"SQL Benchmark - Invalid command line argument");
            Console.WriteLine(@"Written by the Microsoft CSS SQL Networking Team");
            Console.WriteLine();
            Console.WriteLine(@"Usage:");
            Console.WriteLine();
            Console.WriteLine(@"   SQLBench.exe [-n number] [-cpu] [[-file ""FolderPath""]...] [[-sql ""ConnectionString""]...] [-output ""FolderPath""]");
            Console.WriteLine();
            Console.WriteLine(@"Examples:");
            Console.WriteLine();
            Console.WriteLine(@"     SQLBench.exe -cpu -output ""c:\temp""                                                  Command line: CPU and Memory tests.");
            Console.WriteLine(@"     SQLBench.exe -cpu -file ""c:\temp"" -file ""\\datastore\files\test""                     Command line: multple tests.");
            Console.WriteLine();
            Console.WriteLine(@"     SQLBench.exe -n 5 -sql ""server=(local);database=northwind;integrated security=sspi""  Command line: run the database test 5 times.");
            Console.WriteLine();
            Console.WriteLine(@"     If no output is defined, SqlTest.txt will be created in the same folder as the executable.");
        }
    }
}
