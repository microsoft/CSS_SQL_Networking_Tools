// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;
using System.Data;
using System.Data.SqlClient;
using System.Data.Odbc;
using System.Data.OleDb;

namespace DBTest
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Performs database connection tests, and optionally runs a command and returns rows.
    // The connection and command can be repeated to perform a reliability test.
    //
    // The timing and number of rows are displayed to the console. The first 10 rows are displayed by default, as well.
    // If a DataSet is returned, the approximate size in memory is also displayed. Not recommended for large tables.
    //
    // See displayUsage for more details.
    //
    // Windows .NET Framework 4.5 is required
    //

    class Program
    {
        static string ProviderType     = "SQLCLIENT";  // SQLCLIENT, ODBC, OLEDB
        static string ConnectionString = "";
        static string CommandString    = "";
        static int    CommandTimeout   = 30;
        static int    RowsToDisplay    = 10;
        static int    RepeatCount      =  1;
        static int    DelaySec         =  1;
        static bool   StopOnError      = false;
        static string CursorType       = "FIREHOSE";  // FIREHOSE, DATASET, NONE (executing a non-row-returning command)


        static void Main(string[] args)
        {
            //
            // Set command-line rules and parse the command-line
            //

            CommandLineParser cp = new CommandLineParser();
            cp.AddRule(new ArgRule("type", true, false, true, false));            // provider type is optional; SqlClient is assumed
            cp.AddRule(new ArgRule("connect", true, false, true, true));          // connection string is required
            cp.AddRule(new ArgRule("command", true, false, true, false));         // command is optional
            cp.AddRule(new ArgRule("timeout", true, false, true, false));         // command timeout is optional; 30 seconds is assumed; 0 = infinite
            cp.AddRule(new ArgRule("cursor", true, false, true, false));          // cursor type is optional; Firehose is assumed
            cp.AddRule(new ArgRule("top", true, false, true, false));             // rows to display is optional; -1 (all) is assumed
            cp.AddRule(new ArgRule("repeat", true, false, true, false));          // repeat count is optional; 1 is assumed
            cp.AddRule(new ArgRule("delay", true, false, true, false));           // delay (sec) between repetitions is optional; 1 is assumed
            cp.AddRule(new ArgRule("stoponerror", false, false, true, false));    // stop on error has no arguments and is optional

            string ruleViolation = cp.Parse(args);

            if (ruleViolation != "")
            {
                Console.WriteLine("Bad arguments: " + ruleViolation);
                displayUsage();
                return;           // exit the application
            }
            else  // for case-insensitive argument names, use lower-case to match
            {
                string value = "";
                ArrayList values = null;

                ProviderType = cp.GetArgOrBlank("type", "SqlClient").ToUpper();   // argument is optional with a default value
                if (ProviderType != "SQLCLIENT" && ProviderType != "ODBC" && ProviderType != "OLEDB")
                {
                    Console.WriteLine("The provider type must be SqlClient, ODBC, or OLEDB.");
                    displayUsage();
                    return;
                }
                ConnectionString = cp.GetArgOrBlank("connect");                // argument is required
                CommandString = cp.GetArgOrBlank("command");                      // argument is optional
                value = cp.GetArgOrBlank("timeout", "30");                        // argument is optional with a default value
                if (int.TryParse(value, out CommandTimeout) == false || CommandTimeout < 0)
                {
                    Console.WriteLine("The timeout vaue must be numeric and 0 or higher.");
                    displayUsage();
                    return;
                }
                CursorType = cp.GetArgOrBlank("cursor", "Firehose").ToUpper();    // argument is optional with a default value
                if (CursorType != "FIREHOSE" && CursorType != "DATASET" && CursorType != "NONE")
                {
                    Console.WriteLine("The cursor type must be FireHose, DataSet, or None.");
                    displayUsage();
                    return;
                }
                value = cp.GetArgOrBlank("top", "10");                            // argument is optional with a default value
                if (int.TryParse(value, out RowsToDisplay) == false || RowsToDisplay < -1)
                {
                    Console.WriteLine("The top vaue must be numeric and -1 or higher.");
                    displayUsage();
                    return;
                }
                value = cp.GetArgOrBlank("repeat", "1");                          // argument is optional with a default value
                if (int.TryParse(value, out RepeatCount) == false || RepeatCount < 1)
                {
                    Console.WriteLine("The repeat vaue must be numeric and 1 or higher.");
                    displayUsage();
                    return;
                }
                value = cp.GetArgOrBlank("delay", "1");                           // argument is optional with a default value
                if (int.TryParse(value, out DelaySec) == false || DelaySec < 1)
                {
                    Console.WriteLine("The delay vaue must be numeric and 1 or higher.");
                    displayUsage();
                    return;
                }
                values = cp.GetArgs("stoponerror");
                if (values.Count != 0) StopOnError = true;
            }

            //
            // Print the header
            //

            System.Security.Principal.WindowsIdentity w = System.Security.Principal.WindowsIdentity.GetCurrent();

            Console.WriteLine($"Database Test v{System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString()}");
            Console.WriteLine($"Run on: {DateTime.Now.ToString("MM/dd/yyyy hh:mm:ss tt")}");
            Console.WriteLine($"Run by: {w.Name}");
            Console.WriteLine();
            Console.WriteLine($"Command Line Arguments: {string.Join(" ", args)}");
            Console.WriteLine($"Provider Type:          {ProviderType}");
            if (CommandString != "")
            {
                Console.WriteLine($"Command Timeout:        {(CommandTimeout == 0 ? "Infinite" : CommandTimeout.ToString() + " seconds")}");
                Console.WriteLine($"Cursor Type:            {CursorType}");
                switch (CursorType)
                {
                    case "NONE":
                        Console.WriteLine($"Rows to Display:        N/A");
                        break;
                    case "DATASET":
                        Console.WriteLine($"Rows to Display:        {(RowsToDisplay == -1 ? "All" : RowsToDisplay.ToString())}");
                        break;
                    case "FIREHOSE":
                        Console.WriteLine($"Rows to Display:        None");
                        break;
                }
            }
            if (RepeatCount > 1)
            {
                Console.WriteLine($"Test Runs:              {RepeatCount}");
                Console.WriteLine($"Delay Between Runs:     {(DelaySec == 1 ? "1 second" : DelaySec.ToString() + " seconds")}");
                Console.WriteLine($"Stop if Errors:         {(StopOnError ? "Yes" : "No")}");
            }
            Console.WriteLine();

            //
            // Run the tests
            //

            for (int i = 0; i < RepeatCount; i++)
            {
                if (i > 0) System.Threading.Thread.Sleep(DelaySec * 1000);
                bool success = DatabaseTest();
                if (!success && StopOnError) break;
            }
            Console.WriteLine("All Tests Complete.");
        }

        static public void displayUsage()
        {
            Console.WriteLine(@"Database Connection Test - Invalid command line arguments");
            Console.WriteLine();
            Console.WriteLine(@"USAGE:");
            Console.WriteLine();
            Console.WriteLine(@"     DBTEST [-type SqlClient|ODBC|OLEDB] -connect ""connectionstring""");
            Console.WriteLine(@"            [-command ""command""] [-timeout seconds] [-cursor Firehose|DataSet|None] -top rows-to-display");
            Console.WriteLine(@"            [-repeat n] [-delay seconds] [-stopOnError]");
            Console.WriteLine();
            Console.WriteLine(@"     Default type    = SqlClient");
            Console.WriteLine(@"     Default timeout = 30 seconds (0 = infinite CommandTimeout)");
            Console.WriteLine(@"     Default cursor  = Firehose");
            Console.WriteLine(@"     Default top     = 10 (all rows = -1) - applies to DataSet cursor only");
            Console.WriteLine(@"     Default repeat  =  1");
            Console.WriteLine(@"     Default delay   =  1");
            Console.WriteLine();
            Console.WriteLine(@"     -stopOnError terminates repeated commands after the first error");
            Console.WriteLine();
            Console.WriteLine(@"EXAMPLES:");
            Console.WriteLine();
            Console.WriteLine(@"     DBTEST -connect ""server=SQLProd01;database=NorthWind;integrated security=sspi"" -command ""select * from customers""");
            Console.WriteLine(@"     DBTEST -type ODBC -connect ""DSN=Accounting;trusted_connection=yes"" -command ""select * from customers"" -top 20");
            Console.WriteLine(@"     DBTEST -type OLEDB -connect ""Provider=SQLNCLI11;Data Source=SQLProd01;Initial Catalog=NorthWind;Integrated Security=SSPI;OLE DB Services=-4"" -repeat 100 -stoponerror");
            Console.WriteLine();
        }

        static public bool DatabaseTest()  // returns true if successful
        {
            IDbConnection cn = null;
            IDbDataAdapter da = null;

            LogMessage("Beginning Test ...");

            try
            {
                switch (ProviderType)
                {
                    case "SQLCLIENT":
                        using (cn = new SqlConnection(ConnectionString))
                        {
                            cn = new SqlConnection(ConnectionString);
                            da = new SqlDataAdapter(CommandString, (SqlConnection)cn);
                            GenericConnectionTest(cn, da);
                        }
                        break;
                    case "ODBC":
                        using (cn = new OdbcConnection(ConnectionString))
                        {
                            cn = new OdbcConnection(ConnectionString);
                            da = new OdbcDataAdapter(CommandString, (OdbcConnection)cn);
                            GenericConnectionTest(cn, da);
                        }
                        break;
                    case "OLEDB":
                        using (cn = new OleDbConnection(ConnectionString))
                        {
                            cn = new OleDbConnection(ConnectionString);
                            da = new OleDbDataAdapter(CommandString, (OleDbConnection)cn);
                            GenericConnectionTest(cn, da);
                        }
                        break;
                }
                Console.WriteLine("Test Completed.");
                Console.WriteLine();  // separator between runs
                return true;
            }
            catch (Exception ex)
            {
                LogMessage("***** There was an exception thrown during the test *****");
                LogMessage(ex.Message);
                LogMessage(ex.StackTrace);
                Console.WriteLine();  // separator between runs
                return false;
            }
        }

        public static void GenericConnectionTest(IDbConnection cn, IDbDataAdapter da) // exceptions handled in the caller
        {

            IDbCommand cmd = null;
            IDataReader dr = null;
            DataSet ds = null;
            DataTable dt = null;
            DataRow row = null;

            DateTime startTime;
            int iCol = 0;
            long ms = 0, rowsRead = 0;
            long initialMemory = 0, finalMemory = 0;

            startTime = DateTime.Now;
            cn.Open();
            ms = (long)DateTime.Now.Subtract(startTime).TotalMilliseconds;
            LogMessage($"Connected successfully in {ms} milliseconds.");
            if (CommandString != "")
            {
                cmd = cn.CreateCommand();
                cmd.CommandText = CommandString;
                cmd.CommandTimeout = CommandTimeout;
                switch (CursorType)
                {
                    case "NONE":
                        startTime = DateTime.Now;
                        cmd.ExecuteNonQuery();
                        ms = (long)DateTime.Now.Subtract(startTime).TotalMilliseconds;
                        LogMessage($"Executed command successfully in {ms} milliseconds. No rows read.");
                        break;
                    case "DATASET":
                        ds = new DataSet();
                        GC.Collect();
                        initialMemory = GC.GetTotalMemory(true);
                        startTime = DateTime.Now;
                        da.Fill(ds);
                        ms = (long)DateTime.Now.Subtract(startTime).TotalMilliseconds;
                        if (ds.Tables.Count > 0) rowsRead = ds.Tables[0].Rows.Count;
                        LogMessage($"Executed command and filled DataSet successfully in {ms} milliseconds. {rowsRead} rows read.");
                        // memory used - have to reverse-engineer DiagClient43.exe
                        GC.Collect();
                        finalMemory = GC.GetTotalMemory(true);
                        LogMessage($"Approximate memory usage: {finalMemory.ToString("#,##0")} bytes");
                        // display rows
                        if (RowsToDisplay != 0)
                        {
                            dt = ds.Tables[0];
                            int colCount = dt.Columns.Count;
                            string[] colNames = new string[colCount];
                            string[] colValues = null;
                            row = null;
                            iCol = 0;
                            foreach (DataColumn dc in dt.Columns)
                            {
                                colNames[iCol] = dc.ColumnName + ":L";
                                iCol++;
                            }
                            ReportFormatter rf = new ReportFormatter();
                            rf.SetColumnNames(colNames);

                            int rows2disp = RowsToDisplay == -1 ? dt.Rows.Count : RowsToDisplay;
                            for (int r = 0; r < rows2disp; r++)
                            {
                                row = dt.Rows[r];
                                iCol = 0;
                                colValues = new string[colCount];
                                foreach (DataColumn dc in dt.Columns)
                                {
                                    colValues[iCol] = row[iCol] == DBNull.Value ? "" : row[iCol].ToString();
                                    iCol++;
                                }
                                rf.SetcolumnData(colValues);
                            }
                            Console.WriteLine();
                            Console.WriteLine(rf.GetHeaderText());
                            Console.WriteLine(rf.GetSeparatorText());
                            for (int i = 0; i < rf.GetRowCount(); i++)
                            {
                                Console.WriteLine(rf.GetDataText(i));
                            }
                            Console.WriteLine();
                        }
                        break;
                    case "FIREHOSE":
                        int iRows = 0;
                        startTime = DateTime.Now;
                        dr = cmd.ExecuteReader();
                        while (dr.Read())
                        {
                            iRows++;
                            // do nothing - throw the rows away
                        }
                        dr.Close();
                        ms = (long)DateTime.Now.Subtract(startTime).TotalMilliseconds;
                        LogMessage($"Executed command and streamed the rows in {ms} milliseconds. {iRows} rows read.");
                        break;
                }
            }
        }

        static public void DisplayDataSetRows(DataSet ds, int RowsToDisplay)
        {

        }

        static public void LogMessage(string Message)
        {
            Console.WriteLine(GetLogTime() + "  " + Message);
        }

        static public string GetLogTime()
        {
            return DateTime.Now.ToString("MM/dd/yyyy hh:mm:ss.fffffff tt");
        }
    }
}
