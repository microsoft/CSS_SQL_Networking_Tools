// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Data;
using System.IO;

namespace SQLBench
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Creates a DataSet object into which goes the performance data to be displayed on the grid or written to file
    //
    class GenerateDataSet
    {
        public DataSet dsStats;
        public bool mathtest;
        public bool filetest;
        public bool dbtest;
        public GenerateDataSet()
        {
            //Create Dataset to store Statistical data
            dsStats = new DataSet();
            DataTable table1 = new DataTable("Memory");
            table1.Columns.Add("Description", typeof(string));
            table1.Columns.Add("IMath", typeof(double)).Caption = "Integer Math";
            table1.Columns.Add("FMath", typeof(double)).Caption = "Floating Point Math";
            table1.Columns.Add("DMath", typeof(double)).Caption = "Decimal Math";
            table1.Columns.Add("SCat", typeof(double)).Caption = "String Concatenation";
            table1.Columns.Add("TreeCreate", typeof(double)).Caption = "Object Tree Creation";
            table1.Columns.Add("TraverseInOrder", typeof(double)).Caption = "Object Tree Traversal In Order";
            table1.Columns.Add("TraversePreOrder", typeof(double)).Caption = "Object Tree Traversal Pre Order";
            table1.Columns.Add("TraversePostOrder", typeof(double)).Caption = "Object Tree Traversal Post Order";
                dsStats.Tables.Add(table1);
            DataTable table2 = new DataTable("File");
            table2.Columns.Add("Description", typeof(string));
            table2.Columns.Add("Path", typeof(string)).Caption = "File Path";
            table2.Columns.Add("Create", typeof(double)).Caption = "File Creation Time (ms)";
            table2.Columns.Add("SRead", typeof(double)).Caption = "Sequential Read";
            table2.Columns.Add("SWrite", typeof(double)).Caption = "Sequential Write";
            table2.Columns.Add("RRead", typeof(double)).Caption = "Random Read";
            table2.Columns.Add("RWrite", typeof(double)).Caption = "Random Write";
            table2.Columns.Add("Total", typeof(double)).Caption = "Total Time (ms)";
                dsStats.Tables.Add(table2);
            DataTable table3 = new DataTable("Database");
            table3.Columns.Add("Description", typeof(string));
            table3.Columns.Add("Conn", typeof(string)).Caption = "Connection String";
            table3.Columns.Add("Open", typeof(double)).Caption = "Connection Open";
            table3.Columns.Add("Close", typeof(double)).Caption = "Connection Close";
            table3.Columns.Add("Insert", typeof(double)).Caption = "Insert Row";
            table3.Columns.Add("ReadRows", typeof(double)).Caption = "Read Rows";
            table3.Columns.Add("ReadBLOB", typeof(double)).Caption = "Read BLOB";
            table3.Columns.Add("WriteBLOB", typeof(double)).Caption = "Write BLOB";
            table3.Columns.Add("Total", typeof(double)).Caption = "Total Time (ms)";
                dsStats.Tables.Add(table3);
        }

        public void GenerateCSVFile(int numberofrows)
        {
            for (int a =0; a < dsStats.Tables.Count; a++)
            {
                switch (a)
                {
                    case 0:
                        if (mathtest == true)
                        {
                            //Add Statics Rows
                            AddStatisticRows(a);
                            //Calculate Averages
                            calculate_MinMaxAve(numberofrows, a);
                        }
                        break;
                    case 1:
                        if (filetest == true)
                        {
                            //Add Statics Rows
                            AddStatisticRows(a);
                            //Calculate Averages
                            calculate_MinMaxAve(numberofrows, a);
                        }
                        break;
                    case 2:
                        if (dbtest == true)
                        {
                            //Add Statics Rows
                            AddStatisticRows(a);
                            //Calculate Averages
                            calculate_MinMaxAve(numberofrows, a);
                        }
                        break;
                    default:
                        break;
                }
            }
           
        }
        public void DataOutput(string outFile)
        {
            //Generate column Headers.          
            string MathoutFile;
            string FilesoutFile;
            string DBsoutFile;
            if (outFile != "")
            {
                MathoutFile = outFile + "\\MathTests.csv";
                FilesoutFile = outFile + "\\File.csv";
                DBsoutFile = outFile + "\\Database.csv";
            }
            else
            {
                MathoutFile = Environment.CurrentDirectory + "\\MathTests.csv";
                FilesoutFile = Environment.CurrentDirectory + "\\File.csv";
                DBsoutFile = Environment.CurrentDirectory + "\\Database.csv";
            }
            //Math Tests
            Stream myStream = new FileStream(MathoutFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            MathHeader(myStream);
            MathData(MathoutFile);
            //Files tests          
            Stream myFileStream = new FileStream(FilesoutFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            FileHeader(myFileStream);
            FileData(FilesoutFile);
            //DBTests
            Stream myDBStream = new FileStream(DBsoutFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            DBHeader(myDBStream);
            dbData(DBsoutFile);
        }
        private void AddStatisticRows(int a)
        {
            //Add the number of rows for statitics  
            //Set the Decription of column for each new row
            //Add new rows to table
                DataRow newrowmin = dsStats.Tables[a].NewRow();
                DataRow newrowmax = dsStats.Tables[a].NewRow();
                DataRow newrowavg = dsStats.Tables[a].NewRow();
                DataRow newrowrange = dsStats.Tables[a].NewRow();
                DataRow newrowstdiv = dsStats.Tables[a].NewRow();
                DataRow newrowScore = dsStats.Tables[a].NewRow();
                newrowmin["Description"] = "Min";
                newrowmax["Description"] = "Max";
                newrowavg["Description"] = "Average";
                newrowstdiv["Description"] = "Std. Deviation";
                newrowrange["Description"] = "Range";
                newrowScore["Description"] = "Score (100 Base)";
                dsStats.Tables[a].Rows.Add(newrowmin);
                dsStats.Tables[a].Rows.Add(newrowmax);
                dsStats.Tables[a].Rows.Add(newrowrange);
                dsStats.Tables[a].Rows.Add(newrowavg);
                dsStats.Tables[a].Rows.Add(newrowstdiv);
                dsStats.Tables[a].Rows.Add(newrowScore);
        }
        private void calculate_MinMaxAve(int NumberofRows, int t)
        {
            //Caclulates the staticts 
            double Max = 0.0;
            double Min = 1000000000000.0;
            double Average = 0.0;
            int Starting = 1;
                //check if there is at least 1 row in the table
                if (dsStats.Tables[t].Rows.Count > 0)
                {
                    //if Tables are Files and Database start at column 2 else start at Column 1
                    if (t == 1 || t == 2)
                        Starting = 2;
                    else
                        Starting = 1;
                    for (int a = Starting; a < dsStats.Tables[t].Columns.Count; a++)
                    {
                        //Reset each column
                        Average = 0.0; //set the average to 0.0 before each column being calculated
                        if (dsStats.Tables[t].Rows[0][a] != DBNull.Value)
                        { 
                            Max = Convert.ToDouble(dsStats.Tables[t].Rows[0][a]); //set the initial Minimum to the first row in the column
                            Min = Convert.ToDouble(dsStats.Tables[t].Rows[0][a]); //set the inital Maximum to the first row in the column
                        }
                        for (int b = 0; b < NumberofRows; b++)
                        {
                            if (dsStats.Tables[t].Rows[b][a] != DBNull.Value)
                            {
                                //Add to the total average calulation
                                Average += Convert.ToDouble(dsStats.Tables[t].Rows[b][a]);
                                if (Min > Convert.ToDouble(dsStats.Tables[t].Rows[b][a])) //Determin if the new value is smaller than the current value
                                    Min = Convert.ToDouble(dsStats.Tables[t].Rows[b][a]); //If value is smaller set Min to the new value
                                if (Max < Convert.ToDouble(dsStats.Tables[t].Rows[b][a])) //Determin  if the new value is larget than current value
                                    Max = Convert.ToDouble(dsStats.Tables[t].Rows[b][a]); //If the value is larger set Max with the new value
                            }
                        }
                        dsStats.Tables[t].Rows[NumberofRows][a] = Min; //Add value to dataset table
                        dsStats.Tables[t].Rows[NumberofRows + 1][a] = Max; //Add value to dataset table
                        dsStats.Tables[t].Rows[NumberofRows + 2][a] = Max - Min; //Calculate the differance between Min and Max then add it to the dataset table
                        dsStats.Tables[t].Rows[NumberofRows + 3][a] = Average / NumberofRows; //calculate the mean then add the value to the dataset table
                        dsStats.Tables[t].Rows[NumberofRows + 4][a] = CalculateVeriances(t, a, NumberofRows, Average / NumberofRows); //Calculate the standard diviation then add it to the dataset table 
                        dsStats.Tables[t].Rows[NumberofRows + 5][a] = IntmathBase(t, a, Average / NumberofRows, NumberofRows); //Calculate the weighted value against the base line machine then add the values to the dataset table
                    }
                }
        }
        private double CalculateVeriances(int t, int a, int rowcount, double theAverage)
        {
            //Calculate the Veriance for Memory
            double SumOfSquares = 0.0;
            //lopps through to calculate the square of each data point
            for (int c = 0; c < rowcount-1; c++)
            {
                SumOfSquares += (Convert.ToDouble(dsStats.Tables[t].Rows[c][a])-theAverage)* (Convert.ToDouble(dsStats.Tables[t].Rows[c][a]) - theAverage);
            }
            //calculates the square root of the averages
            //Returns to the parent function the Standard Deviation
            return Math.Sqrt(SumOfSquares/(double)(rowcount -1));
        }
        private int IntmathBase(int T, int myCol, double Average, int recCount)
        {
            //Intager Math Base is based off of a Azure VM with 8 gigs of ram and 2 processors.
            //List of the Bench mark average staticstics (sample size is 4)
            double intmath = 20849449.11;
            double floatmath = 135920301.78;
            double decmath = 9626117.54;
            double strcat = 293251.36;
            double Treecreate = 39940617868.12;
            double treetransinorder = 12303431875.62;
            double treetranspreorder = 13573329056.72;
            double treetranspostorder = 13567740514.54;
            double myOpen = 103.75;
            double myClose = 24;
            double myInsert = 377.75;
            double myReadRows = 1071.5;
            double myReadBlobs = 355.5;
            double myWriteBlob = 1187;
            double myTotal = 3149.2005;
            double createtime = 242.68;
            double seqread = 1939932.49;
            double seqwrite = 444895.17;
            double randseekread = 1032058.63;
            double randseekwrite = 7309.7;
            double testdurations = 3408.22;
            int result = 0;
            //Set the result based on the column being calculated
            switch(T)
            {
                case 0:   // CPU / Math test
                    switch (myCol)
                    {
                        case 1:
                            result = Convert.ToInt32(((Average / intmath) * 100));
                            break;
                        case 2:
                            result = Convert.ToInt32(((Average / floatmath) * 100));
                            break;
                        case 3:
                            result = Convert.ToInt32(((Average / decmath) * 100));
                            break;
                        case 4:
                            result = Convert.ToInt32(((Average / strcat) * 100));
                            break;
                        case 5:
                            result = Convert.ToInt32(((Average / Treecreate) * 100));
                            break;
                        case 6:
                            result = Convert.ToInt32(((Average / treetransinorder) * 100));
                            break;
                        case 7:
                            result = Convert.ToInt32(((Average / treetranspreorder) * 100));
                            break;
                        case 8:
                            result = Convert.ToInt32(((Average / treetranspostorder) * 100));
                            break;
                        default:
                            break;
                    }
                    break;
                case 1:   // File test
                    switch (myCol)
                    {
                        case 2:
                            result = Convert.ToInt32(((Average / createtime) * 100));
                            break;
                        case 3:
                            result = Convert.ToInt32(((Average / seqread) * 100));
                            break;
                        case 4:
                            result = Convert.ToInt32(((Average / seqwrite) * 100));
                            break;
                        case 5:
                            result = Convert.ToInt32(((Average/ randseekread) * 100));
                            break;
                        case 6:
                            result = Convert.ToInt32(((Average / randseekwrite) * 100));
                            break;
                        case 7:
                            result = Convert.ToInt32(((Average / testdurations) * 100));
                            break;
                        default:
                            break;
                    }
                    break;
                case 2:  // SQL test
                    switch (myCol)
                    {
                        case 2:
                            result = Convert.ToInt32(((Average / myOpen) * 100));
                            break;
                        case 3:
                            result = Convert.ToInt32(((Average / myClose) * 100));
                            break;
                        case 4:
                            result = Convert.ToInt32((( Average / myInsert) * 100));
                            break;
                        case 5:
                            result = Convert.ToInt32(((Average / myReadRows) * 100));
                            break;
                        case 6:
                            result = Convert.ToInt32(((Average / myReadBlobs) * 100));
                            break;
                        case 7:
                            result = Convert.ToInt32(((Average / myWriteBlob) * 100));
                            break;
                        case 8:
                            result = Convert.ToInt32(((Average / myTotal) * 100));
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
            //return the wieghted score 
            return result;
        }
      
        private void MathHeader(Stream myStream)
        {
            //Set the Column Headers to print
            string Header = "Description, ";
            Header += "Integer Math(ops / sec),";
            Header += "Floating Point(ops/ sec),";
            Header += "Decimal Math(ops/ sec),";
            Header += "String Concat. (ops / sec),";
            Header += "Tree Creation(ops/ sec),";
            Header += "Tree TransversalIn Order(ops / sec),";
            Header += "Tree Transversal Pre Order(ops/ sec),";
            Header += "Tree Transversal Post Order";
            using (StreamWriter SW = new StreamWriter(myStream))
            {
                SW.WriteLine(Header);
            }
        }
        private void MathData(string outFile)
        {
            //Write the dataset to a CSV File
            using (StreamWriter SW = File.AppendText(outFile))
            {            
                foreach (DataRow dr in dsStats.Tables["Memory"].Rows)
                {
                     SW.WriteLine(dr["Description"] + "," + dr["IMath"].ToString() + "," + dr["FMath"].ToString() + "," + dr["DMath"].ToString() + "," + dr["SCat"].ToString()
                                 + ","+dr["TreeCreate"].ToString() + ","+dr["TraversePreOrder"].ToString() + ","+dr["TraversePreOrder"].ToString() 
                                 + ","+dr["TraversePostOrder"].ToString());
                }               
            }
        }

        private void FileHeader(Stream myStream)
        {   //Set the Column Headers to print
            string Header = "Description,";
            Header += "File Path,";
            Header += "Create Time (ms),";
            Header += "Sequence Read (rows/sec),";
            Header += "Sequence Write (rows/sec),";
            Header += "Random Seek/Read (ops/sec),";
            Header += "Random Seek/Writes (ops/sec),";
            Header += "Test Duration(sec";
            using (StreamWriter SW = new StreamWriter(myStream))
            {
                SW.WriteLine(Header);
            }
        }
        
        private void FileData(string outFile)
        {
            //Write the dataset to a CSV File

            using (StreamWriter SW = File.AppendText(outFile))
            {
                foreach (DataRow dr in dsStats.Tables["File"].Rows)
                { 
                    SW.WriteLine(dr["Description"] + "," +
                                 dr["Path"].ToString() + "," +
                                 ToFormattedDouble(dr["Create"]) + "," +
                                 ToFormattedDouble(dr["SRead"]) + ", " +
                                 ToFormattedDouble(dr["SWrite"]) + "," +
                                 ToFormattedDouble(dr["RRead"]) + "," +
                                 ToFormattedDouble(dr["RWrite"]) + "," +
                                 ToFormattedDouble(dr["Total"]));
                }
            }
        }

        private void DBHeader(Stream myStream)
        {
            //Set the Column Headers to print
            string Header = "Description,";
            Header += "Conn,";
            Header += "Open,";
            Header += "Close,";
            Header += "Insert,";
            Header += "ReadRows,";
            Header += "ReadBLOB,";
            Header += "WriteBLOB,";
            Header += "Total";
            using (StreamWriter SW = new StreamWriter(myStream))
            {
                SW.WriteLine(Header);
            }
        }

        private void dbData(string outFile)
        {
            //Write the dataset to a CSV File
            using (StreamWriter SW = File.AppendText(outFile))
            {
                foreach (DataRow dr in dsStats.Tables["Database"].Rows)
                {
                    SW.WriteLine(dr["Description"] + "," + dr["Conn"].ToString() + "," + dr["Open"].ToString() + "," + dr["Close"].ToString() + "," + dr["Insert"].ToString()
                                + "," + dr["ReadRows"].ToString() + "," + dr["ReadBLOB"].ToString() + "," + dr["WriteBLOB"].ToString()
                                + "," + dr["Total"].ToString());
                }
            }
        }

        private string ToFormattedDouble(object o, string Format = "#.##")
        {
            string s = "";
            try
            {
                s = Convert.ToDouble(o).ToString(Format);
            }
            catch (Exception) { /* do nothing, return empty string */}
            return s;
        }
    }
}
