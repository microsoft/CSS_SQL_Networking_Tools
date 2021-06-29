// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.IO;
using System.Data.SqlClient;
using System.Data;
using System.Diagnostics;

namespace SQLBench
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Performs a database benchmark test
    //
    class DBTests
    {
        public string connstr = "";
        public DBTests(string connStr)
        {
            connstr = connStr;
            //if (Source == "File")//this is command line
            //{
            //    if (myFile != "")
            //    {
            //        if (File.Exists(myFile))
            //        {
            //            Console.WriteLine(myFile);
            //            ReadFile(myFile);
            //        }
            //        else
            //        {
            //            connstr.Add(myFile);
            //        }
            //    }
            //    else
            //    {
            //        connstr.Add("server=(local);database=Tempdb;Integrated Security=SSPI");
            //    }
            //}
            //if (Source == "TextBox")//this comes from the GUI interface 
            //{
            //    string[] strArray = myFile.Split('\r');
            //    foreach(string a in strArray)
            //    {
            //        connstr.Add(a);
            //    }
            //}
        }
        //private void ReadFile(string myFile)
        //{
        //    //Stream lines from the file to the list 
        //    string line;
        //    StreamReader SR = new StreamReader(myFile);
        //    while((line = SR.ReadLine()) != null)
        //    {
        //            connstr.Add(line);
        //    }
        //}
        public void Test()
        {
            //command line. 
            //output currenct connection string
            Console.WriteLine(connstr);
        }
        public void ConnTest(out double opentotal, out double closetotal)
        {
            //create times
            Stopwatch openconn = new Stopwatch();
            Stopwatch closeconn = new Stopwatch();
            //Open Connection
            SqlConnection connection = new SqlConnection(connstr);
            opentotal = 0.0;
            closetotal = 0.0;
            for (int a = 0; a < 1000; a++)
            {
                // start timers
                //OPen connection 
                //Close connection
                //Stop times
                openconn.Start();
                connection.Open();
                openconn.Stop();
                closeconn.Start();
                connection.Close();
                closeconn.Stop();
            }
            //calculate ops er second
            opentotal = 4000.0 / openconn.Elapsed.TotalMilliseconds*1000;
            closetotal = 4000.0 /closeconn.Elapsed.TotalMilliseconds*1000;
            
        }
        public void InsertRow(out double myInsert)
        {
            //open connection
            SqlConnection connection = new SqlConnection(connstr);
            //create stopwatches
            Stopwatch myInsertwatch = new Stopwatch();

            //Create String to generate table
            try
            {
                //open connection and create a table
                connection.Open();
                new SqlCommand("DROP TABLE P1", connection).ExecuteNonQuery();
            }
            catch (Exception)
            {
                //ProjectData.SetProjectError(ex);
                //ProjectData.ClearProjectError();
            }
            finally
            {
                connection.Close();
            }
            // Create sql query
            string str1 = "CREATE TABLE P1 (ID int, Description NVarchar(50), BLOB VarBinary(MAX))";

            connection.Open();
            SqlCommand sqlCommand = new SqlCommand(str1, connection); //create sql command
            sqlCommand.ExecuteNonQuery(); //execute query
            connection.Close(); // close connection
            
            for (int a = 0; a < 1000; a++)
            {
                //insert concat string
                connection.Open(); //open connection
                sqlCommand.CommandText = "INSERT INTO P1 (ID,Description) VALUES(" + Convert.ToString(a) + ",'AAAAAAAAAAAAAAAAAAAAAAAAA" + Convert.ToString(a) + "')"; //create sql command
                myInsertwatch.Start(); //start timer
                sqlCommand.ExecuteNonQuery(); //execute query
                myInsertwatch.Stop(); //stop time
                connection.Close(); // close connection
            }
            myInsert = 1000.0 / myInsertwatch.Elapsed.TotalMilliseconds* 1000; // Caclulate ops er second
        }
        public void ReadRowsTest(out double TotalReadRec)
        {
            byte[] numArray1 = new byte[16384];
            int integer;
            string str2;
            //open connection
            SqlConnection connection = new SqlConnection(connstr);
            //creat stopwatches
            Stopwatch ReadRecord = new Stopwatch();
            SqlCommand sqlCommand;//create sqlcommand
            for(int a = 0;a<1000;a++)
            {
                connection.Open(); //open connectoin
                sqlCommand = new SqlCommand("SELECT ID,Description FROM P1", connection); //create query
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader();//create and execute query
                ReadRecord.Start();//stop timer
                while (sqlDataReader.Read())
                {   //read through the records from query
                    integer = Convert.ToInt32(sqlDataReader[0]);
                    str2 = Convert.ToString(sqlDataReader[1]);
                }
                ReadRecord.Stop();//stop timer
                sqlDataReader.Close(); // close reader
                connection.Close();//close connection
            }
            TotalReadRec = 1000000.0 / ReadRecord.Elapsed.TotalMilliseconds* 1000.0; // calculate operation per second
        }
        public void ReadBlobTest(out double TotalReadBlob)
        {
            int integer;
            string str2;
            //open connection
            SqlConnection connection = new SqlConnection(connstr);
            //creat stopwatches
            Stopwatch ReadRecord = new Stopwatch();
            SqlCommand sqlCommand; //create SQLcommand
            for (int a = 0; a < 1000; a++)
            {
                connection.Open();//open connection
                sqlCommand = new SqlCommand("SELECT ID,Description, BLOB FROM P1 WHERE ID=" + Convert.ToString(a), connection);//create query
                ReadRecord.Start();
                SqlDataReader sqlDataReader = sqlCommand.ExecuteReader(); //create and exuecute query
                while (sqlDataReader.Read())
                {
                    integer = Convert.ToInt32(sqlDataReader[0]);
                    str2 = Convert.ToString(sqlDataReader[1]);
                    byte[] numArray2 = (byte[])sqlDataReader[2];
                }
                ReadRecord.Stop();
                sqlDataReader.Close();
                connection.Close();
            }
            TotalReadBlob = 1000000.0 / ReadRecord.Elapsed.TotalMilliseconds * 1000.0;

        }
        public void  WriteBlobTest(out double myBlobWrite)
        {
            byte[] numArray1 = new byte[16384]; //crate byte array
            Stopwatch BlobWrite = new Stopwatch(); //Create Timer
            //open connection
            SqlConnection connection = new SqlConnection(connstr); //create SQL Connection
            connection.Open(); //open connection
            SqlCommand sqlCommand;
            for (int a = 0; a < 1000; a++)
            {
                sqlCommand = new SqlCommand( "select * from P1",connection); //create query
                sqlCommand.CommandText = "UPDATE P1 SET BLOB=@BLOB WHERE ID=" + Convert.ToString(a); 
                sqlCommand.Parameters.Add("@BLOB", SqlDbType.Image, numArray1.Length).Value = (object)numArray1;
                BlobWrite.Start();
                sqlCommand.ExecuteNonQuery();
                BlobWrite.Stop();             
                sqlCommand.Parameters.Clear();
            }
            connection.Close();
            myBlobWrite = 1000.0 / BlobWrite.Elapsed.TotalMilliseconds * 1000; // calculate operations per second
        }
        public void Cleanup()
        {
            //drops tabel from database
            SqlConnection connection = new SqlConnection(connstr);
            connection.Open();
            new SqlCommand("Drop table P1", connection).ExecuteNonQuery();
            connection.Close();
        }
    }
}
