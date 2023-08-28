// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
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
        const int OPEN_COUNT = 1000;
        const int LOOP_COUNT = 1000;
        public string connstr = "";
        public DBTests(string connStr)
        {
            connstr = connStr;
            if (connstr.ToLower().Contains("pooling") == false) connstr += ";Pooling=false";
        }


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
            for (int a = 0; a < OPEN_COUNT; a++)
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
            //calculate ops per second
            opentotal = OPEN_COUNT * 1000.0 / openconn.Elapsed.TotalMilliseconds;
            closetotal = OPEN_COUNT * 1000.0 / closeconn.Elapsed.TotalMilliseconds;
            
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
            
            for (int a = 0; a < LOOP_COUNT; a++)
            {
                //insert concat string
                connection.Open(); //open connection
                sqlCommand.CommandText = "INSERT INTO P1 (ID,Description) VALUES(" + Convert.ToString(a) + ",'AAAAAAAAAAAAAAAAAAAAAAAAA" + Convert.ToString(a) + "')"; //create sql command
                myInsertwatch.Start(); //start timer
                sqlCommand.ExecuteNonQuery(); //execute query
                myInsertwatch.Stop(); //stop time
                connection.Close(); // close connection
            }
            myInsert = LOOP_COUNT * 1000.0 / myInsertwatch.Elapsed.TotalMilliseconds; // Caclulate ops per second
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
            for(int a = 0; a < LOOP_COUNT; a++)
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
            TotalReadRec = LOOP_COUNT * 1000.0 / ReadRecord.Elapsed.TotalMilliseconds; // calculate operations per second
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
            for (int a = 0; a < LOOP_COUNT; a++)
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
            TotalReadBlob = LOOP_COUNT * 1000.0 / ReadRecord.Elapsed.TotalMilliseconds;

        }
        public void  WriteBlobTest(out double myBlobWrite)
        {
            const int size = 100 * 1024;       // 100k was 16k
            byte[] numArray1 = new byte[size]; //create byte array
            var random = new Random();
            random.NextBytes(numArray1);  // randomize the array so compression doesn't come into play.

            Stopwatch BlobWrite = new Stopwatch(); //Create Timer
            //open connection
            SqlConnection connection = new SqlConnection(connstr); //create SQL Connection
            connection.Open(); //open connection
            SqlCommand sqlCommand;
            for (int a = 0; a < LOOP_COUNT; a++)
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
            myBlobWrite = LOOP_COUNT * 1000.0 / BlobWrite.Elapsed.TotalMilliseconds; // calculate operations per second
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
