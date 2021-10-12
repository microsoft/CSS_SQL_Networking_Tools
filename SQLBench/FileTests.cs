// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Diagnostics;
using System.IO;

namespace SQLBench
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Performs a file I/O benchmark test
    //
    class FileTests
    {
        const int RECORD_COUNT = 100000;
        const int RECORD_SIZE = 512;
        const int LOOP_COUNT_A = 500000;
        const int LOOP_COUNT_B = 100;
        
        //Create all the timers 
        Random intrand;
        byte[] array;
        public string path;
        public FileTests()
        {
            intrand = new Random();//create random seed
            array = new byte[RECORD_SIZE];//create byte array of 512   
            path = Environment.CurrentDirectory + @"\test123.bin";   //create path for file manipulation 4
        }
        public string createFile()
        {
            //Create stopwatch to track time
            Stopwatch createfile = new Stopwatch();
            createfile.Start();
            FileStream fileStream1 = System.IO.File.Create(path, RECORD_SIZE, FileOptions.RandomAccess);    //file stream array 
            //loop file stream write
            for(int a = 0; a < RECORD_COUNT; a++)
            {
                fileStream1.Write(array, 0, RECORD_SIZE);
            }
            fileStream1.Close();
            createfile.Stop();
            TimeSpan mytime = createfile.Elapsed; //get time elapsed
            return (RECORD_COUNT * 1000.0f / mytime.TotalMilliseconds).ToString("#,##0");//calculate operations per second
        }
        public string readFile()
        {
            //Read File
            Stopwatch READfile = new Stopwatch();//create timer
            READfile.Start();//Start timer
            FileStream fileStream3 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, RECORD_SIZE, FileOptions.SequentialScan); //reate file stream
            //loop for stream reader
            for (int a = 0; a < RECORD_COUNT; a++)
            {
                fileStream3.Read(array, 0, RECORD_SIZE);
            }
            fileStream3.Close();
            READfile.Stop();
            TimeSpan mytime = READfile.Elapsed;//get time elapsed
            return (RECORD_COUNT * 1000.0f / mytime.TotalMilliseconds).ToString("#,##0");//caclupate operations per second
        }
        public string SequenceWrite()
        {
            //write sequecially
            Stopwatch SeqWritefile = new Stopwatch();//create timer
            SeqWritefile.Start();//start timer
            FileStream fileStream4 = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, RECORD_SIZE, FileOptions.SequentialScan);//create strim with sequential option
            //loop writing a file sequentially
            for (int a = 0; a < RECORD_COUNT; a++)
            {
                fileStream4.Write(array, 0, RECORD_SIZE);
            }
            fileStream4.Close();//close stream
            SeqWritefile.Stop();//stop timer
            TimeSpan mytime = SeqWritefile.Elapsed;//get elapsed time
            return (RECORD_COUNT * 1000.0f / mytime.TotalMilliseconds).ToString("#,##0");//calculate operations per second
        }
        public string randomRead()
        {
            //Random File Reads.
            Stopwatch RndReadfile = new Stopwatch();//create timer
            RndReadfile.Start();//Start timer
            FileStream fileStream5 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, RECORD_SIZE, FileOptions.RandomAccess);//create stream with random access option
            //loop while randomly reading parts of the file
            for (int a = 0; a < RECORD_COUNT; a++)
            {
                long SeekPos = RECORD_SIZE * intrand.Next(RECORD_COUNT);   //(long)Math.Round((512f * (double)(intrand.Next() * 100000f)));
                fileStream5.Seek(SeekPos, SeekOrigin.Begin);
                fileStream5.Read(array, 0, RECORD_SIZE);
            }
            fileStream5.Close();
            RndReadfile.Stop();
            TimeSpan mytime = RndReadfile.Elapsed;
            return (RECORD_COUNT * 1000.0f / mytime.TotalMilliseconds).ToString("#,##0");
        }
        public string randomWrite()
        {
            Stopwatch RndWritefile = new Stopwatch();
            RndWritefile.Start();
            FileStream fileStream6 = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, RECORD_SIZE, FileOptions.RandomAccess);
            for (int a = 0; a < RECORD_COUNT; a++)
            {
                long SeekPos = RECORD_SIZE * intrand.Next(RECORD_COUNT);   //(long)Math.Round((512f * (double)(intrand.Next() * 100000f)));
                fileStream6.Seek(SeekPos, SeekOrigin.Begin);
                fileStream6.Write(array, 0, RECORD_SIZE);
            }
            fileStream6.Close();
            RndWritefile.Stop();
            TimeSpan mytime = RndWritefile.Elapsed;
            return (RECORD_COUNT * 1000.0f / mytime.TotalMilliseconds).ToString("#,##0");
        }
    }
}
