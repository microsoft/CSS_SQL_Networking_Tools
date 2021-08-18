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
        //Create all the timers 
        Random intrand;
        byte[] array;
        public string path;
        public FileTests()
        {
            intrand = new Random();//create random seed
            array = new byte[512];//create byte array of 512   
            path = Environment.CurrentDirectory + "\\test123.bin";//create path for file manipulation 4
        }
        public string createFile()
        {
            //Create stopwatch to track time
            Stopwatch createfile = new Stopwatch();
            createfile.Start();
            FileStream fileStream1 = System.IO.File.Create(path, 512, FileOptions.RandomAccess);//file stream array 
            //loop file stream write
            for(int a =0;a<100000;a++)
            {
                fileStream1.Write(array, 0, 512);
            }
            fileStream1.Close();
            createfile.Stop();
            TimeSpan mytime = createfile.Elapsed; //get time elapsed
            return (mytime.TotalMilliseconds / 5.0).ToString("#,##0");//calculate operations er second
        }
        public string readFile()
        {
            //Read File
            Stopwatch READfile = new Stopwatch();//create timer
            READfile.Start();//Start timer
            FileStream fileStream3 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, 512, FileOptions.SequentialScan); //reate file stream
            //loop for stream reader
            for (int a = 0; a < 100000; a++)
            {
                fileStream3.Read(array, 0, 512);
            }
            fileStream3.Close();
            READfile.Stop();
            TimeSpan mytime = READfile.Elapsed;//get time elapsed
            return (500000.0/mytime.TotalMilliseconds * 1000.0).ToString("#,##0");//caclupate operations per second
        }
        public string SequenceWrite()
        {
            //write sequecially
            Stopwatch SeqWritefile = new Stopwatch();//create timer
            SeqWritefile.Start();//start timer
            FileStream fileStream4 = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 512, FileOptions.SequentialScan);//create strim with sequential option
            //loop writing a file sequentially
            for (int a = 0; a < 100000; a++)
            {
                fileStream4.Write(array, 0, 512);
            }
            fileStream4.Close();//close stream
            SeqWritefile.Stop();//stop timer
            TimeSpan mytime = SeqWritefile.Elapsed;//get elapsed time
            return (500000.0 / mytime.TotalMilliseconds*1000.0).ToString("#,##0");//calculate operations per second
        }
        public string randomRead()
        {
            //Random File Reads.
            Stopwatch RndReadfile = new Stopwatch();//create timer
            RndReadfile.Start();//Start timer
            FileStream fileStream5 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None, 512, FileOptions.RandomAccess);//create stream with random access option
            //loop while randomly reading parts of the file
            for (int a = 0; a < 100000; a++)
            {
                fileStream5.Seek((long)Math.Round((512f * (double)(intrand.Next() * 100000f))), SeekOrigin.Begin);
                fileStream5.Read(array, 0, 512);
            }
            fileStream5.Close();
            RndReadfile.Stop();
            TimeSpan mytime = RndReadfile.Elapsed;
            return (5000.0 / mytime.TotalMilliseconds*1000.0).ToString("#.##0");
        }
        public string randomWrite()
        {
            Stopwatch RndWritefile = new Stopwatch();
            RndWritefile.Start();
            FileStream fileStream6 = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 512, FileOptions.RandomAccess);
            for (int a = 0; a < 100; a++)
            {
                fileStream6.Seek((long)Math.Round((512f * (double)(intrand.Next() * 100000f))), SeekOrigin.Begin);
                fileStream6.Write(array, 0, 512);
            }
            fileStream6.Close();
            RndWritefile.Stop();
            TimeSpan mytime = RndWritefile.Elapsed;
            return (5000.0 / mytime.TotalMilliseconds*1000.0).ToString("#.##0");
        }
    }
}
