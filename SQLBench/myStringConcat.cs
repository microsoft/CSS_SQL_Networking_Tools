// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Diagnostics;

namespace SQLBench
{
    class myStringConcat
    {
        //
        // Written by the Microsoft CSS SQL Networking Team
        //
        // Performs a string concatenation benchmark - tests CPU and Memory performance 
        //

        string mystring;
        public myStringConcat()
        {
            mystring = "";
        }
        public String MyConcatination()
        {
            Stopwatch mytimer = new Stopwatch();
            try
            {
                mytimer.Start();
                for (int a = 0; a < 20000; a++)
                {
                    if (mystring.Length <= 2000)
                    {
                        if (((uint)a & 1) <= 0U)
                            mystring += "CCCCCCCCCCCCCCCCCCCCCC";
                        else
                            mystring += "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                    }
                    else
                        mystring = "";
                }
                mytimer.Stop();
            }
            catch (Exception message) { return message.Message; }
            TimeSpan Totaltime = mytimer.Elapsed;
            return Convert.ToString(20000/ Totaltime.TotalMilliseconds);
        }
    }
}
