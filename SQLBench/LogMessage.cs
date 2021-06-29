// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.IO;

namespace SQLBench
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Wrapper class to log messages
    //

    class LogMessage
    {
        List<string> MessageLog;
        string mySource;
        public LogMessage(string MyProgSource)
        {
            //create  a new List of strings to store messages
            MessageLog = new List<string> { };
            mySource = MyProgSource;
        }
        public void RecordMessage(string Message)
        {
            //add messages to list 
            //if run From Console also print line to screen
              MessageLog.Add(Message);
              if(mySource == "MyConsole")
                  Console.WriteLine(Message);
        }
        public void PrintMessage()
        {   
            //no referances here so might remove this code
            foreach(string a in MessageLog)
            {
                Console.WriteLine(a);
            }
        }
        public void SaveLog(string outFile)
        {
            //Output List to text file
            outFile = outFile + "\\TestLog.txt";
            using (StreamWriter SW = new StreamWriter(outFile))
            {
                foreach (string a in MessageLog)
                {
                    SW.WriteLine(a);
                }
            }
        }

        public string GetMessage()
        {
            //Reteave last sting added to list
            return MessageLog[MessageLog.Count-1];
        }
    }
}
