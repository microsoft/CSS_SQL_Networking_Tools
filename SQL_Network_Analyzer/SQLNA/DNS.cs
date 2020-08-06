// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SQLNA
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Data stored per DNS request/response
    // DNS archtecture - https://technet.microsoft.com/en-us/library/cc772774(v=ws.10).aspx
    //

    class DNS
    {
        //public string srcServerIP;
        public string dnsServerIP;
        public string nameReqested; //Question Name of 'QRecord'
        public uint frameNo;
        //public uint srcPort;
        public string errorMsg=null;
        public string TimeStamp;
        public int errorCode;
        public string ErrorDesc;
        public int QuestionCount;
        public int AnswerCount;
        public int QueryID=0;
        public ConversationData convData;

    }
}
