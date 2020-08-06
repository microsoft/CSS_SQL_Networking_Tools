// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Storage for SQL Browser request / response
    // Helper function to find an existing conversation to be added to
    //

    class SSRPData
    {
        public uint sqlIP = 0;
        public ulong sqlIPHi = 0;
        public ulong sqlIPLo = 0;
        public bool isIPV6 = false;
        public ushort sqlPort;
        public string serverVersion = null;
        public string instanceName;         // polulated by ssrp response
        public string sqlHostName;
        public string namedPipe;
        public string isClustered;
        public String instanceRequested;    // populated by ssrp request
        public bool hasResponse = false;
        public bool hasNoResponse = false;
        public ArrayList conversations = new ArrayList();

        public bool hasConversation(ConversationData c)
        {
            foreach (ConversationData c2 in conversations)
            {
                if (c.destIP == c2.destIP && c.destIPHi == c2.destIPHi && c.destIPLo == c2.destIPLo && c.destPort == c2.destPort &&
                    c.sourceIP == c2.sourceIP && c.sourceIPHi == c2.sourceIPHi && c.sourceIPLo == c2.sourceIPLo && c.sourcePort == c2.sourcePort)
                    return true;

            }
            return false;
        }
    }

}