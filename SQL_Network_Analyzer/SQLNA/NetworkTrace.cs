// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System.Collections;


namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Top level structure for storage
    // Helper methods for getting conversations, SQL Servers, and SSRP conversations
    //
    // ArrayList used for conversations so latest conversation is at the end
    // conversationIndex used to look up conversations. Based on XOR-ing the client port and server port to form an index
    //

    class NetworkTrace                                      // constructed in Main
    {

        public string fileExt = null;
        public ArrayList files = new ArrayList();           // set in ParseFileSpec - added to in ParseFileSpec
        public ArrayList conversations = new ArrayList();   // set in ParseFileSpec - added to in GetIPV4Converation and GetIPV6Conversation
        public ArrayList frames = new ArrayList();          // set in ParseFileSpec - added to in ParseIPV4Frame and ParseIPV6Frame
        public ArrayList sqlServers = new ArrayList();      // added to in ProcessTDS - not pre-sized because of estimated small size
        public ArrayList SSRPRequests = new ArrayList();    // added to in ProcessUDP - not pre-sized because of estimated small size
        public ArrayList DNSResponses = new ArrayList();    // problem DNS responses
        public int DNSRequestCount = 0;                     // total number of DNS Requests
        public ArrayList KerbResponses = new ArrayList();
        public ArrayList[] conversationIndex = new ArrayList[65536];

        public ArrayList GetConversationList(ushort index)  // used for conversationIndex to speed up searching
        {
            ArrayList a = conversationIndex[index];
            if (a == null)
            {
                a = new ArrayList();
                conversationIndex[index] = a;
            }
            return a;
        }

        public ConversationData GetIPV4Conversation(uint sourceIP, ushort sourcePort, uint destIP, ushort destPort)
        {
            //
            // search for existing conversation and return it
            // search down from end is about 4x faster than foreach loop -  since new conversations are added to the end of the ArrayList
            // also search down in case we wrap around port numbers, get the latest conversation, not the earlier one
            //

            ArrayList conv = GetConversationList((ushort)(sourcePort ^ destPort));   // XOR the port numbers together to generate an index into conversationIndex

            for (int i = conv.Count - 1; i >= 0; i--)
            {
                ConversationData c = (ConversationData)conv[i];
                if (c.isIPV6 == false &&
                    ((c.sourceIP == sourceIP && c.destIP == destIP && c.sourcePort == sourcePort && c.destPort == destPort) ||
                     (c.destIP == sourceIP && c.sourceIP == destIP && c.destPort == sourcePort && c.sourcePort == destPort)))
                {
                    return c;
                }
            }

            // not found - create new conversation and return it
            ConversationData c2 = new ConversationData();
            c2.sourceIP = sourceIP;
            c2.destIP = destIP;
            c2.sourcePort = sourcePort;
            c2.destPort = destPort;
            c2.isIPV6 = false;
            conversations.Add(c2);
            conv.Add(c2);
            return c2;
        }

        public ConversationData GetIPV6Conversation(ulong sourceIPHi, ulong sourceIPLo, ushort sourcePort, ulong destIPHi, ulong destIPLo, ushort destPort)
        {
            //
            // search for existing conversation and return it
            // search down from end is about 4x faster than foreach loop -  since new conversations are added to the end of the ArrayList
            // also search down in case we wrap around port numbers, get the latest conversation, not the earlier one     
            //

            ArrayList conv = GetConversationList((ushort)(sourcePort ^ destPort));   // XOR the port numbers together to generate an index into conversationIndex

            for (int i = conv.Count - 1; i >= 0; i--)
            {
                ConversationData c = (ConversationData)conv[i];
                if (c.isIPV6 == true &&
                    ((c.sourceIPHi == sourceIPHi && c.destIPHi == destIPHi && c.sourceIPLo == sourceIPLo && c.destIPLo == destIPLo && c.sourcePort == sourcePort && c.destPort == destPort) ||
                     (c.destIPHi == sourceIPHi && c.sourceIPHi == destIPHi && c.destIPLo == sourceIPLo && c.sourceIPLo == destIPLo && c.destPort == sourcePort && c.sourcePort == destPort)))
                {
                    return c;
                }
            }

            // not found - create new conversation and return it
            ConversationData c2 = new ConversationData();
            c2.sourceIPHi = sourceIPHi;
            c2.sourceIPLo = sourceIPLo;
            c2.destIPHi = destIPHi;
            c2.destIPLo = destIPLo;
            c2.sourcePort = sourcePort;
            c2.destPort = destPort;
            c2.isIPV6 = true;
            conversations.Add(c2);
            conv.Add(c2);
            return c2;
        }

        public SQLServer GetSQLServer(uint IP, ulong IPHi, ulong IPLo, ushort Port, bool isIPV6)
        {
            // search for existing SQL Server and return it - can use foreach loop as this is not called often and there are a small number of entries
            foreach (SQLServer s in sqlServers)
            {
                if (s.isIPV6 == isIPV6 && s.sqlIP == IP && s.sqlIPHi == IPHi && s.sqlIPLo == IPLo && s.sqlPort == Port)
                {
                    return s;
                }
            }

            // not found - create new SQLServer and return it
            SQLServer s2 = new SQLServer();
            s2.sqlIP = IP;
            s2.sqlIPHi = IPHi;
            s2.sqlIPLo = IPLo;
            s2.sqlPort = Port;
            sqlServers.Add(s2);
            return s2;
        }

        public SQLServer FindSQLServer(ConversationData c)
        {
            // search for existing SQL Server and return it - can use foreach loop as this is not called often and there are a small number of entries
            foreach (SQLServer s in sqlServers)
            {
                if (s.isIPV6 == c.isIPV6 &&
                    ((s.sqlIP == c.sourceIP && s.sqlIPHi == c.sourceIPHi && s.sqlIPLo == c.sourceIPLo && s.sqlPort == c.sourcePort) ||
                     (s.sqlIP == c.destIP && s.sqlIPHi == c.destIPHi && s.sqlIPLo == c.destIPLo && s.sqlPort == c.destPort)))
                {
                    return s;
                }
            }
            return null;
        }

        public SQLServer FindSQLServer(uint IP, ulong IPHi, ulong IPLo, ushort Port, bool isIPV6)  // added Dec 5, 2016
        {
            // search for existing SQL Server and return it - can use foreach loop as this is not called often and there are a small number of entries
            foreach (SQLServer s in sqlServers)
            {
                if (s.isIPV6 == isIPV6 && s.sqlIP == IP && s.sqlIPHi == IPHi && s.sqlIPLo == IPLo && s.sqlPort == Port)
                {
                    return s;
                }
            }
            return null;
        }

        public SSRPData GetSSRPRequest(uint IP, ulong IPHi, ulong IPLo, bool isIPV6)
        {
            // search for existing SQL Server and return it - can use foreach loop as this is not called often and there are a small number of entries
            foreach (SSRPData s in SSRPRequests)
            {
                if (s.isIPV6 == isIPV6 && s.sqlIP == IP && s.sqlIPHi == IPHi && s.sqlIPLo == IPLo)
                {
                    return s;
                }
            }

            // not found - create new SSRPRequestr and return it
            SSRPData s2 = new SSRPData();
            s2.sqlIP = IP;
            s2.sqlIPHi = IPHi;
            s2.sqlIPLo = IPLo;
            SSRPRequests.Add(s2);
            return s2;
        }

    }

}