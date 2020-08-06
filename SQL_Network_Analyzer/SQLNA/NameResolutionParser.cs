// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;
using System.Linq;
using System.Text;


namespace SQLNA
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Parses DNS request / response
    //
    // DNS archtecture - https://technet.microsoft.com/en-us/library/cc772774(v=ws.10).aspx
    //

    class NameResolutionParser
    {

        enum  DNSReturnCodes
        {
            NOERROR  = 0,    //No error; successful update.
            FORMERR  = 1,    //Format error; DNS server did not understand the update request / S
            SERVFAIL = 2,    //DNS server encountered an internal error, such as a forwarding timeout
            NXDOMAIN = 3,    //A name that should exist does not exist / Name Error (NETMON)
            NOTIMP   = 4,      //DNS server does not support the specified Operation code / Not Implemented (NETMON)
            REFUSED  = 5,     //DNS server refuses to perform the update / Refused (NETMON)
            YXDOMAIN = 6,    //A name that should not exist does exist
            YXRRSet  = 7,     //A resource record set that should not exist does exist
            NXRRSET  = 8,     //A resource record set that should exist does not exist
            NOTAUTH  = 9,     //DNS server is not authoritative for the zone named in the Zone section;
            NOTZONE  = 10,    //A name used in the Prerequisite or Update sections is not within the zone specified by the Zone section;
		    Reserved = 15
          }

     

        enum DNSQueryTypes
        {
            Request=0,
            Response=1
        }

        public static void DisplayDNSConversation(ConversationData convData)
        {

           Console.WriteLine("-------------------------------");
           foreach (FrameData fd in convData.frames)
           {
               Console.WriteLine("Frame#" + fd.frameNo.ToString());

           }

        }

       public static void ProcessUDP(NetworkTrace trace)
       {

            string[] DnsReturnMessage = new string[] {
                    "Success",
                    "Format error; DNS server did not understand the update request.",
                    "DNS server encountered an internal error, such as a forwarding timeout.",
                    "A name that should exist does not exist.",
                    "DNS server does not support the specified Operation code.",
                    "DNS server refuses to perform the update.",
                    "A name that should not exist does exist.",
                    "A resource record set that should not exist does exist.",
                    "A resource record set that should exist does not exist.",
                    "DNS server is not authoritative for the zone named in the Zone section.",
                    "A name used in the Prerequisite or Update sections is not within the zone specified by the Zone section.",
                    "Invalid return code.",
                    "Invalid return code.",
                    "Invalid return code.",
                    "Invalid return code.",
                    "Reserved."
        };

                foreach (ConversationData c in trace.conversations)
                {

                    //DNS traffic is over UDP. If the current converstion is not UDP then skip that non DNS conversation. 
                    if (!c.isUDP) continue;

                    //Skip the conversation, if  its just UDP, but not DNS
                    if ((c.isUDP) && c.destPort != 53) continue;

                    trace.DNSRequestCount++;

                    try
                    {


                        //Parse the DNS frames of the conversation.
                        foreach (FrameData fd in c.frames)
                        {
                            DNS DNSresponse = new DNS();

                            if (fd.payloadLength < 1)
                                continue;



                            //DNS data starts at 42nd byte of the total payload. so the payload = (Total Payload - 42) bytes.
                            TDSReader ByteReader = new TDSReader(fd.payload, 0, -1, fd.payloadLength);

                           
                            ByteReader.ReadBigEndianUInt16(); //Skip over the query ID. 
                           
                            //Read the Flags and convert into bytes.
                            int FlagsHigh = ByteReader.ReadByte();
                            int FlagsLow = ByteReader.ReadByte();

                            if ((FlagsHigh & (int)0x80) == (int)0x0) // DNS request
                            {
                                //DNSresponse.srcServerIP  = c.sourceIP.ToString();
                                DNSresponse.dnsServerIP = c.destIP.ToString();
                            }
                            else if ((FlagsHigh & (int)0x80) == (int)0x80) // DNS response
                            {
                                int rCode = FlagsLow & 0x0F;   // should be between 0 - 15.

                                //DNSresponse.srcServerIP= c.destIP.ToString();
                                DNSresponse.dnsServerIP = c.sourceIP.ToString();
                                DNSresponse.frameNo = fd.frameNo;
                                DNSresponse.TimeStamp = new DateTime(((FrameData)c.frames[c.frames.Count - 1]).ticks).ToString(utility.TIME_FORMAT);
                                //new DateTime(((FrameData)trace.frames[0]).ticks).ToString(utility.TIME_FORMAT);
                                DNSresponse.errorCode = rCode;
                                DNSresponse.ErrorDesc = DnsReturnMessage[rCode];

                                //Question Count  - 2 bytes
                                DNSresponse.QuestionCount = ByteReader.ReadInt16();

                                //Answer Count - 2 bytes
                                DNSresponse.AnswerCount = ByteReader.ReadInt16();

                                //Skip 2 bytes - Name Server count
                                ByteReader.ReadInt16();

                                //Skip 2 bytes - Additional count
                                ByteReader.ReadInt16();

                                //Start reading the QName
                                //13th byte of the DNS Payload - payload[12]
                                byte length = ByteReader.ReadByte();
                                string Name = "";
                                while (length != 0)
                                {
                                    Name += (Name == "" ? "" : ".") + ByteReader.ReadAnsiString(length);
                                    length = ByteReader.ReadByte();

                                }

                                DNSresponse.nameReqested = Name;
                                DNSresponse.convData = c;
                                //DNSresponse.srcPort = c.sourcePort;

                               // Console.WriteLine(fd.file.filePath + "\t" + fd.frameNo.ToString());
                                if (rCode != (int)DNSReturnCodes.NOERROR)
                                    trace.DNSResponses.Add(DNSresponse);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error parsing DNS conversation: " + ex.Message + "\r\n" + ex.StackTrace);
                        Program.logDiagnostic("Error parsing DNS conversation: " + ex.Message + "\r\n" + ex.StackTrace);
                    }
                }
       }
    
    }//End of class

}//End of namespace
