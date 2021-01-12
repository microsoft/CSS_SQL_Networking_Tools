using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SQLNA
{
    //
    // This class finds domain controllers on the network and parses the TCP conversations to see if any fail to connect.
    // A classic failure is 3 SYN packets.
    // If any of the clients are a SQL Server, then this can be problematic and may be related to a login timeout.
    // If multiple instance son the machine, we cannot say which instance made the call.
    //

    class DomainControllerParser
    {

        public static void Process(NetworkTrace trace)
        {
            trace.DomainControllers = new System.Collections.ArrayList();
            DomainController d = null;

            // Locate TCP and UDP conversations with server ports 53 (DNS) and 88 (KERBEROS) and 389 (LDAP)

            foreach (ConversationData c in trace.conversations)
            {
                if (c.destPort == 53 /* DNS */ || c.destPort == 88 /* Kerberos */ || c.destPort == 389 /* LDAP */)
                {
                    d = trace.GetDomainController(c.destIP, c.destIPHi, c.destIPLo, c.isIPV6);
                    if (c.destPort == 53) d.DNSPort53Count++;
                    if (c.destPort == 88) d.KerbPort88Count++;
                    if (c.destPort == 389) d.LDAPPort389Count++;
                }
            }

            // Find any stray conversations with the DC

            foreach (ConversationData c in trace.conversations)
            {
                d = trace.FindDomainController(c);
                if (d != null)
                {
                    d.conversations.Add(c);
                }
            }

            // Find MSRPC Conversations and Port

            foreach (DomainController dc in trace.DomainControllers)
            {
                foreach (ConversationData c in dc.conversations)
                {
                    if (c.isUDP == false && c.destPort > 1000)  // ignore low port #s
                    {
                        // potential MSRPC traffic
                        foreach (FrameData f in c.frames)
                        {
                            ushort Port = c.destPort;
                            if (isMSRPC(f.payload))
                            {
                                dc.MSRPCPortCount++;
                                if (dc.MSRPCPort == 0)
                                {
                                    dc.MSRPCPort = Port;
                                }
                                else if (dc.MSRPCPort != Port)
                                {
                                    dc.hasMultipleMSRPCPorts = true;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        //
        // MSRPC Header for TCP connections
        //
        // Offset  Field        Size           Value
        // ------  -----------  -------------  --------------------
        //      0  Version      byte           0x05
        //      1  Subversion   byte           0x00 or 0x01
        //      2  Op Type      byte           0, 2, 3, 11..19
        //      3  Flags        byte           no test
        //      4  Packed Type  byte           0x00 or 0x01 or 0x10 or 0x11  (i.e. value & 0xEE == 0) Only the LSB of each nibble can be set.
        //      5  IEEE Packing byte           0, 1, 2, 3
        //      6  Reserved     byte           0x00
        //      7  Reserved     byte           0x00
        //    8-9  Length       int16          Little-Endian, e.g. 0xC600 -> 108 decimal - Length - should match payload length
        //    ...  ... other fields, ignored ...


        public static bool isMSRPC(byte[] b)
        {
            if (b is null) return false;
            if (b.Length < 16) return false;
            if (b[0] != 5 || (b[1] != 0 && b[1] != 1) || b[5] >= 4 || b[6] != 0 || b[7] != 0) return false;
            if ((b[4] & (byte)0xEE) != 0) return false;
            if ((b[2] == 0 || b[2] == 2 || b[2] == 3 || (b[2] >= 11 && b[2] <= 19)) == false) return false;
            int Len = b[8] + b[9] * 16;
            if (Len != b.Length) return false;
            return true;
        }
    }
}
