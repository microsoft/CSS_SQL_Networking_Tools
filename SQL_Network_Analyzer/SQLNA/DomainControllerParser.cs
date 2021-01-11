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
                    if (c.destPort == 53) d.hasDNSPort53 = true;
                    if (c.destPort == 88) d.hasKerbPort88 = true;
                    if (c.destPort == 389) d.hasLDAPPort389 = true;
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
        }
    }
}
