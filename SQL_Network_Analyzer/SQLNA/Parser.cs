// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.IO;
using System.Data;
using System.Collections;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Base parser routines.
    // Takes filespec and converts into an array of files if any wildcards are present
    // For each file:
    //     Opens the file and reads the magic number to determine .CAP, .PCAP, and .PCAPNG regardless of actual file extension or lack thereof. Honors .ETL extension.
    //     Selects the appropriate file parser
    //     Gets the timestamp of the first frame
    // Sorts timestamps and opens the files in timestamp order regardless of filename
    // Selects the appropriate file parser and reads each frame
    // If the frame type is Ethernet, parses the frame
    // If the address type is IPV4 or IPV6, parses it, and reads any shim protocols
    // If the protocol type is TCP or UDP, parses it
    // Tries to find SQL
    // Marks continuation frames
    // Marks retransmitted frames
    // If SQL is accidentally marked as the client-side, reverses the source and destination IP addresses and ports for every frame in the conversation
    //

    class Parser
    {

        const long BYTES_PER_FRAME = 200;
        const long BYTES_PER_CONVERSATION = 50000;

        const int BACK_COUNT_LIMIT = 20;

        public static void ParseFileSpec(string fileSpec, NetworkTrace t)
        {
            string[] files = null;
            FileInfo fi = null;
            DataTable dt = new DataTable();
            DataRow dr = null;
            DataRow[] rows = null;
            long totalSize = 0;

            dt.Columns.Add("FileName", typeof(String));
            dt.Columns.Add("FileDate", typeof(DateTime));
            dt.Columns.Add("FileSize", typeof(long));
            dt.Columns.Add("InitialTick", typeof(long));

            ActivityTimer act = new ActivityTimer();

            try
            {
                // In case a relative path was specified, we need to use the fileInfo class to resolve this into an absolute path
                // If wildcards were specified, replace with letters to make a pseudo-filename; the file name does not have to exist for the calls we are doing
                // Get the directory name and the length of the file name with wild cards so we can split it out
                // e.g.   ..\temp\mytrace*.cap -> c:\users\johnsmith\temp for directory and mytrace*.cap for the filespec as arguments for the GetFiles method
                fi = new FileInfo(fileSpec.Replace("*", "s").Replace("?", "q"));
                files = Directory.GetFiles(fi.DirectoryName, fileSpec.Substring(fileSpec.Length - fi.Name.Length));

                //Enumerate the files that match the file specification

                foreach (String f in files)
                {
                    dr = dt.NewRow();
                    fi = new FileInfo(f);
                    dr["FileName"] = f;
                    dr["FileDate"] = fi.LastWriteTime;
                    dr["FileSize"] = fi.Length;
                    dr["InitialTick"] = GetInitialTick(f);  // we set the Program.reportFilterFormat value in here
                    totalSize = fi.Length;
                    dt.Rows.Add(dr);
                }
            }
            catch (Exception ex)
            {
                Program.logDiagnostic("Error getting file information: " + ex.Message + "\r\n" + ex.StackTrace);
                Console.WriteLine("Error getting file information: " + ex.Message + "\r\n" + ex.StackTrace);
            }

            // order by last write time - first to last
            rows = dt.Select("", "InitialTick");   // changed from FileDate - have seen cases where the files get touched and FileDate is altered
            
            // size ArrayLists based on total size of all files - a guestimate to reduce the number of times the ArrayList must be grown
            t.frames = new System.Collections.ArrayList((int)(totalSize / BYTES_PER_FRAME));
            t.conversations = new System.Collections.ArrayList((int)(totalSize / BYTES_PER_CONVERSATION));
            t.files = new System.Collections.ArrayList(rows.Length);

            Console.WriteLine("Trace file(s) folder:\n" + Path.GetDirectoryName(fileSpec) + "\n");
            // Parse each file in the list
            foreach (DataRow r in rows)
            {
                String fn = r["FileName"].ToString().ToLower();
                // add the file name to the files collection
                FileData f = new FileData();
                f.filePath = fn;
                f.fileDate = (DateTime)r["FileDate"];
                f.fileSize = (long)r["FileSize"];
                t.files.Add(f);
                act.start("Parsing " + Path.GetFileName(fn));
                ParseOneFile(fn, t);
                act.stop();
            }
        }

        public static long GetInitialTick(string filePath)
        {
            BinaryReader r = null;
            ReaderBase rb = null;
            ETLFileReader er = null;
            long initialTick = 0;

            Program.logDiagnostic("Peeking at initial tick for file " + filePath);

            try
            {
                if (filePath.ToLower().EndsWith(".etl"))  // ETL files have no magic number. Must be done by file name.
                {
                    er = new ETLFileReader(filePath);
                    // initialTick = er.GetStartTime().Ticks;
                    er.Init();
                    Frame frame = er.Read();
                    if (frame != null) initialTick = frame.ticks;   // extract tick information
                    if (Program.filterFormat == "A") Program.filterFormat = "N";   // format for "AUTO" format mode based on file type
                }
                else
                {
                    r = new BinaryReader(new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read));
                    UInt32 magicNumber = r.ReadUInt32();

                    switch (magicNumber)
                    {
                        case 0x55424d47:  // NETMON magic number
                            {
                                rb = new NetMonReader(r);
                                if (Program.filterFormat == "A") Program.filterFormat = "N";   // format for "AUTO" format mode based on file type
                                break;
                            }
                        case 0xa1b2c3d4:  // PCAP normal byte order   - millisecond resolution
                        case 0xd4c3b2a1:  // PCAP reversed byte order - millisecond resolution
                        case 0xa1b23c4d:  // PCAP normal byte order   - nanosecond resolution
                        case 0x4d3cb2a1:  // PCAP reversed byte order - nanosecond resolution
                            {
                                rb = new SimplePCAPReader(r);
                                if (Program.filterFormat == "A") Program.filterFormat = "W";   // format for "AUTO" format mode based on file type
                                break;
                            }
                        case 0x0A0D0D0A:  // PCAPNG Section Header Block identifier. Magic number is at file offset 8.
                            {
                                rb = new PcapNGReader(r);
                                if (Program.filterFormat == "A") Program.filterFormat = "W";   // format for "AUTO" format mode based on file type
                                break;
                            }
                        default:
                            {
                                throw new Exception("Magic number " + magicNumber.ToString("X") + " does not correspond to a supported network trace file type.");
                            }
                    }

                    rb.Init();   // reads file header information

                    Frame frame = rb.Read();   // reads one frame; returns null at EOF

                    if (frame != null) initialTick = frame.ticks;   // extract tick information
                }

            }
            catch (Exception ex)
            {
                Program.logDiagnostic("Error reading file " + filePath + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
                Console.WriteLine("Error reading file " + filePath + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
            }
            finally
            {
                if (r != null) r.Close();
                if (er != null) er.Close();
        }

            return initialTick;
        }

        public static void ParseOneFile(string filePath, NetworkTrace t)
        {
            BinaryReader r = null;
            ReaderBase rb = null;
            ETLFileReader er = null;
            bool isETL = filePath.ToLower().EndsWith(".etl");   // ETL files have no magic number. Must be done by file name.
            Frame frame = null;

            bool f_ReportedOther = false;

            FileData file = (FileData)t.files[t.files.Count - 1];
            
            try
            {
                if (isETL)
                {
                    er = new ETLFileReader(filePath);
                    er.Init();
                    frame = er.Read();
                }
                else
                {
                    r = new BinaryReader(new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read));
                    UInt32 magicNumber = r.ReadUInt32();

                    switch (magicNumber)
                    {
                        case 0x55424d47:  // NETMON magic number
                            {
                                rb = new NetMonReader(r);
                                break;
                            }
                        case 0xa1b2c3d4:  // PCAP normal byte order   - millisecond resolution
                        case 0xd4c3b2a1:  // PCAP reversed byte order - millisecond resolution
                        case 0xa1b23c4d:  // PCAP normal byte order   - nanosecond resolution
                        case 0x4d3cb2a1:  // PCAP reversed byte order - nanosecond resolution
                            {
                                rb = new SimplePCAPReader(r);
                                break;
                            }
                        case 0x0A0D0D0A:  // PCAPNG Section Header Block identifier. Magic number is at file offset 8.
                            {
                                rb = new PcapNGReader(r);
                                break;
                            }
                        default:
                            {
                                throw new Exception("Magic number " + magicNumber.ToString("X") + " does not correspond to a supported network trace file type.");
                            }
                    }

                    rb.Init();   // reads file header information

                    frame = rb.Read();   // reads one frame; returns null at EOF
                }

                while (frame != null)
                {
                    if (frame.ticks >= DateTime.MinValue.Ticks && frame.ticks <= DateTime.MaxValue.Ticks)
                    {
                        FrameData f = new FrameData();
                        f.frameNo = frame.frameNumber;
                        f.file = file;
                        f.ticks = frame.ticks;

                        f.frameLength = frame.frameLength;
                        f.capturedFrameLength = frame.bytesAvailable;

                        if (file.startTick == 0) file.startTick = frame.ticks;
                        if (frame.ticks > file.endTick) file.endTick = frame.ticks;
                        file.frameCount++;

                        if (frame.isPKTMON)
                        {
                            ParsePktmonFrame(frame.data, 0, t, f, frame.EventType);
                        }
                        else if (frame.isWFP)
                        {
                            ParseWFPFrame(frame.data, 0, t, f, frame.EventType);
                        }
                        else
                        {
                            switch (frame.linkType)
                            {
                                case 0:  // NULL/Loopback frame in WireShark, Ethernet in NETMON
                                         // Unanswered question: if WireShark is saved as .cap, does it change the link value? NETMON won't read the NULL link layer when reading PCAP
                                    {
                                        if (rb is PcapNGReader || rb is SimplePCAPReader)
                                        {
                                            ParseNullLoopbackFrame(frame.data, 0, t, f);
                                        }
                                        else // ETLReader or NetMonReader
                                        {
                                            ParseEthernetFrame(frame.data, 0, t, f);
                                        }
                                        break;
                                    }
                                case 1:  // Ethernet
                                    {
                                        ParseEthernetFrame(frame.data, 0, t, f);
                                        break;
                                    }
                                case 6:  // WiFi
                                    {
                                        ParseWifiFrame(frame.data, 0, t, f, frame.isNDIS); // TODO flesh this out
                                                                             // Test file: \Documents\Interesting Network Traces\WifiTrace\
                                        break;
                                    }
                                case 101:  // Raw - first byte of payload - high nybble = 0x4n -> IPV4; high nybble = 0x6n -> IPV6
                                    {
                                        byte payloadType = (byte)(frame.data[0] & 0xF0);
                                        switch (payloadType)
                                        {
                                            case 0x40:
                                                {
                                                    ParseIPV4Frame(frame.data, 0, t, f);
                                                    break;
                                                }
                                            case 0x60:
                                                {
                                                    ParseIPV6Frame(frame.data, 0, t, f);
                                                    break;
                                                }
                                            default:
                                                {
                                                    if (!f_ReportedOther)
                                                    {
                                                        Program.logDiagnostic($"Frame {frame.frameNumber}: Raw Protocol {frame.linkType} (0x{frame.linkType.ToString("X4")}). Payload header type {frame.data[0]} is not IPV4 or IPV6.");
                                                        f_ReportedOther = true;
                                                    }
                                                    break;
                                                }

                                        }
                                        break;
                                    }
                                case 0x0071:  // Linux Cooked Capture - no MAC addresses, just IP and higher protocols
                                case 0xE071:  // Linux Cooked Capture - no MAC addresses, just IP and higher protocols
                                    {
                                        ParseLinuxCookedFrame(frame.data, 0, t, f);
                                        break;
                                    }
                                case 0xFFE0:  // NetEvent (usually in ETL and parsed by now) - happens when NETMON saves ETL capture as a CAP file
                                    {
                                        ParseNetEventFrame(frame.data, 0, t, f); // TODO flesh this out
                                                                                 // Test file: \Documents\Interesting Network Traces\Filtered ETL in a CAP File - fix SQLNA\*_filtered.cap
                                        break;
                                    }
                                default:
                                    {
                                        if (!f_ReportedOther)
                                        {
                                            Program.logDiagnostic($"Frame {frame.frameNumber}: Unknown Protocol {frame.linkType} (0x{frame.linkType.ToString("X4")}). Packet ignored.");
                                            f_ReportedOther = true;
                                        }
                                        break;
                                    }
                            }
                        }
                        
                    }
                    else // corrupt packet - bad timestamp - log and drop
                    {
                        Program.logDiagnostic("Bad timestamp. Dropping frame " + frame.frameNumber + " in file " + file.filePath + ".");
                    }

                    if (isETL) frame = er.Read(); else frame = rb.Read();
                }
            }
            catch (Exception ex)
            {
                Program.logDiagnostic("Error reading file " + filePath + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
                Console.WriteLine("Error reading file " + filePath + "\r\n" + ex.Message + "\r\n" + ex.StackTrace);
            }
            finally
            {
                if (r != null) r.Close();
                if (er != null) er.Close();
            }
        }

        //
        // Protocol stacking
        //
        // .ETL NDIS Net Event                 -> Ethernet/Wifi
        // Link Type: NDIS Net Event (.CAP)    -> Ethernet/Wifi
        // Link Type: Null/Loopback            -> IPV4/IPV6
        // Link Type: Ethernet                 -> IPV4/IPV6/VNETTag
        // Link Type: Wifi/LLC/SNAP            -> IPV4/IPV6/VNETTag
        // Link Type: Linux Cooked Capture     -> IPV4/IPV6/VNETTag
        // Link Type: Raw 101 (0x65)           -> IPV4/IPV6
        //
        // GRE                                 -> ERSPAN/IPV4/IPV6
        // ERSPAN                              -> Ethernet
        // IPV4/IPV6                           -> TCP/UDP/GRE (Generic Routing Encapsulation)
        // VNETTag                             -> 802.1Q
        // 802.1Q                              -> IPV4/IPV6
        //
        // UDP                                 -> SSRP
        // TCP                                 -> TDS/Kerberosv5/DNS/SMP
        // SMP                                 -> TDS
        //

        public static void ParseNextProtocol(uint ProtocolNumber, byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            switch (ProtocolNumber)
            {
                case 0x0001:   // ICMP - ignore and do not log
                    break;
                case 0x0006:   // TCP
                    ParseTCPFrame(b, offset, t, f);
                    break;
                case 0x0011:   // UDP
                    ParseUDPFrame(b, offset, t, f);
                    break;
                case 0x002F:   // GRE
                    ParseGenericRoutingEncapsulation(b, offset, t, f);
                    break;
                case 0x0800:   // IPV4
                    ParseIPV4Frame(b, offset, t, f);
                    break;
                case 0x0806:   // ARP - ignore and do not log
                case 0x8035:   // RARP - ignore and do not log - Reverse ARP
                    break;
                case 0x8100:   // 802.1Q
                    Parse8021QFrame(b, offset, t, f);
                    break;
                case 0x86DD:   // IPV6
                    ParseIPV6Frame(b, offset, t, f);
                    break;
                case 0x88BE:   // ERSPAN Type II
                case 0x22EB:   // ERSPAN Type III
                    ParseERSPANFrame(b, offset, t, f);
                    break;
                case 0x88CC:   // LLDP - 802.1 Link Layer Discovery Protocol - ignore and do not log
                    break;
                case 0x8926:   // VNETTag
                    ParseVNTagFrame(b, offset, t, f);
                    break;
                case 0:
                case 60:
                case 43:
                case 44:
                case 51:
                case 135:
                    {
                        Program.logDiagnostic($"Warn: IPV6 packet has extension header {ProtocolNumber} (0x{ProtocolNumber.ToString("X4")}). Frame {f.frameNo} in {f.file.filePath}");
                        break;
                    }
                default:
                    {
                        Program.logDiagnostic($"Unrecognized protocol {ProtocolNumber} (0x{ProtocolNumber.ToString("X4")}).");
                        break;
                    }
            }
        }

        public static void ParseNullLoopbackFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            // NULL/Loopback - first 4 bytes could be big endian or little endian depending on computer recording the trace (BSD UNIX, mainly)
            // 0x00000002 or 0x02000000 means IPV4 is the next protocol
            // 24, 28, or 30 means IPV6 is the next protocol
            // 0x00000018, 0x18000000, 0x0000001C, 0x1C000000, 0x0000001E, 0x1E000000 -> IPV6
            // ignore all others

            UInt32 NextProtocol = utility.ReadUInt32(b, offset);
            offset += 4;
            if (NextProtocol == 0x02000000 || NextProtocol == 0x00000002)
            {
                ParseIPV4Frame(b, offset, t, f);
            }
            else if (NextProtocol == 0x00000018 || NextProtocol == 0x18000000 || NextProtocol == 0x0000001C || NextProtocol == 0x1C000000 || NextProtocol == 0x0000001E || NextProtocol == 0x1E000000)
            {
                ParseIPV6Frame(b, offset, t, f);
            }
        }

        public static void ParseLinuxCookedFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            UInt16 PacketType = 0;        // we just want 0=Incoming and 4=Outgoing
            UInt16 AddressType = 0;       // we just want 0 or 1 = Ethernet
            UInt16 AddressLength = 0;     // we can read MAC address if length = 6
            ulong sourceMAC = 0;
            ulong destMAC = 0;
            ushort NextProtocol = 0;    // IPV4 = 0x0800 (2048)    IPV6 = 0x86DD (34525)     VLAN = 0x8100 inserts 4 bytes at offset 12

            PacketType = utility.B2UInt16(b, offset);
            if (PacketType != 0 && PacketType != 4) return;
            offset += 2;

            AddressType = utility.B2UInt16(b, offset);
            if (AddressType != 0 && AddressType != 1) return;
            offset += 2;

            AddressLength = utility.B2UInt16(b, offset);
            offset += 2;
            switch (AddressLength)
            {
                case 6:
                    {
                        if (PacketType == 0)
                        {
                            sourceMAC = utility.B2UInt48(b, offset);
                        }
                        else
                        {
                            destMAC = utility.B2UInt48(b, offset);
                        }
                        offset += 8;  // ignore implementation-specif c data of 2 bytes
                        break;
                    }
                default:
                    {
                        offset += 8;  // data is always 8 in length, address + remainder bytes
                        break;
                    }
            }

            NextProtocol = utility.B2UInt16(b, offset);
            offset += 2;

            try
            {
                ParseNextProtocol(NextProtocol, b, offset, t, f);
            }
            catch (IndexOutOfRangeException)
            {
                if (f.conversation != null) f.conversation.truncationErrorCount++;
            }
            catch { throw; }

            if (f.conversation != null)
            {
                f.conversation.sourceMAC = sourceMAC;
                f.conversation.destMAC = destMAC;
                // statistical gathering
                if (f.conversation.startTick == 0 || f.ticks < f.conversation.startTick)
                {
                    f.conversation.startTick = f.ticks;
                }
                if (f.conversation.endTick < f.ticks) f.conversation.endTick = f.ticks;
                if (f.isFromClient) f.conversation.sourceFrames++; else f.conversation.destFrames++;
            }
        }

        public static void ParseNetEventFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            Guid NDIS = new Guid("2ED6006E-4729-4609-B423-3EE7BCD678EF");
            Guid PKTMON = new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac");
            ushort eventID = 0;
            ushort flags = 0;
            long fileTicks = 0;
            long ticks = 0;
            Boolean isEthernet = false;
            Boolean isWifi = false;
            Boolean isFragment = false;
            Boolean isPktmon = false;
            Boolean isNDIS = false;
            ushort userDataLength = 0;
            uint ETLFragmentSize = 0;

            // Read NetEvent Header
            offset = 4; // bypass size and header type, 2 bytes each; we get size later
            flags = utility.ReadUInt16(b, offset);
            offset += 2;
            offset += 10; // bypass EventProperty (2), ThreadID (4), and ProcessID (4)
            fileTicks = (long)utility.ReadUInt64(b, offset);
            ticks = DateTime.FromFileTimeUtc(fileTicks).Ticks;
            offset += 8;

            // Is this an NDIS event? If not, exit to go to the next frame.
            byte[] GuidBytes = new byte[16];
            Array.Copy(b, offset, GuidBytes, 0, 16);
            Guid ProviderID = new Guid(GuidBytes); // 0x6E00D62E29470946B4233EE7BCD678EF yields GUID {2ed6006e-4729-4609-b423-3ee7bcd678ef}
            isNDIS = ProviderID.Equals(NDIS);
            isPktmon = ProviderID.Equals(PKTMON);
            if (!isNDIS && !isPktmon) return;  // not the provider we want
            offset += 16;

            // Read Descriptor - Event ID
            eventID = utility.ReadUInt16(b, offset);
            if (isPktmon == false && eventID != 1001) return;   // not the NDIS event we want
            offset += 2;

            offset += 6; // skip Version (1), Channel (1), Level (1), OpCode (1), Task (2)

            // Read Descriptor KeyWord Bytes (8 bytes total)
            isEthernet = (b[offset] & 0x01) != 0;  // isEthernet and isWifi are mutually exclusive
            isWifi = (b[offset + 1] & 0x80) != 0;
            if (isPktmon == false && isEthernet == false && isWifi == false) return;   // not a link layer we support

            isFragment = (b[offset + 3] & 0xC0) != 0xC0;
            if (isFragment)   // we aren't supporting fragments right now, log it
            {
                Program.logDiagnostic("ParseNetEventFrame. Frame " + f.frameNo + " is a fragment. Ignoring.");
                return;
            }
            offset += 8;

            offset += 30; // skip ProcessorTime (8), ActivityID (16), BufferContext (4), ExtendedDataCount (2)

            userDataLength = utility.ReadUInt16(b, offset);
            offset += 2;

            offset += 1;  // skip Reassembled (1)

            // Read NDIS Header (12 bytes for eventID 1001)

            offset += 8;  // skip MiniportIfIndex (4), LowerIfIndex (4)
            ETLFragmentSize = utility.ReadUInt32(b, offset);
            if (ETLFragmentSize + 12 != userDataLength)
            {
                Program.logDiagnostic("ParseNetEventFrame. Frame " + f.frameNo + ". userDataLength - ETLFragmentSize != 12 . Ignoring.");
                return;
            }
            offset += 4;

            // one of these is guaranteed to be called; the case where both are false is tested above
            if (isPktmon)
            {
                ParsePktmonFrame(b, offset, t, f, eventID);
            }
            else if (isEthernet)
            {
                ParseEthernetFrame(b, offset, t, f);
            }
            else if (isWifi)
            {
                ParseWifiFrame(b, offset, t, f, isNDIS);
            }
        }

        public static void ParsePktmonFrame(byte[] b, int offset, NetworkTrace t, FrameData f, ushort eventID)
        {
            switch (eventID)
            {
                case 10:  // PktMon_DriverEntryFailed DriverEntryFailed;
		        case 20:  // PktMon_ComponentInfo ComponentInfo;
		        case 30:  // PktMon_CompPropUint CompPropUint;
		        case 40:  // PktMon_CompPropGuid CompPropGuid;
		        case 50:  // PktMon_CompPropHex32 CompPropHex32;
		        case 60:  // PktMon_CompPropNdisMedium CompPropNdisMedium;
		        case 70:  // PktMon_CompPropBinary CompPropBinary;
		        case 73:  // PktMon_CompPropString CompPropString;
		        case 75:  // PktMon_CompPropEtherType CompPropEtherType;
		        case 80:  // PktMon_PacketDropCounters PacketDropCounters;
		        case 90:  // PktMon_PacketFlowCounters PacketFlowCounters;
		        case 100: // PktMon_PktFilterIPv4 PktFilterIPv4;
		        case 110: // PktMon_PktFilterIPv6 PktFilterIPv6;
		        case 120: // PktMon_NblParsedIpv4 NblParsedIpv4;
		        case 130: // PktMon_NblParsedIpv6 NblParsedIpv6;
		        case 140: // PktMon_NblParsedDropIpv4 NblParsedDropIpv4;
		        case 150: // PktMon_NblParsedDropIpv6 NblParsedDropIpv6;
                case 180: // PktMon_PktNblInfo PktNblInfo;
                case 190: // PktMon_PktDropNblInfo PktDropNblInfo;
                    // ignore the frame
                    break;
		        case 160: // PktMon_FramePayload FramePayload;
		        case 170: // PktMon_FrameDropPayload FrameDropPayload;
                    // check the properties and parse the payload as Ethernet
                    // both event types have the same data structure and is reflected in the PktmonData class
                    PktmonData pkm           = new PktmonData();
                    pkm.eventID              = eventID;   // 160 for the normal frame data event or 170 for the frame drop event
                    pkm.PktGroupId           = utility.ReadUInt64(b, offset);     offset += 8;
                    pkm.PktNumber            = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.AppearanceCount      = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.DirTag               = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.PacketType           = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.ComponentId          = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.EdgeId               = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.FilterId             = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.DropReason           = utility.ReadUInt32(b, offset);     offset += 4;
                    pkm.DropLocation         = utility.ReadUInt32(b, offset);     offset += 4;
                    pkm.OriginalPayloadSize  = utility.ReadUInt16(b, offset);     offset += 2;
                    pkm.LoggedPayloadSize    = utility.ReadUInt16(b, offset);     offset += 2;

                    //
                    // The ETLFileReader files make f.frameLength and f.capturedFrameLength the same even if the packet was truncated.
                    // However, the PKTMON record logs the discrepancy.
                    // Adjust f.capturedFrameLength down by the difference.
                    //
                    if (pkm.LoggedPayloadSize != pkm.OriginalPayloadSize && f.capturedFrameLength == f.frameLength) f.capturedFrameLength -= (ushort)(pkm.OriginalPayloadSize - pkm.LoggedPayloadSize);

                    f.pktmon = pkm;
                    t.hasPktmonRecords = true;
                    if (pkm.eventID == 170) t.hasPktmonDropRecords = true;  // if it's a dropped packet event type
                    ParseEthernetFrame(b, offset, t, f);
                    break;
                default:
                    // ignore the frame
                    break;
            }
        }

        public static void ParseWFPFrame(byte[] b, int offset, NetworkTrace t, FrameData f, ushort eventID)
        {
            //
            // Pseudo IPV4 and IPV6 headers make sure the NextProtocol is UDP or TCP, otherwise, ignore
            //

            switch (eventID)
            {
                case 60011: // WFP MessageV4
                case 60012: // WFP Message2V4
                    {
                        uint sourceIP = utility.B2UInt32(b, offset);                       offset += 4;    // in big-endian byte order
                        uint destIP = utility.B2UInt32(b, offset);                         offset += 4;
                        byte NextProtocol = b[offset];                                     offset++;       // TCP = 6    UDP = 0x11 (17)
                        if (eventID == 60012) offset += 8;                                                 // bypass FlowControl field in the Message2V4 record
                        short payloadLength = (short)utility.ReadUInt16(b, offset);        offset += 2;    // in little-endian byte order

                        // determine the last element of b[] that contains IPV4 data - also the last byte of TCP payload - ethernet may extend beyond this
                        if (payloadLength == 0)
                        {
                            f.lastByteOffSet = (ushort)(b.Length - 1);
                        }
                        else
                        {
                            f.lastByteOffSet = (ushort)(offset + payloadLength - 1);
                        }

                        if (NextProtocol == 6 || NextProtocol == 0x11)
                        {
                            ushort SPort = utility.B2UInt16(b, offset);
                            ushort DPort = utility.B2UInt16(b, offset + 2);
                            ConversationData c = t.GetIPV4Conversation(sourceIP, SPort, destIP, DPort);  // adds conversation if new

                            // Is the Frame from Client or Server? This may be reversed later in ReverseBackwardConversations.
                            if (sourceIP == c.sourceIP && SPort == c.sourcePort) f.isFromClient = true;

                            //
                            // What:   Determine whether the TCP client port has rolled around and is re-used and this should be a new conversation
                            //
                            // Rule:   We see a SYN packet and there is a prior RESET or FIN packet already in the conversation, and is it older than 10 seconds.
                            //
                            // Action: Create a new conversation based on certain key fields of the current conversation.
                            // Action: Add the frame to the new conversation.
                            // Action: Add the new conversation to the conversations collection. 
                            //

                            if (NextProtocol == 6) // TCP
                            {

                                f.flags = b[offset + 13];
                                if ((f.flags & (byte)TCPFlag.SYN) != 0 && (c.finCount > 0 || (c.resetCount > 0) && (f.ticks - ((FrameData)(c.frames[c.frames.Count - 1])).ticks) > 10 * utility.TICKS_PER_SECOND))
                                {
                                    ConversationData cOld = c;
                                    c = new ConversationData();
                                    c.sourceIP = cOld.sourceIP;
                                    c.sourceIPHi = cOld.sourceIPHi;
                                    c.sourceIPLo = cOld.sourceIPLo;
                                    c.sourcePort = cOld.sourcePort;
                                    c.destMAC = cOld.destMAC;
                                    c.destIP = cOld.destIP;
                                    c.destIPHi = cOld.destIPHi;
                                    c.destIPLo = cOld.destIPLo;
                                    c.destPort = cOld.destPort;
                                    c.isIPV6 = cOld.isIPV6;
                                    c.startTick = f.ticks;
                                    c.endTick = f.ticks;
                                    if (f.isFromClient) c.sourceFrames++; else c.destFrames++;
                                    c.totalBytes += (ulong)b.Length;
                                    ArrayList conv = t.GetConversationList((ushort)(c.sourcePort ^ c.destPort));   // XOR the port numbers together to generate an index into conversationIndex
                                    conv.Add(c);
                                    t.conversations.Add(c);
                                }
                            }
                            c.nextProtocol = NextProtocol;
                            if (c.truncatedFrameLength == 0 && f.capturedFrameLength != f.frameLength)
                            {
                                c.truncatedFrameLength = f.capturedFrameLength;
                            }
                            f.conversation = c;
                            c.AddFrame(f, t);  // optionally add to the NetworkTrace frames collection, too
                        }

                        ParseNextProtocol(NextProtocol, b, offset, t, f);

                        break;
                    }
                case 60021: // WFP MessageV6
                case 60022: // WFP Message2V6
                    {
                        ulong sourceIPHi = utility.B2UInt64(b, offset);                   offset += 8;
                        ulong sourceIPLo = utility.B2UInt64(b, offset);                   offset += 8;
                        ulong destIPHi = utility.B2UInt64(b, offset);                     offset += 8;
                        ulong destIPLo = utility.B2UInt64(b, offset);                     offset += 8;
                        byte NextProtocol = b[offset];                                    offset++;        // TCP = 6    UDP = 0x11 (17)
                        if (eventID == 60022) offset += 8;                                                 // bypass FlowContext field in the Message2V4 record
                        short payloadLength = (short)utility.ReadUInt16(b, offset);       offset += 2;

                        // determine the last element of b[] that contains IP64 data - also the last byte of TCP payload - ethernet may extend beyond this
                        if (payloadLength == 0)
                        {
                            f.lastByteOffSet = (ushort)(b.Length - 1);
                        }
                        else
                        {
                            f.lastByteOffSet = (ushort)(offset + payloadLength - 1);
                        }

                        if (NextProtocol == 6 || NextProtocol == 0x11)
                        {
                            ushort SPort = utility.B2UInt16(b, offset);
                            ushort DPort = utility.B2UInt16(b, offset + 2);
                            ConversationData c = t.GetIPV6Conversation(sourceIPHi, sourceIPLo, SPort, destIPHi, destIPLo, DPort);  // adds conversation if new

                            // Is the Frame from Client or Server? This may be reversed later in ReverseBackwardConversations.
                            if (sourceIPHi == c.sourceIPHi && sourceIPLo == c.sourceIPLo && SPort == c.sourcePort) f.isFromClient = true;

                            //
                            // What:   Determine whether the TCP client port has rolled around and is re-used and this should be a new conversation
                            //
                            // Rule:   We see a SYN packet and there is a prior RESET or FIN packet already in the conversation, and is it older than 10 seconds.
                            //
                            // Action: Create a new conversation based on certain key fields of the current conversation.
                            // Action: Add the frame to the new conversation.
                            // Action: Add the new conversation to the conversations collection. 
                            //

                            if (NextProtocol == 6) // TCP
                            {

                                f.flags = b[offset + 13];
                                if ((f.flags & (byte)TCPFlag.SYN) != 0 && (c.finCount > 0 || (c.resetCount > 0) && (f.ticks - ((FrameData)(c.frames[c.frames.Count - 1])).ticks) > 10 * utility.TICKS_PER_SECOND))
                                {
                                    ConversationData cOld = c;
                                    c = new ConversationData();
                                    c.sourceIP = cOld.sourceIP;
                                    c.sourceIPHi = cOld.sourceIPHi;
                                    c.sourceIPLo = cOld.sourceIPLo;
                                    c.sourcePort = cOld.sourcePort;
                                    c.destMAC = cOld.destMAC;
                                    c.destIP = cOld.destIP;
                                    c.destIPHi = cOld.destIPHi;
                                    c.destIPLo = cOld.destIPLo;
                                    c.destPort = cOld.destPort;
                                    c.isIPV6 = cOld.isIPV6;
                                    c.startTick = f.ticks;
                                    c.endTick = f.ticks;
                                    if (f.isFromClient) c.sourceFrames++; else c.destFrames++;
                                    c.totalBytes += (ulong)b.Length;
                                    ArrayList conv = t.GetConversationList((ushort)(c.sourcePort ^ c.destPort));   // XOR the port numbers together to generate an index into conversationIndex
                                    conv.Add(c);
                                    t.conversations.Add(c);
                                }
                            }
                            c.nextProtocol = NextProtocol;
                            if (c.truncatedFrameLength == 0 && f.capturedFrameLength != f.frameLength)
                            {
                                c.truncatedFrameLength = f.capturedFrameLength;
                            }
                            f.conversation = c;
                            c.AddFrame(f, t);  // optionally add to the NetworkTrace frames collection, too
                        }

                        ParseNextProtocol(NextProtocol, b, offset, t, f);

                        break;
                    }
                default:
                    // ignore the frame - we should never get one that's not in the list above
                    break;
            }
        }

        public static void ParseGenericRoutingEncapsulation(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            byte flags1 = b[offset];
            byte flags2 = b[offset + 1];
            offset += 2;

            Boolean fRFC = (flags1 & 0x7F) == 0 && flags2 == 0;
            Boolean fChecksum = (flags1 & 0x80) == 0x80;
            Boolean fRouting = (flags1 & 0x40) == 0x40;
            Boolean fKey = (flags1 & 0x20) == 0x20;
            Boolean fSequence = (flags1 & 0x10) == 0x10;
            Boolean fSSR = (flags1 & 0x08) == 0x08;
            byte RecursionControl = (byte)(flags1 & 0x07);
            Boolean fAck = (flags2 & 0x80) == 0x80;
            byte Version = (byte)(flags2 & 0x07);

            uint NextProtocol = utility.B2UInt16(b, offset);
            offset += 2;

            if (Version ==0)
            {
                if (fRouting || fChecksum) offset += 2;     // bypass checksum
                if (fRFC && fChecksum) offset += 2;         // bypass reserved bytes
                if (fRouting || fChecksum) offset += 2;     // bypass offset
                if (fKey) offset += 4;                      // bypass key value
                if (fSequence) offset += 4;                 // bypass sequence number

                if (fSSR)
                {
                    UInt16 AddressFamily = utility.ReadUInt16(b, offset); ;
                    byte SREOffset = b[offset + 2];
                    byte SRELength = b[offset + 3];
                    offset += 4;

                    while (AddressFamily != 0 && SRELength != 0)  // read until null payload and address family
                    {
                        offset += SRELength;   // bypass SRE payload

                        AddressFamily = utility.ReadUInt16(b, offset); ;
                        SREOffset = b[offset + 2];
                        SRELength = b[offset + 3];
                        offset += 4;
                    }
                }
            }
            else if (Version == 1)
            {
                // bypass PayloadLength (2), CallID (2)
                offset += 4;
                if (fSequence) offset += 4; // bypass the sequence # value
                if (fAck) offset += 4;      // bypass the ACK # value
            }

            ParseNextProtocol(NextProtocol, b, offset, t, f);
        }

        public static void ParseERSPANFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            //
            // ERSPAN is a CISCO router protocol and only works on Ethernet switches
            // Next Protocol = Ethernet
            //
            // https://tools.ietf.org/html/draft-foschiano-erspan-00
            //
            byte flag1 = b[offset];
            byte version = (byte)(flag1 >> 4);

            switch (version)
            {
                case 0:  // Type I ERSPAN Frame - has no data
                    {
                        ParseEthernetFrame(b, offset, t, f);
                        break;
                    }
                case 1:  // Type II ERSPAN Frame
                    {
                        offset += 8;
                        ParseEthernetFrame(b, offset, t, f);
                        break;
                    }
                case 2:  // Type III ERSPAN Frame - 12 byte header + optional 8 byte additional data
                    {
                        Boolean fEthernet = (b[offset + 10] & 0x80) == 0x80;
                        Boolean fOptional = (b[offset + 11] & 0x01) == 0x01;
                        if (fEthernet)
                        {
                            offset += 12;
                            if (fOptional) offset += 8;
                            ParseEthernetFrame(b, offset, t, f);
                        }
                        break;
                    }
            }
        }

        public static void ParseEthernetFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            ulong sourceMAC = 0;
            ulong destMAC = 0;
            ushort NextProtocol = 0;    // IPV4 = 0x0800 (2048)    IPV6 = 0x86DD (34525)     VLAN = 0x8100 inserts 4 bytes at offset 12
            int NextProtocolOffset = 0;

            destMAC = utility.B2UInt48(b, offset);
            sourceMAC = utility.B2UInt48(b, offset + 6);
            NextProtocol = utility.B2UInt16(b, offset + 12);
            NextProtocolOffset = offset + 14;

            try
            {
                ParseNextProtocol(NextProtocol, b, NextProtocolOffset, t, f);  // handles the VLAN as well
            }
            catch (IndexOutOfRangeException)
            {
                if (f.conversation != null) f.conversation.truncationErrorCount++;
            }
            catch { throw; }

            if (f.conversation != null)
            {
                f.conversation.sourceMAC = sourceMAC;
                f.conversation.destMAC = destMAC;
                // statistical gathering
                if (f.conversation.startTick == 0 || f.ticks < f.conversation.startTick)
                {
                    f.conversation.startTick = f.ticks;
                }
                if (f.conversation.endTick < f.ticks) f.conversation.endTick = f.ticks;
                if (f.isFromClient) f.conversation.sourceFrames++; else f.conversation.destFrames++;
            }
        }

        public static void ParseWifiFrame(byte[] b, int offset, NetworkTrace t, FrameData f, bool isNDIS)
        {
            byte version = 0;
            ushort metadataLength = 0;
            byte frameType = 0;
            byte subType = 0;
            byte DSType = 0;
            // byte protectedFrame = 0;
            byte orderedPackets = 0;

            ulong sourceMAC = 0;
            ulong destMAC = 0;
            ushort NextProtocol = 0;    // IPV4 = 0x0800 (2048)    IPV6 = 0x86DD (34525)

            if (isNDIS == false)  // skip the metadata for NDIS captures; they start with the Frame Control
            {
                // Read Wifi Metadata
                version = b[offset];
                if (version != 2)
                {
                    Program.logDiagnostic($"ParseWifiFrame. Frame {f.frameNo}. Unknown Wifi version: {version}");
                    return;
                }

                metadataLength = utility.ReadUInt16(b, offset + 1);
                offset += metadataLength;
            }

            // Read Frame Control

            /*
            subType values - ignore Null or reserved subType values

            0000 Data
            0001 Data + CF-ACK
            0010 Data + CF-poll
            0011 Data + CF-ACK + CF-poll
            0100 Null - no data
            0101 Null + CF-ACK
            0110 Null + CF-poll
            0111 Null + CF-ACK + CF-poll
            1000 QoS Data
            1001 QoS Data + CF-ACK
            1010 QoS Data + CF-poll
            1011 QoS Data + CF-ACK + CF-poll
            1100 QoS Null
            1101 Reserved
            1110 QoS Null + CF-poll
            1111 Reserved
            */

            frameType = (byte)((b[offset] >> 2) & 0x03);  // 0x02 = data. Other values = control frames, etc., that we can ignore
            if (frameType != 2) return;  // not a data packet

            subType = (byte)(b[offset] >> 4);
            if ((subType & 0x04) != 0) return;  // a non-data packet

            DSType = (byte)(b[offset + 1] & 0x03);  // controls where the MAC address values are

            // The protectedFrame flag does not appear to do anything in the trace I examined, commenting out, for now
            // protectedFrame = (byte)(b[offset + 1] & 0x40);
            // if (protectedFrame != 0) return;   // frame is encrypted and we cannot read it; typically only for transmission

            orderedPackets = (byte)(b[offset + 1] >> 7);   // this needs to be known as it can lengthen the header by 4 bytes

            offset += 2;  // two bytes for Frame Control

            offset += 2; // skip Duration

            // Read MAC addresses based on DSType

            switch (DSType)
            {
                case 0:   // Dest, Source, Base Station, Sequence Control = 20 bytes
                    {
                        destMAC = utility.B2UInt48(b, offset);
                        sourceMAC = utility.B2UInt48(b, offset + 6);
                        offset += 20;
                        break;
                    }
                case 1:   // Base Station, Source, Dest, Sequence Control = 20 bytes
                    {
                        sourceMAC = utility.B2UInt48(b, offset + 6);
                        destMAC = utility.B2UInt48(b, offset + 12);
                        offset += 20;
                        break;
                    }
                case 2:   // Dest, Base Station, Source, Sequence Control = 20 bytes
                    {
                        destMAC = utility.B2UInt48(b, offset);
                        sourceMAC = utility.B2UInt48(b, offset + 12);
                        offset += 20;
                        break;
                    }
                case 3:   // Receiver, Transmitter, Dest, Sequence Control, Source = 26 bytes
                    {
                        destMAC = utility.B2UInt48(b, offset + 12);
                        sourceMAC = utility.B2UInt48(b, offset + 20);
                        offset += 26;  // extra length of the header
                        break;
                    }
            }

            if ((subType & 0x08) != 0)
            {
                offset += 2;  // skip Quality of Service (QoS) extra bytes
                if (orderedPackets != 0)
                {
                    offset += 4;  // skip HTControl bytes
                }
            }

            // Parse LLC

            offset += 2; // skip DSAP (1) and SSAP (1)
            offset += ((b[offset] & 0x03) == 0x03 ? 1 : 2);  // flag values 0x00, 0x01, and 0x10 have an extra INFO byte, whereas 0x03 does not

            // Parse SNAP

            offset += 3;  // skip Organization Code
            NextProtocol = utility.B2UInt16(b, offset);
            offset += 2;

            // Choose either IPV4 or IPV6 or VNETTag

            try
            {
                ParseNextProtocol(NextProtocol, b, offset, t, f);
            }
            catch (IndexOutOfRangeException)
            {
                if (f.conversation != null) f.conversation.truncationErrorCount++;
            }
            catch { throw; }

            if (f.conversation != null)
            {
                f.conversation.sourceMAC = sourceMAC;
                f.conversation.destMAC = destMAC;
                // statistical gathering
                if (f.conversation.startTick == 0 || f.ticks < f.conversation.startTick)
                {
                    f.conversation.startTick = f.ticks;
                }
                if (f.conversation.endTick < f.ticks) f.conversation.endTick = f.ticks;
                if (f.isFromClient) f.conversation.sourceFrames++; else f.conversation.destFrames++;
            }
        }

        public static void ParseVNTagFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            //
            // Protocol 0x8926
            //
            // VNTag is an IEEE-defined protocol
            // Next Protocol = 802.1Q Virtual Lan or perhaps IPV4 or IPV6
            //
            // https://www.ieee802.org/1/files/public/docs2009/new-pelissier-vntag-seminar-0508.pdf
            //

            // Skip first 4 bytes, which are just flags - bytes 5 and 6 are the next protocol type

            uint NextProtocol = utility.B2UInt16(b, offset + 4);
            offset += 6;

            ParseNextProtocol(NextProtocol, b, offset, t, f);
        }

        public static void Parse8021QFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            //
            // Protocol 0x8100
            //

            // Skip the first 2 bytes, which are just flags - bytes 3 and 4 are the next protocol

            uint NextProtocol = utility.B2UInt16(b, offset + 2);
            offset += 4;

            ParseNextProtocol(NextProtocol, b, offset, t, f);
        }

        public static void ParseIPV4Frame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            //
            // Frame Structure:
            //
            // 0      (lower nybble) Header Length in DWORDS (4 byte sections). This is typically 5, which means a 20 byte IPV4 header.
            // 0      (upper nybble) ignored
            // 1      ignored
            // 2..3   IPV4 total length, including payload, which includes the higher protocol headers and data
            // 4..5   Packet ID
            // 6..7   ignored
            // 8      Time To Live (TTL)
            // 9      Next Protocol (TCP = 6, UDP = 0x11)
            // 10..11 IPV4 CheckSum (ignored, we look at the TCP CheckSum)
            // 12..15 Source IP Address
            // 16..19 Destination IP Address
            // 20..59 Options (ignored) if Header Length is between 6 and 15 (15 * 4 = 60 bytes) - absent for most packets
            //
            // payload comes after the header, which may start anywhere from byte 20 to 60 depending on the length of the Options section
            // payload length = IPV4 total length - (Header Length * 4)
            //
            // https://en.wikipedia.org/wiki/IPv4
            //

            ushort HeaderLength = 0;
            ushort Length = 0;
            byte TTL = 0;
            byte NextProtocol = 0;     // TCP = 6    UDP = 0x11 (17)
            uint sourceIP = 0;
            uint destIP = 0;
            ushort SPort = 0;
            ushort DPort = 0;

            HeaderLength = (ushort)((b[offset] & 0xf) * 4);
            Length = utility.B2UInt16(b, offset + 2);
            f.packetID = utility.B2UInt16(b, offset + 4);
            TTL = b[offset + 8];                                     // is usually 128 - TTL for # hops, sometimes 64 - TTL or 255 - TTL
            NextProtocol = b[offset + 9];
            sourceIP = utility.B2UInt32(b, offset + 12);
            destIP = utility.B2UInt32(b, offset + 16);

            // determine the last element of b[] that contains IPV4 data - also the last byte of TCP payload - ethernet may extend beyond this
            if (Length == 0)
            {
                f.lastByteOffSet = (ushort)(b.Length - 1);
            }
            else
            {
                f.lastByteOffSet = (ushort)(offset + Length - 1);
            }

            if (NextProtocol == 41)   // IPV6 over IPV4 - ignore eveything but the NextProtcol; extend the IPV4 header by 40
            {
                NextProtocol = b[offset + HeaderLength + 6];
                HeaderLength += 40;           // ignore frames with IPV6 header extensions for now
            }

            if (NextProtocol == 50)   // ESP
            {
                try
                {
                    ushort ESPTrailerLength = GetESPTrailerLength(b, offset + HeaderLength, f.lastByteOffSet, ref NextProtocol);
                    f.lastByteOffSet -= ESPTrailerLength;   // account for the trailer length
                    offset += 8;                            // account for the header length
                }
                catch (Exception)
                {
                    Program.logDiagnostic("Frame " + f.frameNo + " has an unknwn ESP trailer. Ignored.");
                    NextProtocol = 0; // don't parse this frame
                }
            }

            if (NextProtocol == 51)   // AH = Authentication Header
            {
                NextProtocol = b[offset + HeaderLength];
                HeaderLength += (ushort)(b[offset + HeaderLength + 1] * 4 + 8);
            }

            if (NextProtocol == 6 || NextProtocol == 0x11)  // TCP | UDP
            {
                // sneak a peek into the TCP or UDP header for port numbers so we can add the conversation row to the frame data at this time
                // fortunately, the port numbers are in the same location for both protocols
                SPort = utility.B2UInt16(b, offset + HeaderLength);
                DPort = utility.B2UInt16(b, offset + HeaderLength + 2);
                ConversationData c = t.GetIPV4Conversation(sourceIP, SPort, destIP, DPort);  // adds conversation if new

                // Is the Frame from Client or Server? This may be reversed later in ReverseBackwardConversations.
                if (sourceIP == c.sourceIP && SPort == c.sourcePort) f.isFromClient = true;

                // Accumulate TTL stats - record in and out incase the conversation is reversed; report on IN stats

                byte TTLHops = CalculateTTLHops(TTL);
                if (f.isFromClient == false)  // server packets come "In"
                {
                    if (c.TTLCountIn < 10)
                    {
                        c.TTLCountIn++;
                        c.TTLSumIn += TTL;
                    }
                    if (TTLHops < c.minTTLHopsIn) c.minTTLHopsIn = TTLHops;
                }
                else  // client packets go "Out" - should be consistently 128 or 64 or 255 depending on the OS - TTLHops should be 0 always
                {
                    if (c.TTLCountOut < 10)
                    {
                        c.TTLCountOut++;
                        c.TTLSumOut += TTL;
                    }
                    if (TTLHops < c.minTTLHopsOut) c.minTTLHopsOut = TTLHops;
                }

                //
                // Purpose: Do not record duplicate frames unless it has a PktmonData record associated with it
                //
                // Why:     This is an artifact of taking the trace and is not the same as retransmitted frames,
                //          which have the same TCP sequence # but different PacketID values
                //
                // Why:     This will improve statistics.
                //
                // Symptom: The current IPV4 frame has the same IPV4.PacketID as a previous frame.
                // 
                // Action:  Do not add the frame to the conversation.
                // Action:  Increment the duplicate packet count in the conversation.
                //          Sometimes only the client traffic or server traffic will be duplicated but not both, so we have separate counts.
                //
                // Note:    Only IPV4 has a PacketID. IPV6 does not.
                //

                int backCount = 0;

                if (f.pktmon == null)  // we want to avoid the pktmon trace points
                {
                    for (int j = c.frames.Count - 1; j >= 0; j--) // look in descending order for the same Packet ID number
                    {
                        FrameData priorFrame = (FrameData)c.frames[j];
                        if (f.isFromClient == priorFrame.isFromClient)  // only consider packets going in the same direction as the current packet
                        {
                            backCount++;
                            if (f.packetID == priorFrame.packetID)
                            {
                                if (f.isFromClient) c.duplicateClientPackets++; else c.duplicateServerPackets++;
                                return;    // do not record this duplicate frame
                            }
                            if (backCount >= BACK_COUNT_LIMIT) break;  // none found in last 20 frames from the same side of the conversation
                        }
                    }
                }

                //
                // What:   Determine whether the TCP client port has rolled around and is re-used and this should be a new conversation
                //
                // Rule:   We see a SYN packet and there is a prior RESET or FIN packet already in the conversation, and is it older than 10 seconds.
                //
                // Action: Create a new conversation based on certain key fields of the current conversation.
                // Action: Add the frame to the new conversation.
                // Action: Add the new conversation to the conversations collection. 
                //

                if (NextProtocol == 6) // TCP
                {

                    f.flags = b[offset + HeaderLength + 13];
                    if ((f.flags & (byte)TCPFlag.SYN) != 0 && (c.finCount > 0 || (c.resetCount > 0) && (f.ticks - ((FrameData)(c.frames[c.frames.Count - 1])).ticks) > 10 * utility.TICKS_PER_SECOND))
                    {
                        ConversationData cOld = c;
                        c = new ConversationData();
                        c.sourceIP = cOld.sourceIP;
                        c.sourceIPHi = cOld.sourceIPHi;
                        c.sourceIPLo = cOld.sourceIPLo;
                        c.sourcePort = cOld.sourcePort;
                        c.destMAC = cOld.destMAC;
                        c.destIP = cOld.destIP;
                        c.destIPHi = cOld.destIPHi;
                        c.destIPLo = cOld.destIPLo;
                        c.destPort = cOld.destPort;
                        c.isIPV6 = cOld.isIPV6;
                        c.startTick = f.ticks;
                        c.endTick = f.ticks;
                        if (f.isFromClient) c.sourceFrames++; else c.destFrames++;
                        c.totalBytes += (ulong)b.Length;
                        ArrayList conv = t.GetConversationList((ushort)(c.sourcePort ^ c.destPort));   // XOR the port numbers together to generate an index into conversationIndex
                        conv.Add(c);
                        t.conversations.Add(c);
                    }
                }
                c.nextProtocol = NextProtocol;
                if (c.truncatedFrameLength == 0 && f.capturedFrameLength != f.frameLength)
                {
                    c.truncatedFrameLength = f.capturedFrameLength;
                }
                f.conversation = c;
                c.AddFrame(f, t);  // optionally add to the NetworkTrace frames collection, too

             }

            ParseNextProtocol(NextProtocol, b, offset + HeaderLength, t, f);
        }

        public static void ParseIPV6Frame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            ushort HeaderLength = 40;   // we ignore packets with header extensions right now ... http://en.wikipedia.org/wiki/IPv6_packet
            ushort PayloadLength = 0;
            byte NextProtocol = 0;     // TCP = 6    UDP = 0x11 (17)
            byte TTL = 0;  // in IPV6 frame, it is called Hop Limit - is usually 128 - TTL for # hops, sometimes 64 - TTL or 255 - TTL
            ulong sourceIPHi = 0;
            ulong sourceIPLo = 0;
            ulong destIPHi = 0;
            ulong destIPLo = 0;
            ushort SPort = 0;
            ushort DPort = 0;

            PayloadLength = utility.B2UInt16(b, offset + 4);
            NextProtocol = b[offset + 6];
            TTL = b[offset + 7];
            sourceIPHi = utility.B2UInt64(b, offset + 8);
            sourceIPLo = utility.B2UInt64(b, offset + 16);
            destIPHi = utility.B2UInt64(b, offset + 24);
            destIPLo = utility.B2UInt64(b, offset + 32);

            // determine the last element of b[] that contains IPV4 data - also the last byte of TCP payload - ethernet may extend beyond this
            if (PayloadLength == 0)
            {
                f.lastByteOffSet = (ushort)(b.Length - 1);
            }
            else
            {
                f.lastByteOffSet = (ushort)(offset + HeaderLength + PayloadLength - 1);  // added HeaderLength
            }

            if (NextProtocol == 50)   // ESP
            {
                try
                {
                    ushort ESPTrailerLength = GetESPTrailerLength(b, offset + HeaderLength, f.lastByteOffSet, ref NextProtocol);
                    f.lastByteOffSet -= ESPTrailerLength;   // account for the trailer length
                    offset += 8;                            // account for the header length
                }
                catch (Exception)
                {
                    Program.logDiagnostic("Frame " + f.frameNo + " has an unknwn ESP trailer. Ignored.");
                    NextProtocol = 0; // don't parse this frame
                }
            }

            if (NextProtocol == 51)   // AH = Authentication Header
            {
                NextProtocol = b[offset + HeaderLength];
                HeaderLength += (ushort)(b[offset + HeaderLength + 1] * 4 + 8);
            }

            if (NextProtocol == 6 || NextProtocol == 0x11)
            {
                // sneak a peek into the TCP or UDP header for port numbers so we can add the conversation row to the frame data at this time
                // fortunately, the port numbers are in the same location for both protocols
                SPort = utility.B2UInt16(b, offset + HeaderLength);
                DPort = utility.B2UInt16(b, offset + HeaderLength + 2);
                ConversationData c = t.GetIPV6Conversation(sourceIPHi, sourceIPLo, SPort, destIPHi, destIPLo, DPort);

                //Is the Frame from Client or Server?
                if (sourceIPHi == c.sourceIPHi && sourceIPLo == c.sourceIPLo && SPort == c.sourcePort) f.isFromClient = true;

                // Accumulate TTL stats - record in and out incase the conversation is reversed; report on IN stats

                byte TTLHops = CalculateTTLHops(TTL);
                if (f.isFromClient == false)  // server packets come "In"
                {
                    if (c.TTLCountIn < 10)
                    {
                        c.TTLCountIn++;
                        c.TTLSumIn += TTL;
                    }
                    if (TTLHops < c.minTTLHopsIn) c.minTTLHopsIn = TTLHops;
                }
                else  // client packets go "Out" - should be consistently 128 or 64 or 255 depending on the OS - TTLHops should be 0 always
                {
                    if (c.TTLCountOut < 10)
                    {
                        c.TTLCountOut++;
                        c.TTLSumOut += TTL;
                    }
                    if (TTLHops < c.minTTLHopsOut) c.minTTLHopsOut = TTLHops;
                }

                //
                // Determine whether the TCP client port has rolled around and this should be a new conversation
                //
                // The rule is if we see a SYN packet, then is there a RESET or FIN packet already in the conversation, and is it older than 10 seconds. If so, then new conversation.
                //
                if (NextProtocol == 6) // TCP
                {
                    f.flags = b[offset + HeaderLength + 13];
                    if ((f.flags & (byte)TCPFlag.SYN) != 0 && (c.finCount > 0 || (c.resetCount > 0) && (f.ticks - ((FrameData)(c.frames[c.frames.Count - 1])).ticks) > 10 * utility.TICKS_PER_SECOND))
                    {
                        ConversationData cOld = c;
                        c = new ConversationData();
                        c.sourceIP = cOld.sourceIP;
                        c.sourceIPHi = cOld.sourceIPHi;
                        c.sourceIPLo = cOld.sourceIPLo;
                        c.sourcePort = cOld.sourcePort;
                        c.destMAC = cOld.destMAC;
                        c.destIP = cOld.destIP;
                        c.destIPHi = cOld.destIPHi;
                        c.destIPLo = cOld.destIPLo;
                        c.destPort = cOld.destPort;
                        c.isIPV6 = cOld.isIPV6;
                        c.startTick = f.ticks;
                        c.endTick = f.ticks;
                        if (f.isFromClient) c.sourceFrames++; else c.destFrames++;
                        c.totalBytes += (ulong)b.Length;
                        ArrayList conv = t.GetConversationList((ushort)(c.sourcePort ^ c.destPort));   // XOR the port numbers together to generate an index into conversationIndex
                        conv.Add(c);
                        t.conversations.Add(c);
                    }
                }
                c.nextProtocol = NextProtocol;
                if (c.truncatedFrameLength == 0 && f.capturedFrameLength != f.frameLength)
                {
                    c.truncatedFrameLength = f.capturedFrameLength;
                }
                f.conversation = c;
                c.AddFrame(f, t);
            }

            ParseNextProtocol(NextProtocol, b, offset + HeaderLength, t, f);
       }

        public static ushort GetESPTrailerLength(byte[] b, int offset, int LastByteOffset, ref byte NextProtocol)
        {
            // no direct way to tell the length of the security BLOB, it is either 12 or 16 bytes long
            ushort secLen = 12;
            NextProtocol = b[LastByteOffset - secLen];
            byte padLen = b[LastByteOffset - secLen - 1];
            if (ESPOffsetOkay(b, LastByteOffset - secLen - 2, padLen) == false)  // try 16
            {
                secLen = 16;
                NextProtocol = b[LastByteOffset - secLen];
                padLen = b[LastByteOffset - secLen - 1];
                if (ESPOffsetOkay(b, LastByteOffset - secLen - 2, padLen) == false) throw new Exception("Invalid ESP protocol security trailer.");
            }
            // Program.logDiagnostic("ESP Trailer Length = " + (secLen + 2 + padLen) + ". Next Protocol = " + NextProtocol);
            return (ushort)(secLen + 2 + padLen);
        }

        public static bool ESPOffsetOkay(byte[] b, int offset, byte padLen)
        {
            for (int i = 0; i < padLen; i++)
            {
                if (b[offset - i] != (padLen - i)) return false;  // padding is 1, 2, 3, 4, 5, ...
            }
            return true;
        }

        public static void ParseTCPFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            int headerLength = (b[offset + 12] >> 4) * 4; // upper nybble * 4
            int smpLength = 0;
            bool canTestChecksum = true;
            ushort CheckSum = 0;

            if ((b[offset + 12] & 0xF) != 0) canTestChecksum = false;  // we want the lower 4 bits to be all 0
            if (headerLength != 20) canTestChecksum = false;           // we want no TCP options

            // port number offsets handled in IPV4 and IPV6 parsers in order to create the ConversationData object
            f.seqNo = utility.B2UInt32(b, offset + 4);
            f.ackNo = utility.B2UInt32(b, offset + 8);
            f.flags = b[offset + 13];
            f.windowSize = utility.B2UInt16(b, offset + 14);
            if (f.isZeroWindowPacket)
            {
                f.conversation.zeroWindowCount++;
                if (f.isFromClient)
                {
                    f.conversation.hasClientZeroWindow = true;
                }
                else
                {
                    f.conversation.hasServerZeroWindow = true;
                }
            }
            CheckSum = utility.B2UInt16(b, offset + 16);
            if (utility.B2UInt16(b, offset + 18) != 0) canTestChecksum = false;   // we only want to test if the Urgent flag is 0
            if (f.hasSYNFlag)
            {
                if (f.hasACKFlag)
                {
                    if (f.conversation.ackSynTime == 0) f.conversation.ackSynTime = f.ticks;
                }
                else
                {
                    if (f.conversation.synTime == 0) f.conversation.synTime = f.ticks;
                }
            }

            // raw payload length
            int payloadLen = f.lastByteOffSet - offset - headerLength + 1;
            if (payloadLen != 0) canTestChecksum = false;  // want to keep it simple - don't test if there's a payload

            // accumulate captured bytes
            f.conversation.totalBytes += (ulong)b.Length;                  // total packet size
            f.conversation.totalPayloadBytes += (ulong)payloadLen;         // tcp payload length
            if (b.Length > f.conversation.maxPayloadSize)
            {
                f.conversation.maxPayloadSize = payloadLen;
                if (f.hasPUSHFlag || payloadLen < 2) // Definitely not the max if just an ACK flag (len=0) or a Keep-ALive packet (len=1) or has a PUSH flag
                {
                    f.conversation.maxPayloadLimit = false;
                }
                else
                {
                    f.conversation.maxPayloadLimit = true; // Payload > 1 + no PUSH flag, means this should be the maximum frame size
                }
            }

            // captured payload length may be less than actual frame length
            if (f.lastByteOffSet >= b.Length) f.lastByteOffSet = (ushort)(b.Length - 1); // last element position = Length - 1

            //
            // Session MultiPlex Protocol
            //
            // TCPPayload may have SMP header before TDS - 16 bytes, begins with byte 0x53 (83 decimal)
            // Done here because SMP could potentially be for non-SQL conversations; needs to be validated
            //
            // Type = 1     SMP:SYN     No payload after this
            // Type = 2     SMP:ACK     No payload after this
            // Type = 4     SMP:FIN     No payload after this
            // Type = 8     SMP:DATA    Should have a payload of at least 1 byte - this assumption is baked into the code below
            //
            // Documented here: https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-smp/04c8edde-371d-4af5-bb33-a39b3948f0af
            //

            if ((f.isContinuation == false) && (payloadLen > 15) && (b[offset + headerLength] == 0x53))
            {
                byte smpType = b[offset + headerLength + 1];  // valid values 1=SMP:SYN; 2=SMP:ACK; 4=SMP:FIN; 8=SMP:DATA
                uint smpPayloadLength = utility.ReadUInt32(b, offset + headerLength + 4);

                if (((smpType == 1 || smpType == 2 || smpType == 4) && payloadLen == 16 && smpPayloadLength == 16)  // no payload for SMP:SYN, SMP:ACK, SMP:FIN
                   || (smpType == 8 && payloadLen > 16 && smpPayloadLength == payloadLen))                          // spec indicates that flags cannot be OR-ed together
                {
                    //
                    // we are almost 100% sure we have an SMP packet
                    //
                    smpLength = 16;  // added to offset later to provide a new payload offset if SMP:DATA, others have no payload
                    f.smpType = smpType;
                    f.smpSession = utility.ReadUInt16(b, offset + headerLength + 2);
                    if (f.smpSession > f.conversation.smpMaxSession) f.conversation.smpMaxSession = f.smpSession;
                    // f.conversation.isMARSEnabled = true;   // set in TDS Parser
                    if (smpType == 1) { f.conversation.smpSynCount++; f.frameType = FrameType.SMPSyn; }
                    if (smpType == 2) { f.conversation.smpAckCount++; f.frameType = FrameType.SMPAck; }
                    if (smpType == 4)
                    {
                        f.conversation.smpFinCount++;
                        f.frameType = FrameType.SMPFin;
                        if (f.conversation.smpFinTime == 0) f.conversation.smpFinTime = f.ticks; // so we can tell if reset occurs after SMP:FIN
                    }
                    if (smpType == 8) f.conversation.smpDataCount++;
                }
            }

            // copy the remaining bytes from b[] into f.Payload[]. The smpLength value means we skip the smp header, if present.
            payloadLen = f.lastByteOffSet - offset - headerLength - smpLength + 1;
            if (payloadLen > 0)
            {
                f.payload = new byte[payloadLen];
                Array.Copy(b, offset + headerLength + smpLength, f.payload, 0, payloadLen);
            }

            // conversation statistics
            if (f.hasFINFlag)
            {
                f.conversation.finCount++;
                if (f.conversation.FinTime == 0) f.conversation.FinTime = f.ticks;
                if (f.isFromClient)
                {
                    f.conversation.hasClientFin = true;
                }
                else
                {
                    f.conversation.hasServerFin = true;
                    if (!f.conversation.hasClientFin) f.conversation.hasServerFinFirst = true;  // not a good thing, need to report on it
                }
            }
            if (f.hasSYNFlag) f.conversation.synCount++;
            if (f.hasRESETFlag)
            {
                f.conversation.resetCount++;
                if (f.conversation.ResetTime == 0) f.conversation.ResetTime = f.ticks;
            }
            if (f.hasPUSHFlag) f.conversation.pushCount++;
            if (f.hasACKFlag) f.conversation.ackCount++;

            // keep alive - ACK packet has a 1 byte payload that equals 0
            if (f.isKeepAlive)
            {
                f.conversation.keepAliveCount++;  // 2 should happen every 30 seconds of idle time; one from the client and one from the server
            }

            // see if the packet has Named Pipes on port 445
            if ((f.conversation.destPort == 445 || f.conversation.sourcePort == 445) && f.payload != null)
            {
                if (f.conversation.PipeAdminName == "")
                {
                    string pipeName = GetAdminPipeName(f);
                    if (pipeName != "")
                    {
                        f.conversation.PipeAdminName = pipeName;
                        System.Diagnostics.Debug.WriteLine(pipeName);
                    }
                }

                PipeNameData pipeInfo = GetPipeName(f);
                if (pipeInfo != null && pipeInfo.PipeName != "")
                {
                    f.conversation.PipeNames.Add(pipeInfo);
                    System.Diagnostics.Debug.WriteLine(pipeInfo.PipeName);
                }
            }

            // test checksum to find where the trace was taken
            if (t.BadChecksumFrames.Count < 10 && canTestChecksum)
            {
                ushort CalcCheckSum = CalculateTCPCheckSum(f, (ushort)headerLength);
                if (CalcCheckSum != CheckSum)
                {
                    t.BadChecksumFrames.Add(f); // the source IP is the one we want
                }
            }
        }

        public static void ParseUDPFrame(byte[] b, int offset, NetworkTrace t, FrameData f)
        {
            f.conversation.isUDP = true;
            f.isUDP = true;

            //if (f.conversation.sourcePort == 61591) // for debugging purposes only
            //{
            //    Console.WriteLine();
            //}

            // captured payload length may be less than actual frame length
            if (f.lastByteOffSet >= b.Length) f.lastByteOffSet = (ushort)(b.Length - 1); // last element position = Length - 1

            int payloadLen = f.lastByteOffSet - offset - 8 + 1;  // 8 is UDP header length
            if (payloadLen > 0)
            {
                f.payload = new byte[payloadLen];
                Array.Copy(b, offset + 8, f.payload, 0, payloadLen);   // 8 is UDP header length
            }

        }

        // a post processing parser - do first
        public static void ReverseBackwardConversations(NetworkTrace t)
        {
            foreach (ConversationData c in t.conversations)
            {
                FrameData f = (FrameData)c.frames[0];  // get first frame

                if (f.hasSYNFlag && !f.hasACKFlag && !f.isFromClient)
                {
                    TDSParser.reverseSourceDest(c);    // if the first packet is SYN and from the server - reverse the conversation
                }
                else if (f.hasSYNFlag && f.hasACKFlag && f.isFromClient)
                {
                    TDSParser.reverseSourceDest(c);    // if the first packet is ACK+SYN and from client - reverse the conversation
                }
            }
        }

        // a post processing parser
        public static void FindRetransmits(NetworkTrace t)
        {
            int payloadLen = 0;
            int priorPayloadLen = 0;

            foreach (ConversationData c in t.conversations)
            {
                for (int i = 0; i < c.frames.Count; i++) // process the frames in the current conversation in ascending order
                {
                    FrameData f = (FrameData)c.frames[i];

                    int backCount = 0;
                    payloadLen = f.payloadLength;
                    if (payloadLen < 8) continue;   // skip non-TDS packets, especially keep-alive ACKs that have a payload length of 1 - may skip a retransmit of a continuation packet with a small residual payload

                    for (int j = i - 1; j >= 0; j--) // look in descending order for the same sequence number and payload length
                    {
                        FrameData priorFrame = (FrameData)c.frames[j];

                        if (f.isFromClient == priorFrame.isFromClient)
                        {
                            backCount++;
                            if (f.conversation.isIPV6 == false && f.packetID == priorFrame.packetID) continue;  // if packet is IPV4 and Packet IDs match, that's not a retransmitted packet
                            priorPayloadLen = priorFrame.payloadLength;
                            if ((payloadLen == priorPayloadLen) &&
                                ((f.seqNo == priorFrame.seqNo) || ((f.seqNo > priorFrame.seqNo) && (f.seqNo < (priorFrame.seqNo + priorPayloadLen)))))
                            {
                                f.isRetransmit = true;
                                f.conversation.rawRetransmits++;
                                if (payloadLen > 1) f.conversation.sigRetransmits++;
                                FrameData originalFrame = priorFrame.originalFrame == null ? priorFrame : priorFrame.originalFrame;
                                f.originalFrame = originalFrame;
                                originalFrame.retransmitCount++;
                                if (originalFrame.retransmitCount > c.maxRetransmitCount) c.maxRetransmitCount = originalFrame.retransmitCount;
                                break; // each frame locates one retransmit; if retransmitted multiple times, later retransmits will get counted on their own
                            }
                            if (backCount >= BACK_COUNT_LIMIT) break;  // none found in last 20 frames from the same side of the conversation
                        }
                    }
                }
            }
        }

        public static void FindKeepAliveRetransmits(NetworkTrace t)
        {
            foreach (ConversationData c in t.conversations)
            {
                for (int i = 0; i < c.frames.Count; i++) // process the frames in the current conversation in ascending order
                {
                    FrameData f = (FrameData)c.frames[i];
                    if (!f.isKeepAlive) continue;   // skip non-Keep-Alive packets; payload = 1 and flags = ACK and no others

                    int backCount = 0;

                    for (int j = i - 1; j >= 0; j--) // look in descending order for the same sequence number and payload length
                    {
                        FrameData priorFrame = (FrameData)c.frames[j];

                        if (f.isFromClient == priorFrame.isFromClient)
                        {
                            backCount++;
                            long oneSecond = (long)utility.TICKS_PER_SECOND;
                            long tickDiff = f.ticks - priorFrame.ticks;  // frames should be 1 second apart, so this difference should be close to 0
                            if (priorFrame.isKeepAlive && tickDiff < utility.TICKS_PER_SECOND * 1.1) // 0.1 second error on the 1-second timer if diff > 1 second
                            {
                                f.isKeepAliveRetransmit = true;
                                FrameData originalFrame = priorFrame.originalFrame == null ? priorFrame : priorFrame.originalFrame;
                                f.originalFrame = originalFrame;
                                originalFrame.kaRetransmitCount++;
                                if (originalFrame.kaRetransmitCount > c.maxKeepAliveRetransmits) c.maxKeepAliveRetransmits = originalFrame.kaRetransmitCount;
                                break; // each frame locates one retransmit; if retransmitted multiple times, later retransmits will get counted on their own
                            }
                            if (backCount >= BACK_COUNT_LIMIT) break;  // none found in last 20 frames from the same side of the conversation
                        }
                    }
                }
            }
        }

        // a post processing parser - must be done after finding retransmits
        public static void FindContinuationFrames(NetworkTrace t)
        {
            foreach (ConversationData c in t.conversations)
            {
                for (int i = 0; i < c.frames.Count; i++) // process the frames in the current conversation in ascending order
                {
                    FrameData f = (FrameData)c.frames[i];

                    int backCount = 0;
                    if (f.payloadLength == 0) continue;   // not checking ACK packets

                    for (int j = i - 1; j >= 0; j--) // look in descending order for the same ack number - if push flag set, abort
                    {
                        FrameData priorFrame = (FrameData)c.frames[j];

                        if ((f.isFromClient == priorFrame.isFromClient)) // continuation frames have no SMP header, so no need to match on that field
                        {
                            backCount++;
                            if ((priorFrame.flags & (byte)TCPFlag.PUSH) > 0) break; // push flag indicates end of prior continuation, if any
                            if ((priorFrame.ackNo == f.ackNo) && (priorFrame.isRetransmit == false) && (priorFrame.payloadLength > 0))
                            {
                                f.isContinuation = true;
                                break;
                            }
                            if (backCount >= BACK_COUNT_LIMIT) break;  // none found in last 20 frames from the same side of the conversation
                        }  // if
                    }  // for
                }  // for
            }  // foreach
        }

        //
        // Calculate TCPChecksum calculates the TCP Check Sum so we can tell which machine/IP address the trace was taken on
        // This is based on the fact that if TCP Offloading is enabled, then packets orginating on the trace machine will give a bad checksum
        // We will calculate the checksum until 10 packets are found with a mismatch.
        // The IP address that appears most often will be reported.
        // If none are found, or none that repeat a significant amount (exact rubrik TBD) then we cannot identify the machine the trace was taken on
        //
        // *** Designed to be called on short frames that were not truncated and no payload - we are not validating every frame, just enough to determine our goal
        //

        public static ushort CalculateTCPCheckSum(FrameData f, ushort TcpLength)
        {
            int Accumulator = 0;

            ConversationData c = f.conversation;

            // Add IPV6 or IPV4 Pseudoheader
            if (c.isIPV6)
            {
                Accumulator += (ushort)((c.sourceIPHi >> 48) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIPHi >> 32) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIPHi >> 16) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIPHi) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIPLo >> 48) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIPLo >> 32) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIPLo >> 16) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIPLo) & 0xFFFF);

                Accumulator += (ushort)((c.destIPHi >> 12) & 0xFFFF);
                Accumulator += (ushort)((c.destIPHi >> 8) & 0xFFFF);
                Accumulator += (ushort)((c.destIPHi >> 4) & 0xFFFF);
                Accumulator += (ushort)((c.destIPHi) & 0xFFFF);
                Accumulator += (ushort)((c.destIPLo >> 12) & 0xFFFF);
                Accumulator += (ushort)((c.destIPLo >> 8) & 0xFFFF);
                Accumulator += (ushort)((c.destIPLo >> 4) & 0xFFFF);
                Accumulator += (ushort)((c.destIPLo) & 0xFFFF);

                Accumulator += 6; // Protocol 6 = TCP
                Accumulator += TcpLength + f.payloadLength;
            }
            else  // IPv4
            {
                Accumulator += (ushort)((c.sourceIP >> 16) & 0xFFFF);
                Accumulator += (ushort)((c.sourceIP) & 0xFFFF);
                Accumulator += (ushort)((c.destIP >> 16) & 0xFFFF);
                Accumulator += (ushort)((c.destIP) & 0xFFFF);

                Accumulator += 6; // Protocol 6 = TCP
                Accumulator += TcpLength + f.payloadLength;
            }

            // Add TCP fields

            Accumulator += c.sourcePort;
            Accumulator += c.destPort;

            Accumulator += (ushort)((f.seqNo >> 16) & 0xFFFF);
            Accumulator += (ushort)((f.seqNo) & 0xFFFF);
            Accumulator += (ushort)((f.ackNo >> 16) & 0xFFFF);
            Accumulator += (ushort)((f.ackNo) & 0xFFFF);

            Accumulator += (ushort)(((TcpLength / 4) << 12) + f.flags);  // we are assuming Reserved and Nonce Sum are all 0 for bits 4-7
            Accumulator += f.windowSize;

            // use 0 for checksum - NOP

            // Assume Urgent pointer is 0  - must be managed by caller
            // Assume no TCP options       - must be managed by caller (header length must be 20)
            // Assume no payload           - must be managed by the caller

            // add overflow amount - for one's complement addition
            if (Accumulator > 65535) Accumulator = (Accumulator & 0xFFFF) + (Accumulator >> 16);
            // Might overflow once more
            if (Accumulator > 65535) Accumulator -= 65535;  // subtract 65536 (0x10000) and add 1 - same effect as the calculation above, but more specialized form

            // take one's complement = invert all bits (xor against 0xFFFF)
            Accumulator ^= 0xFFFF;

            return (ushort)Accumulator;
        }

        public static string GetAdminPipeName(FrameData f)
        {
            //
            // The Admin pipe name has this format: hostname\IPC$
            //

            int pos1 = -1, pos2 = -1;
            byte backslash = (byte)'\\';

            // Does it contain the Admin pipe suffix

            pos1 = utility.FindUNICODEString(f.payload, 0, @"\IPC$");
            if (pos1 == -1) return "";

            // Read backward for a low character
            for (int i = pos1 - 1; i >=0; i--)
            {
                if (f.payload[i] == backslash)  // ignore the null byte between letters
                {
                    pos2 = i - 2; // we stop on the first one found. Subtract to to get the one closer to the start of the byte array
                    break;
                }
            }

            if (pos2 == -1) return "";

            // Length in characters, not bytes, but pos in byte offset
            string pipeName = utility.ReadUnicodeString(f.payload, pos2, (pos1 - pos2) / 2 + 5);  // Length of "\IPC$" = 5 characters

            return pipeName;

        }  // end of GetAdminPipeName

        public static PipeNameData GetPipeName(FrameData f)
        {
            //
            // Named pipes names can be one of two formats:
            //
            // Default instance:              sql\query
            // Named instance:                MSSQL$instance\sql\query
            //

            int pos1 = -1, pos2 = -1;

            // Does it contain a SQL pipe

            pos1 = utility.FindUNICODEString(f.payload, 0, @"sql\query");
            if (pos1 == -1) return null;

            // Does it contain instance prefix
            pos2 = utility.FindUNICODEString(f.payload, 0, @"MSSQL$");

            if (pos2 == -1)   // default instance
            {
                PipeNameData pipeInfo = new PipeNameData();
                pipeInfo.PipeName = @"sql\query";
                pipeInfo.frame = f;
                return pipeInfo;
            }
            else              // named instance - pos2 has a lower offset than pos1
            {
                PipeNameData pipeInfo = new PipeNameData();
                pipeInfo.PipeName = utility.ReadUnicodeString(f.payload, pos2, (pos1 - pos2) / 2 + 9);  // Length of "sql\query" = 9 characters
                pipeInfo.frame = f;
                return pipeInfo;
            }
        }  // end of GetPipeName

        public static byte CalculateTTLHops(byte TTL)
        {
            if (TTL <= 64) return (byte)(64 - TTL);
            if (TTL <= 128) return (byte)(128 - TTL);
            return (byte)(255 - TTL);
        }

    }  // end of class
}      // end of namespace
