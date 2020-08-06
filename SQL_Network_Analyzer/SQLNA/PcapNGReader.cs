// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.IO;
using System.Collections;
using System.Net;
using System.Text;

namespace SQLNA
{
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Spec URL: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
    //
    // Order of calling:
    //
    // <constructor> passing an open BinaryReader
    // Init - call once
    // Read - repeatedly until it returns null instead of a Frame object
    //

    class PcapNGReader : ReaderBase
    {
        Int64 sectionStart = 0;
        UInt64 sectionLength = 0;
        UInt32 frameNumber = 0;
        UInt32 magicNumber = 0;
        UInt32 blockLength = 0;
        Int64 blockStart = 0;
        Int64 nextBlockStart = 0;
        // internal bool fReverseBytes = false;  -- implemented in ReaderBase.cs
        // BinaryReader r = null;                -- implemented in ReaderBase.cs

        ArrayList interfaceOptions = new ArrayList();

        public PcapNGReader(BinaryReader r) : base(r) {}

        public override void Init()
        {
            readHeaderBlock();
        }

        public override Frame Read()
        {
            Frame nf = null;
            try
            {
                while (nf == null)
                {
                    nf = readBlock();
                }
                return nf;
            }
            catch (System.IO.EndOfStreamException)
            {
                return null;
            }
        }

        Frame readBlock()
        {
            UInt32 blockType = read4Bytes();
            switch (blockType)
            {
                case 0x0A0D0D0A:
                    {
                        readHeaderBlock();
                        return null;
                    }
                case 0x00000001:
                    {
                        readInterfaceBlock();
                        return null;
                    }
                case 0x00000002:
                    {
                        return readPacketBlock();
                    }
                case 0x00000003:
                    {
                        return readSimplePacketBlock();
                    }
                case 0x00000006:
                    {
                        return readEnahancedPacketBlock();
                    }
                case 0x00000004:     // name resolution block
                case 0x00000005:     // interface statistics block
                default:
                    {
                        if (blockType != 4 && blockType != 5)
                        {
                            Program.logDiagnostic("Unknown block type " + blockType.ToString("X") + " at offset " + blockStart);
                        }
                        readGenericBlock();
                        return null;
                    }
            }
        }


        void readHeaderBlock()
        {
            //
            // This must be the first block in the file.
            // There may be other header blocks in the file that may change the byte order of data in the following blocks.
            //
            blockStart = r.BaseStream.Position - 4;
            sectionStart = blockStart;
            blockLength = r.ReadUInt32();

            magicNumber = r.ReadUInt32();

            switch (magicNumber)
            {
                case 0x1A2B3C4D:
                    {
                        fReverseBytes = false;
                        break;
                    }
                case 0x4D3C2B1A:
                    {
                        fReverseBytes = true;
                        blockLength = utility.ReverseUInt32(blockLength);
                        break;
                    }
                default:
                    {
                        throw new Exception("Magic number " + magicNumber.ToString("X") + " is incorrect, source file is not a PCAPNG format capture file.");
                    }
            }

            nextBlockStart = blockStart + blockLength; // have to do this after we reverse bytes, if necessary


            UInt16 majorVersion = 0;
            UInt16 minorVersion = 0;

            majorVersion = read2Bytes();           // not currently used
            minorVersion = read2Bytes();           // not currently used
            sectionLength = read8Bytes();          // not really used as we are reading sequentially

            interfaceOptions = new ArrayList();    // new section = new interface block(s)

            // Seek to beginning of the next block
            r.BaseStream.Seek(nextBlockStart, SeekOrigin.Begin);
        }

        void readInterfaceBlock()
        {
            //
            // There must be at least one of these following the header block and before the first packet block.
            // According to the spec, it must be immediately following, but the app doesn't care as long as we haven't hit a packet without a corresponding entry.
            //
            // We only support Ethernet (LinkType = InterfaceID = 1). All other packet blocks are ignored.
            //
            // For Simple Packet blocks, there must be 1 and only 1 Interface block in that section. Other packet types have the InterfaceID == LinkType in them.
            // We do not support Simple Packet blocks because they do not contain a timestamp.
            //

            blockStart = r.BaseStream.Position - 4;
            blockLength = r.ReadUInt32();
            nextBlockStart = blockStart + blockLength;

            InterfaceOptions intOpt = new InterfaceOptions();

            intOpt.LinkType = read2Bytes();
            read2Bytes(); // skip unused portion of block
            intOpt.maxBytesRead = read4Bytes();

            interfaceOptions.Add(intOpt);

            // read interface options

            UInt16 OptType = 0;
            UInt16 OptLen = 0;
            int padding = 0;

            if (blockLength > 40)
            {
                OptType = read2Bytes();
                OptLen = read2Bytes();
                padding = OptLen % 4;

                while (OptType != 0)
                {
                    switch (OptType)
                    {
                        case 9:
                            {
                                intOpt.timeResolution = r.ReadByte();
                                r.ReadBytes(padding);
                                break;
                            }
                        case 14:
                            {
                                intOpt.timestampOffset = (Int32)read8Bytes();
                                break;
                            }
                        default:  // skip unhandled option types
                            {
                                r.ReadBytes(OptLen + padding);
                                break;
                            }
                    }

                    OptType = read2Bytes();
                    OptLen = read2Bytes();
                    padding = OptLen % 4;
                }
            }

            // Seek to beginning of the next block
            r.BaseStream.Seek(nextBlockStart, SeekOrigin.Begin);
        }

        Frame readPacketBlock()   // an obsolete type but we may see it
        {
            blockStart = r.BaseStream.Position - 4;
            blockLength = r.ReadUInt32();
            nextBlockStart = blockStart + blockLength;

            Frame nf = null;
            UInt16 InterfaceID = read2Bytes();  // InterfaceID is 0-based
            UInt16 DropsCount = read2Bytes();
            UInt32 timestampHi = read4Bytes();
            UInt32 timestampLo = read4Bytes();
            UInt32 capturedLen = read4Bytes();
            UInt32 packetLen = read4Bytes();

            InterfaceOptions intOpt = (InterfaceOptions)(interfaceOptions[InterfaceID]);

            if (intOpt.LinkType == 1)   // Ethernet - return null for all others
            {
                frameNumber++; 
                nf = new Frame();
                nf.frameLength = packetLen;
                nf.bytesAvailable = capturedLen;
                nf.frameNumber = frameNumber;
                nf.length = capturedLen;
                nf.ticks = timeToTicks(timestampHi, timestampLo, intOpt.timeResolution, intOpt.timestampOffset);
                nf.data = r.ReadBytes((Int32)capturedLen);
                nf.linkType = (UInt16)intOpt.LinkType;
            }
            
            // Seek to beginning of the next block
            r.BaseStream.Seek(nextBlockStart, SeekOrigin.Begin);

            return nf;
        }

        Frame readSimplePacketBlock()  // not supported because it does not contain a timestamp
        {
            blockStart = r.BaseStream.Position - 4;
            blockLength = r.ReadUInt32();
            nextBlockStart = blockStart + blockLength;

            if (interfaceOptions == null || interfaceOptions.Count == 0)
            {
                throw new Exception("Invalid PCAPNG file. Simple Packet Block at offset " + blockStart + " not allowed. Section at offset " + sectionStart + " has no Interface Description Blocks.");
            }

            if (interfaceOptions.Count > 1)
            {
                throw new Exception("Invalid PCAPNG file. Simple Packet Block at offset " + blockStart + " not allowed. Section at offset " + sectionStart + " has more than one Interface Description Block.");
            }

            // does not have timestamps, so we really do not want these ...

            InterfaceOptions intOpt = (InterfaceOptions)(interfaceOptions[0]);

            if (intOpt.LinkType == 1)   // Ethernet - return null for all others
            {
                throw new Exception("Simple Packet Block not allowed since it does not contain any timestamp information.");
            }

            // ignore the block if not Ethernet - perhaps a new section will have Ethernet traffic

            // Seek to beginning of the next block
            r.BaseStream.Seek(nextBlockStart, SeekOrigin.Begin);

            return null;
        }

        Frame readEnahancedPacketBlock()
        {
            blockStart = r.BaseStream.Position - 4;
            blockLength = r.ReadUInt32();
            nextBlockStart = blockStart + blockLength;

            //
            // The main change from readPacketBlock and readEnhancedPacketBlock is that the InterfaceID is now 32-bits instead of 16 bits
            // and we no longer read the number of dropped packets (16 bite) as part of the block header. For dropped packet count, need to
            // read packet options after the frame data: OptID = 4, OptLen = 8
            //
            // See readInterfaceBlock for implementation details.
            // Need to find the remainder for the frame data to align to DWORD boundary before reading options.
            //

            Frame nf = null;
            UInt32 InterfaceID = read4Bytes();   // InterfaceID is 0-based
            UInt32 timestampHi = read4Bytes();
            UInt32 timestampLo = read4Bytes();
            UInt32 capturedLen = read4Bytes();
            UInt32 packetLen = read4Bytes();

            InterfaceOptions intOpt = (InterfaceOptions)(interfaceOptions[(Int32)InterfaceID]);

            if (intOpt.LinkType == 1)   // Ethernet - return null for all others
            {
                frameNumber++;
                nf = new Frame();
                nf.frameLength = packetLen;
                nf.bytesAvailable = capturedLen;
                nf.frameNumber = frameNumber;
                nf.length = capturedLen;
                nf.ticks = timeToTicks(timestampHi, timestampLo, intOpt.timeResolution, intOpt.timestampOffset);
                nf.data = r.ReadBytes((Int32)capturedLen);
            }

            // Seek to beginning of the next block
            r.BaseStream.Seek(nextBlockStart, SeekOrigin.Begin);

            return nf;
        }

        void readGenericBlock()
        {
            blockStart = r.BaseStream.Position - 4;
            blockLength = r.ReadUInt32();
            nextBlockStart = blockStart + blockLength;

            // do nothing - just skip the block contents

            // Seek to beginning of the next block
            r.BaseStream.Seek(nextBlockStart, SeekOrigin.Begin);
        }

        long timeToTicks(UInt32 Hi, UInt32 Lo, byte resolution, Int64 offset)
        {
            //
            // Per the spec, time is a 64-bit number indicating the # seconds past 1/1/1970 00:00:00 UTC
            // Fraction resolution is: if MSB is 0, then 10 ^ -resolution
            //                         if MSB is 1, then 2 ^ -resultion of remaining bits
            //
            // offset is in seconds - add to the timestamp to get the absolute time - default offset is 0, so times are normally absolute in the frame
            //
            double divisor =  ((resolution & 0x80) == (byte)0x80) ? Math.Pow(2, (resolution & 0x7F)) : Math.Pow(10, resolution);
            long frameTicks = (((long)(Hi)) << 32) | Lo;
            double frameSeconds = (double)frameTicks  / divisor;
            DateTime frameTime = new DateTime(1970, 1, 1, 0, 0, 0);
            frameTime = frameTime.AddSeconds(frameSeconds + (long)offset);  // takes a double, so can account for fractional seconds
            return frameTime.Ticks;
        }

    }

    public class InterfaceOptions
    {
        public UInt16   LinkType = 0;                           // 1 = Ethernet, the only type we support
        public UInt32   maxBytesRead = 0;
        public byte     timeResolution = 6;                     // default (6 = microseconds) if this option is missing
        public Int64    timestampOffset = 0;                    // default (0 = none) if this noption is missing
    }
}
