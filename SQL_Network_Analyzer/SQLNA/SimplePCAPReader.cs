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
    // Reads .PCAP files and returns frames
    // Spec URL: http://wiki.wireshark.org/Development/LibpcapFileFormat
    //
    // Calling order:
    //
    // <constructor> passing an open BinaryReader
    // Init - call once
    // Read - repeatedly until it returns null instead of a Frame object
    //

    class SimplePCAPReader : ReaderBase
    {

        UInt32 frameNumber = 0;
        UInt32 magicNumber = 0;
        // BinaryReader r = null;                -- implemented in ReaderBase.cs
        // internal bool fReverseBytes = false;  -- implemented in ReaderBase.cs
        bool fNanosecondResolution = false;
        UInt16 versionMajor = 0;                 // Current version is 2.4
        UInt16 versionMinor = 0;
        UInt32 gmtOffsetSeconds = 0;             // Add to timestamp to get GMT time - normally 0
        UInt32 sigFigs = 0;                      // should be 0
        UInt32 maxFrameLength = 0;               // typically 0xFFFF but can be larger
        UInt32 networkType = 0;                  // we only support: 1 = Ethernet

        public SimplePCAPReader(BinaryReader r) : base(r) {}

        public override void Init()
        {
 
            r.BaseStream.Seek(0, SeekOrigin.Begin);  // seek to beginning and re-read magic number

            magicNumber = r.ReadUInt32();

            switch (magicNumber)
            {
                case 0xa1b2c3d4:   // PCAP normal byte order   - millisecond resolution
                    {
                        fReverseBytes = false;
                        fNanosecondResolution = false;
                        break;
                    }
                case 0xd4c3b2a1:  // PCAP reversed byte order - millisecond resolution
                    {
                        fReverseBytes = true;
                        fNanosecondResolution = false;
                        break;
                    }
                case 0xa1b23c4d:  // PCAP normal byte order   - nanosecond resolution
                    {
                        fReverseBytes = false;
                        fNanosecondResolution = true;
                        break;
                    }
                case 0x4d3cb2a1:  // PCAP reversed byte order - nanosecond resolution
                    {
                        fReverseBytes = true;
                        fNanosecondResolution = true;
                        break;
                    }
                default:
                    {
                        throw new Exception("Magic number " + magicNumber.ToString("X") + " is incorrect, source file is not a PCAP format capture file.");
                    }
            }

            versionMajor = read2Bytes();
            versionMinor = read2Bytes();
            gmtOffsetSeconds = read4Bytes();
            sigFigs = read4Bytes();
            maxFrameLength = read4Bytes();
            networkType = read4Bytes();
        }

        public override Frame Read()
        {
            Frame nf = new Frame();

            try
            {
                UInt32 timeSeconds = read4Bytes();
                UInt32 timeFraction = read4Bytes();   // can be milliseconds or nanoseconds; if > 1 sec, keep remainder and increment timeSeconds
                UInt32 captureLength = read4Bytes();  // bytes saved in the file
                UInt32 frameLength = read4Bytes();    // original frame length; should be >= captureLength

                frameNumber += 1;

                //
                // timeSeconds is seconds after 1/1/1970 00:00:00 GMT
                //
                DateTime frameTime = new DateTime(1970, 1, 1, 0, 0, 0);
                frameTime = frameTime.AddSeconds(timeSeconds);

                //
                // ticks have a 100 nanosecond resolution - so have to adjust timeFraction based on fractional seconds resolution
                //
                if (fNanosecondResolution)
                {
                   frameTime = frameTime.AddTicks(timeFraction / 100);
                }
                else  // microsecond resolution
                {
                    frameTime = frameTime.AddTicks(timeFraction * 10);
                }

                nf.bytesAvailable = captureLength;
                nf.frameLength = frameLength;
                nf.frameNumber = frameNumber;
                nf.ticks = frameTime.Ticks;

                nf.data = r.ReadBytes((int)nf.bytesAvailable);
                nf.length = nf.bytesAvailable;
                nf.linkType = (UInt16)networkType;

                return nf;
            }
            catch (System.IO.EndOfStreamException)
            {
                return null;
            }
        }

    }
}
