// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.IO;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Base class for network file readers
    // Frame definition
    //

    public class Frame
    {
        public UInt32 frameNumber;		   // Frame number.
        public UInt32 frameLength;		   // actual length of packet
        public UInt32 bytesAvailable;	   // number of bytes available in packet.
        public long ticks;				   // Absolute ticks of frame (calculated)
        public byte[] data;		   	       // Byte data for frame.
        public long length = 0;		       // Length of data in bytes.
        public bool isPKTMON = false;      // ETLFileReader sets this - if false, use the linkType to determine the parser
        public ushort pktmonEventType = 0; // ETLFileReader sets this
        public ushort linkType = 0;        // what provider is it - Ethernet (0 or 1), Wifi, etc.
    };

    public abstract class ReaderBase
    {
        internal BinaryReader r = null;
        internal bool fReverseBytes = false;  

        public ReaderBase(BinaryReader reader)
        {
            r = reader;
        }

        public abstract void Init();

        public abstract Frame Read();

        internal UInt16 read2Bytes()
        {
            UInt16 data = r.ReadUInt16();
            if (fReverseBytes)
                return utility.ReverseUInt16(data);
            else
                return data;
        }

        internal UInt32 read4Bytes()
        {
            UInt32 data = r.ReadUInt32();
            if (fReverseBytes)
                return utility.ReverseUInt32(data);
            else
                return data;
        }

        internal UInt64 read8Bytes()
        {
            UInt64 data = r.ReadUInt64();
            if (fReverseBytes)
                return utility.ReverseUInt64(data);
            else
                return data;
        }

    }
}
