// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.IO;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Order of calling: <constructor> passing an open BinaryReader.
    //                   Init - call once
    //                   Read - call repeatedly until it returns null instead of a Frame object
    //

    class NetMonReader : ReaderBase
    {
        private const int MAX_FRAME_SIZE = 0x100000; // upped from 0x10000 (64Kb) to 0x100000 (1Mb) - no real reason for these limits as they are UINT32
        private const byte ESP_PROTOCOL = 0x32;
        private const byte IP_PROTOCOL = 0x06;
        public UInt32 magicNumber;		// Netmon magic number 
        public byte minorVersion;			// Minor version number
        public byte majorVersion;			// Major version number
        public UInt16 networkType;		// Network type
        public SYSTEMTIME captureTime;		// SYSTEMTIME when capture was started
        private UInt32 frameTableOffset;	// Frame index table offset
        private UInt32 frameTableLength;	// Frame index table length (bytes)
        private UInt32 userDataOffset;		// User data offset
        private UInt32 userDataLength;		// User data length (bytes)
        private UInt32 commentDataOffset;	// Comment data offset
        private UInt32 commentDataLength;	// Comment data length (bytes)
        private UInt32 statisticsOffset;	// Statistics structure offset
        private UInt32 statisticsLength;	// Statistics structure length (bytes)
        private UInt32 networkInfoOffset;	// offset to network info structure 
        private UInt32 networkInfoLength;	// length of network info structure
        public DateTime captureDateTime;	// captureTime in DateTime format
        public long startTicks;			// captureTime converted to Ticks
        private UInt32[] frameTable;		// Table of frame offset's
        public long frameCount;				// Number of frames in the Netmon file (frames start with 0)
        // private BinaryReader r = null;		// BinaryReader used to read data from Netmon file -- implemented in ReaderBase.rs
        private UInt32 frameNumber = 0;

        public NetMonReader(BinaryReader r) : base(r) {}
        
        // Opens Netmon capture file, reads netmon capture file header info.
        // Throws exception if anything goes wrong.
        // public void Open(string captureFileName, NetworkTrace t)
        
        public override void Init()
        {
            int i;

            // r = new BinaryReader(new FileStream(captureFileName, FileMode.Open, FileAccess.Read, FileShare.Read));

            r.BaseStream.Seek(0, SeekOrigin.Begin);  // seek to beginning and re-read magic number

            magicNumber = r.ReadUInt32();

            if (0x55424d47 != magicNumber)
            {
                throw new Exception("Magic number " + magicNumber.ToString("X") + " is incorrect, source file is not a Netmon 2.x format capture file.");
            }

            minorVersion = r.ReadByte();
            majorVersion = r.ReadByte();

            if (2 != majorVersion)
            {
                throw new Exception("majorVersion is not Netmon 2.x format, cannot continue.");
            }

            networkType = r.ReadUInt16();   // used if none specified after the packet data
            captureTime = new SYSTEMTIME();
            captureTime.wYear = r.ReadUInt16();
            captureTime.wMonth = r.ReadUInt16();
            captureTime.wDayOfWeek = r.ReadUInt16();
            captureTime.wDay = r.ReadUInt16();
            captureTime.wHour = r.ReadUInt16();
            captureTime.wMinute = r.ReadUInt16();
            captureTime.wSecond = r.ReadUInt16();
            captureTime.wMilliseconds = r.ReadUInt16();

            // Adjust for junk data, I have seen this with Ethereal conversions.
            if ((captureTime.wMilliseconds < 0) || (captureTime.wMilliseconds > 999)) captureTime.wMilliseconds = 0;

            // Calculate captureDateTime and startTicks.
            captureDateTime = new DateTime(captureTime.wYear, captureTime.wMonth, captureTime.wDay,
                captureTime.wHour, captureTime.wMinute, captureTime.wSecond, captureTime.wMilliseconds);

            startTicks = captureDateTime.Ticks;

            // Read rest of offset values from netmon header.
            frameTableOffset = r.ReadUInt32();
            frameTableLength = r.ReadUInt32();
            userDataOffset = r.ReadUInt32();
            userDataLength = r.ReadUInt32();
            commentDataOffset = r.ReadUInt32();
            commentDataLength = r.ReadUInt32();
            statisticsOffset = r.ReadUInt32();
            statisticsLength = r.ReadUInt32();
            networkInfoOffset = r.ReadUInt32();
            networkInfoLength = r.ReadUInt32();

            // Build table of frame offsets (frameTable).
            if (0 == frameTableLength)
            {
                throw new Exception("Zero length frame table found, source file is invalid netmon capture file.");
            }

            // One DWORD per frame offset.
            frameTable = new UInt32[frameTableLength / 4];

            // Set frameCount.
            frameCount = frameTable.Length;

            // Seek to base of frame table.
            r.BaseStream.Seek(frameTableOffset, SeekOrigin.Begin);

            // Read frame table offsets into frame table.
            for (i = 0; i < frameTable.Length; i++)
            {
                frameTable[i] = r.ReadUInt32();
            }

            frameNumber = 0;
        }

        public override Frame Read()
        {
            Frame nf = null;
            long ticksLo;
            long seekOffset;
            long nextOffset = 0;
            int linkLayerBytes = 0;

            frameNumber++;

            if (frameNumber > frameTable.Length)
            {
                frameTable = null;
                return null;
            }
            nf = new Frame();

            nf.frameNumber = frameNumber;

            // Jump to start of frame using frame table information.
            // Note I try to use relative seeks if I can, because I found
            // via LOP profiler that using absolute seeks cost me about 12% of my
            // total time spent reading the netmon file.

            // Hopefully this is the most common seek direction, forward!
            if (r.BaseStream.Position <= frameTable[frameNumber - 1])
            {
                seekOffset = (long)(frameTable[frameNumber - 1] - r.BaseStream.Position);
                r.BaseStream.Seek(seekOffset, SeekOrigin.Current);
            }
            else
            {
                // Had some problems with reverse seek, so just doing an absolute seek
                // here for safety.
                r.BaseStream.Seek(frameTable[frameNumber - 1], SeekOrigin.Begin);
            }

            // Read frame header.
            ticksLo = (long)r.ReadUInt32();
            nf.ticks = (long)r.ReadUInt32();
            nf.ticks <<= 32;
            nf.ticks += ticksLo;
            nf.ticks *= 10;
            nf.ticks += startTicks;
            nf.frameLength = r.ReadUInt32();
            nf.bytesAvailable = r.ReadUInt32();

            // Read frame raw data
            if (nf.bytesAvailable > MAX_FRAME_SIZE)
            {
                // TODO: Fix this!
                // throw new Exception( "Frame size exceeds MAX_FRAME_SIZE." );
                nf.length = 0;
                nf.data = new byte[0];
                return nf;
            }
            nf.data = r.ReadBytes((int)nf.bytesAvailable);
            nf.length = nf.bytesAvailable;

            //
            // nf.linkType = r.ReadUInt16();  // initial code based on spec notes and data structures
            //
            // After direct examination of some problematic NETMON traces, it appears that the Link Type
            // can be stored in either 1 or 2 bytes depending on where the start of the next frame is.
            // If the length is 0, then we use the default networkType read from the .CAP file header.
            // Any other length results in default networkType, as well.
            //
            // Because Frame numbers are 1-based and the table is 0-based, the frame offset is frameTable[frameNumber - 1],
            // so the next frame's offset is frameTable[frameNumber]. For the last frame, the frame table starts immediately afterwards.
            //
            nextOffset = (frameNumber < frameTable.Length) ? frameTable[frameNumber] : frameTableOffset;  // last frame ends right before the frame table
            linkLayerBytes = (int)(nextOffset - r.BaseStream.Position);

            //
            // Log the link types and where reading them from. NETMON files aren't 100% consistent.
            //
            // Program.logDiagnostic($"Frame={frameNumber} StartOffset=x{frameTable[frameNumber - 1].ToString("X8")} Length={nf.length} (x{nf.length.ToString("X4")}) " +
            //                       $"LinkPos={r.BaseStream.Position} (x{r.BaseStream.Position.ToString("X8")}) " +
            //                       $"NextOffset={nextOffset} (x{nextOffset.ToString("X8")})");

            switch (linkLayerBytes)
            {
                case 0:
                    {
                        nf.linkType = networkType; // Read in the file header
                        // Too much noise
                        // Program.logDiagnostic($"NetMonReader: Using default link layer type of {networkType} at frame {frameNumber}.");
                        break;
                    }
                case 1:
                    {
                        nf.linkType = r.ReadByte();
                        break;
                    }
                case 2:
                    {
                        nf.linkType = r.ReadUInt16();
                        break;
                    }
                default:
                    {
                        bool fReadTwoBytes = false;
                        if (linkLayerBytes > 2)  
                        {
                            fReadTwoBytes = true;
                            nf.linkType = r.ReadUInt16();
                        }
                        else
                        {
                            nf.linkType = networkType; // Read in the file header
                        }
                        Program.logDiagnostic($"NetMonReader: Invalid link type length of {linkLayerBytes} at frame {frameNumber}. Should be 0, 1, or 2. {(fReadTwoBytes ? "Reading first 2 bytes." : "Using default link type.")}");
                        break;
                    }
            }

            return nf;
        }

    }
}
