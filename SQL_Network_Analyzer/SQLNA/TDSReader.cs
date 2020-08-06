// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // A reader class to encapsultate reading the frame data and handle the offset management
    //
    // Used by several parsers
    // Needs to be improved for TDS packets by having a method coalese TCP continuation frames and coalescing TDS multi-packet messages
    //

    public class TDSReader
    {
        byte[] b;
        int startOffset;
        int currentOffset;
        int offsetLimit;          // last valid offset
        int childHighOffset;
        int nextTokenOffset = -1;
        TDSReader ParentReader = null; 
        UInt32 m_TDSVersion = 0;      // Set by Login ACK token - otherwise 0

        public TDSReader(byte[] data, int initialOffset, int lastTDSIndex = -1, int TDSlength = -1)
        {
            b = data;
            startOffset = initialOffset;
            currentOffset = initialOffset;
            childHighOffset = initialOffset;
            if (lastTDSIndex != -1) offsetLimit = lastTDSIndex;
            if (TDSlength != -1) offsetLimit = initialOffset + TDSlength - 1;
        }

        //
        // Used when creating child TDSReaders - called by the OffsetReader method - See Prelogin token for an example
        //

        internal TDSReader(TDSReader parent, byte[] data, int initialOffset, int lastTDSIndex = -1, int TDSlength = -1)
            : this(data, initialOffset, lastTDSIndex, TDSlength)
        {
            ParentReader = parent;
        }

        public byte ReadByte()
        {
            currentOffset++;
            ValidatePosition();
            UpdateParentOffset();
            return b[currentOffset - 1];
        }

        public ushort ReadUInt16()
        {
            currentOffset += 2;
            ValidatePosition();
            UpdateParentOffset();
            return utility.ReadUInt16(b, currentOffset - 2);
        }

        public ushort ReadBigEndianUInt16()
        {
            currentOffset += 2;
            ValidatePosition();
            UpdateParentOffset();
            return utility.B2UInt16(b, currentOffset - 2);
        }

        public short ReadInt16()
        {
            return (short)ReadUInt16();
        }

        public short ReadBigendianInt16()
        {
            return (short)ReadBigEndianUInt16();
        }

        public uint ReadUInt32()
        {
            currentOffset += 4;
            ValidatePosition();
            UpdateParentOffset();
            return utility.ReadUInt32(b, currentOffset - 4);
        }

        public uint ReadBigEndianUInt32()
        {
            currentOffset += 4;
            ValidatePosition();
            UpdateParentOffset();
            return utility.B2UInt32(b, currentOffset - 4);
        }

        public int ReadInt32()
        {
            return (int)ReadUInt32();
        }

        public int ReadBigendianInt32()
        {
            return (int)ReadBigEndianUInt32();
        }

        public ulong ReadUInt64()
        {
            currentOffset += 8;
            ValidatePosition();
            UpdateParentOffset();
            return utility.ReadUInt64(b, currentOffset - 8);
        }

        public ulong ReadBigEndianUInt64()
        {
            currentOffset += 8;
            ValidatePosition();
            UpdateParentOffset();
            return utility.B2UInt64(b, currentOffset - 8);
        }

        public Int64 ReadInt64()
        {
            return (Int64)ReadUInt64();
        }

        public Int64 ReadBigendianInt64()
        {
            return (Int64)ReadBigEndianUInt64();
        }

        public string ReadUnicodeString1()  // length argument is 1 byte
        {
            int Length = ReadByte();
            return ReadUnicodeString(Length);
        }

        public string ReadUnicodeString2()  // length argument is 2 bytes
        {
            int Length = ReadUInt16();
            return ReadUnicodeString(Length);
        }

        public string ReadUnicodeStringToEOF()  // Read until the end
        {
            int Length = (offsetLimit - currentOffset + 1) / 2;
            return ReadUnicodeString(Length);
        }

        public string ReadUnicodeString(int Length)  // Read Length characters
        {
            currentOffset += Length * 2;
            ValidatePosition();
            UpdateParentOffset();
            return utility.ReadUnicodeString(b, currentOffset - Length * 2, Length);
        }

        public string ReadAnsiString1()  // length argument is 1 byte
        {
            int Length = ReadByte();
            return ReadAnsiString(Length);
        }

        public string ReadAnsiString2()  // length argument is 2 bytes
        {
            int Length = ReadUInt16();
            return ReadAnsiString(Length);
        }

        public string ReadAnsiString(int Length)  // Read Length characters
        {
            currentOffset += Length;
            ValidatePosition();
            UpdateParentOffset();
            return utility.ReadAnsiString(b, currentOffset - Length, Length);
        }

        public byte[] ReadBytes1()  // length argument is 1 byte
        {
            int Length = ReadByte();
            return ReadBytes(Length);
        }

        public byte[] ReadBytes2()  // length argument is 2 bytes
        {
            int Length = ReadUInt16();
            return ReadBytes(Length);
        }

        public byte[] ReadBytes4()  // length argument is 4 bytes
        {
            int Length = (int)ReadUInt32();
            return ReadBytes(Length);
        }

        public byte[] ReadBytes(int Length)  // Read Length characters
        {
            currentOffset += Length;
            ValidatePosition();
            UpdateParentOffset();
            if (Length == 0) return null;
            byte[] data = new byte[Length];
            for (int i = 0; i < Length; i++) data[i] = b[currentOffset - Length + i];
            return data;
        }

        //
        // A check on whether we have valid TDS. If the token has a Length value, this routing checks whether the Readxxx command will read beyond this.
        // It also does an EOF check - for truncated packets. If not truncated, this also means invalid TDS.
        //

        private void ValidatePosition()
        {
            if (nextTokenOffset != -1 && currentOffset > nextTokenOffset) throw new InvalidTDSException("Read beyond end of token.");
            if (currentOffset - 1 > offsetLimit) throw new UnexpectedEndOfTDSException("Unexpected end of TDS Stream.");
        }

        //
        // Some packet types, such as the PreLogin packet, have data read from an offset.
        //
        // Create a child TDSReader by calling OffsetReader to read the offset data. Create this for every offset in the main token.
        // The UpdateParentOffset method is called by the various Readxxx methods to say how far the child reader has read.
        // When done, call DoneWithChildReaders to update the parent reader's currentOffset with 1 past where the highest read took place.
        //

        private void UpdateParentOffset()
        {
            if (ParentReader != null)
                if (ParentReader.childHighOffset < currentOffset)
                    ParentReader.childHighOffset = currentOffset;
        }

        public TDSReader OffsetReader(int offset)
        {
            return new TDSReader(this, b, startOffset + offset, offsetLimit, -1);
        }

        public void DoneWithChildReaders()
        {
            currentOffset = childHighOffset;
        }

        //
        // For tokens with a Length, call TokenStart after reading the Length and then TokenDone when finished reading the rest of the token data
        // This is an additional layer of checking that the TDS is well formed and correct
        //

        public void TokenStart(int length)
        {
            nextTokenOffset = currentOffset + length;
        }

        public void TokenDone()
        {
            if (currentOffset != nextTokenOffset)
            {
                throw new InvalidTDSException("Token Length does not match bytes read.");
            }
            nextTokenOffset = -1;  // some tokens do not have a Length argument - set to -1 so not compared on next call unless explicitly initialized with TokenStart
        }

        public UInt32 TDSVersion
        {
            get { return m_TDSVersion; }
            set
            {
                m_TDSVersion = value;
                if (ParentReader != null) ParentReader.TDSVersion = value;
            }
        }
    }
}
