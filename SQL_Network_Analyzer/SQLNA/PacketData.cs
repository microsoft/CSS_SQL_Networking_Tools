// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;

namespace SQLNA
{
    //
    // Recombines frames into packets.
    // If the frames are truncated (conversation.truncatedFrameLength s non-zero), then this collection is useless. Building and Reporting needs to acknowledge this.
    // Does not include flow control packets, such as SYN, ACK, FIN, RESET, SMP:xxx, etc.
    // Does not include retransmitted packets.
    // Does not include anything before the TCP payload. Look at ((FrameData)(frames[0])) for that information.
    // For isFromClient, smpSession,  look at the first frame.
    //
    public class PacketData
    {
        public ConversationData conversation = null;      // check conversation.truncatedFrameLength; if non-zero, this is invalid
        public ArrayList frames = new ArrayList();
        public int packetLength = 0;

        public byte[] GetPayload()
        {
            if (frames == null) throw new InvalidOperationException("Packet must have at least one frame.");
            int index = 0;
            byte[] payload = new byte[packetLength];
            foreach (FrameData frame in frames)
            {
                frame.payload.CopyTo(payload, index);
                index += frame.payload.Length;
            }
            return payload;
        }

        public byte GetPayloadByte(int index)
        {
            if (frames == null) throw new InvalidOperationException("Packet must have at least one frame.");
            int offset = 0;
            foreach (FrameData frame in frames)
            {
                if ((index - offset) < frame.payload.Length) return frame.payload[index - offset];
                offset += frame.payload.Length;
            }
            throw new IndexOutOfRangeException($"Packet payload index must be between 0 and {packetLength}. Frame {((FrameData)(frames[0])).frameNo}. File {((FrameData)(frames[0])).file.filePath} ");
        }

        public TDSHeader GetTDSHeader()
        {
            if (frames == null) throw new InvalidOperationException("Packet must have at least one frame.");
            TDSHeader head = null;
            TDSReader r = null;                 // TDSReader does not need to be closed; GC is all it needs
            try
            {
                r = new TDSReader(((FrameData)(frames[0])).payload, 0);  // header does not span packets, so we can read without aggregating
                head = TDSHeader.Read(r);
            }
            catch (Exception) { return null; }  // null if error
            return head;
        }

        public bool isFromClient
        {
            get
            {
                if (frames == null) throw new InvalidOperationException("Packet must have at least one frame.");
                return ((FrameData)(frames[0])).isFromClient;
            }
        }

        public bool isEncrypted
        {
            get
            {
                if (frames == null) throw new InvalidOperationException("Packet must have at least one frame.");
                return conversation.isEncrypted;
            }
        }
    }
}
