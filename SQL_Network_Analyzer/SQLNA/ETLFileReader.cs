// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security;
using System.Diagnostics;
using System.Threading;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Implements a managed callback function for the Win32 API OpenTraceW
    // Implements unmanaged struct marshalling and * unsafe * pointers
    // This operates on a background thread
    // Processes the NDIS event
    // Turns the data push on the background thread into a pull on the main thread
    // Joins partial events into complete events
    // Handles missing events or partial events
    //

    public class PartialFrame
    {
        public int ProcessID = 0;
        public int ThreadID = 0;
        public Frame f = null;
    }

    public unsafe class ETLFileReader  // write a reader and async layer to go from push to pull processing
    {

        private Guid NDIS = new Guid("2ED6006E-4729-4609-B423-3EE7BCD678EF");
        private Guid PKTMON = new Guid("4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac");
        private Guid WFP = new Guid("C22D1B14-C242-49DE-9F17-1D76B8B9C458");
        private readonly Int16 NDIS_HEADER_LENGTH = 12;
        private long FirstTimeStamp = 0;  // should be okay to use m_sessionStartTimeQPC

        private long m_QPCFreq;
        private uint m_eventCount;

        private DateTime m_sessionStartTime;

        private TraceEventInterop.EVENT_TRACE_LOGFILEW m_logFile;
        private UInt64 m_handle;

        private List<PartialFrame> PartialFrameBuffer = new List<PartialFrame>();   // only ever used by TraceEvent_EventCallback
        private List<Frame> FrameBuffer = new List<Frame>();                        // buffers writes from TraceEvent_EventCallback and reads from Read - LOCK !!!
        private bool m_traceCompleted = false;        

        public ETLFileReader(string FilePath)
        {
            m_logFile.LogFileName = FilePath;
            m_logFile.BufferCallback = this.TraceEvent_BufferCallback;
            m_logFile.EventCallback = this.TraceEvent_EventCallback;

            m_handle = TraceEventInterop.OpenTraceFile(ref m_logFile);

            m_sessionStartTime = DateTime.FromFileTime(m_logFile.LogfileHeader.StartTime);
            Program.logDiagnostic("There were " + m_logFile.EventsLost + " events lost.");
            m_QPCFreq = m_logFile.LogfileHeader.PerfFreq;

            if (m_QPCFreq == 0) m_QPCFreq = Stopwatch.Frequency;

            // We ask for raw timestamps, but the log file may have used system time as its raw timestamp.
            // SystemTime is like a QPC time that happens 10M times a second (100ns).  
            // ReservedFlags is actually the ClockType 0 = Raw, 1 = QPC, 2 = SystemTimne 3 = CpuTick (we don't support)
            if (m_logFile.LogfileHeader.ReservedFlags == 2)   // If ClockType == EVENT_TRACE_CLOCK_SYSTEMTIME
                m_QPCFreq = 10000000;

            Debug.Assert(m_QPCFreq != 0);
        }

        public DateTime GetStartTime()
        {
            return m_sessionStartTime;
        }

        [AllowReversePInvokeCalls]
        private bool TraceEvent_BufferCallback(IntPtr rawLogFile)
        {
            return true;
        }

        [AllowReversePInvokeCalls]
        private void TraceEvent_EventCallback(TraceEventInterop.EVENT_RECORD* rawData)  // write buffering layer to reassemble pakets & remove extraneous material.
        {
            if (FirstTimeStamp == 0) FirstTimeStamp = (rawData->EventHeader).TimeStamp;

            int ProcessID = rawData->EventHeader.ProcessId;
            int ThreadID = rawData->EventHeader.ThreadId;
            bool f_start = ((rawData->EventHeader.Keyword) & 0x40000000) != 0;
            bool f_end = ((rawData->EventHeader.Keyword) & 0x80000000) != 0;
            bool f_Ethernet8023 = ((rawData->EventHeader.Keyword) & 0x1) != 0;  // process Ethernet events
            bool f_Wifi = ((rawData->EventHeader.Keyword) & 0x10000) != 0;        // process Wi-Fi events -  Native802.11, not Wireless WAN
            Guid gu = (&rawData->EventHeader)->ProviderId;
            ushort eventID = rawData->EventHeader.Id;
            ushort WFPFragmentEventType = 0;              // WFP fragments need to remove the fragment header in event type 2000
            uint WFPFragmentGroup = 0;                    // all fragments of the same packet have the same group number
            uint WFPFragmentLength = 0;                   // this is 10 less than the user payload length as header is 10 bytes in length
            bool WFPIncoming = ((rawData->EventHeader.Keyword) & 0x100000000) != 0;  // only take incoming packets and reject outgoing ones 0x200000000
            Frame f = null;
            PartialFrame pf = null;
            byte[] userData = null;

            // debug code
            //if (ProcessID == xxxx && ThreadID == xxxx)
            //{
            //    Console.WriteLine(ThreadID.ToString());    // break on this line
            //    // look at m_eventCount for the prior frame number
            //}
            // end debug code

            short arrayOffset = gu == PKTMON || gu == WFP ? (short)0 : NDIS_HEADER_LENGTH;  // we want the pktmon header to be part of the data, not so with the NDIS/wfp header

            // Debug.WriteLine($"TraceEvent_EventCallback: Frame:{m_eventCount + 1}, ProviderID: {gu}, NDIS: {NDIS}, PKTMON: {PKTMON}");

            if (gu != NDIS && gu != PKTMON && gu != WFP)
            {
                m_eventCount++; // assuming no fragmentation of events
                return;         // process only NDIS and PKTMON events
            }

            if (gu == NDIS && f_Ethernet8023 == false && f_Wifi == false)  // added Ethernet/Wi-Fi check to ignore non-parsable events
            {
                m_eventCount++; // assuming no fragmentation of non-NDIS events. could be wrong, but no way of knowing.
                return;         // process only NDIS events
            }

            if (gu == PKTMON)
            {
                if (eventID != 160 && eventID != 170)
                {
                    m_eventCount++; // Track the count
                    return;
                }
                // Only preocess PKTMON events that contain a network payload
                f_start = true;   // these flags aren't set for PKTMON captures, but are used by the logic below, so set both to TRUE to get the effect we want
                f_end = true;
                // Debug.WriteLine($"TraceEvent_EventCallback: It's a PKTMON event.");
            }

            if (gu == WFP)
            {
                if (eventID != 60011 && eventID != 60012 && eventID != 60021 && eventID != 60022 && eventID != 2000)  // 2000 is a fragmented packet, needs special handling
                {
                    m_eventCount++; // Track the count
                    return;
                }
                if (!WFPIncoming)  // easier to disable than if combined with the conditions above
                {
                    m_eventCount++; // Track the count
                    return;
                }
                // Debug.WriteLine($"TraceEvent_EventCallback: It's a WFP event.");
            }

            if (f_start)  // data complete in a single event or the initial fragment of several
            {
                m_eventCount++;   // only increment on the initial event

                // remove partial event from the PartialFrameBuffer

                pf = GetPartialFrame(ProcessID, ThreadID);
                if (pf != null)
                {
                    PartialFrameBuffer.Remove(pf); // Houston, we lost an event somewhere
                    // *** TODO *** Log it properly
                    // causes a race condition in memory for some traces...
                    // Program.logDiagnostic("Lost end of partial frame " + pf.f.frameNumber + " (PID=" + pf.ProcessID + ", TID=" + pf.ThreadID + ").");
                    // Console.WriteLine("Lost end of partial frame " + pf.f.frameNumber + " (PID=" + pf.ProcessID + ", TID=" + pf.ThreadID + ").");
                }
                f = new Frame();
                f.frameNumber = m_eventCount;

                // debug code
                //if (m_eventCount > 94)
                //{
                //    Console.WriteLine();
                //}
                // end debug code

                if (m_QPCFreq == 10000000)
                {
                    f.ticks = m_sessionStartTime.Ticks + ((long)(((rawData->EventHeader).TimeStamp - FirstTimeStamp))); // reduce math errors if the stopwatch frequency is 1 tick
                }
                else
                {
                    f.ticks = m_sessionStartTime.Ticks + ((long)(((rawData->EventHeader).TimeStamp - FirstTimeStamp) * ((double)10000000.0 / m_QPCFreq)));  // 10-million (seven 0's)
                }
                userData = new byte[rawData->UserDataLength - arrayOffset];
                var x = ((byte*)rawData->UserData);
                for (int i = 0; i < userData.Length; i++) userData[i] = x[i + arrayOffset];  // move bytes over

                if (gu == WFP && eventID == 2000)  // fragmented WFP packet
                {
                    WFPFragmentEventType = utility.ReadUInt16(userData, 0);
                    WFPFragmentGroup = utility.ReadUInt32(userData, 2);
                    WFPFragmentLength = utility.ReadUInt32(userData, 6);
                    byte[] temp = new byte[userData.Length - 10];
                    Array.Copy(userData, 10, temp, 0, temp.Length);  // copies from userData[10..userData.Length-1] to temp [0..temp.Length-11]
                    userData = temp;
                }
                f.length = userData.Length;
                f.frameLength = (uint)userData.Length;
                f.bytesAvailable = (uint)userData.Length;
                f.data = userData;
                f.linkType = (ushort)(f_Ethernet8023 ? 1 : f_Wifi ? 6 : 0);  // Ethernet -> 1, Wifi -> 6, else 0

                if (gu == NDIS)
                {
                    f.isNDIS = true;
                }
                if (gu == PKTMON)
                {
                    f.isPKTMON = true;
                    f.EventType = eventID;
                }

                if (gu == WFP)
                {
                    f.isWFP = true;
                    f.EventType = eventID == 2000 ? WFPFragmentEventType : eventID;  // use eventID for non-fragmented events and WFPFragmentEventType for fragmented ones
                }

                if (f_end) // add Frame to FrameBuffer directly - no fragmentation
                {
                    lock (FrameBuffer)
                    {
                        FrameBuffer.Add(f);
                        f = null;
                    }
                }
                else // add partial frame to PartialFrameBuffer
                {
                    pf = new PartialFrame();
                    pf.ProcessID = ProcessID;
                    pf.ThreadID = ThreadID;
                    pf.f = f;
                    PartialFrameBuffer.Add(pf);
                }
            }
            else  // intermediate or terminal fragment of several
            {
                pf = GetPartialFrame(ProcessID, ThreadID);
                if (pf == null)
                {
                    // Houston, something happened; toss the event and log
                    // *** TODO *** Log it properly
                    // causes a race condition in memory
                    // Program.logDiagnostic("Lost start of partial frame ~ " + (m_eventCount + 1) + " (PID=" + ProcessID + ", TID=" + ThreadID + ").");
                    // Console.WriteLine("Lost start of partial frame ~ " + (m_eventCount + 1) + " (PID=" + ProcessID + ", TID=" + ThreadID + ").");
                    return;
                }

                userData = new byte[rawData->UserDataLength - arrayOffset];
                var x = ((byte*)rawData->UserData);
                for (int i = 0; i < userData.Length; i++) userData[i] = x[i + arrayOffset];

                if (gu == WFP && eventID == 2000)  // fragmented WFP packet
                {
                    WFPFragmentEventType = utility.ReadUInt16(userData, 0);
                    WFPFragmentGroup = utility.ReadUInt32(userData, 2);
                    WFPFragmentLength = utility.ReadUInt32(userData, 6);
                    byte[] temp = new byte[userData.Length - 10];
                    Array.Copy(userData, 10, temp, 0, temp.Length);  // copies from userData[10..userData.Length-1] to temp [0..temp.Length-11]
                    userData = temp;
                }

                pf.f.length += userData.Length;
                pf.f.frameLength += (uint)userData.Length;
                pf.f.bytesAvailable += (uint)userData.Length;
                pf.f.data = ConcatBytes(pf.f.data, userData);

                if (f_end)
                {
                    PartialFrameBuffer.Remove(pf); // done with this - let's fill the Frame Buffer
                    lock (FrameBuffer)
                    {
                        FrameBuffer.Add(pf.f);
                    }
                }
            }
        }

        private byte[] ConcatBytes(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            for (int i = 0; i < a.Length; i++) c[i] = a[i];
            for (int i = 0; i < b.Length; i++) c[i + a.Length] = b[i];
            return c;
        }

        private PartialFrame GetPartialFrame(int ProcessID, int ThreadID)
        {
            foreach (PartialFrame pf in PartialFrameBuffer)
            {
                if (pf.ProcessID == ProcessID && pf.ThreadID == ThreadID) return pf;
            }
            return null;
        }

        public void Init()
        {
            // fire off Process trace on a backgroun thread
            Thread t = new Thread(new ThreadStart(ProcessTrace));
            m_traceCompleted = false;
            t.Start();
        }

        private void ProcessTrace()
        {
            m_eventCount = 0;
            UInt64[] handles = new UInt64[1];
            handles[0] = m_handle;  // have to pass in an array, even though we only have one handle

            int dwErr = TraceEventInterop.ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);

            m_traceCompleted = true;
            Close();

            if (dwErr == 6)
            {
                throw new ApplicationException("Error opening ETL file. Most likely caused by opening a Win8 Trace on a Pre Win8 OS.");
            }
        }

        public Frame Read()
        {
            while (true)
            {
                lock (FrameBuffer)
                {
                    if (FrameBuffer.Count == 0 && m_traceCompleted) return null;

                    if (FrameBuffer.Count > 0)
                    {
                        Frame f = FrameBuffer[0];
                        FrameBuffer.RemoveAt(0);
                        // Program.logDiagnostic($"***** Frame # {f.frameNumber}, Len: {f.frameLength}, isPktmon: {f.isPKTMON}, isWFP: {f.isWFP} Event Type: {f.EventType}");
                        return f;
                    }
                }
                
                // FrameBuffer is empty and we're not done with the trace
                // Spin and give the event handler time to add a few rows to the frame buffer
                // Thread.Sleep(1); // can we remove the delay?
            }
        }

        public void Close() // call after all reads have completed or upon exception
        {
            TraceEventInterop.CloseTrace(ref m_handle);  // worst case scenario, process exit will do this
        }

    }

    #region "ETL Event Types"

    /// <summary>
    /// TraceEventNativeMethods contains the PINVOKE declarations needed
    /// to get at the Win32 TraceEvent infrastructure.  It is effectively
    /// a port of evntrace.h to C# declarations.  
    /// </summary>
    internal unsafe static class TraceEventInterop
    {
        internal static void CloseTrace(ref ulong handle)
        {
            if (handle != INVALID_HANDLE_VALUE)
            {
                TraceEventInterop.CloseTrace(handle);
                handle = INVALID_HANDLE_VALUE;
            }
        }

        internal static ulong OpenTraceFile(ref TraceEventInterop.EVENT_TRACE_LOGFILEW logFile)
        {
            logFile.LogFileMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;

            ulong handle = TraceEventInterop.OpenTrace(ref logFile);

            if (handle == INVALID_HANDLE_VALUE)
            {
                Marshal.ThrowExceptionForHR(TraceEventInterop.GetHRForLastWin32Error());
            }

            return handle;
        }

        /// <summary>
        ///	Time zone info.  Used as one field of TRACE_EVENT_LOGFILE, below.
        ///	Total struct size is 0xac.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Size = 0xac, CharSet = CharSet.Unicode)]
        internal struct TIME_ZONE_INFORMATION
        {
            public uint bias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string standardName;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 8)]
            public UInt16[] standardDate;
            public uint standardBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string daylightName;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 8)]
            public UInt16[] daylightDate;
            public uint daylightBias;
        }

        //	Delegates for use with ETW EVENT_TRACE_LOGFILEW struct.
        //	These are the callbacks that ETW will call while processing a moduleFile
        //	so that we can process each line of the trace moduleFile.
        internal delegate bool EventTraceBufferCallback(
            [In] IntPtr logfile); // Really a EVENT_TRACE_LOGFILEW, but more efficient to marshal manually);

        internal delegate void EventTraceEventCallback(
            [In] EVENT_RECORD* rawData);

        internal const ulong INVALID_HANDLE_VALUE = unchecked((ulong)(-1));

        //  EVENT_TRACE_LOGFILE.LogFileMode should be set to PROCESS_TRACE_MODE_EVENT_RECORD 
        //  to consume events using EventRecordCallback
        internal const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        internal const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        internal const uint PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000;

        internal const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;


        internal const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
        internal const uint EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000;

        /// <summary>
        ///	EventTraceHeader and structure used to defined EVENT_TRACE (the main packet)
        ///	I have simplified from the original struct definitions.  I have
        ///	omitted alternate union-fields which we don't use.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVENT_TRACE_HEADER
        {
            public ushort Size;
            public ushort FieldTypeFlags;	// holds our MarkerFlags too
            public byte Type;
            public byte Level;
            public ushort Version;
            public int ThreadId;
            public int ProcessId;
            public long TimeStamp;          // Offset 0x10 
            public Guid Guid;
            //	no access to GuidPtr, union'd with guid field
            //	no access to ClientContext & MatchAnyKeywords, ProcessorTime, 
            //	union'd with kernelTime,userTime
            public int KernelTime;         // Offset 0x28
            public int UserTime;
        }

        /// <summary>
        /// EVENT_TRACE is the structure that represents a single 'packet'
        /// of data repesenting a single event.  
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVENT_TRACE
        {
            public EVENT_TRACE_HEADER Header;
            public uint InstanceId;
            public uint ParentInstanceId;
            public Guid ParentGuid;
            public IntPtr MofData; // PVOID
            public int MofLength;
            public ETW_BUFFER_CONTEXT BufferContext;
        }

        /// <summary>
        /// TRACE_LOGFILE_HEADER is a header used to define EVENT_TRACE_LOGFILEW.
        ///	Total struct size is 0x110.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct TRACE_LOGFILE_HEADER
        {
            public uint BufferSize;
            public uint Version;            // This is for the operating system it was collected on.  Major, Minor, SubVerMajor, subVerMinor
            public uint ProviderVersion;
            public uint NumberOfProcessors;
            public long EndTime;            // 0x10
            public uint TimerResolution;
            public uint MaximumFileSize;
            public uint LogFileMode;        // 0x20
            public uint BuffersWritten;
            public uint StartBuffers;
            public uint PointerSize;
            public uint EventsLost;         // 0x30
            public uint CpuSpeedInMHz;
            public IntPtr LoggerName;	// string, but not CoTaskMemAlloc'd
            public IntPtr LogFileName;	// string, but not CoTaskMemAlloc'd
            public TIME_ZONE_INFORMATION TimeZone;   // 0x40         0xac size
            public long BootTime;
            public long PerfFreq;
            public long StartTime;
            public uint ReservedFlags;
            public uint BuffersLost;        // 0x10C?        
        }

        /// <summary>
        ///	EVENT_TRACE_LOGFILEW Main struct passed to OpenTrace() to be filled in.
        /// It represents the collection of ETW events as a whole.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct EVENT_TRACE_LOGFILEW
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string LogFileName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string LoggerName;
            public Int64 CurrentTime;
            public uint BuffersRead;
            public uint LogFileMode;
            // EVENT_TRACE for the current event.  Nulled-out when we are opening files.
            // [FieldOffset(0x18)] 
            public EVENT_TRACE CurrentEvent;
            // [FieldOffset(0x70)]
            public TRACE_LOGFILE_HEADER LogfileHeader;
            // callback before each buffer is read
            // [FieldOffset(0x180)]
            public EventTraceBufferCallback BufferCallback;
            public Int32 BufferSize;
            public Int32 Filled;
            public Int32 EventsLost;
            // callback for every 'event', each line of the trace moduleFile
            // [FieldOffset(0x190)]
            public EventTraceEventCallback EventCallback;
            public Int32 IsKernelTrace;     // TRUE for kernel logfile
            public IntPtr Context;	        // reserved for internal use
        }

        internal const ushort EVENT_HEADER_FLAG_STRING_ONLY = 0x0004;
        internal const ushort EVENT_HEADER_FLAG_32_BIT_HEADER = 0x0020;
        internal const ushort EVENT_HEADER_FLAG_64_BIT_HEADER = 0x0040;
        internal const ushort EVENT_HEADER_FLAG_CLASSIC_HEADER = 0x0100;

        /// <summary>
        ///	EventTraceHeader and structure used to define EVENT_TRACE_LOGFILE (the main packet on Vista and above)
        ///	I have simplified from the original struct definitions.  I have
        ///	omitted alternate union-fields which we don't use.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVENT_HEADER
        {
            public ushort Size;
            public ushort HeaderType;
            public ushort Flags;            // offset: 0x4
            public ushort EventProperty;
            public int ThreadId;            // offset: 0x8
            public int ProcessId;           // offset: 0xc
            public long TimeStamp;          // offset: 0x10
            public Guid ProviderId;         // offset: 0x18
            public ushort Id;               // offset: 0x28
            public byte Version;            // offset: 0x2a
            public byte Channel;
            public byte Level;              // offset: 0x2c
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
            public uint KernelTime;         // offset: 0x38
            public int UserTime;           // offset: 0x3C
            public Guid ActivityId;
        }

        /// <summary>
        ///	Provides context information about the event
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct ETW_BUFFER_CONTEXT
        {
            public byte ProcessorNumber;
            public byte Alignment;
            public ushort LoggerId;
        }

        /// <summary>
        ///	Defines the layout of an event that ETW delivers
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVENT_RECORD
        {
            public EVENT_HEADER EventHeader;           //  size: 80
            public ETW_BUFFER_CONTEXT BufferContext;         //  size: 4
            public ushort ExtendedDataCount;
            public ushort UserDataLength;        //  offset: 86
            public EVENT_HEADER_EXTENDED_DATA_ITEM* ExtendedData;
            public IntPtr UserData;
            public IntPtr UserContext;
        }

        // Values for the ExtType field 
        internal const ushort EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID = 0x0001;
        internal const ushort EVENT_HEADER_EXT_TYPE_SID = 0x0002;
        internal const ushort EVENT_HEADER_EXT_TYPE_TS_ID = 0x0003;
        internal const ushort EVENT_HEADER_EXT_TYPE_INSTANCE_INFO = 0x0004;
        internal const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE32 = 0x0005;
        internal const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE64 = 0x0006;

        [StructLayout(LayoutKind.Sequential)]
        internal struct EVENT_HEADER_EXTENDED_DATA_ITEM
        {
            public ushort Reserved1;
            public ushort ExtType;
            public ushort Reserved2;
            public ushort DataSize;
            public ulong DataPtr;
        };

        //	TRACEHANDLE handle type is a ULONG64 in evntrace.h.  Use UInt64 here.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass")]
        [DllImport("advapi32.dll", EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern UInt64 OpenTrace([In][Out] ref EVENT_TRACE_LOGFILEW logfile);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass")]
        [DllImport("advapi32.dll"), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern int ProcessTrace(
            [In] UInt64[] handleArray,
            [In] uint handleCount,
            [In] IntPtr StartTime,
            [In] IntPtr EndTime);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass")]
        [DllImport("advapi32.dll"), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern int CloseTrace([In] UInt64 traceHandle);

        // Values for ENABLE_TRACE_PARAMETERS.Version
        internal const uint ENABLE_TRACE_PARAMETERS_VERSION = 1;

        // TODO what is this for?
        internal static int GetHRForLastWin32Error()
        {
            int dwLastError = Marshal.GetLastWin32Error();
            if ((dwLastError & 0x80000000) == 0x80000000)
                return dwLastError;
            else
                return (dwLastError & 0x0000FFFF) | unchecked((int)0x80070000);
        }

        // TODO why do we need this? 
        internal static int GetHRFromWin32(int dwErr)
        {
            return (int)((0 != dwErr) ? (0x80070000 | ((uint)dwErr & 0xffff)) : 0);
        }

    } // end class

    #endregion
}
