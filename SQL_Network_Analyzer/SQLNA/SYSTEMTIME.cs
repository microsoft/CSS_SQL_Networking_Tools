// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Used by NetMonRader.cs
    //
    // TODO Investigate if we can remove this
    //

    class SYSTEMTIME
    {
        public UInt16 wYear;
        public UInt16 wMonth;
        public UInt16 wDayOfWeek;
        public UInt16 wDay;
        public UInt16 wHour;
        public UInt16 wMinute;
        public UInt16 wSecond;
        public UInt16 wMilliseconds;
        public SYSTEMTIME() { }
        public SYSTEMTIME(long ticks)
        {
            Initialize(new DateTime(ticks));
        }
        public SYSTEMTIME(DateTime dt)
        {
            Initialize(dt);
        }
        private void Initialize(DateTime dt)
        {
            wYear = (UInt16)dt.Year;
            wMonth = (UInt16)dt.Month;
            wDayOfWeek = (UInt16)dt.DayOfWeek;
            wDay = (UInt16)dt.Day;
            wHour = (UInt16)dt.Hour;
            wMinute = (UInt16)dt.Minute;
            wSecond = (UInt16)dt.Second;
            wMilliseconds = (UInt16)dt.Millisecond;
        }
    }
}
