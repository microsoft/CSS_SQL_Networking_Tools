// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SQLCheck
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //


    public class NICInfo
    {
        public string valueName = "";
        public string paramDesc = "";
        public string effectiveValue = "";
        public string enumeration = "";

        public override string ToString()
        {
            string line = "";
            line = paramDesc == "" ? valueName + ":" : $"{paramDesc} ({valueName}):";
            line += " " + (enumeration == "" ? effectiveValue : $"{enumeration} ({effectiveValue})");
            return line;
        }

        public string ToValueString()
        {
            string line = "";
            line = (enumeration == "" ? effectiveValue : $"{enumeration} ({effectiveValue})");
            return line;
        }
    }
}
