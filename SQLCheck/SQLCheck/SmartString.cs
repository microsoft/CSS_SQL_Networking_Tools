// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.IO;

namespace SQLCheck
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //


    public class SmartString
    {
        public string value = "";
        public string remainder = "";
        StringComparison sc = StringComparison.CurrentCulture;
        public bool insensitive = false;
        public bool autoTrim = false;

        public SmartString(string Value, Boolean Insensitive = false, Boolean AutoTrim = false)
        {
            value = Value;
            insensitive = Insensitive;
            if (insensitive) sc = StringComparison.CurrentCultureIgnoreCase;
            autoTrim = AutoTrim;
        }

        #region Instance Methods

        #endregion

        #region Static Methods

        public static string ChopWord(string value, ref string remainder, string delimiter = " ", bool insensitive = false, bool autoTrim = false)
        {

            //
            // Removes the first word from the front of the string and returns it.
            // The remainder - after the delimiter - is returned in "remainder" if it's not null.
            //

            int p = value.IndexOf(delimiter, insensitive ? StringComparison.CurrentCultureIgnoreCase : StringComparison.CurrentCulture);
            if (p < 0)  // all one word
            {
                if (remainder != null) remainder = "";
                return value;
            }
            else  // split the string
            {
                //
                // index:   0123456
                // s =     "abc def"
                // p = 3
                // Delimiter.Length = 1
                // p + Delimiter.Length = 4
                // s.Substring(0, 3) = "abc"   // return
                // s.SubString(4) = "def"      // remainder
                //

                if (remainder != null) remainder = value.Substring(p + delimiter.Length);
                return autoTrim ? value.Substring(0, p).Trim() : value.Substring(0, p);
            }
        }

        public static string GetRemainder(string value, string delimiter = " ", bool insensitive = false, bool autoTrim = false)
        {
            string remainder = "";
            ChopWord(value, ref remainder, delimiter, insensitive);
            return autoTrim ? remainder.Trim() : remainder;
        }

        public static string ReplaceBeginning(string value, string oldval, string newVal, bool insensitive = false)
        {
            StringComparison sc = insensitive ? StringComparison.InvariantCultureIgnoreCase : StringComparison.InvariantCulture;
            if (value.StartsWith(oldval, sc))
            {
                return newVal + value.Substring(oldval.Length);
            }
            return value;
        }

        public static string GetStringLine(string lines, string keyword, bool insensitive = false)
        {
            StringReader sr = new StringReader(lines);
            string line = sr.ReadLine();
            while (line != null)
            {
                if (line.IndexOf(keyword, insensitive ? StringComparison.CurrentCultureIgnoreCase : StringComparison.CurrentCulture) > -1) return line;
                line = sr.ReadLine();
            }
            return "";
        }

        //
        // Returns text between two other strings - the Prefix and the Suffix
        //

        public static string GetBetween(string line, string prefix, string suffix, bool insensitive = false, bool autoTrim = false)
        {
            string remainder = "", s = "";
            ChopWord(line, ref remainder, prefix, insensitive, autoTrim);
            line = remainder;
            s = ChopWord(line, ref remainder, suffix, insensitive, autoTrim);
            return s;
        }

        //
        // Returns text centered in a field of dashes
        //

        public static string CenterText(string Message, int Length = 80, char Filler = '-', bool SpaceGap = true, int MinFillerLength = 10)
        {
            string line = "";
            int startFiller = (int)((Length - Message.Length) / 2) - (SpaceGap ? 1 : 0);
            int endFiller = Length - startFiller - Message.Length - (SpaceGap ? 2 : 0);  // "2" to take account of startFiller being shorter, so both gap lengths need to be taken into account
            if (MinFillerLength < 0) MinFillerLength = 10;  // deal with bad input
            if (startFiller < MinFillerLength || endFiller < MinFillerLength) startFiller = endFiller = MinFillerLength;
            line = new string(Filler, startFiller) + (SpaceGap ? " " : "") + Message + (SpaceGap ? " " : "") + new string(Filler, endFiller);
            return line;
        }
        #endregion
    }
}
