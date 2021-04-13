// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;

namespace SQLCheck
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // dynamically formats tabular output for various text reports
    // Makes sure columns and headers are evenly spaced according to the actual length of the data
    //
    // Calling order:
    //
    // SetColumnNames            - columnName:R|L, e.g. "ID:R:, "Name:L" - for Left or Right alignment
    // SetColumnData - n times
    // GetHeaderText
    // GetSeparatorText
    // GetRowCount - unless you tracked it earlier
    // GetDataText[i] - GetRowCount times, i.e. 0..GetRowCount -1
    //


    class ReportFormatter
    {
        public string[] columnNames = null;
        public string[] columnAlignment = null;
        public int[] columnWidth = null;
        public ArrayList Lines = null;
        public int columnSpacing = 2;
        public int indent = 4;

        public void SetColumnNames(params string[] names)
        {
            columnNames = new string[names.Length];
            columnAlignment = new string[names.Length];
            columnWidth = new int[names.Length];
            string[] parts = null;

            for (int i = 0; i < names.Length; i++)
            {
                parts = names[i].Split(':');
                if (parts.Length != 2)
                    throw new ArgumentException("Invalid format: " + names[i]);
                parts[1] = parts[1].ToUpper();
                if (parts[1] != "L" && parts[1] != "R")
                    throw new ArgumentException("Invalid alignment '" + parts[1] + " for column " + parts[0] + ".");
                columnNames[i] = parts[0];
                columnAlignment[i] = parts[1];
                columnWidth[i] = parts[0].Length;
            }
            Lines = new ArrayList();
        }

        public void SetcolumnData(params string[] values)
        {
            if (columnNames == null)
                throw new InvalidOperationException("SetColumnNames must be called before SetColumnData.");
            if (values.Length != columnNames.Length)
                throw new ArgumentException(values.Length + " values specified. " + columnNames.Length + " required.");
            Lines.Add(values);
            for (int i = 0; i < values.Length; i++)
            {
                if (values[i] == null) values[i] = "";
                if (values[i].Length > columnWidth[i]) columnWidth[i] = values[i].Length;
            }
        }

        public int GetRowCount()
        {
            return Lines.Count;
        }

        public string GetHeaderText()
        {
            return FormatText(columnNames);
        }

        public string GetSeparatorText()
        {
            string Line = "".PadRight(indent);
            string Spacing = "".PadRight(columnSpacing);
            for (int i = 0; i < columnNames.Length; i++)
            {
                if (i > 0) Line += Spacing;
                Line += "".PadLeft(columnWidth[i], '-');
            }
            return Line;
        }

        public string GetDataText(int i)
        {
            return FormatText((string[])(Lines[i]));
        }

        public string FormatText(params string[] values)
        {
            string Line = "".PadRight(indent);
            string Spacing = "".PadRight(columnSpacing);
            for (int i = 0; i < columnNames.Length; i++)
            {
                if (i > 0) Line += Spacing;
                if (columnAlignment[i] == "R")
                {
                    Line += values[i].PadLeft(columnWidth[i]);
                }
                else
                {
                    Line += values[i].PadRight(columnWidth[i]);
                }
            }
            return Line;
        }
    }
}
