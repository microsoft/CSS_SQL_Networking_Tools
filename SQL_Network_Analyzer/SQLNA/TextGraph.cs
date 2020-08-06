// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections;

namespace SQLNA
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Takes a series of timestamps and produces a graph over the timespan
    // The graph is 100 units wide, so accumulates the number of items that fall into each timestamp percentile
    //
    // Call sequence:
    //
    // SetGraphWidth      - optional, deafult is 100
    // startTime          - optional, defaults to lowest DateTime entered via AddData
    // endTime            - optional, defaults to highest DateTime entered via AddData
    // fAbsoluteScale     - optional, default is false, i.e. % scale
    // fLogarithmic       - optional, default is false, not used if calling SetCutoffValues or if fAbsoluteScale is set true
    // SetCutoffValues    - optional if fAbsoluteScale is false, required if it is true
    // AddData            - n times
    // ProcessData        - once
    // GetLine(0)         - once, gets top line of the graph
    // GetLine(1)         - once, gets second line of the graph
    // GetLine(2)         - once, gets middle line of the graph
    // GetLine(3)         - once, gets fourth line of the graph
    // GetLine(4)         - once, gets bottom line of the graph
    // GetLine(5)         - once, gets the scale line
    //

    public class TextGraph
    {
        ArrayList data = new ArrayList();
        public DateTime startTime = new DateTime(2900, 1, 1);
        public DateTime endTime = new DateTime(1900, 1, 1);
        object[] graph = null;
        int graphWidth = 100;
        int yAxisLabelWidth = 0;
        int[] cutoffValues = null;
        public bool fLogarithmic = false;     // default to linear scale for y-Axis
        public bool fAbsoluteScale = false;   // default to % of maxValue


        public void SetGraphWidth(int width)
        {
            graphWidth = width;
        }

        public void SetCutoffValues(int zero, int one, int two, int three, int four)
        {
            if (zero >= one || one >= two || two >= three || three >= four)
                throw new ArgumentException("Cutoff values must be in ascending order.");

            cutoffValues = new int[] { zero, one, two, three, four };
            yAxisLabelWidth = four.ToString().Length;                    // assumes numbers are in ascenading order
        }

        public void AddData(DateTime timeStamp, double value)
        {
            GraphData x = new GraphData();
            x.timeStamp = timeStamp;
            x.value = value;
            data.Add(x);
            if (timeStamp < startTime) startTime = timeStamp;
            if (timeStamp > endTime) endTime = timeStamp;
        }

        public void ProcessData()
        {
            graph = new object[] { new char[graphWidth], new char[graphWidth], new char[graphWidth], new char[graphWidth], new char[graphWidth] };

            if (cutoffValues == null)
            {
                if (fAbsoluteScale)
                {
                    throw new InvalidOperationException("Absolute graph scale requires explicitly set cut-off values.");
                }
                else if (fLogarithmic)
                {
                    SetCutoffValues(1, 3, 9, 27, 81);  // logarithmic percentages
                }
                else
                {
                    SetCutoffValues(5, 30, 50, 70, 90); // linear precentages
                }
            }

            long interval = (endTime.AddSeconds(1).Ticks - startTime.Ticks) / graphWidth;
            double[] accumulator = new double[graphWidth];
            double maxValue = 0.0;
            int temp = 0;
            int i = 0;
            foreach (GraphData x in data)
            {
                i = (int)((x.timeStamp.Ticks - startTime.Ticks) / interval);
                if (i > graphWidth - 1) i = graphWidth - 1;
                if (i < 0) i = 0;
                accumulator[i] += x.value;
                if (accumulator[i] > maxValue) maxValue = accumulator[i];
            }
            for (int j = 0; j < graphWidth; j++)
            {
                if (fAbsoluteScale)
                {
                    temp = (int)(accumulator[j]);
                }
                else // percentage
                {
                    temp = (int)(accumulator[j] / maxValue * 100.0);
                }

                if (temp < cutoffValues[0])
                    SetGraphPoints(j, ' ', ' ', ' ', ' ', ' ');
                else if (temp < cutoffValues[1])
                    SetGraphPoints(j, 'X', ' ', ' ', ' ', ' ');
                else if (temp < cutoffValues[2])
                    SetGraphPoints(j, 'X', 'X', ' ', ' ', ' ');
                else if (temp < cutoffValues[3])
                    SetGraphPoints(j, 'X', 'X', 'X', ' ', ' ');
                else if (temp < cutoffValues[4])
                    SetGraphPoints(j, 'X', 'X', 'X', 'X', ' ');
                else
                    SetGraphPoints(j, 'X', 'X', 'X', 'X', 'X');
            }
        }

        private void SetGraphPoints(int index, char value20, char value40, char value60, char value80, char value100)
        {
            ((char[])graph[0])[index] = value100;
            ((char[])graph[1])[index] = value80;
            ((char[])graph[2])[index] = value60;
            ((char[])graph[3])[index] = value40;
            ((char[])graph[4])[index] = value20;
        }

        public string GetLine(int index)
        {
            if (index < 5)
            {
                return cutoffValues[4 - index].ToString().PadLeft(yAxisLabelWidth) + (fAbsoluteScale == false ? "%" : "+") + "|" + new string((char[])(graph[index]));
            }
            else
            {
                string Line = "".PadLeft(yAxisLabelWidth + 1) + "|";
                int tempWidth = graphWidth;
                while (tempWidth >= 10)
                {
                    Line += "---------|";
                    tempWidth -= 10;
                }
                if (tempWidth > 0) Line += "".PadRight(tempWidth, '-');
                return Line;
            }
        }

    }

    public class GraphData
    {
        public DateTime timeStamp;
        public double value;
    }
}
