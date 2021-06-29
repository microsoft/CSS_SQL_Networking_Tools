using System;
using System.Diagnostics;
using Microsoft.Win32;
using System.Security.AccessControl;
using System.Collections.Generic;
using System.Net.Sockets;

namespace SQLBench
{
    //<summary>
    //Class used to calculate Integer, and floating point math
    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    //</summary>
    public class MathTest
    {
        public string CPU_Integer_Addition()
        {
            Stopwatch timer = new Stopwatch();
            List<long> num1 = new List<long>();
            List<long> num2 = new List<long>();
            Random myrand = new Random();
            long result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.Next(1000));
                    num2.Add(myrand.Next(1000));
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 0; a <= num1.Count - 1; a++)
                {
                    result = num1[a] + num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }

        }
        public string CPU_Integer_Subtraction()
        {
            Stopwatch timer = new Stopwatch();
            List<long> num1 = new List<long>();
            List<long> num2 = new List<long>();
            Random myrand = new Random();
            long result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.Next(1000));
                    num2.Add(myrand.Next(1000));
                }
            }
            catch (Exception ex) { return ex.Message; }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 0; a <= num1.Count - 1; a++)
                {
                    result = num1[a] - num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }

        }
        public string CPU_Integer_Multiplication()
        {
            Stopwatch timer = new Stopwatch();
            List<long> num1 = new List<long>();
            List<long> num2 = new List<long>();
            Random myrand = new Random();
            long result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.Next(1000));
                    num2.Add(myrand.Next(1000));
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 0; a <= num1.Count - 1; a++)
                {
                    result = num1[a] * num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string CPU_Integer_Division()
        {
            Stopwatch timer = new Stopwatch();
            List<long> num1 = new List<long>();
            List<long> num2 = new List<long>();
            Random myrand = new Random();
            long result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.Next(1,1000));
                    num2.Add(myrand.Next(1,1000));
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] / num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string CPU_Float_Division()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                    num2.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] / num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string CPU_Float_Multiplication()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                    num2.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] * num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string CPU_Float_Addition()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                    num2.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] + num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string CPU_Float_Subtraction()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                    num2.Add(myrand.NextDouble() * (1.0 - 1000000.0) + 1.0);
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] - num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public string CPU_Decimal_Subtraction()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            Random myrand2 = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * myrand2.Next(10000));
                    num2.Add(myrand.NextDouble() * myrand2.Next(10000));
                 }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] - num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                 return ex.Message;
            }
        }
        public string CPU_Decimal_Addition()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            Random myrand2 = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * myrand2.Next(10000));
                    num2.Add(myrand.NextDouble() * myrand2.Next(10000));
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] + num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string CPU_Decimal_Multiplication()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            Random myrand2 = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * myrand2.Next(10000));
                    num2.Add(myrand.NextDouble() * myrand2.Next(10000));
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] * num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string CPU_Decimal_Division()
        {
            Stopwatch timer = new Stopwatch();
            List<double> num1 = new List<double>();
            List<double> num2 = new List<double>();
            Random myrand = new Random();
            Random myrand2 = new Random();
            double result = 0;
            //populate arrays
            try
            {
                for (int a = 0; a < 100000; a++)
                {
                    num1.Add(myrand.NextDouble() * myrand2.Next(10000));
                    num2.Add(myrand.NextDouble() * myrand2.Next(10000));
                }
            }
            catch (Exception) { return num1.Count.ToString(); }

            //Integer Addition
            try
            {
                timer.Start();
                for (int a = 1; a <= num1.Count - 1; a++)
                {
                    result = num1[a] / num2[a];
                }
                timer.Stop();
                TimeSpan Totaltime = timer.Elapsed;
                return Convert.ToString(100000 / Totaltime.TotalMilliseconds);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }
}
