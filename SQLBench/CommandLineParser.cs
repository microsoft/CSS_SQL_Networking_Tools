// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System.Collections;

namespace SQLBench
{

    //
    // Written by the Microsoft CSS SQL Networking Team
    //
    // Calling order:
    //
    //    AddRule                                        - n times
    //    string result = Parse(args)                    - once, result contains error message or "" if okay
    //    ArrayList List = GetArgs(argname)              - once per arg, returns an ArrayList of 0..n CommandlineArgs
    //
    // Arguments can have the following properties:
    //
    //    Case sensitive or case-insensitive
    //    Required or optional
    //    Appear once or many times (or 0 times if optional)
    //    Have a value or not
    //    If the arg name is "" then the value must not be proceeded by a flag that requires a value
    //
    // EXAMPLE USAGE:
    //
    //    appname.exe filename [-out filename] [-g value] [-G] -h value [-flags value [-flags value [...]]]
    //
    //    ArgRule(string argName, bool hasValue, bool allowDuplicates = false, bool caseInsensitive = true, bool required = true)
    //
    //                                                  ignore
    //                           name     value  dup    case   req
    //    cp.AddRule(new ArgRule("",      true,  false, true,  true));            // file name is required
    //    cp.AddRule(new ArgRule("flags", true,  true,  true,  false));           // flags is optional but may appear more than once
    //    cp.AddRule(new ArgRule("out",   true,  false, true,  false));           // out is optional but may only appear once
    //    cp.AddRule(new ArgRule("g",     true,  false, false, false));           // g is optional and case-sensitive
    //    cp.AddRule(new ArgRule("G",     false, false, false, false));           // G is optional and takes no value and is case sensitive
    //    cp.AddRule(new ArgRule("h",     true,  false, true,  true));            // h is required and takes an argument
    //
    //    argements can appear in any order, as long as name/value pairs are adjacent
    //    arguments other than -g and -G are case-insensitive
    //    -flags may appear 0..n times
    //    -G can come before filename
    //    name value pairs can be: -x=y, -x:y, or -x y
    //
    // Test harness: cmdParser
    //

    /*! 
     * \brief      
     * \details    
     *  \author    Malcolm Stewart
     *  \version   2.0
     *  \date      Feb 18th 2015
     *  \pre       None
     *  \bug       None
     *  \warning   None 
     *  \copyright Microsoft Corporation 
     */
    class CommandLineParser
    {
        public ArrayList Args = new ArrayList();
        public ArrayList Rules = new ArrayList();

        public string Parse(string[] args)
        {
            string lastToken = "";
            string ruleViolation = "";

            foreach (string arg in args)
            {
                string argName = "";
                if (arg.StartsWith("-") || arg.StartsWith("/"))
                {
                    string[] parts = null;
                    argName = arg.Substring(1); // strip leading - or /

                    //
                    // process lastToken, if it has a value
                    //
                    if (lastToken.Length > 0)
                    {
                        if (lastToken.StartsWith("-") || lastToken.StartsWith("/"))
                        {
                            ruleViolation = AddArg(lastToken.Substring(1), "");  // switch with no arguments
                        }
                        else
                        {
                            ruleViolation = AddArg("", lastToken);               // switch-less argument
                        }
                        if (ruleViolation != "") return ruleViolation;
                        lastToken = "";
                    }

                    //
                    // does the switch have a value in the same arg ???
                    //
                    if (argName.Contains(":") || argName.Contains("="))
                    {
                        parts = argName.Split(new char[] {':', '='}, 2);
                        ruleViolation = AddArg(parts[0], parts[1]);                  // switch with argument separated by : or =
                        if (ruleViolation != "") return ruleViolation;
                    }
                    else
                    {
                        lastToken = arg;                                             // switch - argument may be in next arg - wait for next iteration
                    }
                }
                else                                                                 // switchless argument - process lastToken
                {
                    if (lastToken.Length > 0)
                    {
                        if (lastToken.StartsWith("-") || lastToken.StartsWith("/"))
                        {
                            //
                            // Should the switch take an argument?
                            //
                            lastToken = lastToken.Substring(1); // trim - or /
                            ArgRule r = GetArgRule(lastToken);
                            if (r.fHasValue)
                            {
                                ruleViolation = AddArg(lastToken, arg);          // switch with value in next argument
                                if (ruleViolation != "") return ruleViolation;
                                lastToken = "";
                            }
                            else
                            {
                                ruleViolation = AddArg(lastToken, "");              // switch takes no arguments, promote arg to lastToken
                                if (ruleViolation != "") return ruleViolation;
                                lastToken = arg;
                            }
                        }
                        else
                        {
                            ruleViolation = AddArg("", lastToken);                  // switch-less argument
                            if (ruleViolation != "") return ruleViolation;
                            lastToken = "";
                        }
                    }
                    else
                    {
                        lastToken = arg;
                    }
                }
            }

            //
            // Process lastToken if one exists
            //
            if (lastToken.Length > 0)
            {
                if (lastToken.StartsWith("-") || lastToken.StartsWith("/"))
                {
                    ruleViolation = AddArg(lastToken.Substring(1), "");              // switch takes no arguments, promote arg to lastToken
                    if (ruleViolation != "") return ruleViolation;
                }
                else
                {
                    ruleViolation = AddArg("", lastToken);                  // switch-less argument
                    if (ruleViolation != "") return ruleViolation;
                }
            }

            if (ruleViolation != "") return ruleViolation;

            //
            // Evaluate missing required switches
            //

            foreach (ArgRule r in Rules)
            {
                if (r.fMustAppear && (GetArgs(r.name).Count == 0))
                {
                    if (r.name == "")
                        return @"Required value is missing.";
                    else
                        return @"Required switch " + r.name + " is missing.";
                }
            }

            return "";
        }

        private string AddArg(string name, string value)
        {
            // check rules
            ArgRule r = GetArgRule(name);
            if (r == null && name == "") return @"Invalid argument: " + value;
            if (r == null) return @"Invalid switch: " + name;

            if (r.fInsensitive) name = name.ToLower();

            if (r.fDuplicates == false) if (GetArgs(name).Count > 0)
                {
                    if (name == "")
                        return @"A switch-less value can only appear once.";
                    else
                        return @"Switch " + name + " can only appear once.";
                }
            if (r.fHasValue == false) if (value != "") return @"Switch " + name + " does not take an argument.";
            if (r.fHasValue == true) if (value == "") return @"Switch " + name + " requires an argument.";
            //
            // if fall through, we add the argument
            //
            if (value == "") value = "true";
            CommandLineArgs a = new CommandLineArgs();
            a.name = name;
            a.value = value;
            Args.Add(a);
            return "";
        }

        public ArrayList GetArgs(string name)
        {
            ArrayList outList = new ArrayList();
            foreach (CommandLineArgs a in Args)
            {
                if (a.name == name)
                    outList.Add(a);
            }
            return outList;
        }

        private ArgRule GetArgRule(string name)
        {
            foreach (ArgRule r in Rules)
            {
                if (r.name == name)
                    return r;
                if (r.fInsensitive && (r.name.ToLower() == name.ToLower()))
                    return r;
            }
            return null;
        }

        public void AddRule(ArgRule r)
        {
            Rules.Add(r);
        }
    }

    public class CommandLineArgs
    {
        public string name = "";
        public string value = "";
    }

    public class ArgRule
    {
        public string name = "";
        public bool fHasValue = false;
        public bool fDuplicates = false;
        public bool fInsensitive = true;
        public bool fMustAppear = true;

        public ArgRule(string argName, bool hasValue, bool allowDuplicates = false, bool caseInsensitive = true, bool required = true)
        {
            name = caseInsensitive ? argName.ToLower() : argName;
            fHasValue = hasValue;
            fDuplicates = allowDuplicates;
            fInsensitive = caseInsensitive;
            fMustAppear = required;
        }
    }
}
