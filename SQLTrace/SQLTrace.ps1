##
## Copyright (c) Microsoft Corporation.
## Licensed under the MIT license.
##
## Written by the SQL Server Network Support Team
## GitHub Site: https://github.com/microsoft/CSS_SQL_Networking_Tools/wiki
##

## Set-ExecutionPolicy Unrestricted -Scope CurrentUser

#=======================================Script parameters =====================================

# Several mutually exclusive parameter sets are defined
#
# .\SQLTrace.ps1 -Help
# .\SQLTrace.ps1 -Setup [-INIFile SQLTrace.ini]
# .\SQLTrace.ps1 -Start [-StopAfter 0] [-INIFile SQLTrace.ini]
# .\SQLTrace.ps1 -Stop [-INIFile SQLTrace.ini]
# .\SQLTrace.ps1 -Cleanup [-INIFile SQLTrace.ini]
#

param
(
    [Parameter(ParameterSetName = 'Help', Mandatory=$true)]
    [switch] $Help,
     
    [Parameter(ParameterSetName = 'Setup', Mandatory=$true)]
    [switch] $Setup,

    [Parameter(ParameterSetName = 'Start', Mandatory=$true)]
    [switch] $Start,

#    [Parameter(ParameterSetName = 'Start', Mandatory=$false)]
#    [int] $StopAfter = [int]::Parse("0"),

    [Parameter(ParameterSetName = 'Stop', Mandatory=$false)]
    [switch] $Stop,

    [Parameter(ParameterSetName = 'Cleanup', Mandatory=$true)]
    [switch] $Cleanup,

    [Parameter(ParameterSetName = 'Setup', Mandatory=$false)]
    [Parameter(ParameterSetName = 'Start', Mandatory=$false)]
    [Parameter(ParameterSetName = 'Stop', Mandatory=$false)]
    [Parameter(ParameterSetName = 'Cleanup', Mandatory=$false)]
    [string] $INIFile = "SQLTrace.ini",

    [Parameter(ParameterSetName = 'Start', Mandatory=$false)]
    [string] $LogFolder = ""

)


#======================================= Globals =====================================

# [console]::TreatControlCAsInput = $false   # may change this later
[string]$global:CurrentFolder = Get-Location
[string]$global:LogFolderName = ""
[string]$global:LogProgressFileName = ""
[string]$global:LogFolderEnvName = "SQLTraceLogFolder"

$global:INISettings = $null                  # set in ReadINIFile


#======================================= Code =====================================

Function Main
{
	$OutputEncoding = [console]::OutputEncoding                                           # Prevents mix of UNICODE and ANSI logs in SQLTrace.log
    if (PreReqsOkay)
    {
        ReadINIFile
        # DisplayINIValues  # TODO hide

        if     ($Setup)    { DisplayLicenseAndHeader; SetupTraces }                       # set BID Trace :Path registry if asked for in the INI file
        elseif ($Start)    { SetLogFolderName; DisplayLicenseAndHeader; StartTraces }     # set BID Trace registry if not already set, then pause and prompt to restart app
        elseif ($Stop)     { GetLogFolderName; StopTraces }
        elseif ($Cleanup)  { CleanupTraces }
        else               { DisplayLicenseAndHeader; DisplayHelpMessage }
    }
}

Function DisplayLicenseAndHeader
{
# Text is left-justified to prevent leading spaces. Column width not to exceed 79 for smaller console sizes.
LogRaw "
  _________________   .____   ___________                              
 /   _____/\_____  \  |    |  \__    ___/_______ _____     ____   ____
 \_____  \  /  / \  \ |    |    |    |   \_  __ \\__  \  _/ ___\_/ __ \
 /        \/   \_/.  \|    |___ |    |    |  | \/ / __ \_\  \___\  ___/
/_______  /\_____\ \_/|_______ \|____|    |__|   (____  / \___  >\___  >
        \/        \__>        \/                      \/      \/     \/

                  SQLTrace.ps1 version 1.0.0085.0
               by the Microsoft SQL Server Networking Team
"

Start-Sleep -Milliseconds 1500

LogRaw "
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the 'Software'), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE

Disclaimers

This tool does not communicate with any external systems or with Microsoft.
This tool does not make a connection to SQL Server, IIS, or other services.
This tool DOES take network traces and other traces on the local machine and
records them to the local folder. This is controlled by the SQLTrace.ini file.
"
}

Function DisplayHelpMessage
{
"
Usage:

   .\SQLTrace.ps1 -Help
   .\SQLTrace.ps1 -Setup [-INIFile SQLTrace.ini]
   .\SQLTrace.ps1 -Start [-INIFile SQLTrace.ini] [-LogFolder folderpath]
   .\SQLTrace.ps1 -Stop [-INIFile SQLTrace.ini]
   .\SQLTrace.ps1 -Cleanup [-INIFile SQLTrace.ini]
"
#    .\SQLTrace.ps1 -Start [-StopAfter 0] [-INIFile SQLTrace.ini] [-LogFolder folderpath]
}

Function ReadINIFile
{
    #$global:INISettings = New-Object IniValueClass

    $global:INISettings =   @{                                     # a "splat" aka Dictionary
                                BidTrace         = "No"            # No | Yes
                                BidWow           = "No"            # No | Yes | Both
                                BidProviderList  = ""

                                NetTrace         = "No"
                                Netsh            = "No"
                                Netmon           = "No"
                                Wireshark        = "No"
                                Pktmon           = "No"
                                TruncatePackets  = "No"

                                AuthTrace        = "No"
                                SSL              = "No"
                                Kerberos         = "No"
                                LSA              = "No"
                                Credssp          = "No"

                                EventViewer      = "No"
                                SQLErrorLog      = "No"
                                SQLXEventLog     = "No"
                                DeleteOldFiles   = "No"
                            }

    $fileName = $INIFile

    $fileData = get-content $fileName

    foreach ($line in $fileData)
    {
        # trim leading and trailing spaces and comments
        [String]$l = $line
        $l = $l.Trim()
        $hashPos = $l.IndexOf('#')
        if ($hashPos -ge 0) { $l = $l.SubString(0, $hashPos) }
        if ($l.Trim() -eq "") { continue }

        # $l contains some text, split it on the = character and trim the parts

        [String[]]$lineParts = $l.Split('=')

        if ($lineParts.Length -ne 2)
        {
            "Badly formatted setting: $l"
            continue
        }

        $keyWord = $lineParts[0].Trim()
        $value = $lineParts[1].Trim()

        
        switch($keyWord)
        {
           "BIDTrace"          { $global:INISettings.BIDTrace           = $value }
           "BIDWow"            { $global:INISettings.BIDWow             = $value }
           "BIDProviderList"   { $global:INISettings.BIDProviderList    = $value ; while ( $global:INISettings.BIDProviderList.IndexOf("  ") -ge 0) { $global:INISettings.BIDProviderList = $global:INISettings.BIDProviderList.Replace("  ", " ") } } # remove extra spaces between provider names
           "NETTrace"          { $global:INISettings.NetTrace           = $value }
           "NETSH"             { $global:INISettings.NETSH              = $value }
           "NETMON"            { $global:INISettings.NETMON             = $value }
           "WireShark"         { $global:INISettings.WireShark          = $value }
           "PktMon"            { $global:INISettings.PktMon             = $value }
           "TruncatePackets"   { $global:INISettings.TruncatePackets    = $value }
           "AuthTrace"         { $global:INISettings.AuthTrace          = $value }
           "SSL"               { $global:INISettings.SSL                = $value }
           "CredSSP_NTLM"      { $global:INISettings.CredSSP            = $value }
           "Kerberos"          { $global:INISettings.Kerberos           = $value }
           "LSA"               { $global:INISettings.LSA                = $value }
           "EventViewer"       { $global:INISettings.EventViewer        = $value }
           "SQLErrorLog"       { $global:INISettings.SQLErrorLog        = $value }
           "SQLXEventLog"      { $global:INISettings.SQLXEventLog       = $value }
           "DeleteOldFiles"    { $global:INISettings.DeleteOldFiles     = $value }
           default             { "Unknown keyword $keyWord in line: $l" }
        }
    }
}

Function DisplayINIValues
{
    "Read the ini file: $INIFile"
    ""
    "BIDTrace            " + $global:INISettings.BIDTrace
    "BIDWow              " + $global:INISettings.BIDWow
    "BIDProviderList     " + $global:INISettings.BIDProviderList
    ""
    "NETTrace            " + $global:INISettings.NETTrace
    "NETSH               " + $global:INISettings.NETSH
    "NETMON              " + $global:INISettings.NETMON
    "WireShark           " + $global:INISettings.WireShark
    "PktMon              " + $global:INISettings.PktMon
    "TruncatePackets     " + $global:INISettings.TruncatePackets
    ""
    "AuthTrace           " + $global:INISettings.AuthTrace
    "SSL                 " + $global:INISettings.SSL
    "CredSSP_NTLM        " + $global:INISettings.CredSSP
    "Kerberos            " + $global:INISettings.Kerberos
    "LSA                 " + $global:INISettings.LSA
    ""
    "EventViewer         " + $global:INISettings.EventViewer
    "SQLErrorLog         " + $global:INISettings.SQLErrorLog
    "SQLXEventLog        " + $global:INISettings.SQLXEventLog
    "DeleteOldFiles      " + $global:INISettings.DeleteOldFiles
}

Function PreReqsOkay
{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent( ) )
    if ( -not ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ) ) )
    {
	    LogError "SQLTrace requires elevated privileges. Please run the PowerShell command prompt ""As Administrator""."
        return $false
    }
    return $true
}

Function SetLogFolderName
{
    if ($LogFolder.Length -gt 0)
    {
        # Cannot resolve the [potential] relative path until the folder is created
        mkdir $LogFolder | out-null
        $global:LogFolderName = Resolve-Path $LogFolder
    }
    else  # generate a name in the current folder
    {
       $global:LogFolderName = "$($global:CurrentFolder)\SQLTrace_$(Get-Date -Format ""yyyyMMdd_HHmmss"")"
       mkdir $global:LogFolderName | out-null
    }
    [System.Environment]::SetEnvironmentVariable($global:LogFolderEnvName,$global:LogFolderName, [System.EnvironmentVariableTarget]::Machine)
    $global:LogProgressFileName = "$($global:LogFolderName)\SQLTrace.log"
    # LogInfo "Log folder name: $($global:LogFolderName)"
    # LogInfo "Progress Log name: $($global:LogProgressFileName)"
}

Function GetLogFolderName
{
    $global:LogFolderName = [System.Environment]::GetEnvironmentVariable($global:LogFolderEnvName, [System.EnvironmentVariableTarget]::Machine)
    $global:LogProgressFileName = "$($global:LogFolderName)\SQLTrace.log"
    LogInfo "Log folder name: $($global:LogFolderName)"
    LogInfo "Progress Log name: $($global:LogProgressFileName)"
}


# ======================================= Setup Traces =========================================

Function SetupTraces
{
	SetupBIDRegistry
}

Function SetupBIDRegistry
{
	if($global:INISettings.BidTrace -eq "Yes")
    {
        if (-not(HasBIDBeenSet))
		{
			SetBIDRegistry
			LogWarning "Restart the application to be traced if it is a service or desktop application."
			LogRaw ""
		}
    }
    else
    {
        LogInfo "BID Tracing is not enabled for this trace."
		LogRaw ""
    }
}

Function HasBIDBeenSet
{
	$BIDPath = "HKLM:\Software\Microsoft\BidInterface\Loader"
	$BID32Path = "HKLM:\Software\WOW6432Node\Microsoft\BidInterface\Loader"

	# 32-bit test
	if ($global:INISettings.BidWow -eq "Only" -or $global:INISettings.BidWow -eq "Both")
	{
		$Path = Get-ItemProperty $BID32Path -Name ":Path" -ErrorAction SilentlyContinue  # $Path will be $null if :Path does not exist
		if ($Path -eq $null) { return $false }
		if ($Path.":Path" -ne "MSDADIAG.DLL") { return $false }   # case insensitive comparison
	}

	# 64-bit test
	if ($global:INISettings.BidWow -eq "Both" -or $global:INISettings.BidWow -eq "No")
	{
		$Path = Get-ItemProperty $BIDPath -Name ":Path" -ErrorAction SilentlyContinue  # $Path will be $null if :Path does not exist
		if ($Path -eq $null) { return $false }
		if ($Path.":Path" -ne "MSDADIAG.DLL") { return $false }   # case insensitive comparison
	}

	return $true
}

Function SetBIDRegistry
{
	LogInfo "Setting BID trace registry keys ..."
	if($global:INISettings.BidWow -eq "Only")
	{
		LogInfo "BIDTrace - Set BIDInterface WOW64 MSDADIAG.DLL"
		reg add HKLM\Software\WOW6432Node\Microsoft\BidInterface\Loader /v :Path /t  REG_SZ  /d MsdaDiag.DLL /f
	}
	elseif($global:INISettings.BidWow -eq "Both")
	{
		LogInfo "BIDTrace - Set BIDInterface MSDADIAG.DLL"
		reg add HKLM\Software\Microsoft\BidInterface\Loader /v :Path /t  REG_SZ  /d MsdaDiag.DLL /f
		LogInfo "BIDTrace - Set BIDInterface WOW64 MSDADIAG.DLL"
		reg add HKLM\Software\WOW6432Node\Microsoft\BidInterface\Loader /v :Path /t  REG_SZ  /d MsdaDiag.DLL /f
	}
	else ## BIDWOW = No
	{
	LogInfo "BIDTrace - Set BIDInterface MSDADIAG.DLL"
	reg  add HKLM\Software\Microsoft\BidInterface\Loader /v :Path /t  REG_SZ  /d MsdaDiag.DLL /f
	}
}

# ======================================= Start Traces =========================================

Function StartTraces
{
    LogInfo "Starting traces ..."
    LogRaw ""
    LogInfo "Log folder name: $($global:LogFolderName)"
    LogInfo "Progress Log name: $($global:LogProgressFileName)"

    # $PSDefaultParameterValues['*:Encoding'] = 'Ascii'

    FlushExistingTraces
    FlushCaches

    tasklist > "$($global:LogFolderName)\TasklistAtStart.txt"
    netstat -abon > "$($global:LogFolderName)\NetStatAtStart.txt"
    StartBIDTraces
    StartAuthenticationTraces
    StartNetworkTraces

    LogInfo "Traces have started..."
}

Function FlushExistingTraces
{
    # flush everything regardless of settings - may interfere with custom tracing

    LogInfo "Stopping previously running traces ..."

    logman stop SQLTraceBID -ets  2>&1 | Out-Null

    logman stop SQLTraceNDIS -ets  2>&1 | Out-Null
    netsh trace stop  2>&1 | Out-Null
    nslookup "stopsqltrace.microsoft.com" 2>&1 | Out-Null     # Why the 2>&1 pipe? Do we still need that?
    Stop-Process -Name "dumpcap" -Force  2>&1 | Out-Null

    logman stop "SQLTraceKerberos" -ets  2>&1 | Out-Null
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /f  2>&1 | Out-Null
    logman stop "SQLTraceNtlm_CredSSP" -ets  2>&1 | Out-Null
    logman stop "SQLTraceSSL" -ets  2>&1 | Out-Null

    nltest /dbflag:0x0  2>&1 | Out-Null
    
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f  2>&1 | Out-Null
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f  2>&1 | Out-Null
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f  2>&1 | Out-Null
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters /v InfoLevel /f  2>&1 | Out-Null
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters /v InfoLevel /f  2>&1 | Out-Null
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /f  2>&1 | Out-Null
    reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /f  2>&1 | Out-Null
            
    logman stop "SQLTraceLSA" -ets  2>&1 | Out-Null
}

Function FlushCaches
{
    LogInfo (IPCONFIG /flushdns)
    LogInfo (NBTSTAT -R)
    Get-WmiObject Win32_LogonSession | Where-Object {$_.AuthenticationPackage -ne 'NTLM'} | ForEach-Object { LogInfo(c:\windows\system32\klist.exe purge -li ([Convert]::ToString($_.LogonId, 16))) }

    ## ToDO: Cleanup any orphan jobs from last run.
    StopCleanupETLTraceFiles -jobname  "BIDTRACECLEANUP"
    StopCleanupETLTraceFiles -jobname  "NETWORKTRACECLEANUP"
}

Function GETBIDTraceGuid($bidProvider)
{
    
    switch($bidProvider)
    {
       "MSDADIAG"                         { return "{8B98D3F2-3CC6-0B9C-6651-9649CCE5C752} 0x630ff  0   MSDADIAG.ETW "}
       "ADODB"                            { return "{04C8A86F-3369-12F8-4769-24E484A9E725} 0x630ff  0   ADODB.1 "}
       "ADOMD"                            { return "{7EA56435-3F2F-3F63-A829-F0B35B5CAD41} 0x630ff  0   ADOMD.1 "}
       "BCP"                              { return "{24722B88-DF97-4FF6-E395-DB533AC42A1E} 0x630ff  0   BCP.1 "}
       "BCP10"                            { return "{ED303448-5479-CA3F-5686-E020BA4F47F9} 0x630ff  0   BCP10.1 "}
       "DBNETLIB"                         { return "{BD568F20-FCCD-B948-054E-DB3421115D61} 0x630ff  0   DBNETLIB.1 "}
       "MSADCE"                           { return "{76DBA919-5A36-FC80-2CAD-3185532B7CB1} 0x630ff  0   MSADCE.1 "}
       "MSADCF"                           { return "{101C0E21-EBBA-A60A-EC3D-58797788928A} 0x630ff  0   MSADCF.1 "}
       "MSADCO"                           { return "{5C6CE734-1B3E-705E-C2AB-B272D99AAF8F} 0x630ff  0   MSADCO.1 "}
       "MSADDS"                           { return "{13CD7F92-5BAA-8C7C-3D72-B69FAC139A46} 0x630ff  0   MSADDS.1 "}
       "MSADOX"                           { return "{6C770D53-0441-AFD4-DCAB-1D89155FECFC} 0x630ff  0   MSADOX.1 "}
       "MSDAORA"                          { return "{F02A5DAC-6DB2-F77F-F6A8-6404FE697B7D} 0x630ff  0   MSDAORA.1 "}
       "MSDAPRST"                         { return "{64A552E0-6C60-B907-E59C-10F1DFF76B0D} 0x630ff  0   MSDAPRST.1 "}
       "MSDAREM"                          { return "{564F1E24-FC86-28E1-74F8-5CA0D950BEE0} 0x630ff  0   MSDAREM.1 "}
       "MSDART"                           { return "{CEB7253C-BB96-9DFE-51D1-53D966D0CF8B} 0x630ff  0   MSDART.1 "}
       "MSDASQL"                          { return "{B6501BA0-C61A-C4E6-6FA2-A4E7F8C8E7A0} 0x630ff  0   MSDASQL.1 "}
       "MSDATL3"                          { return "{87B93A44-1F73-EC83-7261-2DFC972D9B1E} 0x630ff  0   MSDATL3.1 "}
       "ODBC"                             { return "{F34765F6-A1BE-4B9D-1400-B8A12921F704} 0x630ff  0   ODBC.1 "}
       "ODBCBCP"                          { return "{932B59F1-90C2-D8BA-0956-3975C344AE2B} 0x630ff  0   ODBCBCP.1 "}
       "OLEDB"                            { return "{0DD082C4-66F2-271F-74BA-2BF1F9F65C66} 0x630ff  0   OLEDB.1 "}
       "RowsetHelper"                     { return "{74A75B02-36D8-EDE6-D10E-95B691503408} 0x630ff  0   RowsetHelper.1 "}
       "SQLBROWSER"                       { return "{FC9F92E6-D521-9C9A-1D8C-D8980B9978A9} 0x630ff  0   SQLBROWSER.1 "}
       "SQLOLEDB"                         { return "{C5BFFE2E-9D87-D568-A09E-08FC83D0C7C2} 0x630ff  0   SQLOLEDB.1 "}
       "SQLNCLI"                          { return "{BA798F36-2325-EC5B-ECF8-76958A2AF9B5} 0x630ff  0   SQLNCLI.1 "}
       "SQLNCLI10"                        { return "{A9377239-477A-DD22-6E21-75912A95FD08} 0x630ff  0   SQLNCLI10.1 "}
       "SQLNCLI11"                        { return "{2DA81B52-908E-7DB6-EF81-76856BB47C4F} 0x630ff  0   SQLNCLI11.1 "}
       "SQLSERVER.SNI"                    { return "{AB6D5EEB-0132-74AB-C5F5-B23E1644DADA} 0x630ff  0   SQLSERVER.SNI.1 "}
       "SQLSERVER.SNI10"                  { return "{48D59D84-105B-00FA-6B49-03462F696737} 0x630ff  0   SQLSERVER.SNI10.1 "}
       "SQLSERVER.SNI11"                  { return "{B2A28C42-A7C2-1563-97CC-3BE49FDA19F9} 0x630ff  0   SQLSERVER.SNI11.1 "}
       "SQLSERVER.SNI12"                  { return "{5BD84A98-C66F-1694-6E42-B18A6243602B} 0x630ff  0   SQLSERVER.SNI12.1 "}
       "SQLSRV32"                         { return "{4B647745-F438-0A42-F870-5DBD29949C99} 0x630ff  0   SQLSRV32.1 "}
       "MSODBCSQL11"                      { return "{7C360F7F-7102-250A-A233-F9BEBB9875C2} 0x630ff  0   MSODBCSQL11.1 "}
       "MSODBCSQL13"                      { return "{85DC6E48-9394-F805-45C9-C8B2ACA2E7FE} 0x630ff  0   MSODBCSQL13.1 "}
       "MSODBCSQL17"                      { return "{053A11C4-BC2B-F7CE-4A10-9D2602643DA0} 0x630ff  0   MSODBCSQL17.1 "}
       "System.Data"                      { return "{914ABDE2-171E-C600-3348-C514171DE148} 0x630ff  0   System.Data.1 "}
       "System.Data.OracleClient"         { return "{DCD90923-4953-20C2-8708-01976FB15287} 0x630ff  0   System.Data.OracleClient.1 "}
       "System.Data.SNI"                  { return "{C9996FA5-C06F-F20C-8A20-69B3BA392315} 0x630ff  0   System.Data.SNI.1 "}
       "System.Data.Entity"               { return "{A68D8BB7-4F92-9A7A-D50B-CEC0F44C4808} 0x630ff  0   System.Data.Entity.1 "}
       "SQLJDBC,XA"                       { return "{172E580D-9BEF-D154-EABB-83429A6F3718} 0x630ff  0   SQLJDBC,XA.1 "}
       "MSOLEDBSQL"                       { return "{EE7FB59C-D3E8-9684-AEAC-B214EFD91B31} 0x630ff  0   MSOLEDBSQL.1 "}
       "MSOLEDBSQL19"                     { return "{699773CA-18E7-57DF-5718-C244760A9F44} 0x630ff  0   MSOLEDBSQL19.1 "}

    }
}

Function StartBIDTraces
{
    $vGUIDs = [System.Collections.ArrayList]::new()
    if($global:INISettings.BidTrace -eq "Yes")
    {
		if (-not (HasBIDBeenSet))
		{
			SetBIDRegistry
			LogWarning "Please retart the application being traced if it is a desktop application or a service."
			LogWarning "Press Enter once restarted."
			Read-Host
		}

        LogInfo "Starting BID Traces ..."

        ## Get Provider GUIDs - Add MSDIAG by default
        $guid = GETBIDTraceGUID("MSDADIAG")
        $vGUIDs.Add($guid) | out-null

        ## Add the ones listed in the INI file
        $global:INISettings.BidProviderList.Split(" ") | ForEach { $guid = GETBIDTraceGUID($_); $vGUIDs.Add($guid) | out-null }

        if((Test-Path "$($global:LogFolderName)\BIDTraces" -PathType Container) -eq $false)
		{
			md "$($global:LogFolderName)\BIDTraces" > $null
        }
        
        # Add DNS GUID and then add BID Trace Providers
        "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d} 0xc0001ffff0000100  0x04   Microsoft-Windows-DNS-Client " | Out-File -FilePath "$($global:LogFolderName)\BIDTraces\ctrl.guid" -Encoding Ascii

        foreach($guid in $vGUIDs)
        { 
            $guid | Out-File -FilePath "$($global:LogFolderName)\BIDTraces\ctrl.guid" -Append -Encoding Ascii
        }

        $result = logman start SQLTraceBID -pf "$($global:LogFolderName)\BIDTraces\ctrl.guid" -o "$($global:LogFolderName)\BIDTraces\bidtrace%d.etl" -bs 1024 -nb 1024 1024 -mode NewFile -max 200 -ets
        LogInfo "LOGMAN: $result"

        if((Test-Path "$($global:LogFolderName)\BIDTraces" -PathType Container) -eq $True)
		{          
          StartCleanupETLTraceFiles -jobname "BIDTRACECLEANUP" -folder "$($global:LogFolderName)\BIDTraces" -numofFilesToKeep 30 -jobrunintervalMin 30
        }
    }
}

Function StartWireshark
{
    ## Get Number of Devices
    $WiresharkPath = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe\' -Name Path
    $WiresharkCmd = $WiresharkPath + "\dumpcap.exe"
    $DeviceList = invoke-expression '& $WiresharkCmd -D'
    $ArgumentList = ""
    For($cDevices=0;$cDevices -lt $DeviceList.Count;$cDevices++) { $ArgumentList = $ArgumentList + " -i " + ($cDevices+1) }
    ##Prepare command arguments 
    $ArgumentList = $ArgumentList + " -w $($global:LogFolderName)\NetworkTraces\nettrace.pcap -b filesize:200000 -b files:10"
    [System.Diagnostics.Process] $WiresharkProcess = Start-Process $WiresharkCmd -PassThru -NoNewWindow -ArgumentList $ArgumentList
    LogInfo "Wireshark is running with PID: " + $WiresharkProcess.ID
}


Function StartNetworkMonitor
{

    $trucatePackets = ""
    if ($global:INISettings.TruncatePackets -eq "Yes") { $trucatePackets = "/maxframelength 180"; }

    #Look for the path where Wireshark is installed
    $NMCap = Get-ItemPropertyValue -Path 'HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Netmon3\' -Name InstallDir

    $NMCap = '"' + $NMCap + "nmcap.exe" + '" '
    $ArgumentList = "/network * /capture /file $($global:LogFolderName)\NetworkTraces\nettrace.chn:200M /StopWhen /Frame dns.qrecord.questionname.Contains('stopsqltrace') $truncatePackets"
    
    #Start the capture
    [System.Diagnostics.Process] $NetmonProcess = Start-Process $NMCap -PassThru -NoNewWindow -ArgumentList $ArgumentList
    LogInfo "Network Monitor is running with PID: " + $NetmonProcess.ID
    LogWarning "Killing this process will corrupt the most recent capture file."
    LogWarning "Run SQLTrace.ps1 with the -stop option to terminate safely."
    LogRaw ""
}


## Create generic version of Cleanup Traces for BIDS, Network etc.
Function StartCleanupETLTraceFiles
{
 param
 (
    [string] $jobname,      
    [string] $folder,        
    [int]    $numofFilesToKeep,
    [int]    $jobrunintervalMin
 )
  
  $job=Register-ScheduledJob  -Name $jobname -scriptblock {  
  Param($jobname, 
        [string] $folder, 
        [int] $numofFilesToKeep, 
        [int] $jobrunintervalMin)
  gci -Path $folder -Recurse | where {(-not $_.PsIsContainer) -and ($_.name -notmatch "deleteme.etl") -and ($_.name -match ".etl") } | sort CreationTime -desc | select -skip $numofFilesToKeep | Remove-Item  -Force @args
  } -ArgumentList $jobname, $folder, $numofFilesToKeep, $jobrunintervalMin 
  $job.Options.RunElevated=$True
  $cleanupJob=New-JobTrigger -Once -At (get-date).AddSeconds(2) -RepetitionInterval (New-TimeSpan -Minutes $jobrunintervalMin) -RepeatIndefinitely  ## -RepetitionDuration (New-TimeSpan -Minutes 20)  
  Add-JobTrigger -Trigger $cleanupjob -Name $jobname    
}


Function StopCleanupETLTraceFiles
{
  param(
  $jobname    
  )
  try
  {
   Stop-Job $jobname -ErrorAction SilentlyContinue
   Remove-Job $jobname -Force -ErrorAction SilentlyContinue
   Remove-JobTrigger $jobname -ErrorAction SilentlyContinue
   UnRegister-ScheduledJob -Name $jobname -Force -ErrorAction SilentlyContinue
  }
  catch { "Cleanup Job." }
}


Function StartNetworkTraces
{
    
    if($global:INISettings.NETTrace -eq "Yes")
    {
        LogInfo "Starting Network Traces..."
        if((Test-Path "$($global:LogFolderName)\NetworkTraces" -PathType Container) -eq $false)
        {
            md "$($global:LogFolderName)\NetworkTraces" > $null
        }

        if($global:INISettings.NETSH -eq "Yes")
        {
            LogInfo "Starting NETSH..."
            # $commandLine = "netsh trace start capture=yes overwrite=yes tracefile=$($global:LogFolderName)\NetworkTraces\" + $env:computername +".etl filemode=circular maxSize=200MB"
            # Invoke-Expression $commandLine
            
            $trucatePackets = ""
            if ($global:INISettings.TruncatePackets -eq "Yes") { $trucatePackets = "PACKETTRUNCATEBYTES=250"; }

            $result = netsh trace start capture=yes maxsize=1 report=disabled TRACEFILE="$($global:LogFolderName)\NetworkTraces\deleteme.etl $truncatePackets" # Faster netsh shutdown clintonw #53

            LogInfo "NETSH: $result"
            $result = logman start SQLTraceNDIS -p Microsoft-Windows-NDIS-PacketCapture -mode newfile -max 200 -o "$($global:LogFolderName)\NetworkTraces\nettrace%d.etl" -ets
            LogInfo "LOGMAN: $result"

            # StartCleanupNetworkTraces  -folder "$($global:LogFolderName)\NetworkTraces"  # Clintonw
            StartCleanupETLTraceFiles -jobname "NETWORKTRACECLEANUP" -folder "$($global:LogFolderName)\NetworkTraces" -numofFilesToKeep 30 -jobrunintervalMin 30           
        }
        if($global:INISettings.NETMON -eq "Yes")
        {
            LogInfo "Starting Network Monitor..."
            StartNetworkMonitor
        }
        if($global:INISettings.WIRESHARK -eq "Yes")
        {
            LogInfo "Starting Wireshark..."
            StartWireshark
        }
    }
}

Function StartAuthenticationTraces
{
    if($global:INISettings.AuthTrace -eq "Yes")
    {
 
        if((Test-Path "$($global:LogFolderName)\Auth" -PathType Container) -eq $false){
           md "$($global:LogFolderName)\Auth" > $null
        }
   
        if($global:INISettings.Kerberos -eq "Yes")
        {
            LogInfo "Starting Kerberos ETL Traces..."

            # **Kerberos**
            $KerberosProviders = @(
            '{6B510852-3583-4e2d-AFFE-A67F9F223438}!0x7ffffff'
            '{60A7AB7A-BC57-43E9-B78A-A1D516577AE3}!0xffffff'
            '{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}!0xffffffff'
            '{97A38277-13C0-4394-A0B2-2A70B465D64F}!0xff'
            '{8a4fc74e-b158-4fc1-a266-f7670c6aa75d}!0xffffffffffffffff'
            '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}!0xffffffffffffffff'
            ) 

            # Kerberos Logging to SYSTEM event log in case this is a client
            reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /t REG_DWORD /d 1 /f
    
            $result = logman start "SQLTraceKerberos" -o "$($global:LogFolderName)\Auth\Kerberos.etl" -ets
            LogInfo "Kerberos: $result"

            ForEach($KerberosProvider in $KerberosProviders)
            {
                # Update Logman Kerberos
                $KerberosParams = $KerberosProvider.Split('!')
                $KerberosSingleTraceGUID = $KerberosParams[0]
                $KerberosSingleTraceFlags = $KerberosParams[1]    
                $result = logman update trace "SQLTraceKerberos" -p `"$KerberosSingleTraceGUID`" $KerberosSingleTraceFlags 0xff -ets
                LogInfo "Kerberos: $result"
            }
        }
        
        if($global:INISettings.Credssp -eq "Yes")
        {

            LogInfo "Starting CredSSP/NTLM Traces..."
            # **Ntlm_CredSSP**
            $Ntlm_CredSSPProviders = @(
            '{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}!0x5ffDf'
            '{AC69AE5B-5B21-405F-8266-4424944A43E9}!0xffffffff'
            '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!0xffffffff'
            '{AC43300D-5FCC-4800-8E99-1BD3F85F0320}!0xffffffffffffffff'
            '{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E}!0xffffffffffffffff'
            )

            $result = logman create trace "SQLTraceNtlm_CredSSP" -o "$($global:LogFolderName)\Auth\Ntlm_CredSSP.etl" -ets
            LogInfo "NTLM_CredSSP: $result"

            ForEach($Ntlm_CredSSPProvider in $Ntlm_CredSSPProviders)
            {
                # Update Logman Ntlm_CredSSP
                $Ntlm_CredSSPParams = $Ntlm_CredSSPProvider.Split('!')
                $Ntlm_CredSSPSingleTraceGUID = $Ntlm_CredSSPParams[0]
                $Ntlm_CredSSPSingleTraceFlags = $Ntlm_CredSSPParams[1]
        
                $result = logman update trace "SQLTraceNtlm_CredSSP" -p `"$Ntlm_CredSSPSingleTraceGUID`" $Ntlm_CredSSPSingleTraceFlags 0xff -ets
                LogInfo "NTLM_CredSSP: $result"
            }
        }
        

        if($global:INISettings.SSL -eq "Yes")
        {
            LogInfo "Starting SSL Traces..."
            # **SSL**
            $SSLProviders = @(
            '{37D2C3CD-C5D4-4587-8531-4696C44244C8}!0x4000ffff'
            )

            # Start Logman SSL     
            $result = logman start "SQLTraceSSL" -o "$($global:LogFolderName)\Auth\SSL.etl" -ets
            LogInfo "SSL: $result"

            ForEach($SSLProvider in $SSLProviders)
            {
                # Update Logman SSL
                $SSLParams = $SSLProvider.Split('!')
                $SSLSingleTraceGUID = $SSLParams[0]
                $SSLSingleTraceFlags = $SSLParams[1]
        
                $result = logman update trace "SQLTraceSSL" -p `"$SSLSingleTraceGUID`" $SSLSingleTraceFlags 0xff -ets
                LogInfo "SSL: $result"
            }
        }

        
        if($global:INISettings.LSA -eq "Yes")
        {
            LogInfo "Starting LSA Traces..."

            # **Netlogon logging**
            $result = nltest /dbflag:0x2EFFFFFF 2>&1
            LogInfo "NLTEST: $result"

            # **LSA**
            $LSAProviders = @(
            '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!0xC43EFF'
            '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!0xffffff'
            '{DAA76F6A-2D11-4399-A646-1D62B7380F15}!0xffffff'
            '{366B218A-A5AA-4096-8131-0BDAFCC90E93}!0xfffffff'
            '{4D9DFB91-4337-465A-A8B5-05A27D930D48}!0xff'
            '{7FDD167C-79E5-4403-8C84-B7C0BB9923A1}!0xFFF'
            '{CA030134-54CD-4130-9177-DAE76A3C5791}!0xfffffff'
            '{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e}!0xffffffffffffffff'
            '{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3}!0xffffffffffffffff'
            '{C00D6865-9D89-47F1-8ACB-7777D43AC2B9}!0xffffffffffffffff'
            '{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6}!0xffffffffffffffff'
            '{794FE30E-A052-4B53-8E29-C49EF3FC8CBE}!0xffffffffffffffff'
            '{ba634d53-0db8-55c4-d406-5c57a9dd0264}!0xffffffffffffffff'
            )
    
            #Registry LSA
            reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /t REG_DWORD /d 0xC43EFF /f 2>&1
            reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /t REG_DWORD /d 1 /f 2>&1
            reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /t REG_DWORD /d 0xF /f 2>&1
            
            # NEGOEXT
            reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

            # PKU2U
            reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

            # LSP Logging
            reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /t REG_DWORD /d 0x41C20800 /f 2>&1 | Out-Null
            reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /t REG_DWORD /d 0x1 /f 2>&1 | Out-Null



            # Start Logman LSA
            $LSASingleTraceName = "SQLTraceLSA"
            $result = logman create trace $LSASingleTraceName -o "$($global:LogFolderName)\Auth\LSA.etl" -ets
            LogInfo "LSA: $result"

            ForEach($LSAProvider in $LSAProviders)
                {
                    # "Updating: $LSAProvider" # debug statement
                    # Update Logman LSA
                    $LSAParams = $LSAProvider.Split('!')
                    $LSASingleTraceGUID = $LSAParams[0]
                    $LSASingleTraceFlags = $LSAParams[1]
        
                    $result = logman update trace $LSASingleTraceName -p `"$LSASingleTraceGUID`" $LSASingleTraceFlags 0xff -ets
                    LogInfo "LSA: $result"
                }
        }

    }

    # Not controlled by the Auth Flag
    if($global:INISettings.EventViewer -eq "Yes")
    {

        LogInfo "Enabling/Collecting Event Viewer Logs..."
        # Enable Eventvwr logging
        $result = wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /ms:102400000 2>&1
        LogInfo "CAPI2 events: $result"
        $result = wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true 2>&1
        LogInfo "Kerberos events: $result"
    }
}

# ================================================= Stop Traces ====================================================

Function StopTraces
{
    LogInfo "Stopping Traces ..."
    netstat -abon > "$($global:LogFolderName)\NetStatAtEnd.txt"
    tasklist > "$($global:LogFolderName)\TasklistAtEnd.txt"
    StopBIDTraces
    StopAuthenticationTraces
    StopNetworkTraces
    CopySqlErrorLog
    LogInfo "Traces have stopped ..."
    LogRaw ""
    LogRaw "Please ZIP the contents of ""$($global:LogFolderName)"" and upload to Microsoft for analysis."
    LogRaw "Please see our GitHub site for more information: https://github.com/microsoft/CSS_SQL_Networking_Tools"
}

Function StopBIDTraces
{
    if($global:INISettings.BidTrace -eq "Yes")
    {
        ## StopCleanupBIDTraces   # Clintonw
        StopCleanupETLTraceFiles -jobname "BIDTRACECLEANUP"

        LogInfo "Stopping BID Traces ..."
		# Do not clear the registry keys in case we run a second trace; use the -cleanup switch explicitly
        logman stop SQLTraceBID -ets
    }
}


Function StopNetworkTraces
{
    
    if($global:INISettings.NETTrace -eq "Yes")
    {

        LogInfo "Stopping Network Traces..."
        if($global:INISettings.NETSH -eq "Yes")
        {
            LogInfo "Stopping NETSH..."
            # netsh trace stop
            logman stop SQLTraceNDIS -ets
            netsh trace stop

            if (Test-Path "$($global:LogFolderName)\NetworkTraces\deleteme.etl")
            {
               del "$($global:LogFolderName)\NetworkTraces\deleteme.etl"
            }
             
            if (Test-Path "$($global:LogFolderName)\NetworkTraces\deleteme.cab")
            {
             Rename-Item "$($global:LogFolderName)\NetworkTraces\deleteme.cab" "network_settings.cab"
            }

            ## StopCleanupNetworkTraces    # clintonw
            StopCleanupETLTraceFiles -jobname "NETWORKTRACECLEANUP"
        }
        if($global:INISettings.NETMON -eq "Yes")
        {
            $NetmonPID = Get-Process -Name "nmcap"
            LogInfo "Stopping Network Monitor with PID: " + $NetmonPID.ID
            nslookup "stopsqltrace.microsoft.com" 2>&1 | Out-Null     # Why the 2>&1 pipe? Do we still need that?
        }
        if($global:INISettings.WIRESHARK -eq "Yes")
        {
            $WiresharkPID = Get-Process -Name "dumpcap"
            LogInfo "Stopping Wireshark with PID: " + $WiresharkPID.ID
            Stop-Process -Name "dumpcap" -Force
        }
    }
}

Function StopAuthenticationTraces
{

    if($global:INISettings.AuthTrace -eq "Yes")
    {

        if($global:INISettings.Kerberos -eq "Yes")
        {
            LogInfo "Stopping Kerberos ETL Traces..."
            logman stop "SQLTraceKerberos" -ets
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /f  2>&1
        }
        if($global:INISettings.Credssp -eq "Yes")
        {
            LogInfo "Stopping CredSSP/NTLM Traces..."
            logman stop "SQLTraceNtlm_CredSSP" -ets
        }
        if($global:INISettings.SSL -eq "Yes")
        {
            LogInfo "Stopping SSL Traces..."
            logman stop "SQLTraceSSL" -ets
        }
        if($global:INISettings.LSA -eq "Yes")
        {
            LogInfo "Stopping LSA Traces..."
            #Netlogon
            nltest /dbflag:0x0  2>&1 | Out-Null

            #LSA
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f  2>&1 | Out-Null
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f  2>&1 | Out-Null
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f  2>&1 | Out-Null
			
            #NegoExt
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters /v InfoLevel /f  2>&1 | Out-Null
            
            #Pku2u
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters /v InfoLevel /f  2>&1 | Out-Null
            
            #LSP
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /f  2>&1 | Out-Null
            reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /f  2>&1 | Out-Null
            
            logman stop "SQLTraceLSA" -ets

            Copy-Item -Path "$($env:windir)\debug\Netlogon.*" -Destination "$($global:LogFolderName)\Auth" -Force 2>&1

            if (Test-Path "$($env:windir)\system32\Lsass.log")
            {
                Copy-Item -Path "$($env:windir)\system32\Lsass.log" -Destination "$($global:LogFolderName)\Auth" -Force 2>&1
            }
            else
            {
                LogWarning "File $($env:windir)\system32\Lsass.log does not exist."
            }
        }
    }

    # Not controlled by the Auth Flag
    if($global:INISettings.EventViewer -eq "Yes")
    {

        LogInfo "Disabling/Collecting Event Viewer Logs..."
			
		# Filter to just the last 24 hours:                                                "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
		# Alternate filter, events after a set time. Use variables in implementation:      "/q:*[System[TimeCreated[@SystemTime>='2022-08-08T10:00:00']]]"
		$EventLogFilter = "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
			
        # Event/Operational logs
        wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false  2>&1   # stop logging
        wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "$($global:LogFolderName)\Auth\Capi2_Oper.evtx" "$EventLogFilter" /overwrite:true  2>&1  # export recent events to .evtx
		wevtutil.exe query-events "Microsoft-Windows-CAPI2/Operational" "$EventLogFilter" /f:Text > "$($global:LogFolderName)\Auth\Capi2_Oper.txt"             # export recent events to .txt
			
        wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false  2>&1   # stop logging
        wevtutil.exe export-log "Microsoft-Windows-Kerberos/Operational" "$($global:LogFolderName)\Auth\Kerb_Oper.evtx" "$EventLogFilter" /overwrite:true  2>&1  # export recent events to .evtx
		wevtutil.exe query-events "Microsoft-Windows-Kerberos/Operational" "$EventLogFilter" /f:Text > "$($global:LogFolderName)\Auth\Kerb_Oper.txt"             # export recent events to .txt

        # Main event logs - security, system, and application
        wevtutil.exe export-log SECURITY "$($global:LogFolderName)\Auth\Security.evtx" "$EventLogFilter" /overwrite:true  2>&1        # export recent events to .evtx
		wevtutil.exe query-events SECURITY "$EventLogFilter" /f:Text > "$($global:LogFolderName)\Auth\Security.txt"                   # export recent events to .txt
			
        wevtutil.exe export-log SYSTEM "$($global:LogFolderName)\Auth\System.evtx" "$EventLogFilter" /overwrite:true  2>&1            # export recent events to .evtx
		wevtutil.exe query-events SYSTEM "$EventLogFilter" /f:Text > "$($global:LogFolderName)\Auth\System.txt"                       # export recent events to .txt
			
        wevtutil.exe export-log APPLICATION "$($global:LogFolderName)\Auth\Application.evtx" "$EventLogFilter" /overwrite:true  2>&1  # export recent events to .evtx
		wevtutil.exe query-events APPLICATION "$EventLogFilter" /f:Text > "$($global:LogFolderName)\Auth\Application.txt"             # export recent events to .txt
    }
}

# Function CopySQLErrorLog
# Searches for the Log folder of each SQL instance installed on the server
# Makes a copy of ERRORLOG and Extended Events as long as the file size is lower than 500MB
Function CopySQLErrorLog()
{
    if(($global:INISettings.SQLErrorLog -eq "Yes") -or ($global:INISettings.SQLXEventLog -eq "Yes"))
    {
        LogInfo "Saving SQL Server files"

        if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"))
        {
            LogInfo "No SQL Server instances were found on this machine."
            return;
        }

        $SQLKey = Get-Item "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
        $ValueNames = $SQLKey.GetValueNames()
        cd $($global:LogFolderName)
        mkdir "SQLLogFolder" | out-null
        cd "SQLLogFolder" | out-null
        ForEach ($ValueName in $ValueNames)
        {
           LogInfo("Copying SQL files for instance: $ValueName")
           mkdir $ValueName | out-null
           $instanceFolderName = $SQLKey.GetValue($ValueName); #Get Instance Folder Name
           $errorLogPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceFolderName\MSSQLServer\Parameters\").psobject.properties |
              where {$_.name -like "xls*" -or $_.value -like "*ERRORLOG*"} |
                select value

            #Remove any parameter prior to the path
            $errorLogPath = $($errorLogPath.Value.ToString()).Substring(2)
            #Clear the error log from the string
            $errorLogPath = $errorLogPath.Substring(0,$errorLogPath.LastIndexOf('\')+1)
        
            if ($global:INISettings.SQLErrorLog -eq "Yes")
            {
                #Copy Error Log files as long as they are less than 500Mb
                $items=Get-ChildItem $errorLogPath -filter ERRORLOG* | Where { $_.Length -lt 500MB}
                Foreach($item in $items){
                copy-item $item.fullname .\$ValueName -force
                }
            }

            if ($global:INISettings.SQLXEventLog -eq "Yes")
            {
                #Copy XEvents Log files as long as they are less than 500Mb
                $items=Get-ChildItem $errorLogPath -filter *.xel | Where { $_.Length -lt 500MB}
                Foreach($item in $items){
                copy-item $item.fullname .\$ValueName -force
                }
            }

        }

        cd .. | out-null
        cd .. | out-null
    }


# ======================================= Cleanup Traces =========================================

Function CleanupTraces
{
	CleanEnvironment
	ClearBIDRegistry
}

Function CleanEnvironment
{
    # After we stop tracing, clear the environment variable, so we do not re-use the folder name
    [System.Environment]::SetEnvironmentVariable($global:LogFolderEnvName, $null, [System.EnvironmentVariableTarget]::Machine)
}

Function ClearBIDRegistry
{
	LogInfo "Clearing BID trace registry keys ..."
	if($global:INISettings.BidWow -eq "Only")
	{
		LogInfo "BIDTrace - Unset BIDInterface WOW64 MSDADIAG.DLL"
		reg delete HKLM\Software\WOW6432Node\Microsoft\BidInterface\Loader /v :Path /f
	}
	elseif($global:INISettings.BidWow -eq "Both")
	{
		LogInfo "BIDTrace - Unset BIDInterface MSDADIAG.DLL"
		reg delete HKLM\Software\Microsoft\BidInterface\Loader /v :Path /f

		LogInfo "BIDTrace - Unset BIDInterface WOW64 MSDADIAG.DLL"
		reg delete HKLM\Software\WOW6432Node\Microsoft\BidInterface\Loader /v :Path /f
	}
	else ## BIDWOW = No
	{
		LogInfo "BIDTrace - Unset BIDInterface MSDADIAG.DLL"
		reg delete HKLM\Software\Microsoft\BidInterface\Loader /v :Path /f
	}
}

# ======================================= Logging ===============================

Function LogMessage($Message, $LogLevel = "info")
{
    # Determine colors from log level - defaults are for info or any unknown log level
    $ForeColor = "White"

    # Build raw message or decorated message
    if ($LogLevel -eq "Raw")
    {
        $LogMessage = $Message
    }
    else
    {
        $LevelText = "INFO"
        switch ($LogLevel)
        {
            "Warning" { $ForeColor = "Yellow"; $LevelText = "WARN"; }
            "Error"   { $ForeColor = "Red";    $LevelText = "ERR "; }
        }

        # timestamp prefix
        $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss.fff")

        $LogMessage = "$Stamp $LevelText    $Message"
    }

	Write-Host $LogMessage -ForegroundColor $ForeColor
    if ($global:LogFolderName.Length -gt 0) { $LogMessage >> $global:LogProgressFileName }
}

Function LogRaw($Message)     { LogMessage $Message "Raw";     }
Function LogInfo($Message)    { LogMessage $Message "Info";    }
Function LogWarning($Message) { LogMessage $Message "Warning"; }
Function LogError($Message)   { LogMessage $Message "Error";   }

# ================================= start everything here =======================
Main
# ===============================================================================