function Invoke-NmapScan {
<#
.SYNOPSIS
Starts a nmap scan.
.DESCRIPTION
Performs an nmap scan.
.PARAMETER Nmap
The location of the nmap.exe executable. Required if nmap.exe is not in the user's path.
.PARAMETER MinRate
The minimum scanning rate. The default is 100 packets per second.
.PARAMETER MaxRate
The maximum scanning rate. The default is MinRate + 100 packets per second.
.PARAMETER TargetFile
The file containing a list of target hosts and/or networks.
.PARAMETER OutputBaseName
The base name and path to use for the results and log files.
.PARAMETER StartTime
The start time for the scan.
.PARAMETER EndTime
The end time for the scan.
.PARAMETER DoNotResume
Start a new scan instead of resuming an older one.
.EXAMPLE
Invoke-NmapScan -MinRate 200 -MaxRate 400 -TargetFile targets.txt -OutputBaseName network_scan
This example will perform the nmap scan with a minimum rate of 200 pps, a maximu rate of 400 pps, using
the targets.txt file for the list of hosts and/or networks, and will output the log file to network_scan.log and
the scan output to network_scan.gnmap.
#>

    [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Nmap,
            
            [Parameter(Mandatory=$False)]
            [ValidateRange(1, [int]::MaxValue)]
            [int]$MinRate = 100,

            [Parameter(Mandatory=$False)]
            [ValidateRange(1, [int]::MaxValue)]
            [int]$MaxRate = 200,

            [Parameter(Mandatory=$True)]
            [string]$TargetFile,

            [Parameter(Mandatory=$True)]
            [string]$OutputBaseName,

            [Parameter(Mandatory=$False)]
            [string]$StartTime,

            [Parameter(Mandatory=$False)]
            [string]$EndTime,

            [Parameter(Mandatory=$False)]
            [Switch]$DoNotResume = $False
        )

BEGIN {
    # verify all parameters
    # verify nmap.exe can be found
    if (!$PSBoundParameters.ContainsKey('Nmap')) {
        if ($null -eq (Get-Command "nmap.exe" -ErrorAction SilentlyContinue)) {
            Write-Host -ForegroundColor Red -BackgroundColor Black "nmap.exe is not in your PATH"
            return
        }
        else {
            $Nmap = "nmap.exe"
        }
    }
    elseif ($null -eq (Get-Command $Nmap)) {
        Write-Host -ForegroundColor Red -BackgroundColor Black "$Nmap not found"
        return
    }

    # figure out rates
    if ($PSBoundParameters.ContainsKey('MinRate') -and !$PSBoundParameters.ContainsKey('MaxRate')) {
        # min rate but no max rate
        $MaxRate = $MinRate + 100
    }
    elseif (!$PSBoundParameters.ContainsKey('MinRate') -and $PSBoundParameters.ContainsKey('MaxRate')) {
        # max rate but no min rate
        $MinRate = $MaxRate - 100
    }
    elseif ($PSBoundParameters.ContainsKey('MinRate') -and $PSBoundParameters.ContainsKey('MaxRate')) {
        # both provided, check logic
        $MinRate = $MaxRate, $MinRate | Measure-Object -Minimum
        $MaxRate = $MaxRate, $MinRate | Measure-Object -Maximum
    }

    # 

    $OutputGnmap = "$OutputBaseName.gnmap"
    $OutputLog = "$OutputBaseName.log"
    $Stdout = "$OutputBaseName.stdout"
    $Stderr = "$OutputBaseName.stderr"

    $StartTimeObj = $null
    $EndTimeObj = $null
    if ($PSBoundParameters.ContainsKey('StartTime') -and ([String]$StartTime -as [DateTime])) {
        $StartTimeObj = [String]$StartTime -as [DateTime]
    }

    if ($PSBoundParameters.ContainsKey('EndTime') -and ([String]$EndTime -as [DateTime])) {
        $EndTimeObj = [String]$EndTime -as [DateTime]
    }    

}

PROCESS {
    "Starting Invoke-NmapScan" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "Parameters:" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "Nmap = $Nmap" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "TargetFile = $TargetFile" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "MinRate = $MinRate" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "MaxRate = $MaxRate" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "DoNotResume = $DoNotResume" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "StartTime = $StartTime" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "EndTime = $EndTime" | Out-File -Encoding ascii -FilePath $OutputLog -Append

    $command = $Nmap
    $args = @()

    # determine if resumption is possible
    if ([System.IO.File]::Exists($OutputGnmap) -and !$DoNotResume.IsPresent) {
        # resume the old scan
        Write-Host "[*] Resuming from old scan file $OutputGnmap, cancel and set -DoNotResume flag if this is not desired"
        "Resuming from scan file $OutputGnmap" | Out-File -FilePath $OutputLog -Append
        $args = $args + "--resume" + $OutputGnmap
    }
    else {
        # build command
        $ports = "1,3,7,9,13,17,19,21-23,25-26,37,53,67-69,79-82,88,100,106,110,111,113,119,123,135,137-139,143-144,161,179,"
        $ports += "199,254,255,280,311,389,427,443-445,464,465,497,500,513-515,520,543,544,548,554,587,593,623,625,631,636,"
        $ports += "646,787,808,873,902-903,993,995,999,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053,1054,1056,1058,1059,"
        $ports += "1064-1066,1069,1071,1074,1080,1110,1234,1433,1434,1494,1521,1720,1723,1755,1761,1801,1900,1935,1993,1998,"
        $ports += "2000-2002,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000,3001,3128,3268,3306,"
        $ports += "3389,3689,3690,3703,3986,4000,4001,4045,4505,4506,4899,5000,5001,5003,5009,5050,5051,5060,5101,5120,5190,"
        $ports += "5357,5432,5555,5556,5631,5666,5800,5900,5901,5985,6000-6002,6004,6112,6646,7000-7002,7070-7071,7937,7938,"
        $ports += "8000-8002,8008-8010,8031,8080,8081,8443,8888,9000,9001,9090,9100,9102,9999,10000,10010,32768,32771,"
        $ports += "49152-49157,50000"
        $args = $args + "--min-rate" + $MinRate
        $args = $args + "--max-rate" + $MaxRate
        $args = $args + "-Pn"
        $args = $args + "-n"
        $args = $args + "-v"
        $args = $args + "-sSU"
        $args = $args + "-p$ports"
        $args = $args + "-iL" + "$TargetFile"
        $args = $args + "-oG" + $OutputGnmap
    }

    # Log important info to log file
    "=================route table=====================" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    route print | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "=============network interfaces==================" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    ipconfig /all | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "=================nmap command=====================" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    $command | Out-File -Encoding ascii -FilePath $OutputLog -Append
    $args | Out-File -Encoding ascii -FilePath $OutputLog -Append
    "====================targets=======================" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    Get-Content $TargetFile | Out-File -Encoding ascii -FilePath $OutputLog -Append

    # determine if start time was provided
    if ($null -ne $StartTimeObj) {
        if ($StartTimeObj -gt $(get-date)) {
            $SecondsToWait = [system.math]::ceiling(($($(get-date $StartTime) - $(get-date)).totalseconds))
            Write-Host "[*] sleeping $SecondsToWait seconds until $StartTime"
            Start-Sleep -seconds $SecondsToWait
        }
    }

    $now = $(get-date)
    "=======Starting nmap $now=======" | Out-File -Encoding ascii -FilePath $OutputLog -Append
    $process = Start-Process -PassThru -FilePath $command -ArgumentList $args -WorkingDirectory "." -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
    Write-Host "[*] nmap process started"

    # determine if end time was provided
    if ($null -ne $EndTimeObj) {
        if ($EndTime -gt $(get-date)) {
            $SecondsToWait = [system.math]::ceiling(($($EndTimeObj - $(get-date)).totalseconds))
            Write-Host "[*] sleeping $SecondsToWait seconds until $EndTime"
            Start-Sleep -seconds $SecondsToWait
            # kill process
            $id = $process.Id
            $now = $(get-date)
            "=======Stopping nmap $now [PID: $id]=======" | Out-File -Encoding ascii -FilePath $OutputLog -Append
            if (!$process.HasExited) {
                Stop-Process -Id $id
                Write-Host -ForegroundColor "red" -BackgroundColor "black" "[*] Killing process $id"
            }
            else {
                Write-Host -ForegroundColor "green" -BackgroundColor "black" "[*] nmap scan completed before specified end time"
            }
        }
    }
    else {
        $SleepSeconds = 2
        $i = 0
        while (!$process.HasExited)
        {
            $NumSeconds = $i * $SleepSeconds
            Write-Host "[*] waiting for nmap to finish ($NumSeconds seconds)"
            Start-Sleep -seconds $SleepSeconds
            $i = $i + 1
        }
        $now = $(get-date)
        "=======nmap finished $now=======" | Out-File -Encoding ascii -FilePath $OutputLog -Append
        Write-Host -ForegroundColor "green" -BackgroundColor "black" "[+] nmap scan complete, exiting"
    }
}

}