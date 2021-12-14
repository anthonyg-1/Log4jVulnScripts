<#
    .SYNOPSIS
        MitigateLog4jVuln.ps1
    .DESCRIPTION
        This PowerShell script serves to detect and mitigate CVE-2021-44228 (Log4j vulnerability) on Windows systems.
    .PARAMETER DriveLetter
        The drive letter containing the target file to be modified. Note that if no drive letter is passed, all drives are searched.
    .PARAMETER RestartService
        Tells the script to restart the discovered SOLR service.
    .EXAMPLE
        \MitigateLog4jVuln.ps1

        Searches all drives for solr.in.cmd and applies mitigation without restarting the service.
    .EXAMPLE
        .\MitigateLog4jVuln.ps1 -RestartService

        Searches all drives for solr.in.cmd, applies mitigation, and restarts service.
    .EXAMPLE
        .\MitigateLog4jVuln.ps1 -DriveLetter E -RestartService

        Searches only the E: drive for solr.in.cmd, applies mitigation, and restarts service.
    .NOTES
        This mitigation applies only to Log4j version 2.10 or higher. Requires administrative privileges and PowerShell version 4.0 or higher.
    .LINK
        https://solr.apache.org/security.html#apache-solr-affected-by-apache-log4j-cve-2021-44228
        https://blog.malwarebytes.com/exploits-and-vulnerabilities/2021/12/log4j-zero-day-log4shell-arrives-just-in-time-to-ruin-your-weekend/
        https://github.com/anthonyg-1/Log4jVulnScripts
#>

#requires -RunAsAdministrator
#requires -Version 4

#region Script Parameters:

Param
(
    # If no drive is specified, all are searched:
    [Parameter(Mandatory = $false, Position = 0)][ValidateSet("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z")][String]$DriveLetter = "C",

    # Determines if we are going to restart the SOLR service when executed. Default value is false:
    [Parameter(Mandatory = $false, Position = 1)][Switch]$RestartService
)

#endregion


#region Configuration Values

# The file that we will attempt to write to:
$targetFileName = "solr.in.cmd"

# Entry to add to target file:
$mitigation = "set SOLR_OPTS=%SOLR_OPTS% -Dlog4j2.formatMsgNoLookups=true"

# Minimum version that this mitigation requires (per https://blog.malwarebytes.com/exploits-and-vulnerabilities/2021/12/log4j-zero-day-log4shell-arrives-just-in-time-to-ruin-your-weekend/):
$targetFileVersionMinimum = 2.10

#endregion


#region Functions

# Retrieve SOLR service name and version:
function Get-SolrServiceDetail {
    $solServiceSearchString = "sol"
    $targetService = Get-WmiObject Win32_Service | Where-Object Name -Match $solServiceSearchString

    if ($null -eq $targetService) {
        $FileNotFoundException = New-Object -TypeName IO.FileNotFoundException -ArgumentList "Sitecore Search Service not found."
        Write-Error -Exception $FileNotFoundException -ErrorAction Stop
    }

    $solServiceName = ""
    $solrVersion = 0.0
    try {
        $exePath = $targetService.PathName -replace '"', ""
        $solrVersion = (Get-Item -Path $exePath -ErrorAction Stop).VersionInfo.FileVersion
        $solServiceName = $targetService.Name
    }
    catch {
        Write-Error -Exception $_.Exception -ErrorAction Stop
    }

    return $([PSCustomObject]@{ServiceName = $solServiceName; ServiceVersion = $solrVersion })
}

#endregion


#region Checks

# Determine if OS is Windows and if not, throw terminating exception:
[bool]$isMicrosoftWindows = $env:OS -like "*Windows*"
if (-not($isMicrosoftWindows)) {
    $NotSupportedException = New-Object -TypeName NotSupportedException -ArgumentList "This script is only supported on Microsoft Windows operating systems."
    Write-Error -Exception $NotSupportedException -Category NotImplemented -ErrorAction Stop
}

# If minimum version is not met, throw a terminating exception:
if ((Get-SolrServiceDetail).ServiceVersion -le $targetFileVersionMinimum) {
    $argumentExceptionMessage = "This script is only applicable to SOLR versions $targetFileVersionMinimum or higher. Execution halted."
    $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $argumentExceptionMessage
    Write-Error -Exception $ArgumentException -ErrorAction Stop
}

#endregion


#region Main

# If a drive is specified use that else search all:
$detectedDrives = Get-PSDrive | Where-Object { $_.Provider.Name -like "*File*" } | Select-Object -ExpandProperty Name

$drives = @()
if ($PSBoundParameters.ContainsKey("DriveLetter")) {

    if ($DriveLetter -in $detectedDrives) {
        $drives += $DriveLetter
    }
    else {
        $argumentExceptionMessage = "$DriveLetter drive not found on this computer."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $argumentExceptionMessage
        Write-Error -Exception $ArgumentException -ErrorAction Stop
    }
}
else {
    $drives = $detectedDrives
}

# Get the service name:
$serviceName = Get-SolrServiceDetail | Select-Object -ExpandProperty ServiceName

# Clear console between each run:
Clear-Host

# Determine if service has been restarted once during this run. The intent is to restart the service only once:
[bool]$serviceHasBeenRestarted = $false

# Iterate through each drive on the system, find the target files, and apply fix. Optionally restart the service as specified in the $RestartService variable at the top of this script:
foreach ($driveLetter in $drives) {
    $targetDrive = $driveLetter + ":"

    Write-Verbose "Searching for $targetFileName in $driveLetter drive..." -Verbose

    $targetFiles = Get-Childitem -Path $targetDrive -Include $targetFileName -Recurse -File -ErrorAction SilentlyContinue

    if ($targetFiles.Count -gt 0) {
        Write-Verbose "Found $targetFileName. Determining if mitigation needs to be applied..." -Verbose

        foreach ($foundFile in $targetFiles) {
            [bool]$mitigationDetected = $false

            $filePath = $foundFile.FullName

            try {
                $fileContent = Get-Content -Path $filePath -Raw -ErrorAction Stop

                if ($fileContent -match $mitigation) {
                    $mitigationDetected = $true
                    Write-Verbose "$filePath is already patched. No action taken." -Verbose
                }
                else {
                    Write-Warning "Mitigation not currently applied. Applying mitigation to the following file: $filePath"

                    # Add a carriage return, REM line (comment), and the mitigation:
                    Add-Content -Path $filePath -Value "`r`n" -ErrorAction Stop
                    Add-Content -Path $filePath -Value "REM log4j vulnerability mitigation:" -ErrorAction Stop
                    Add-Content -Path $filePath -Value $mitigation -Verbose -ErrorAction Stop

                    if ($PSBoundParameters.ContainsKey("RestartService")) {
                        if (-not($mitigationDetected)) {
                            Write-Verbose "Restarting the $serviceName service" -Verbose

                            if (-not($serviceHasBeenRestarted)) {
                                Restart-Service -Name $serviceName -Force -Verbose -ErrorAction Stop
                                $serviceHasBeenRestarted = $true
                            }
                        }
                    }
                    else {
                        Write-Warning "Please restart the following service for the mitigation to take effect: $serviceName"
                    }
                }
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Continue
            }
        }
    }
    else {
        Write-Warning "$targetFileName not found in $targetDrive"
    }
}

Write-Verbose ("Finished searching the following drives: {0}" -f ($drives -join ", ")) -Verbose

#endregion
