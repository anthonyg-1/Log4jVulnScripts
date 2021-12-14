<#
    .SYNOPSIS
        DetectLog4jVuln.ps1
    .DESCRIPTION
        This PowerShell script serves to detect CVE-2021-44228 (Log4j vulnerability) on Windows systems.
    .EXAMPLE
        .\DetectLog4jVuln.ps1

        Searches all file system drives for solr.in.cmd and determines if mitigation needs to be applied.
    .NOTES
        Requires administrative privileges and PowerShell version 4.0 or higher.
    .LINK
        https://solr.apache.org/security.html#apache-solr-affected-by-apache-log4j-cve-2021-44228
        https://blog.malwarebytes.com/exploits-and-vulnerabilities/2021/12/log4j-zero-day-log4shell-arrives-just-in-time-to-ruin-your-weekend/
        https://github.com/anthonyg-1/Log4jVulnScripts

#>

#requires -RunAsAdministrator
#requires -Version 4

# The file that we will attempt to find:
$targetFileName = "solr.in.cmd"

# Entry in $targetFileName that determines if the mitigation has been applied:
$mitigation = "set SOLR_OPTS=%SOLR_OPTS% -Dlog4j2.formatMsgNoLookups=true"

# Get all drives:
$drives = Get-PSDrive | Where-Object { $_.Provider.Name -like "*File*" } | Select-Object -ExpandProperty Name

# Clear console between each run:
Clear-Host

# Iterate through each drive on the system, find the target files, and determine if mitigation is necessary:
foreach ($driveLetter in $drives) {
    $targetDrive = $driveLetter + ":"

    Write-Verbose "Searching for $targetFileName in $driveLetter drive..." -Verbose

    $targetFiles = Get-Childitem -Path $targetDrive -Include $targetFileName -Recurse -File -ErrorAction SilentlyContinue

    $targetDirectory = $targetFiles.DirectoryName

    if ($targetFiles.Count -gt 0) {
        Write-Warning "Found $targetFileName in $targetDirectory. Determining if mitigation needs to be applied..." -Verbose

        foreach ($foundFile in $targetFiles) {
            [bool]$fileIsPatched = $false

            $filePath = $foundFile.FullName

            try {
                $fileContent = Get-Content -Path $filePath -Raw -ErrorAction Stop

                if ($fileContent -match $mitigation) {
                    $fileIsPatched = $true
                    Write-Verbose "Mitigation already applied on $filePath." -Verbose
                }
                else {
                    Write-Warning "Mitigation not currently applied on $filePath."
                }
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Continue
            }
        }
    }
}

Write-Verbose ("Finished searching the following drives: {0}" -f ($drives -join ", ")) -Verbose
