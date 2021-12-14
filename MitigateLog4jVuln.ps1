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

# Minimum version that this mitigation requires:
$targetFileVersionMinimum = 2.15

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

    $exePath = $targetService.PathName -replace '"', ""
    $solrVersion = (Get-Item -Path $exePath).VersionInfo.FileVersion
    $solServiceName = $targetService.Name

    return $([PSCustomObject]@{ServiceName = $solServiceName; ServiceVersion = $solrVersion })
}

#endregion


#region Checks

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
        $argumentExceptionMessage = "{0} drive not found on this computer. " -f $DriveLetter
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $argumentExceptionMessage
        Write-Error -Exception $ArgumentException -ErrorAction Stop
    }
}
else {
    $drives = $detectedDrives
}

# Get the service name:
$serviceName = (Get-SolrServiceDetail).ServiceName

# Clear console between each run:
Clear-Host

# Iterate through each drive on the system, find the target files, and apply fix. Optionally restart the service as specified in the $RestartService variable at the top of this script:
foreach ($driveLetter in $drives) {
    $targetDrive = $driveLetter + ":"

    Write-Verbose "Searching for $targetFileName in $driveLetter drive..." -Verbose

    $targetFiles = Get-Childitem -Path $targetDrive -Include $targetFileName -Recurse -File -ErrorAction SilentlyContinue

    if ($targetFiles.Count -gt 0) {
        Write-Verbose "Found $targetFileName. Determining if mitigation needs to be applied..." -Verbose

        foreach ($foundFile in $targetFiles) {
            [bool]$fileIsPatched = $false

            $filePath = $foundFile.FullName

            try {
                $fileContent = Get-Content -Path $filePath -Raw -ErrorAction Stop

                if ($fileContent -match $mitigation) {
                    $fileIsPatched = $true
                    Write-Verbose "$filePath is already patched. No action taken." -Verbose
                }
                else {
                    Write-Warning "Mitigation not currently applied. Applying mitigation to the following file: $filePath"

                    # Add a carriage return, REM line (comment), and the mitigation:
                    Add-Content -Path $filePath -Value "`r`n" -ErrorAction Stop
                    Add-Content -Path $filePath -Value "REM log4j vulnerability mitigation:" -ErrorAction Stop
                    Add-Content -Path $filePath -Value $mitigation -Verbose -ErrorAction Stop

                    if ($PSBoundParameters.ContainsKey("RestartService")) {
                        if (-not($fileIsPatched)) {
                            Write-Verbose "Restarting the $serviceName service" -Verbose
                            Restart-Service -Name $serviceName -Force -Verbose -ErrorAction Stop
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

#endregion
