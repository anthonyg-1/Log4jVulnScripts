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
                    Write-Verbose "$filePath is already patched. No action taken." -Verbose
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
