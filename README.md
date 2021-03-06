# Log4jVulnScripts

This repository contains PowerShell scripts that serve to detect and mitigate CVE-2021-44228 (Log4j vulnerability) on Windows systems with Sitecore installed per the steps outlined in the following: https://solr.apache.org/security.html#apache-solr-affected-by-apache-log4j-cve-2021-44228. 

Note that this mitigation applies only to Log4j version 2.10 or higher. More on that here: https://blog.malwarebytes.com/exploits-and-vulnerabilities/2021/12/log4j-zero-day-log4shell-arrives-just-in-time-to-ruin-your-weekend/

This MitigateLog4jVuln.ps1 script takes two parameters; target drive letter and a switch parameter to instruct this script to restart the service. If no drive letter is specified, all file system drives are searched.

Use at your own risk, optimally in a test environment before attempting to execute on several servers at once. Pull requests welcome and encouraged!

### Requirements
Requires PowerShell 4 or above.

### Usage
#### Mitigation
```powershell
# Searches all file system drives for solr.in.cmd and applies mitigation without restarting the service:
.\MitigateLog4jVuln.ps1

# Searches all file system drives for solr.in.cmd, applies mitigation, and restarts service:
.\MitigateLog4jVuln.ps1 -RestartService

# Searches only the E: drive for solr.in.cmd, applies mitigation, and restarts service:
.\MitigateLog4jVuln.ps1 -DriveLetter E -RestartService
```
#### Detection
```powershell
# Searches all file system drives for solr.in.cmd and determines if mitigation needs to be applied.
.\DetectLog4jVuln.ps1
```
