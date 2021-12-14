# Log4jVulnScripts

This repository contains PowerShell scripts that serve to mitigate CVE-2021-44228 (Log4j vulnerability) on Windows systems only per the steps outlined in the following: https://solr.apache.org/security.html#apache-solr-affected-by-apache-log4j-cve-2021-44228

This script takes two parameters; target drive letter and a switch parameter to tell this script to restart the service. If no drive letter is specified, all file system drives are searched.

Use at your own risk, optimally in a test environment before attempting to execute on several servers at once. Pull requests welcome.
