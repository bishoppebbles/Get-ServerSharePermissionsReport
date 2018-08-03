# Get-ServerSharePermissionsReport
This script is designed to pull the NTFS Access Control List (ACL) permissions of Windows server shares (including hidden ones). The search is based on the hostname prefix using a wildcard or it can be an exact hostname match.

The majority of the script (and all the important stuff) is written by GitHub user VeeFu at: https://github.com/VeeFu/SysAdminScripts/tree/master/SecurityReports

This version was not forked as the script filename was changed and it required pulling all of his SysAdminScripts code. Additions to this version include PowerShell formatted documentation/help and some more error handling.
