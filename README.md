# Get-ServerSharePermissionsReport
This script is designed to pull the NTFS Access Control List (ACL) permissions of Windows shares (including hidden ones). The search is based on and assumes a common hostname prefix (using a wildcard) or it can be an exact hostname match.

The majority of the script (and all the important stuff) is written by GitHub user [VeeFu](https://github.com/VeeFu/SysAdminScripts/tree/master/SecurityReports).

This version was not forked as the script filename was changed.  It also required pulling all of his SysAdminScripts code. Additions to this version include PowerShell formatted documentation/help and some extra error handling.

## Running the script

Here’s an example of using this script where all server hostnames start with the name 'Contoso':
 
    Get-ServerSharePermissionsReport.ps1 –Filter contoso* -SearchBase ‘ou=servers,dc=mycompany,dc=local’
 
Note that the `–SearchBase` option should be the full distinguished name (DN) where the servers of interest reside in your Active Directory (AD) environment.  It may still work even if you don’t do that but could be a slower.

By default this script will produce a HTML file in the same directory where you ran it called ‘NTFS_ACL_Report.html’.  That’s what you want for your analysis. You can change this default file name using the `–HTMLFile` option.

Note that all errors are not necessarily handled so if PowerShell spits out any error messages it’s likely still fine.  Allow the script to continue running.  As expected it also can’t pull permissions for things you don’t have admin rights to.

Like with all PowerShell cmdlets you can run `Get-Help Get-ServerSharePermissionsReport.ps1` for the built-in documentation.

## Analysis

Keep in mind that the analysis with this is still far from perfect as it doesn’t provide a complete picture.  The main issue being that it doesn’t tell you who is a member for a given group.  For instance, you may see that ‘BUILTIN\Users’ has full control of a given share.  Depending on what **other** groups or users are members of the local Users group on that system will ultimately determine if that share is properly controlled.  This can be checked by browsing to the share of interest with Windows Explorer.  Alternatively, you can do this by looking at the local group membership directly.  If you’re on that system you can use the MMC GUI with ‘lusrmgr.msc’.  There are PowerShell options too via WMI/CIM or possibly some built-in cmdlets if you have PowerShell version 5 installed.  The one advantage of the latter is you can run the commands remotely assuming you have admin rights to the system of interest.

Another reminder that Windows shares that ends in a dollar sign ‘$’ mean the share is hidden.  Windows boxes have several default hidden shares (e.g., ADMIN$, IPC$, C$) that may be used for a variety of reasons by the OS or humans.
