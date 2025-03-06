<#
.SYNOPSIS
    This script is designed to pull the NTFS Access Control List (ACL) permissions of Windows shares (including hidden ones) based on their hostname prefix. It can use a wildcard (*) or it can be an exact match.
.DESCRIPTION
    This script attempts to gather NTFS ACL permissions on Windows shares.  It can use a wildcard search based on the hostname prefix or it can be an exact hostname.  Rights are required on the systems to access the respective NTFS permissions, likely local administrative rights. This script cannot access permissions on things like printers, Linux based appliances and servers, and will get rejected on Windows' hosts where you do not have local rights.
.PARAMETER Filter
    Specify the hostname search term.  It can be an exact name or use a wildcard (*) to match multiple systems.
.PARAMETER SearchBase
    Specify the distinguished name for the domain of interest to search (i.e., the domain where the hosts reside).
.PARAMETER SystemList
    The list of fully qualified domain systems to collect.
.PARAMETER ReportStyle
    Specify if the final HTML report should have a nested table style (default) or a flat table sytle.
.PARAMETER HTMLFile
    Specify the HTML report file name (default: NTFS_ACL_Report.html).
.EXAMPLE
    Get-ServerSharePermissionsReport.ps1 -Filter fileprint* -SearchBase 'dc=mycompany,dc=local'
    This command attempts to pull all systems in the 'mycompany.local' domain that have a hostname starting with 'fileprint*'.  It uses the default nesting table format and writes the final HTML report to the default file name of NTFS_ACL_Report.html.
.EXAMPLE
    Get-ServerSharePermissionsReport.ps1 -SystemList (Get-Content servers.txt)
    This command attempts to pull all FQDN system names listed in the servers.txt file.  It performs no Active Directory lookups.  It uses the default nesting table format and writes the final HTML report to the default file name of NTFS_ACL_Report.html.
.EXAMPLE
    Get-ServerSharePermissionsReport.ps1 -SystemList 'svr1.domain.com','svr2.domain.com','svr3.domain.com'
    This command attempts to pull all FQDN system names as defined on the commandline.  It performs no Active Directory lookups.  It uses the default nesting table format and writes the final HTML report to the default file name of NTFS_ACL_Report.html.
.EXAMPLE
    Get-ServerSharePermissionsReport.ps1 -Filter sql* -SearchBase 'dc=branch1,dc=business,dc=net' -ReportStyle FlatTable -HTMLFile SqlServerSharePermissions.html
    This command attempts to pull all systems in the 'branch1.business.net' domain that have a hostname starting with 'sql*'.  It uses the flat table format and writes the final HTML report to a file named SqlServerOfficeSharePermissions.html.
.NOTES
    Version 1.1 - Last Modified 06 March 2025
    Main author: Vincent Drake
    Documentation and additional edits: Sam Pursglove
#>

param 
(
    [Parameter(ParameterSetName='Domain', Mandatory=$True,  ValueFromPipeline=$False, HelpMessage='Enter the hostname search term.  For instance, to identify servers that have a common hostname prefix of "file", using "file*" will attempt to pull the ACL of all shares on each host that match.')]
    [string]$Filter,
    
    [Parameter(ParameterSetName='Domain', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the full distinguished name where the servers of interest reside (e.g. 'dc=hq,dc=company,dc=com')")]
    [string]$SearchBase,

    [Parameter(ParameterSetName='List', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the list of fully qualified domain name systems (e.g. 'svr1.domain.com','svr2.domain.com')")]
    [string[]]$SystemList = '',
    
    [Parameter(Mandatory=$false, ValueFromPipeline=$false, HelpMessage='Select the final report formatting style.')]
    [ValidateSet('NestedTable','FlatTable')]$ReportStyle = 'NestedTable',
    
    [Parameter(Mandatory=$false, ValueFromPipeline=$false, HelpMessage='Set the HTML final report name.')]
    [string]$HTMLFile = "NTFS_ACL_Report.html"
)

$xslTransforms = @{
    NestedTable = @"
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
  <h2>File System Security Report</h2>
  <table border="1" style="border-collapse:collapse" width='100%'>
    <tr bgcolor="#9acd32">
      <th>Path</th>
      <th>Owner</th>
      <th>Group</th>
      <th>Access</th>
    </tr>
    <xsl:for-each select="Objects/Object">
    <tr>
      <td><xsl:value-of select="Property[@Name='Path']"/></td>
      <td><xsl:value-of select="Property[@Name='Owner']"/></td>
      <td><xsl:value-of select="Property[@Name='Group']"/></td>
      <td><table border='1' style='border-collapse:collapse' width='100%'>
        <tr bgcolor="#8abd32">
          <th>Id</th>
          <th>Access</th>
          <th>Rights</th>
        </tr>
        <xsl:for-each
select="Property[@Name='Access']/Property[@Type='System.Management.Automation.PSCustomObject']">
        <tr>
          <td><xsl:value-of select="Property[@Name='IdentityReference']"/></td>
          <td><xsl:value-of select="Property[@Name='AccessControlType']"/></td>
          <td><xsl:value-of select="Property[@Name='FileSystemRights']"/></td>
        </tr>
        </xsl:for-each>
      </table></td>
    </tr>
    </xsl:for-each>
  </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
"@
    FlatTable = @"
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
  <h2>File System Security Report</h2>
  <table border="1" style="border-collapse:collapse" width='100%'>
    <tr bgcolor="#9acd32">
      <th>Path</th>
      <th>Owner</th>
      <th>Group</th>      
      <th>Id</th>
      <th>Access</th>
      <th>Rights</th>
    </tr>
    <xsl:for-each select="Objects/*/Property[@Name='Access']/Property[@Type='System.Management.Automation.PSCustomObject']">
    <tr>      
      <td><xsl:value-of select="../../Property[@Name='Path']"/></td>
      <td><xsl:value-of select="../../Property[@Name='Owner']"/></td>
      <td><xsl:value-of select="../../Property[@Name='Group']"/></td>
      <td><xsl:value-of select="Property[@Name='IdentityReference']"/></td>
      <td><xsl:value-of select="Property[@Name='AccessControlType']"/></td>
      <td><xsl:value-of select="Property[@Name='FileSystemRights']"/></td>      
    </tr>
    </xsl:for-each> 
  </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
"@
}

function Get-ACLData {
    Param(
        [parameter(mandatory=$true,ValueFromPipeline=$true)]
        [String]
        $path
    )
    begin{
        $accessMask = [ordered]@{
            [int32]'0x80000000' = 'GenericRead'
            [int32]'0x40000000' = 'GenericWrite'
            [int32]'0x20000000' = 'GenericExecute'
            [int32]'0x10000000' = 'GenericAll'
            [int32]'0x02000000' = 'MaximumAllowed'
            [int32]'0x01000000' = 'AccessSystemSecurity'
            [int32]'0x00100000' = 'Synchronize'
            [int32]'0x00080000' = 'WriteOwner'
            [int32]'0x00040000' = 'WriteDAC'
            [int32]'0x00020000' = 'ReadControl'
            [int32]'0x00010000' = 'Delete'
            [int32]'0x00000100' = 'WriteAttributes'
            [int32]'0x00000080' = 'ReadAttributes'
            [int32]'0x00000040' = 'DeleteChild'
            [int32]'0x00000020' = 'Execute/Traverse'
            [int32]'0x00000010' = 'WriteExtendedAttributes'
            [int32]'0x00000008' = 'ReadExtendedAttributes'
            [int32]'0x00000004' = 'AppendData/AddSubdirectory'
            [int32]'0x00000002' = 'WriteData/AddFile'
            [int32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $Selections = @{
            FileSecurity = @(
                @{label='Path';Expression={$_.Path -replace 'Microsoft.PowerShell.Core\\FileSystem::',''}},
                'Owner',
                'Group',
                'Sddl',
                @{label='Access';Expression={$_.Access | Select-Object $Selections.FileSystemAccessRule}}
            )
            FileSystemAccessRule = @(
                'IdentityReference',
                @{
                    Label='FileSystemRights'
                    Expression={
                        $accessObj = $_
                        if ($accessObj.FileSystemRights -match "[-0-9]+") {                            
                            ($accessMask.Keys | Where-Object {$accessObj.FileSystemRights.Value__ -band $_ } | ForEach-Object { $accessMask.($_) } ) -join ', '
                        } else {
                            $_.FileSystemRights
                        }
                    }
                },
                'AccessControlType'
            )
        }
        $Selections.DirectorySecurity = $Selections.FileSecurity
    }    
    process {        
        try {
            Get-ACL -Path $path -ErrorAction Stop | ForEach-Object { $_ | Select-Object -Property $Selections.($_.GetType().name) }
            Write-Host "Exporting NTFS ACL --> $path"
        } catch {
            if ($_ | Select-String "access is denied" -Quiet) {
                Write-Host "Continuing ----------> $path access is denied"
            } elseif ($_ | Select-String "does not exist" -Quiet) {
                Write-Host "Continuing ----------> $path does not exist"
            }
        } 
    }
    end {}
}

function Get-TargetServers {
    Param (
        [String]$SearchBase,
        [String]$Filter
    )
    
    $GCPort = 3268 
    $globalCatalogServer = Get-ADDomainController -discover -service GlobalCatalog
    Get-ADComputer -Filter $Filter -SearchBase $SearchBase -Server "$($globalCatalogServer):$GCPort" |
        Where-Object {
            Test-Connection -ComputerName ($_.dnsHostName,$_.Name)[$_.dnsHostName -eq $null] -Count 1 -ErrorAction SilentlyContinue
        }
}

function Get-ServerSMBShares { 
    Param ( 
        [Parameter (ValueFromPipeline=$true)] $ADComputer 
    ) 
    begin{} 
    process{ 
        try { 
            if($SystemList) {
                Get-WmiObject -Class win32_share -ComputerName $ADComputer -ErrorAction Stop | 
                Select-Object @( 
                    'Name', 
                    @{  Label="RemotePath" 
                        expression={ 
                            "\\$($ADComputer)\$($_.name)" 
                        } 
                    }, 
                    'Description' 
                )
            } else {
                Get-WmiObject -Class win32_share -ComputerName $ADComputer.DNSHostName -ErrorAction Stop | 
                Select-Object @( 
                    'Name', 
                    @{  Label="RemotePath" 
                        expression={ 
                            "\\$($ADComputer.DNSHostName)\$($_.name)" 
                        } 
                    }, 
                    'Description' 
                )
            }
        } catch { 
            Write-Host "Continuing ----------> Failed to get the WMI Object for $($ADComputer.name)" 
        }
    } 
    end {} 
} 

function Generate-Report {
    Param(        
        [XML]$XMLSource,
        [String]$HTMLOutput,
        [ValidateSet('NestedTable','FlatTable')] $ReportStyle = 'NestedTable'
    )
    $xslt = new-object System.Xml.Xsl.XslCompiledTransform    
    $xmlReader = [System.Xml.XmlReader]::Create((new-object System.IO.StringReader -ArgumentList $xslTransforms.$ReportStyle))
    $xslt.Load($xmlReader)
    $xmlSourceNavigator = $XMLSource.CreateNavigator()
    $htmlOutputWriter = [System.Xml.XmlWriter]::Create($HTMLOutput)

    $xslt.Transform($xmlSourceNavigator, $htmlOutputWriter)
}

$htmlFilePath = Resolve-Path (New-Item $HTMLFile -ItemType file -ErrorAction Stop)

if($SystemList) {
    $postServers = $SystemList
} else {
    $postServers = Get-TargetServers -SearchBase $SearchBase -Filter "(Enabled -eq 'True') -and (Name -like '$Filter')"
}

$smbServerShares = $postServers | Get-ServerSMBShares

$dataset = $smbServerShares.RemotePath | Get-ACLData

[XML]$xmlDataset = $dataset | ConvertTo-XML -depth 2

Generate-Report -XMLSource $xmlDataset -HTMLOutput $htmlFilePath -ReportStyle $ReportStyle