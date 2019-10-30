<#
.SYNOPSIS
    Import configuration JSON file
.DESCRIPTION
    Import configuration JSON file (for future use)
.PARAMETER InputFile
    Path and name of configuration file (default is config.json)
.EXAMPLE
    Import-UdCmJson -InputFile "c:\apps\config.json"
.NOTES
    1910.29 - 0.1 - Initial release
#>
function Import-UdCmJson {
    param(
        [parameter()][ValidateNotNullOrEmpty()][string]$InputFile = "config.json"
    )
    if (Test-Path $InputFile) {
        $hashtable = @{}
        Write-Output $(Get-Content -Path $InputFile | ConvertFrom-Json) -NoEnumerate
    }
    else {
        Write-Warning "file not found: $InputFile"
    }
}

<#
.SYNOPSIS
    Launch udcm web service
.DESCRIPTION
    Launch udcm web service and establish data stores for 
    ConfigMgr, and Active Directory objects
.PARAMETER SiteCode
    Configuration Manager site code
.PARAMETER Database
    Configuration Manager site database name (e.g. "CM_P01")
.PARAMETER DbHost
    Configuration Manager site database instance hostname (default is localhost)
.PARAMETER Port
    TCP port number for web service (default is 10001)
.PARAMETER ConfigFile
    (not currently used, planned for the future)
.EXAMPLE
    New-UDCM -SiteCode "P01"
    Launch web service and query data from database CM_P01 on localhost and AD using port 10001
.EXAMPLE
    New-UDCM -SiteCode "P01" -DbHost "cm02"
    Launch web service and query data from database CM_P01 on instance host cm02 and AD using port 10001
.EXAMPLE
    New-UDCM -SiteCode "P01" -Port 8080
    Launch web service and query data from database CM_P01 on localhost and AD using port 8080
.NOTES
    Tested with UD Community Edition 2.7, AdsiPS 1.0.0.8, dbatools 1.0.51
    0.1 - 1910.29 - Initial release as prototype
#>
function New-UDCM {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)][ValidateLength(3,3)][string] $SiteCode,
        [parameter()][ValidateNotNullOrEmpty()][string] $Database = "CM_$SiteCode",
        [parameter()][ValidateNotNullOrEmpty()][string] $DbHost = "localhost",
        [parameter()][int] $Port = 10001,
        [parameter()][ValidateNotNullOrEmpty()][string] $ConfigFile = "config.json"
    )
    $ErrorActionPreference = 'stop'
    try {
        $Endpoints = @()

        Write-Verbose "cmdevices"
        $def = @{
            SqlInstance = $DbHost
            Database    = $Database
            Query = "SELECT DISTINCT
    sys.ResourceID,
    sys.Name0 AS Name,
    case
        when (sys.Client0 = 1) then 'Yes'
        else 'No' end as Client,
    sys.Client_Version0 AS ClientVersion,
    sys.AD_Site_Name0 AS ADSiteName,
    sys.Operating_System_Name_and0 AS OSName,
    sys.Build01 as OSBuild,
    ws.UserName,
    ws.LastHardwareScan AS LastHwScan,
    ws.LastDDR, ws.LastPolicyRequest AS LastPolicyReq,
    ws.LastMPServerName AS LastMP,
    ws.IsVirtualMachine AS IsVM,
    cs.Manufacturer0 AS Manufacturer,
    cs.Model0 AS Model,
    se.SerialNumber0 AS SerialNumber
FROM
    dbo.v_R_System AS sys LEFT OUTER JOIN
    dbo.v_GS_SYSTEM_ENCLOSURE AS se ON sys.ResourceID = se.ResourceID LEFT OUTER JOIN
    dbo.v_GS_COMPUTER_SYSTEM AS cs ON sys.ResourceID = cs.ResourceID LEFT OUTER JOIN
    dbo.vWorkstationStatus AS ws ON sys.ResourceID = ws.ResourceID
order by
    sys.Name0"
        }
        $Cache:CMDevices = @( Invoke-DbaQuery @def | Select ResourceID,Name,Client,ClientVersion,ADSiteName,OSName,OSBuild,UserName,LastHwScan,LastDDR,LastPolicyReq,LastMP,IsVM,Manufacturer,Model,SerialNumber )
        $Endpoints += New-UDEndpoint -Url "cmdevices" -Endpoint { $Cache:CMDevices | ConvertTo-Json }

        Write-Verbose "cmusers"
        $def = @{
            Class = "SMS_R_User"
            Namespace = "root\SMS\Site_$SiteCode"
        }
        $Cache:CMUsers = @( Get-WmiObject @def | select UserName,FullUserName,DistinguishedName,Mail,UserPrincipalName,UserAccountControl,UserGroupName,UserOUName,ObjectGUID,WindowsNTDomain )
        $Endpoints += New-UDEndpoint -Url "cmusers" -Endpoint { $Cache:CMUsers | ConvertTo-Json }

        Write-Verbose "cmapps"
        $def = @{
            SqlInstance = $DbHost
            Database    = $Database
            Query = "select ARPDisplayName0 as ProductName,ProductVersion0 as Version,Publisher0 as Publisher,ProductCode0 as ProductCode, COUNT(*) as Installs 
            from dbo.v_GS_INSTALLED_SOFTWARE_CATEGORIZED 
            group by ARPDisplayName0,ProductVersion0,Publisher0,ProductCode0 
            order by ARPDisplayName0,ProductVersion0"
        }
        $Cache:CMApps = @( Invoke-DbaQuery @def | Select ProductName,Version,Publisher,ProductCode,Installs )
        $Endpoints += New-UDEndpoint -Url "cmapps" -Endpoint { $Cache:CMApps | ConvertTo-Json }

        Write-Verbose "cmhardware"
        $def = @{
            SqlInstance = $DbHost
            Database    = $Database
            Query = "select Manufacturer0 as Manufacturer, Model0 as Model, COUNT(*) as Devices from dbo.v_GS_COMPUTER_SYSTEM group by Manufacturer0,Model0 order by Manufacturer0,Model0"
        }
        $Cache:CMHardware = @( Invoke-DbaQuery @def | Select Manufacturer,Model,Devices )
        $Endpoints += New-UDEndpoint -Url "cmhardware" -Endpoint { $Cache:CMHardware | ConvertTo-Json }
        
        $Cache:ADUsers = @( Get-ADSIUser -NoResultLimit )
        $Endpoints += New-UDEndpoint -Url "adusers" -Endpoint { $Cache:ADUsers | ConvertTo-Json }

        $Cache:ADGroups = @( Get-ADSIGroup )
        $Endpoints += New-UDEndpoint -Url "adgroups" -Endpoint { $Cache:ADGroups | ConvertTo-Json }

        Start-UDRestApi -Endpoint $Endpoints -Port $Port -AutoReload -Name "udcm"
    }
    catch {
        Write-Error $_.Exception.Message
    }
}
