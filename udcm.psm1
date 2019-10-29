function New-UDCM {
    [CmdletBinding()]
    param(
        [parameter()][ValidateLength(3,3)][string] $SiteCode = "P01",
        [parameter()][ValidateNotNullOrEmpty()][string] $Database = "CM_$SiteCode",
        [parameter()][ValidateNotNullOrEmpty()][string] $DbHost = "localhost",
        [parameter()][ValidateNotNullOrEmpty()][string] $ConfigFile = "config.json",
        [parameter()][int] $Port = 10001
    )
    $ErrorActionPreference = 'stop'
    try {
        $Endpoints = @()

        Write-Verbose "sms_r_system"
        $def = @{
            Class = "SMS_R_System"
            Namespace = "root\SMS\Site_$SiteCode"
        }
        $Cache:CMDevices = @( Get-WmiObject @def | select ResourceID,Name,Client,ClientVersion,ADSiteName,DistinguishedName,MACAddresses,IPAddresses,LastLogonTimestamp,OperatingSystemNameandVersion,Build )
        $Endpoints += New-UDEndpoint -Url "cmdevices" -Endpoint { $Cache:CMDevices | ConvertTo-Json }

        Write-Verbose "sms_r_user"
        $def = @{
            Class = "SMS_R_User"
            Namespace = "root\SMS\Site_$SiteCode"
        }
        $Cache:CMUsers = @( Get-WmiObject @def | select UserName,FullUserName,DistinguishedName,Mail,UserPrincipalName,UserAccountControl,UserGroupName,UserOUName,ObjectGUID,WindowsNTDomain )
        $Endpoints += New-UDEndpoint -Url "cmusers" -Endpoint { $Cache:CMUsers | ConvertTo-Json }

        Write-Verbose "host: $DbHost / database: $Database"
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

        $def = @{
            SqlInstance = $DbHost
            Database    = $Database
            Query = "select Manufacturer0 as Manufacturer, Model0 as Model, COUNT(*) as Devices from dbo.v_GS_COMPUTER_SYSTEM order by Manufacturer0,Model0"
        }
        $Cache:CMHardware = @( Invoke-DbaQuery @def | Select Manufacturer,Model,Devices )
        $Endpoints += New-UDEndpoint -Url "cmhardware" -Endpoint { $Cache:CMHardware | ConvertTo-Json }
        
        <#
        adusers = "properties": "SamAccountName,DisplayName,DistinguishedName,Mail,UserPrincipalName"
        adgroups = "properties": "Name,DisplayName,DistinguishedName"
        #>
        Start-UDRestApi -Endpoint $Endpoints -Port $Port -AutoReload -Name "udcm"
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

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
