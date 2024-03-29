# Module manifest for module 'udcm'
# Generated by: David Stein
# Generated on: 10/29/2019

@{
RootModule = '.\udcm.psm1'
ModuleVersion = '0.1'
# CompatiblePSEditions = @()
GUID = '7c3a8049-dce8-43ff-89f5-a9801552774d'
Author = 'David Stein'
CompanyName = 'Skatterbrainz'
Copyright = '(c) 2019 David Stein. All rights reserved.'
Description = 'Universal Dashboard Web Service for Configuration Manager and Active Directory'
PowerShellVersion = '5.1'
# PowerShellHostName = ''
PowerShellHostVersion = '5.1'
# DotNetFrameworkVersion = ''
# CLRVersion = ''
# ProcessorArchitecture = ''
RequiredModules = @('UniversalDashboard.Community','dbatools','adsips')
# RequiredAssemblies = @()
# ScriptsToProcess = @()
# TypesToProcess = @()
# FormatsToProcess = @()
# NestedModules = @()
FunctionsToExport = '*'
CmdletsToExport = '*'
VariablesToExport = '*'
AliasesToExport = '*'
# DscResourcesToExport = @()
# ModuleList = @()
# FileList = @()
PrivateData = @{
    PSData = @{
        Tags = @('udcm','dashboard','configmgr','sccm','webservice','universal','rest')
        LicenseUri = 'https://github.com/Skatterbrainz/udcm/blob/master/LICENSE'
        ProjectUri = 'https://github.com/Skatterbrainz/udcm'
        # IconUri = ''
        # ReleaseNotes = ''
    } # End of PSData hashtable
} # End of PrivateData hashtable
# HelpInfoURI = ''
# DefaultCommandPrefix = ''
}