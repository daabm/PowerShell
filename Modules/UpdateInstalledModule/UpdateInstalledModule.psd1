@{

# Module Loader File
RootModule = 'loader.psm1'

# Version Number
ModuleVersion = '1.1'

# Unique Module ID
GUID = '1c4e6775-cf7b-4a5c-b8b0-61906cb033be'

# Module Author
Author = 'Martin Binder'

# Company
CompanyName = ''

# Copyright
Copyright = '(c) 2016 Martin Binder. All rights reserved.'

# Module Description
Description = 'Updates a module from the Powershell Gallery if a newer version is available. Wraps the PowerShellGet function Update-Module and is much faster.
This module exports 2 functions: Get-PublishedModuleVersion and Update-InstalledModule.
Get-PublishedModuleVersion checks the most recent version of a module in the Powershell gallery. It is based on ideas from Tobias Weltner (powertheshell.com) and scriptingfee.de
Update-InstalledModule uses this version check to prepare a list of modules that are outdated. This list then is passed on to the original Update-Module function. If no outdated modules are found, Update-Module is not called at all.
The fast check for outdated versions makes it easy to include an update check in your profile script. Simply add the following two lines to your profile:
Try { Import-Module -Name UpdateInstalledModule; Update-InstalledModule -Name <Module Names you want to automatically check and update> }
Catch { $_ }
'

# Minimum PowerShell Version Required
PowerShellVersion = '5.0'

# Name of Required PowerShell Host
PowerShellHostName = ''

# Minimum Host Version Required
PowerShellHostVersion = ''

# Minimum .NET Framework-Version
DotNetFrameworkVersion = ''

# Minimum CLR (Common Language Runtime) Version
CLRVersion = ''

# Processor Architecture Required (X86, Amd64, IA64)
ProcessorArchitecture = ''

# Required Modules (will load before this module loads)
RequiredModules = @( 'PowerShellGet' )

# Required Assemblies
RequiredAssemblies = @()

# PowerShell Scripts (.ps1) that need to be executed before this module loads
ScriptsToProcess = @()

# Type files (.ps1xml) that need to be loaded when this module loads
TypesToProcess = @()

# Format files (.ps1xml) that need to be loaded when this module loads
FormatsToProcess = @()

# 
NestedModules = @()

# List of exportable functions
FunctionsToExport = @( 'Update-InstalledModule', 'Get-PublishedModuleVersion' )

# List of exportable cmdlets
CmdletsToExport = '*'

# List of exportable variables
VariablesToExport = '*'

# List of exportable aliases
AliasesToExport = '*'

# List of all modules contained in this module
ModuleList = @()

# List of all files contained in this module
FileList = @()

# Private data that needs to be passed to this module
PrivateData = ''

}