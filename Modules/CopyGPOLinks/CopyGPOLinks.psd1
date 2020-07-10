@{

# Module Loader File
RootModule = 'loader.psm1'

# Version Number
ModuleVersion = '1.2'

# Unique Module ID
GUID = '8FB07182-107A-4D06-B326-2F941DEDC1B3'

# Module Author
Author = 'Martin Binder'

# Company
CompanyName = ''

# Copyright
Copyright = '(c) 2017 Martin Binder. All rights reserved.'

# Module Description
Description = 'When staging environments in a single AD, it is common to create a new identical OU structure for testing purposes. This structure should match the original one, including all child OUs and their linked GPOs. Copy-GPOLinks copies all linked GPOs from a source OU to a target OU in a given domain. Optionally, it recurses through child OUs and copies their GPOs, too. It also can create missing target child OUs automatically.'

# Minimum PowerShell Version Required
PowerShellVersion = '3.0'

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
RequiredModules = @('ActiveDirectory','GroupPolicy')

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
FunctionsToExport = @( 'Copy-GPOLinks' )

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
PrivateData = @{
    PSData = @{
        Tags=@( 'grouppolicy', 'gplink', 'gpolinks' )
        ExternalModuleDependencies=@( 'ActiveDirectory', 'GroupPolicy' )
    }
}

}
