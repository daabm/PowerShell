@{

    # Module Loader File
    RootModule = 'GetGPVersionMismatch.psm1'
    
    # Version Number
    ModuleVersion = '1.0'
    
    # Unique Module ID
    GUID = 'af2be4e4-e934-43ae-b142-f85b0363827e'
    
    # Module Author
    Author = 'Martin Binder'
    
    # Company
    CompanyName = ''
    
    # Copyright
    Copyright = '(c) 2020 Martin Binder. All rights reserved.'
    
    # Module Description
    Description = 'Gets GPOs in a domain and checks them for version mismatches in AD and Sysvol.'
    
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
    RequiredModules = @( 'GroupPolicy', 'ActiveDirectory' )
    
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
    FunctionsToExport = @( 'Get-GPVersionMismatch' )
    
    # List of exportable cmdlets
    CmdletsToExport = @()
    
    # List of exportable variables
    VariablesToExport = @()
    
    # List of exportable aliases
    AliasesToExport = @()
    
    # List of all modules contained in this module
    ModuleList = @()
    
    # List of all files contained in this module
    FileList = @()
    
    # Private data that needs to be passed to this module
    PrivateData = @{
        PSData = @{
            Tags=@( 'grouppolicy','gplink', 'unlinked' )
            ExternalModuleDependencies = @( 'GroupPolicy', 'ActiveDirectory' )
        }
    }
        
    }
    