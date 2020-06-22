function Update-InstalledModule {
  <#
      .SYNOPSIS
      This function updates one or more modules that were installed from the PowerShell gallery if newer versions are available. It accepts pipeline input for the module name as well as an array of names.

      It wraps the PowerShellGet function Update-Module and works way faster.

      .DESCRIPTION
      Updating modules from the Powershell Gallery can be done via calling Update-Module. This can even be used in a pipeline with Get-InstalledModule | Update-Module. But that's a quite slow command - so this workaround was created. Update-InstalledModule checks the module's download URL for the most current version number, and it calls the original Update-Module only if the local version is older.

      For modules that are installed for all users, it obviously requires an elevated session to work - unlike the original Update-Module function, this wrapper does not check where the module is installed and whether admin rights are required or not.

      The main reason for the original Update-Module slowness are its connectivity checks to various web sites via ping or http get requests. The helper function Get-PublishedModuleVersion omits all of these checks and only sends a single http get. The response is then parsed for the location which contains the version number. This check is performed for all modules passed in, and finally all modules that need to be updated are passed to Update-Module.

      .PARAMETER Name
      The name of the module(s) to update. Can also be a module object returned from Get-Module or Get-InstalledModule. If the module name is omitted, all installed modules are checked.

      .PARAMETER Force
      Updates the module even if the currently installed version is up to date.

      .EXAMPLE
      Update-InstalledModule
      Checks if newer versions for any installed module are available.

      .EXAMPLE
      Update-InstalledModule Foo -Force
      Updates the module Foo regardless of the current version.

      .EXAMPLE
      Update-InstalledModule -Name ScriptCop,EzOut
      Checks if newer versions are available for ScriptCop and EzOut.

      .LINK
      http://powertheshell.com
      https://evilgpo.blogspot.com

      .INPUTS
      System.String
      System.Management.Automation.PSModuleInfo

      .OUTPUTS
      None
  #>

  [CmdletBinding(SupportsShouldProcess=$True)]
  param
  (
    [Parameter( Position = 0,
    ValueFromPipelineByPropertyName = $true )]
    [String[]]
    $Name,

    [Parameter()]
    [ValidateSet( 'AllUsers', 'CurrentUser')]
    [String]$Scope,

    [Switch]
    $Force
  )

  begin {

    # ModulesToUpdate keeps track of all modules that need to be updated.
    # These are then finally passed to the original Update-Module in order
    # to speed up processing if more than one module needs updates.
    
    $ModulesToUpdate = @()

    # The -verbose switch cannot properly be passed down to called functions/scripts,
    # so we determine the VerbosePreference value and create an appropriate bool.

    If ( $VerbosePreference -eq "Continue" ) {
      $Verbose = $True
    } else {
      $Verbose = $False
    }
  }
  
  process {

    # ModulesToVerify keeps track of all modules that need to be verified.
    # This can be one or more modules passed on the commandline,
    # or if no modules are passed, we grab all of them for checking.

    If ( $Scope ) {
      If ( $Name ) {
        $ModulesToVerify = ( Get-InstalledModule -Name $Name )
      } else {
        Write-Verbose -Message 'No module name specified, checking all installed modules'
        $ModulesToVerify = ( Get-InstalledModule )
      }
    } Else {
      If ( $Name ) {
        $ModulesToVerify = ( Get-InstalledModule -Name $Name -Scope $Scope )
      } else {
        Write-Verbose -Message 'No module name specified, checking all installed modules'
        $ModulesToVerify = ( Get-InstalledModule -Scope $Scope )
      }
    }
       
    ForEach ( $CurrentModule in $ModulesToVerify ) {
    
      # Get the version of the currently installed module. If it is not installed,
      # Get-InstalledModule will throw a non-terminating error

      Write-Verbose -Message ( 'Trying to check module version for {0}...' -f $CurrentModule.Name )
      $CurrentModuleVersion = $CurrentModule.Version

      If ( $CurrentModuleVersion -eq $null ) {
        Write-Verbose -Message 'Module is not installed or has no version number, skipping...'
        Continue 
      }

      Write-Verbose -Message ( 'Found installed version : {0}' -f $CurrentModuleVersion.ToString() )

      # Get the version that is available in the powershell gallery. If it is not in the gallery,
      # Get-PublishedModuleVersion will throw a warning

      Write-Host ( 'Checking current {0} version {1} for updates...' -f $CurrentModule.Name, $CurrentModuleVersion )
      $AvailableModuleVersion = ( Get-PublishedModuleVersion -Name $( $CurrentModule.Name ) -Verbose:$Verbose ).Version

      If ( $AvailableModuleVersion -eq $null ) { 
        Write-Verbose -Message 'Module version not found in the gallery, skipping...'
        Continue
      }

      Write-Verbose -Message ( 'Latest available version: {0}' -f $AvailableModuleVersion.ToString() )

      # Check if versions already match. Since we use [version] types,
      # we don't care if the version has 2, 3 or 4 parts.

      If ( $CurrentModuleVersion -ge $AvailableModuleVersion )
      {
        If ( $Force ) { 
          Write-Verbose -Message ( '{0} version is up to date, but -Force specified - updating anyway...' -f $CurrentModule.Name )
        } else {
          Write-Host ( '{0} version is already up to date.' -f $CurrentModule.Name ) -ForegroundColor Green
        }
      }

      # check if versions do not match

      If ( ( $CurrentModuleVersion -lt $AvailableModuleVersion ) -or $Force )
      { 
        Write-Host ( '{0} will be updated to version {1}...' -f $CurrentModule.Name, $AvailableModuleVersion ) -ForegroundColor Yellow
        $ModulesToUpdate += $CurrentModule
      }

    }
  }
  
  end {

    # finally update all modules in one call to Update-Module to speed up things...
    If ( $ModulesToUpdate -and $PSCmdlet.ShouldProcess( $ModulesToUpdate.Name ) )
    {
      If ( $Scope ) {
        Update-Module -Name ( $ModulesToUpdate.Name ) -Force:$Force -ErrorAction SilentlyContinue -Verbose:$Verbose -Scope $Scope
      } Else {
        Update-Module -Name ( $ModulesToUpdate.Name ) -Force:$Force -ErrorAction SilentlyContinue -Verbose:$Verbose
      }
    }
    
  }
}
