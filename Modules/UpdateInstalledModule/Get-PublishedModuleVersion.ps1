function Get-PublishedModuleVersion
{
  <#
      .SYNOPSIS
      Takes a module name and searches the Powershell gallery for its current version number. It accepts pipeline input for the module name. Matches are returned as custom objects with a Name and a Version property.

      .DESCRIPTION
      When using Get-InstalledModule | Update-Module, this takes a long time. So some smart people on the web thought about how to improve this process.
      The result is impressing - fetching the version number from the Powershell gallery location for a module is a huge improvement over relying on Update-Module to detect the version numbers on its own.
      The function was originally published by Tobias Weltner from powertheshell.com - credits to him! His function is based on an approach that ScriptingFee developed - credits to her, too. See the related links for more information about the evolvment of the idea.

      .PARAMETER Name
      Specifies one or more module names to search the current version for. Can also be a module object as retrieved from Get-Module or Get-InstalledModule.

      .EXAMPLE
      Get-PublishedModuleVersion -Name IseSteroids
      Searches for the IseSteroids version in the Powershell gallery and returns its version number.

      .EXAMPLE
      Get-InstalledModule | Get-PublishedModuleVersion
      Searches for all modules that were installed from the gallery and returns their version numbers.

      .LINK
      http://www.powertheshell.com/findmoduleversion/
      http://scriptingfee.de/isesteroids-auf-aktuellem-stand-halten/

      .INPUTS
      System.String
      System.Management.Automation.PSModuleInfo

      .OUTPUTS
      System.Management.Automation.PSCustomObject
  #>

  [CmdletBinding()]
  param
  (
    [Parameter( Position=0, 
                Mandatory=$True,
                ValueFromPipelineByPropertyName=$True)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Name
    
  )
  
  begin {
    $BaseUrl= 'https://www.powershellgallery.com/packages'
  }

  process {
    ForEach ( $ModuleName in $Name ) {
      Write-Verbose -Message ( 'Searching for published version of module {0}...' -f $ModuleName )
      # access the main module page, and add a random number to trick proxies
      $url = ( '{0}/{1}/?dummy={2}' -f $BaseUrl, $ModuleName, ( Get-Random ) )
      Write-Verbose -Message ( 'Current request URL: {0}' -f $url )
      $request = [System.Net.WebRequest]::Create( $url )
      # do not allow to redirect. The result is a "MovedPermanently"
      $request.AllowAutoRedirect = $false
      try
      {
        # send the request
        $response = $request.GetResponse()
        Write-Verbose -Message ( 'Web server response: {0}' -f $Response.GetResponseHeader( 'Location' ) ) 
        # get back the URL of the true destination page, and split off the version
        $Properties = @{ "Name" = $ModuleName; "Version" = $response.GetResponseHeader( 'Location' ).Split( '/' )[-1] -as [Version] }
        # make sure to clean up
        $response.Close()
        $response.Dispose()
        $Object = New-Object -TypeName PSObject -Property $Properties
        $Object
      }
      catch
      {
        Write-Warning -Message $_.Exception.Message
      }
    }
  }
}