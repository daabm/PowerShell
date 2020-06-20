<#
.SYNOPSIS

Retrieves all GPOs in a domain. For each GPO, it determines whether the GPO is linked to any OU. All unlinked GPOs are returned.

.DESCRIPTION

For housekeeping reasons, you might want to get rid of GPOs that do not apply to anything. This includes unlinked GPOs as well as GPOs that have disabled links only or where both computer and user part are disabled.

The Get-UnlinkedGPOs function searches a domain for these GPOs and returns the resulting GPO objects. It also adds 3 boolean properties to each returned GPO:
$GPO.Unlinked: The GPO is selected because it is not linked at all
$GPO.AllLinksDisabled: The GPO is selected because it has links, but all of these links are disabled
$GPO.AllSettingsDisabled: The GPO is selected because all settings are disabled. Already contained in $GPO.GPOStatus, but for convenience.

DYNAMIC PARAMETERS

-Domain <String>
    The domain where the operation should be performed. This must the user's current domain or a trusting domain. Tab completion searches through the list of possible target domains.

    Required?                    true
    Position?                    1
    Default value                False
    Accept pipeline input?       false
    Accept wildcard characters?  false

.PARAMETER IncludeDisabledLinks

By default, only GPOs are returned that have no links at all. Use this switch to also return all GPOs that have no enabled links (all links are disabled).

.PARAMETER IncludeDisabledGPOs

By default, only GPOs are returned that have no links at all. Use this switch to also return all GPOs where all settings are disabled (both user and computer settings).

.INPUTS

This cmdlet does not take pipeline input

.OUTPUTS

[[Microsoft.GroupPolicy.GPMGPO]]

.EXAMPLE

Get-UnlinkedGPOs -Domain corp.contoso.com

Gets all unlinked GPOs in the corp.contoso.com domain.

.EXAMPLE

Get-UnlinkedGPOs -Domain corp.contoso.com -IncludeDisabledLinks | Remove-GPO -Confirm:$False

Gets all unlinked GPOs including those with disabled links and pipes them to Remove-GPO for instant deletion (not recommended to use in the first place).

.NOTES

There are a lot of samples how to find unlinked GPOs with Powershell. All of them use Get-GPReport against all GPOs and parse the report for <LinksTo>-Elements. Whilst this approach works well in small environments, it is a complete mess in large domains with thousands of GPOs.

This function thus takes a completely different approach. It retrieves all SOMs that have a populated GPLink attribute and creates a hash of all GPOs in all these GPLinks. Then it compares all GPO IDs to this hash.

Although prepraring the hash takes some time (roughly 2 seconds per 100 SOMs), the overall time is significantly lower compared to Get-GPReport.

#>
function Get-UnlinkedGPOs {

    [CmdletBinding()]
    [Alias()]
    Param(
        [Parameter()]
        [Switch] $IncludeDisabledLinks,
        [Parameter()]
        [Switch] $IncludeDisabledGPOs
    )

    DynamicParam {

        # To enable tab expansion for the target domain, create a hash of all trusting domains and add this
        # as a ValidateSet to both parameters. Also add the user's current domain.

        $DomainArray = New-Object System.Collections.ArrayList
        [void]$DomainArray.Add( $env:USERDNSDOMAIN )

        $Trusts = Get-ADTrust -LDAPFilter '(!(trustDirection=2))' -Properties Name -Server $env:USERDNSDOMAIN | Select-Object -Property 'Name'
        Foreach ( $Trust in $Trusts ) {
            [void]$DomainArray.Add( $Trust.Name )
        }

        # Create the DynamicParam Array. Each array member is a hashtable containing the parmeter definition.
        # ParameterAttributes is an embedded Array of hashtables containing the attributes for each ParameterSet.
        # The comments for the Domain parameter definition show some commonly used attributes.

        # Parameter references:
        # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_parameters
        # https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/validating-parameter-input
        # https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/parameter-attribute-declaration

        $DynamicParameters = @(
            @{
                Name = 'Domain'
                # ValidateCount = @( [int]Min, [int]Max )
                # ValidateLenght = @( [int]Min, [int]Max )
                # ValidateRange = @( [int]Min, [int]Max )
                # ValidateSet = @( 'a', 'b', 'c' )
                ValidateSet = $DomainArray
                ParameterAttributes = @(
                    @{
                        # ParameterSetName = 'a'
                        # Mandatory = $True
                        # ValueFromPipeline = $True
                        # ValueFromPipelineByPropertyName = $True
                        Mandatory = $True
                    }
                )
            }
        )
    
        # Create and populate the parameter dictionary
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        Foreach( $DynamicParameter in $DynamicParameters ) {
            $RuntimeParameter = New-DynamicParameter @DynamicParameter
            $RuntimeParameterDictionary.Add( $DynamicParameter.Name, $RuntimeParameter )
        }

        Return $RuntimeParameterDictionary
    }

    Begin {
        Foreach ( $BoundParam in $PSBoundParameters.GetEnumerator() ) {
            New-Variable -Name $BoundParam.Key -Value $BoundParam.Value -ErrorAction 'SilentlyContinue' -Whatif:$False
        }
    }

    Process {

        $PDC = ( Get-ADDomain -Identity $Domain ).PDCEmulator
        Write-Verbose "Retrieving unlinked GPOs in domain $Domain ($PDC).`n"

        $UnlinkedGPOs = New-Object System.Collections.ArrayList
        $AllSoms = New-Object System.Collections.ArrayList
        $GPLinkHash = @{}

        Write-Verbose "Retrieving GPOs..."

        $ProcessingTime = ( Measure-Command {
            $AllGPOs = Get-GPO -All -Domain $Domain -Server $PDC
        } ).TotalSeconds

        Write-Verbose "Found $( $AllGPOs.Count ) GPOs in $ProcessingTime seconds.`n"

        Write-Verbose "Retrieving GPLink SOMs..."

        $ProcessingTime = ( Measure-Command { 
            $OUDomainSOMS = Get-ADObject -LDAPFilter '(&(|((objectClass=organizationalUnit)(objectClass=domain)))(gpLink=[LDAP*))' -Properties 'GPLink' -Server $PDC | Select-Object -Property 'GPLink'
            If ( $OUDomainSOMS ) {
                [void]$AllSOMs.AddRange( $OUDomainSOMS )
            }
            $SiteSOMS = Get-ADReplicationSite -Filter * -Properties 'GPLink' -Server $PDC | Where-Object { $_.GPLink -match '^\[LDAP' } | Select-Object -Property 'GPLink'
            If ( $SiteSOMs ) {
                [void]$AllSoms.AddRange( $SiteSoms )
            }
        } ).TotalSeconds

        Write-Verbose "Found $( $AllSOMs.Count ) SOMs in $ProcessingTime seconds.`n"

        Write-Verbose "Preparing linked GPO hashtable..."

        $ProcessingTime = ( Measure-Command {
            Foreach ( $SOM in $AllSOMs ) {

                # GPLink has a weird format - [GPO-DN;LinkFlags][GPO-DN;LinkFlags][...]
                # remove leading [ and trailing ], then split on ][

                $GPLinks = $SOM.GPLink.Substring( 1, $SOM.GPLink.Length - 2 ) -split '\]\['

                # we want an array that holds all GPO Ids that are linked somewhere. So extract all GPO IDs from the GPLinks

                Foreach ( $GPLink in $GPLinks ) {

                    # GUID is 11...47, Flag is last char.
                    $GpoGuid = $GPLink.Substring( 11, 36 )
                    $Flags = $GPLink.Substring( $GPLink.Length -1 )
                    $Enabled   = ( ( $Flags -band 1 ) -eq 0 )  # $Flags bit 0 unset means "Link enabled"

                    # If the GPO hash already contains 1, do NOT overwrite it. This ensures
                    # that if at least one link is enabled, the hash always contains 1.
                    If ( $GPLinkHash[ $GpoGuid ] -ne 1 ) {
                        $GPLinkHash[ $GpoGuid ] = $Enabled
                    }
               }
            }
        } ).TotalSeconds

        Write-Verbose "GPO hashtable containing $( $GPLinkHash.Count ) GUIDs prepared in $ProcessingTime seconds.`n"

        Write-Verbose "Processing $( $AllGPOs.Count ) GPOs..."

        $ProcessingTime = ( Measure-Command {
            Foreach ( $GPO in $AllGPOs ) {
                Add-Member -InputObject $GPO -MemberType NoteProperty -Name 'Unlinked' -Value $False
                Add-Member -InputObject $GPO -MemberType NoteProperty -Name 'AllLinksDisabled' -Value $False
                Add-Member -InputObject $GPO -MemberType NoteProperty -Name 'AllSettingsDisabled' -Value $False
                # GPO is not linked at all...
                If ( -not $GPLinkHash.Contains( $GPO.ID.Guid ) ) {
                    [void]$UnlinkedGPOs.Add( $GPO )
                    $GPO.Unlinked = $True
                } 
                # GPO is linked but all links are disabled - the GUID hash contains 1 if at least one link is enabled.
                ElseIf ( $IncludeDisabledLinks -and $GPLinkHash[ $GPO.ID.Guid ] -ne 1 ) {
                    [void]$UnlinkedGPOs.Add( $GPO )
                    $GPO.AllLinksDisabled = $True
                }
                # GpoStatus is 'AllSettingsDisabled'
                If ( $IncludeDisabledGPOs -and $GPO.GPOStatus.Value__ -eq 0 ) {
                    [void]$UnlinkedGPOs.Add( $GPO )
                    $GPO.AllSettingsDisabled = $True
                }

            }
        } ).TotalSeconds

        Write-Verbose "$( $AllGPOs.Count ) GPOs processed in $ProcessingTime seconds.`n"

        Write-Verbose "$( $UnlinkedGPOs.Count ) unlinked GPOs found.`n"

        $UnlinkedGPOs
    }

    End {}

}

Function New-DynamicParameter {
    # based on the work of adamtheautomator
    # https://github.com/adbertram/Random-PowerShell-Work/blob/master/PowerShell%20Internals/New-DynamicParam.ps1
    [CmdletBinding()]
    [OutputType('System.Management.Automation.RuntimeDefinedParameter')]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
        [String] $Name,

        [Parameter()][ValidateNotNullOrEmpty()]
        [Type] $Type = [String],

        [Parameter()][ValidateNotNullOrEmpty()][ValidateCount( 2, 2 )]
        [Int[]] $ValidateCount,
        
        [Parameter()][ValidateNotNullOrEmpty()][ValidateCount( 2, 2 )]
        [Int[]] $ValidateLength,
        
        [Parameter()][ValidateNotNullOrEmpty()]
        [String] $ValidatePattern,

        [Parameter()][ValidateNotNullOrEmpty()][ValidateCount( 2, 2 )]
        [Int[]] $ValidateRange,

        [Parameter()][ValidateNotNullOrEmpty()]
        [Scriptblock] $ValidateScript,

        [Parameter()][ValidateNotNullOrEmpty()]
        [Array] $ValidateSet,

        [Parameter()][ValidateNotNullOrEmpty()]
        [Switch] $ValidateNotNullOrEmpty,
		
        [Parameter()][ValidateNotNullOrEmpty()]
        [Array] $ParameterAttributes
    )
	
    $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

    Foreach ( $ParameterAttribute in $ParameterAttributes ) {
        $ParamAttrib = New-Object System.Management.Automation.ParameterAttribute
        # Get all settable properties of the $ParamAttrib object
        $AttribNames = ( Get-Member -InputObject $ParamAttrib -MemberType Property | Where-Object -FilterScript { $_.Definition -match '{.*set;.*}$' } ).Name
        # Loop through settable properties and assign value if present in $ParameterAttribute
        Foreach ( $AttribName in $AttribNames ){
            If ( $ParameterAttribute.$AttribName ) { $ParamAttrib.$AttribName = $ParameterAttribute.$AttribName }
        }
        $AttribColl.Add( $ParamAttrib )
    }

    $ValidationAttributes = @( 'Count', 'Length', 'Pattern', 'Range', 'Script', 'Set' )

    # create all validation attributes
    Foreach ( $ValidationAttribute in $ValidationAttributes ){
        If ( $PSBoundParameters.ContainsKey( "Validate$ValidationAttribute" )) {
            $TypeName = 'System.Management.Automation.Validate' + $ValidationAttribute + 'Attribute'
            $AttribColl.Add(( New-Object $TypeName -ArgumentList ( Get-Variable -Name "Validate$ValidationAttribute" ).Value ))
        }
    }

    # need to handle this one separately - it does not take parameters in its constructor
    If ( $ValidateNotNullOrEmpty.IsPresent ) {
        $AttribColl.Add(( New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute ))
    }
	
    $RuntimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter( $Name, $Type, $AttribColl )
    Return $RuntimeParam
	
}
