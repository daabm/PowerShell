<#
.SYNOPSIS

Links a new GPO to all OUs where a given GPO is already linked. Optionally removes the given GPO. Does not process GPOs linked to sites or the domain itself.

.DESCRIPTION

Sometimes, new GPOs need to be deployed everywhere a given GPO is already in use. Or a given GPO needs to be replaced globally after testing.

The Append-GPLink function takes a reference GPO and a new GPO (both must already exist). Then it enumerates the OUs where the reference GPO is linked. It then links the new GPO to these OUs (bottom most link order by default). Link order and link properties can be modified.

DYNAMIC PARAMETERS

-ReferenceGPO <String>
    The GPO that serves as a reference. The OUs this GPO is linked to are enumerated and updated.
    Tab completion searches the list of GPOs in TargetDomain.

    Required?                    true
    Position?                    2
    Default value                False
    Accept pipeline input?       false
    Accept wildcard characters?  false

-NewGPO <String>
    The GPO that will be linked to the OUs where ReferenceGPO is linked.
    This parameter is required if -RemoveLink is not specified.
    Tab completion searches the list of GPOs in TargetDomain.

    Required?                    true
    Position?                    3
    Default value                False
    Accept pipeline input?       false
    Accept wildcard characters?  false

.PARAMETER TargetDomain

The domain where the actions should be performed. Defaults to the domain of the currently logged on user.

.PARAMETER OUFilter

By default, all OUs are processed where the ReferenceGPO is linked. Use this parameter to restrict the OUs to process. The filter is evaluated as a regular expression match against the distinguished name of the OUs where the ReferenceGPO is linked.
Filtering would be smarter if done via LDAPFilter, but there's no possibility to escape LDAP filters like it can be done with [Regex]::Escape for regular expressions.

.PARAMETER SearchBase

Use this distinguished name to limit the search for OUs where ReferenceGPO is linked to a specific searchbase. Since the domain is already defined, omit the domain from the searchbase (do not include the DC=... parts)

.PARAMETER RegexEscape

By default, the OUFilter will be used literally in a regex match. This means if you want to search for special characters like \ or *, you must escape them properly. Use this switch to let the cmdlet escape your filter string.

.PARAMETER RelativeLinkPos

By default, NewGPO will be appended at the bottom of the linked GPOs. With RelativeLinkPos, you can specify whether NewGPO should be inserted directly above or below ReferenceGPO. Valid options are "before" and "after".

.PARAMETER ReplaceLink

Specify this switch if you want to remove the link to ReferenceGPO, leaving only the NewGPO link active. NewGPO will be linked at the position where ReferenceGPO was linked.

.PARAMETER LinkOrder

By default, NewGPO is linked at the last position (bottom) or near ReferenceGPO. Specify a different LinkOrder to link it e.g. at the top (Linkorder 1) or anywhere in between.

.PARAMETER Enforced

Specify this parameter to select an enforcement state for the GPO link. The default is "unspecified" which effectively means "not enforced". Valid options are "unspecified" (0), "no" (1) and "yes" (2).

.PARAMETER LinkEnabled

Specify this parameter to select an enablement state for the GPO link. The default is "unspecified" which effectively means "enabled". Valid options are "unspecified" (0), "no" (1) and "yes" (2).

.PARAMETER RemoveLink

Specify this switch to only remove the link to ReferenceGPO.

.INPUTS

This cmdlet does not take pipeline input.

.OUTPUTS

This cmdlet does not return pipeline output.

.EXAMPLE

Append-GPLink -ReferenceGPO 'Server Default Policy' -NewGPO 'Server Addon Policy'

Searches all OUs where the GPO named 'Server Default Policy' is linked, and links the GPO named 'Server Addon Policy' to these OUs. The link will be disabled and enforced.

.EXAMPLE

Append-GPLink -ReferenceGPO 'Server Default Policy' -NewGPO 'Server New Default Policy' -OUFilter 'OU=Servers' -Replace -LinkOrder 1

Searches all OUs matching 'OU=Servers' where the GPO named 'Server Default Policy' is linked, and links the GPO named 'Server New Default Policy' to these OUs at position 1 . Then it removes the existing link to 'Server Default Policy'.

.EXAMPLE

Append-GPLink -ReferenceGPO 'Server Default Policy' -Remove

Searches all OUs where the GPO named 'Server Default Policy' is linked, and removes the existing link.

.NOTES

Because such mass operations are usually not required for sites or for the domain itself, it does not process these SOM types. Only OUs are searched.

#>
Function Add-GPLink {
    [CmdletBinding( SupportsShouldProcess = $True, DefaultParameterSetName = 'Add' )]
    [Alias()]

    Param(

        [Parameter( Position = 0 )]
        [ValidateScript( { Get-ADDomain $_ } )] # verify TargetDomain is reachable
        [String] $TargetDomain = $env:USERDNSDOMAIN,
        
        [Parameter()]
        [ValidateScript( { $_ -match '^(?:OU=[^,]+,?)+$' } )] # match any number of OU=xxx,OU=yyy...
        [String] $SearchBase,
        
        [Parameter()]
        [String] $OUFilter,

        [Parameter()]
        [Switch] $RegexEscape,
        
        [Parameter( ParameterSetName = 'Add' )]
        [ValidateSet('before','after')]
        [String] $RelativeLinkPos,
        
        [Parameter( ParameterSetName = 'Replace' )]
        [Switch] $ReplaceLink,
        
        [Parameter( ParameterSetName = 'AddWithOrder' )]
        [ValidateRange( 1, 999 )] # maximum number of linked GPOs is 1000 due to size limitation of the GPLink attribute...
        [Int32] $LinkOrder,
        
        [Parameter( ParameterSetName = 'Add' )]
        [Parameter( ParameterSetName = 'Replace' )]
        [Parameter( ParameterSetName = 'AddWithOrder' )]
        [Microsoft.GroupPolicy.EnforceLink] $Enforced = [Microsoft.GroupPolicy.EnforceLink]::Unspecified,
        
        [Parameter( ParameterSetName = 'Add' )]
        [Parameter( ParameterSetName = 'Replace' )]
        [Parameter( ParameterSetName = 'AddWithOrder' )]
        [Microsoft.GroupPolicy.EnableLink] $LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Unspecified,

        [Parameter( ParameterSetName = 'Remove' )]
        [Switch] $RemoveLink

    )

    DynamicParam {

        # To enable tab expansion for ReferenceGPO and NewGPO, create a hash of all GPO names in TargetDomain and add this
        # as a ValidateSet to both parameters.

        # GPOHash contains the GPO names for the ValidateSet.
        # GuidHash is used to resolve linked GPOs from the GPLink attribute. Usually one would search these with a
        # Where clause in the GPOHash. But in domains wit a large number of GPOs, that's way too slow. The GuidHash
        # allows direct access to all GPOs by Guid.

        $GPOHash = @{}
        $GuidHash = @{}
        $GPOs = Sort-Object ( Get-GPO -All -Domain $TargetDomain ) -Property ModificationTime
        Foreach ( $GPO in $GPOs ) {
            $GPOHash[ $GPO.DisplayName ] = $GPO
            $GuidHash[ $GPO.Id.Guid ] = $GPO
        }

        # Create the DynamicParam Array. Each array member is a hashtable containing the parmeter definition.
        # ParameterAttributes is an embedded Array of hashtables containing the attributes for each ParameterSet.
        # The comments for the ReferenceGPO parameter definition show some commonly used attributes.

        # Parameter references:
        # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced_parameters
        # https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/validating-parameter-input
        # https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/parameter-attribute-declaration

        $DynamicParameters = @(
            @{
                Name = 'ReferenceGPO'
                # ValidateCount = @( [int]Min, [int]Max )
                # ValidateLenght = @( [int]Min, [int]Max )
                # ValidateRange = @( [int]Min, [int]Max )
                # ValidateSet = @( 'a', 'b', 'c' )
                ValidateSet = $GPOHash.Keys
                ParameterAttributes = @(
                    @{
                        # ParameterSetName = 'a'
                        # Mandatory = $True
                        # ValueFromPipeline = $True
                        # ValueFromPipelineByPropertyName = $True
                        Mandatory = $True
                    }
                )
            },
            @{
                Name = 'NewGPO'
                ValidateSet = $GPOHash.Keys
                ParameterAttributes = @(
                    @{
                        ParameterSetName = 'Add'
                        Mandatory = $True
                    },
                    @{
                        ParameterSetName = 'Replace'
                        Mandatory = $True
                    },
                    @{
                        ParameterSetName = 'AddWithOrder'
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
        $SourceGPO = $GPOHash[ $ReferenceGPO ]
        If ( $NewGPO ) { $TargetGPO = $GPOHash[ $NewGPO ] }

        $Domain    = Get-ADDomain -Identity $TargetDomain
        $DomainDN  = $Domain.DistinguishedName
        $DomainDNS = $Domain.DNSRoot
        $PDC       = $Domain.PDCEmulator

        # default parameters for GP Cmdlets
        $GPParms = @{
            Server      = $PDC
            Domain      = $DomainDNS
        }

    }

    Process {

        Write-Progress -Activity 'Enumerating organizational units.' -Id 0 -PercentComplete 0

        $LDAPSearchBase = $DomainDN
        If ( $SearchBase ) { $LDAPSearchBase = "$SearchBase,$DomainDN" }
        If ( $RegexEscape ) { $OUFilter = [Regex]::Escape( $OUFilter ) }

        $LDAPParms = @{
            LDAPFilter = "(GPLink=*$($SourceGPO.Id.Guid)*)"
            Properties = 'GPLink'
            SearchBase = $LDAPSearchBase
            SearchScope = 'SubTree'
            Server = $PDC
        }

        $OrganizationalUnits = Where-Object -InputObject ( Get-ADOrganizationalUnit @LDAPParms ) -FilterScript { $_.DistinguishedName -match $OUFilter }

        $Counter = 0
        Foreach ( $OU in $OrganizationalUnits ) {

            $Counter += 1
            $ActivityParms = @{
                Activity = 'Processing organizational units ({0}/{1})' -f $Counter, $OrganizationalUnits.Count
                Status = $OU.DistinguishedName
                PercentComplete = $Counter * 100 / $OrganizationalUnits.Count
            }
            Write-Progress @ActivityParms -Id 0 

            If ( -not $RemoveLink ) {

                # First, get the current GPO links as a hashtable with the GPO id as key and the link properties as a custom object
                $GPLinks = Resolve-GPLinksFromHashtable -OU $OU -GuidHash $GuidHash

                $UpdateLink = $False

                # Need current LinkOrder of both GPOs if we want to link before/after or replace.
                $SourceGPOLink = $GPLinks[ $SourceGPO.Id.Guid ]
                $SourceGPOLinkOrder = $SourceGPOLink.Order
                $TargetGPOLink = $GPLinks[ $TargetGPO.Id.Guid ] # might be empty if not already linked
                $TargetGPOLinkOrder = $TargetGPOLink.Order 
                
                If ( $ReplaceLink -Or $RelativeLinkPos ) {

                    # link order of new gpo defaults to same as old gpo (will be inserted above)
                    $TargetGPONewLinkOrder = $SourceGPOLinkOrder

                    # Need to fix LinkOrder if NewGPO is already linked above ReferenceGPO. Removing moves ReferenceGPO one position to top...
                    If ( $TargetGPOLinkOrder -and $TargetGPOLinkOrder -lt $SourceGPOLinkOrder ) { $TargetGPONewLinkOrder-- }

                    # If NewGPO should be linked below ReferenceGPO, add 1 position.
                    If ( $RelativeLinkPos -match 'after' ) { $TargetGPONewLinkOrder++ }

                } ElseIf ( $LinkOrder ) {

                    # Static link order, make sure $LinkOrder does not exceed the number of currently linked GPOs...
                    $TargetGPONewLinkOrder = [Math]::Min( $LinkOrder, $GPLinks.Count + 1 )

                } Else {

                    If ( $TargetGPOLinkOrder ) {

                        # Already linked, keep current link order
                        $TargetGPONewLinkOrder = $TargetGPOLinkOrder

                    } Else {

                        # Not already linked and no order specified through parameters? Then append at the bottom.
                        $TargetGPONewLinkOrder = $GPLinks.Count + 1

                    }

                }

                # verify if the existing link must be updated
                If ( 
                        ( $TargetGPOLinkOrder -ne $TargetGPONewLinkOrder ) -or
                        ( $LinkEnabled -ne [Microsoft.GroupPolicy.EnableLink]::Unspecified -and $TargetGPOLink.Enabled -ne $LinkEnabled ) -or
                        ( $Enforced -ne [Microsoft.GroupPolicy.EnforceLink]::Unspecified -and $TargetGPOLink.Enforced -ne $Enforced )
                    ) {
                    $UpdateLink = $True
                }

                $LinkParms = @{
                    Guid = $TargetGPO.Id
                    Target = $OU.DistinguishedName
                    Order = $TargetGPONewLinkOrder
                    LinkEnabled = $LinkEnabled
                    Enforced = $Enforced
                    ErrorAction = 'Stop'
                }

                If ( $TargetGPOLinkOrder ) {

                    # NewGPO is already linked, so simply update Link if required
                    If ( $UpdateLink ) { Set-GPLink @LinkParms @GPParms }

                } Else {

                    # NewGPO is currently not linked - create new link
                    New-GPLink @LinkParms @GPParms

                }
            }

            If ( $ReplaceLink -Or $RemoveLink ) { Remove-GPLink -Guid $SourceGPO.Id -Target $OU.DistinguishedName @GPParms -ErrorAction 'Stop' }

        }

    }

    End {

        Write-Progress -Activity 'Processing organizational units' -Id 0 -PercentComplete 100 -Completed

    }
    
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
        $AttribNames = ( Where-Object -InputObject ( Get-Member $ParamAttrib -MemberType Property ) -FilterScript { $_.Definition -match '{.*set;.*}$' } ).Name
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

Function Resolve-GPLinksFromHashtable{
    # based on the work of Thomas Bouchereau
    # https://gallery.technet.microsoft.com/scriptcenter/Get-GPlink-Function-V13-b31253b4
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][Microsoft.ActiveDirectory.Management.ADOrganizationalUnit] $OU,
        [Parameter(Mandatory)][System.Collections.HashTable] $GuidHash
    )

    $o = 0

    # GPLink has a weird format - [GPO-DN;LinkFlags][GPO-DN;LinkFlags][...]
    # remove leading [ and trailing ], then split on ][
    $GPLinks = $OU.GPLink.Substring( 1, $OU.GPLink.Length - 2 ) -split '\]\['
    $Target = $OU.DistinguishedName

    $Return = @{}

    # we need to do reverse to get the proper link order - last GPO in GPLink is link order 1
    for ( $s = $GPLinks.Count - 1; $s -ge 0; $s-- ) {
        $o++
        $Order = $o

        $null = $GPLinks[$s] -match '{(?<GpoGuid>.*)}.*;(?<Flags>\d)$'
        $GpoGuid = $Matches.GpoGuid
        $Flags = $Matches.Flags

        # Retrieve current GPO from GuidHash - much faster than using Where...
		$MyGpo = $GuidHash[ $GPOGuid ]

		If ( $MyGpo ) {
			$GpoName = $MyGPO.DisplayName
			$GpoDomain = $MyGPO.DomainName
		} Else {
			$GpoName = 'Orphaned GPLink'
            $GpoDomain = '<undefined>'
    	}

        # The GroupPolicy Link enums have the following values:
        # 0 - unspecified (impossible for existing links)
        # 1 - No  (link is disabled or not enforced )
        # 2 - Yes (link is enabled or enforced)

        [Microsoft.GroupPolicy.EnableLink]$Enabled   = ( ( $Flags -band 1 ) -eq 0 ) + 1     # $Flags bit 0 unset means "Link enabled"
        [Microsoft.GroupPolicy.EnforceLink]$Enforced = ( ( $Flags -band 2 ) -eq 2 ) + 1     # $Flags bit 1 set means "Link enforced"

        # Create an object for each GPOs, its link status and order
        $Return[ $GpoGuid ] = [PSCustomObject]@{
                GPOID = $GpoGuid
                DisplayName = $GpoName
                Domain = $GpoDomain
                Target = $Target
                Enabled = $Enabled
                Enforced = $Enforced
                Order = $Order
        }
    }
    Return $Return
}
