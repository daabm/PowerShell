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
        [ValidateScript( { Get-ADDomain $_ } )]
        [String] $TargetDomain = $env:USERDNSDOMAIN,
        
        [Parameter()]
        [ValidateScript( { $_ -match '^(?:(?<path>(?:(?:OU)=[^,]+,?)+),)?$' } )]
        [String] $SearchBase,
        
        [Parameter()]
        [String] $OUFilter,

        [Parameter()]
        [Switch] $RegexEscape,
        
        [Parameter( ParameterSetName = 'Add'     )]
        [ValidateSet('before','after')]
        [String] $RelativeLinkPos,
        
        [Parameter( ParameterSetName = 'Replace')]
        [Switch] $ReplaceLink,
        
        [Parameter( ParameterSetName = 'AddWithOrder'  )]
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

        $GPOHash = New-Object System.Collections.Hashtable
        $GuidHash = New-Object System.Collections.Hashtable
        $GPOs = Get-GPO -All -Domain $TargetDomain | Sort-Object -Property ModificationTime
        Foreach ( $GPO in $GPOs ) {
            $GPOHash[ $GPO.DisplayName ] = $GPO
            $GuidHash[ $GPO.Id.Guid ] = $GPO
        }

        $ParamOptions = @(
            @{
                Name = 'ReferenceGPO'
                ValidateSetOptions = $GPOHash.Keys
                ParameterAttributes = @(
                    @{
                        Mandatory = $True
                    }
                )
            },
            @{
                Name = 'NewGPO'
                ValidateSetOptions = $GPOHash.Keys
                ParameterAttributes = @(
                    @{
                        Mandatory = $True
                        ParameterSetName = 'Add'
                    },
                    @{
                        Mandatory = $True
                        ParameterSetName = 'Replace'
                    },
                    @{
                        Mandatory = $True
                        ParameterSetName = 'AddWithOrder'
                    }
                )
            }
        )
    
        # Create the dictionary
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        Foreach( $Param in $ParamOptions ) {
            $RuntimeParameter = New-DynamicParameter @Param
            $RuntimeParameterDictionary.Add( $Param.Name, $RuntimeParameter )
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
            LDAPFilter = "(&(objectClass=organizationalUnit)(GPLink=*$($SourceGPO.Id.Guid)*))"
            Properties = 'GPLink'
            SearchBase = $LDAPSearchBase
            SearchScope = 'SubTree'
        }

        $OrganizationalUnits = Get-ADObject @LDAPParms | Where-Object { $_.DistinguishedName -match $OUFilter }

        $Counter = 0
        Foreach ( $OU in $OrganizationalUnits ) {

            $Counter += 1
            $ActivityParms = @{
                Activity = 'Processing organizational units ({0}/{1})' -f $Counter, $OrganizationalUnits.Count
                Status = $OU.DistinguishedName
                PercentComplete = $Counter * 100 / $OrganizationalUnits.Count
            }
            Write-Progress @ActivityParms -Id 0 

            # First, get the current GPO links as a hashtable with the GPO id as key and the link properties as a custom object
            $GPLinks = Resolve-GPLinksFromHashtable -OU $OU -GpoHash $GuidHash

            $OldOrder = ( $GPLinks[ $TargetGPO.Id.Guid ] ).Order

            # Need LinkOrder of ReferenceGPO if we want to replace the current link or link before/after.
            If ( $ReplaceLink -Or $RelativeLinkPos ) {

                $LinkOrder = ( $GPLinks[ $SourceGPO.Id.Guid ] ).Order

                # Need to fix LinkOrder if NewGPO is already linked above ReferenceGPO...
                If ( $OldOrder -and $OldOrder -lt $LinkOrder ) { $LinkOrder -= 1 }

                If ( $RelativeLinkPos -match 'after' ) {
                    $LinkOrder += 1
                }

            } ElseIf ( -not $LinkOrder ) {

                # If a LinkOrder is not already specified, append at the bottom
                $LinkOrder = $GPLinks.Count + 1

            }


            If ( $NewGPO ) {

                $LinkParms = @{
                    Guid = $TargetGPO.Id
                    Target = $OU.DistinguishedName
                    Order = $LinkOrder
                    LinkEnabled = $LinkEnabled
                    Enforced = $Enforced
                }

                If ( $OldOrder ) {

                    # NewGPO is already linked, so simply update LinkOrder
                    Set-GPLink @LinkParms @GPParms

                } Else {

                    # NewGPO is currently not linked - create new link
                    New-GPLink @LinkParms @GPParms

                }
            }

            If ( $ReplaceLink -Or $RemoveLink ) { Remove-GPLink -Guid $SourceGPO.Id -Target $OU.DistinguishedName @GPParms }

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

        [ValidateNotNullOrEmpty()][Parameter()]
        [Array] $ValidateSetOptions,

        [Parameter()][ValidateNotNullOrEmpty()]
        [Switch] $ValidateNotNullOrEmpty,
		
        [Parameter()][ValidateNotNullOrEmpty()][ValidateCount( 2, 2 )]
        [Int[]] $ValidateRange,
        
        [Parameter()]
        [Array] $ParameterAttributes
    )
	
    $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

    Foreach ( $ParameterAttribute in $ParameterAttributes ) {
        $ParamAttrib = New-Object System.Management.Automation.ParameterAttribute

        $ParamAttrib.Mandatory = $ParameterAttribute.Mandatory
        If ( $ParameterAttribute.Position ) { $ParamAttrib.Position = $ParameterAttribute.Position }
        If ( $ParameterAttribute.ParameterSetName ) { $ParamAttrib.ParameterSetName = $ParameterAttribute.ParameterSetName }
        $ParamAttrib.ValueFromPipeline = $ParameterAttribute.ValueFromPipeline
        $ParamAttrib.ValueFromPipelineByPropertyName = $ParameterAttribute.ValueFromPipelineByPropertyName

        $AttribColl.Add( $ParamAttrib )
    }

    If ( $PSBoundParameters.ContainsKey( 'ValidateSetOptions' )) {
        $AttribColl.Add(( New-Object System.Management.Automation.ValidateSetAttribute( $ValidateSetOptions ) ))
    }
    If ( $PSBoundParameters.ContainsKey( 'ValidateRange' )) {
        $AttribColl.Add(( New-Object System.Management.Automation.ValidateRangeAttribute( $ValidateRange )))
    }
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

    # remove leading [ and trailing ], then split on ][
    $GPLinks = $OU.GPLink.Substring( 1, $OU.GPLink.Length - 2 ) -split '\]\['
    $Target = $OU.DistinguishedName

    $Return = New-Object System.Collections.Hashtable

    #we need to do reverse to get the proper link order
    for ( $s = $GPLinks.Count - 1; $s -gt -1; $s-- ) {
        $o++
        $Order = $o

        $GPLinks[$s] -match '{(?<GpoGuid>.*)}.*;(?<Flags>\d)$' | Out-Null
        $GpoGuid = $Matches.GpoGuid
        $Flags = $Matches.Flags

		$MyGpo = $GuidHash[ $GPOGuid ]

		If ( $MyGpo ) {
			$GpoName = $MyGPO.DisplayName
			$GpoDomain = $MyGPO.DomainName
		} Else {
			$GpoName = 'Orphaned GPLink'
            $GpoDomain = '<undefined>'
    	}
    				
        # Create an object for each GPOs, its links status and link order
        $Return[ $GpoGuid ] = [PSCustomObject]@{
                GPOID = $GpoGuid
                DisplayName = $GpoName
                Domain = $GpoDomain
                Target = $Target
                Enabled = ( $Flags -band 1 ) -eq 0   # $Flags bit 0 set means "link disabled", comparing to 0 to get $true/$false
                Enforced = ( $Flags -band 2 ) -ne 0  # $Flags bit 1 set means "link enforced", comparing to 0 to get $true/$false
                Order = $Order
        }
    }
    Return $Return
}
