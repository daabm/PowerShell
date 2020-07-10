Function Copy-LinkedGPOs {
    <#
    .SYNOPSIS
    Copies the GPLink attribute from a specified source OU to a target OU in the same domain. Optionally appends or prepends to existing GPO links.
    Requires $CopyMode and @ServerConnection from caller context.

    .PARAMETER SourceOU
    Active Directory Organizational Unit to copy the GPLink attribute from.

    .PARAMETER TargetOU
    Active Directory Organizational Unit to copy the GPLink attribute to.
    #>

    [ CmdletBinding( SupportsShouldProcess = $True ) ]
    Param (
        [ Parameter( Position = 1, Mandatory = $True ) ]
        [ Microsoft.ActiveDirectory.Management.ADOrganizationalUnit ] $deSourceOU,
        [ Parameter( Position = 2, Mandatory = $True ) ]
        [ Microsoft.ActiveDirectory.Management.ADOrganizationalUnit ] $deTargetOU
    )

    Write-Verbose ( 'Retrieving GPLink for "{0}"...' -f $deSourceOU.DistinguishedName )

    # The GPLink attribute contains all linked GPOs from bottom (highest number in GPMC) to top (number 1 in GPMC)
    # First entry is last GPO in GPMC, last entry is GPO #1 in GPMC :-)

    $SourceLinks = ( Get-ADOrganizationalUnit -Identity $deSourceOU -Properties GPLink @ServerConnection ).GPLink

    If ( $SourceLinks ) {

        If ( $ResolveGPONames ) { 
            ForEach ( $Link in $SourceLinks.Trim( ']' ).Split( ']' ) ) {
                $Link -match '.*{(.*)}.*' | Out-Null
                Write-Verbose ( 'Linked GPO {0}: "{1}"' -f $Matches[1], ( Get-GPO -Guid $Matches[1] ).DisplayName )
            }
        } Else { Write-Verbose $SourceLinks }

        $TargetLinks = ( Get-ADOrganizationalUnit -Identity $deTargetOU -Properties GPLink @ServerConnection ).GPLink

        switch ( $CopyMode ) {
            'Append' { $GPLinks = $SourceLinks + $TargetLinks }
            'Prepend' { $GPLinks = $TargetLinks + $SourceLinks }
            default { $GPLinks = $SourceLinks }
        }

        # If GPLink is already present on the target, -Replace is required instead of -Add

        If( $TargetLinks ) {
            Write-Verbose ( 'Replacing GPLink at target "{0}"...' -f $deTargetOU )
            Set-ADOrganizationalUnit -Identity $deTargetOU -Replace @{ GPLink=$GPLinks } @ServerConnection
        } Else {
            Write-Verbose ( 'Adding GPLink at target "{0}"...' -f $TargetOU )
            Set-ADOrganizationalUnit -Identity $deTargetOU -Add @{ GPLink=$GPLinks } @ServerConnection
        }

    } Else {

        Write-Verbose ( 'Source {0} has no linked GPOs.' -f $deSourceOU )
        If ( $CopyMode -EQ 'Replace' ) {

            # If the source OU has no GPOs linked and we are in replace mode,
            # the target OU GPLink needs to be cleared.
            Set-ADOrganizationalUnit -Identity $deTargetOU -Clear 'GPLink' @ServerConnection
        }
    }

}


Function Process-OU {
    <#
    .SYNOPSIS
    Processes a single OU target and source, and optionally calls itself recursively to process childs. Enumerates child OUs in the source OU and searches for a matching child (by name) in the target OU.
    Requires $CopyMode, $Recurse and @ServerConnection from caller context.
    
    .PARAMETER deSourceOU
    Active Directory Organizational Unit to copy GPO Links from and to start enumerating childs.
    
    .PARAMETER deTargetOU
    Active Directory Organizational Unit to copy GPO Links to and to search for matching childs.
    #>

    [ CmdletBinding( SupportsShouldProcess = $True ) ]
    Param (
        [ Parameter( Position = 1, Mandatory = $True ) ]
        [ Microsoft.ActiveDirectory.Management.ADOrganizationalUnit ] $deSourceOU,
        [ Parameter( Position = 2, Mandatory = $True ) ]
        [ Microsoft.ActiveDirectory.Management.ADOrganizationalUnit ] $deTargetOU
    )

    If ( $CopyMode -NE 'None' ) { Copy-LinkedGPOs -deSourceOU $deSourceOU -deTargetOU $deTargetOU }

    If ( $Recurse ) {
        Write-Verbose ( 'Enumerating source childs in "{0}"' -f $deSourceOU )
        Foreach ( $deSourceChildOU in ( Get-ADOrganizationalUnit -SearchBase $deSourceOU -SearchScope OneLevel -Filter * @ServerConnection | Select-Object -Property * ) ) {
            Write-Verbose ( 'Processing source child "{0}"...' -f $deSourceChildOU.Name )
            $deTargetChildOU = Get-ADOrganizationalUnit -SearchBase $deTargetOU -SearchScope OneLevel -Filter { Name -EQ $deSourceChildOU.Name } @ServerConnection
            If ( $deTargetChildOU ) {
                Write-Verbose ( 'Found matching target child "{0}"' -f $deTargetChildOU )
            } Else {
                Write-Verbose ( 'No matching target child found for "{0}".' -f $deSourceChildOU.Name )
                If ( $CreateMissingChilds ) {
                    Write-Verbose ( 'Creating missing target child "OU={0},{1}"...' -f $deSourceChildOU.Name, $deTargetOU )
                    $deTargetChildOU = New-ADOrganizationalUnit -Name $deSourceChildOU.Name -Path $deTargetOU -ProtectedFromAccidentalDeletion $ProtectedFromAccidentalDeletion -PassThru -Verbose @ServerConnection
                }
            }
            If ( $deTargetChildOU ) { Process-OU -deSourceOU $deSourceChildOU -deTargetOU $deTargetChildOU }
        }
        Write-Verbose ( 'Finished processing "{0}".' -f $deSourceOU )
    }
}


Function Copy-GPOLinks {
    <#
    .SYNOPSIS
    Copies the GPLink attribute from a specified source OU to a target OU in the same domain. Optionally appends or prepends to existing GPO links and recurses through child OUs.
    
    .DESCRIPTION
    When staging environments in a single AD, it is common to create a new identical OU structure for testing purposes. This structure should match the original one, including all child OUs and their linked GPOs. Copy-GPOLinks copies all linked GPOs from a source OU to a target OU in a given domain. Optionally, it recurses through child OUs and copies their GPOs, too. It also can create missing target child OUs automatically.

    Note: By default, Copy-GPOLinks will not produce any screen output. If you want on-screen information, run it -verbose. If you need logging, intercept output streams or pipe to a file.

    .PARAMETER SourceOU
    Distinguished name of the OU to copy the GPLink attribute from. Both SourceOU and TargetOU must belong to the same domain.
    
    .PARAMETER TargetOU
    Distinguished name of the OU to copy the GPLink attribute to. Regardless of the CreateMissingChild switch, this OU must already exist or the cmdlet will fail.
    
    .PARAMETER TargetDomain
    The Domain where TargetDomain can be found. Can be a different domain or forest. Defaults to the callers domain.

    .PARAMETER Credential
    If the target domain requires different credentials, a credential object can be passed in.

    .PARAMETER CopyMode
    The copy mode for GPLink: Replace (overwrite), append or prepend to existing, or None. If you append or prepend and you run the command multiple times, you will create multiple links of the same set of GPOs. Within GPMC this cannot be done (GPMC has builtin logic that prevents this), but technically it is possible and valid. The 'None' value is useful when combined with -CreateMissingChilds and -Whatif, see the samples section for more information.

    .PARAMETER Recurse
    Process child OUs, too. The target child OU names must match the names of the respective source child OUs. Child OUs that are found in source, but not in target, are ignored and will not raise an error.

    .PARAMETER CreateMissingChilds
    If the recurse switch is specified and for a given source child OU no matching target child OU is found, the target child OU is created automatically. ACLs are not copied.

    .PARAMETER ProtectedFromAccidentalDeletion
    If missing child OUs are created, this parameter specifies whether they should be protected from accidental deletion or not. The default value is $True.

    .PARAMETER ResolveGPONames
    By default Copy-GPOLinks operates on the GPLink attribute. This attribute only contains GPO GUIDs, so if you want to know what was copied, you'll need to look either in GPMC or resolve those GUIDs. If you specify this switch, the source GPO names will be resolved and listed in the verbose output.

    .EXAMPLE
    Copy-GPOLinks -SourceOU 'OU=Corp,DC=Corp,DC=Contoso,DC=Com' -TargetOU 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com'
    This command copies all linked GPOs from OU=Corp to OU=Corp-Test.

    .EXAMPLE
    $VerbosePreference = 'Continue'
    $SourceOU = 'OU=Corp,DC=Corp,DC=Contoso,DC=Com'
    $TargetOU = 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com'
    Copy-GPOLinks -SourceOU $SourceOU -TargetOU $TargetOU -CopyMode Replace -Recurse -CreateMissingChilds -Whatif

    This command recursively travels down OU=Corp. It would copy all GPOs linked, and it would create all missing OUs. Due to -WhatIf, for missing OUs it will write out that it would create them. But it will not write out that it would copy their GPOs, because copying is a different step. Since the target OU was not really created, the copy function will exit silently.

    .EXAMPLE
    Copy-GPOLinks -SourceOU 'OU=Corp,DC=Corp,DC=Contoso,DC=Com' -TargetOU 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com' -CreateMissingChilds -Recurse -CopyMode None
    This Command works almost the same as above. But due to not trying to copy the GPLink attribute, it will only create some missing OUs. This can then be used with the next example.

    .EXAMPLE
    Copy-GPOLinks -SourceOU 'OU=Corp,DC=Corp,DC=Contoso,DC=Com' -TargetOU 'OU=Corp-Test,DC=Corp,DC=Contoso,DC=Com' -Recurse -WhatIf
    This again works almost the same as example #2 above. But if you first ran example #3, now all OUs are present and -WhatIf will be able to fully show what GPLinks it would copy.
    #>

    [ CmdletBinding( SupportsShouldProcess = $True ) ]
    Param (
        [ Parameter( Position = 1, Mandatory = $True ) ][ String ] $SourceOU,
        [ Parameter( Position = 2, Mandatory = $True ) ][ String ] $TargetOU,
        [ ValidateSet ( 'Replace','Append','Prepend','None' ) ][ String ] $CopyMode = 'Replace',
        [ Switch ] $Recurse,
        [ Switch ] $CreateMissingChilds,
        [ Bool ] $ProtectedFromAccidentalDeletion = $True,
        [ Switch ] $ResolveGPONames,
        [ String ] $TargetDomain = ( Get-ADDomain ).DNSRoot,
        [ PsCredential ] $Credential = $null

    )

    # Splatting the AD cmdlets to make $Credential a truely optional parameter
    # Get-ADDomain requires -Identity whereas all other AD cmdlets require -Server

    $IdentityConnection = @{ Identity = $TargetDomain }
    $ServerConnection = @{ Identity = $TargetDomain }
    
    If ( $Credential ) {
        $IdentityConnection.Credential = $Credential
        $ServerConnection.Credential = $Credential
    }
    
    $ServerConnection.Server = $( Get-ADDomain @IdentityConnection ).PDCEmulator

    Try {
        $deSourceOU = Get-ADOrganizationalUnit -Identity $SourceOU @ServerConnection
        $deTargetOU = Get-ADOrganizationalUnit -Identity $TargetOU @ServerConnection
    }

    Catch [ Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException ] {
        Write-Warning ( 'A directory entry could not be found. Make sure that the following OU exists and you have access to it:' )
        Write-Warning ( '{0}' -f $_.CategoryInfo.TargetName )
        Return $_.Exception.HResult
    }
      
    Process-OU -deSourceOU $deSourceOU -deTargetOU $deTargetOU

}

