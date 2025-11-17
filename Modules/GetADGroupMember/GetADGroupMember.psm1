<#
.SYNOPSIS
ActiveDirectory\Get-ADGroupMember: Rekursive Auflösung und Berücksichtigung von Foreign Security Principals (FSP) und Shadow principals
ActiveDirectory\Get-ADPrincipalGroupMembership: Rekursive Auflösung und Berücksichtigung von Foreign Security Principals (FSP) und Shadow principals

.DESCRIPTION
Mit -recursive werden Mitgliedschaften (Member/MemberOf) in der aktuellen Domäne ermittelt. Mit -IncludeTrustingDomains werden auch die Namen der FSPs aufgelöst und deren Mitglieder zurückgegeben (beides können die "originalen" Cmdlets nicht). Zusätzlich werden alle Shadow Principals ermittelt und ebenfalls aufgelöst.
Rückgabe sind benutzerdefinierte [ADCustomObject] Objekte. Das ist erforderlich, da unterschiedliche Objektklassen gefunden werden können (Group, ForeignSecurityPrincipal, ShadowPrincipal, Service Accounts, User, Computer etc.). Damit wäre keine einhetliche Darstellung der Ergebnisse möglich.

.EXAMPLE
Get-ADGroup LM-RZG-$env:UserOU-FIS-ADMIN -Server ddfp | Get-ADGroupMember -Recursive -IncludeTrustingDomains
Ermittelt alle Mitglieder der angegebenen Gruppe in DDFP inkl. rekursive Mitgliedschaften aus anderen Domänen (IDFP)

.EXAMPLE
Get-ADUser $env:username -Server idfp | Get-ADPrincipalGroupMembership -Recursive
Ermittelt alle Gruppenmitgliedschaften des angemeldeten Benutzers in seiner Domäne. Gruppenverschachtelungen innerhalb dieser Domäne werden dabei aufgelöst. Mitgliedschaften in FSPs in anderen Domains werden nicht aufgelöst.

.EXAMPLE
Get-ADUser $env:username -Server idfp | Get-ADPrincipalGroupMembership -Recursive -IncludeTrustingDomains
Ermittelt alle Gruppenmitgliedschaften des angemeldeten Benutzers in seiner Domäne und in allen vertrauenden Domänen. Dabei werden auch Mitgliedschaften über Shadow Principals ausgewertet.

.NOTES
Hängt man an den Aufruf jeweils
| Out-Gridview
an, wird das Ergebnis in einer grafischen Tabelle ausgegeben. Mit
| Export-CSV <PfadZurDatei.csv> -Delimiter ';' -NoTypeInformation
erhält man eine CSV-Datei, die in Excel direkt geöffnet werden kann.
#>

using namespace System.Management
using namespace System.Management.Automation
using namespace Microsoft.ActiveDirectory.Management
using namespace System.Security
using namespace System.Security.Authentication
using namespace System.Security.Principal

$GetADObjectParams = @{
    Properties = @('objectClass','objectGUID','objectSid','sAMAccountName')
}

$GetADShadowParams = @{
    Properties = @('objectClass','objectGUID','msDS-ShadowPrincipalSid')
}


# Custom class to join [ADGroup],[ADPrincipal] and [ADObject].
# ADGroup has SID where ADPrincipal has objectSid, and ADObject has nothing if you don't request it explicitly with -Properties.

# Requires the ActiveDirectory module to be already loaded. Happens automatically upon module import.
# If you want to dot-source the .psm1, make sure to Import-Module ActiveDirectory first.

class ADCustomObject {
    [String] $Domain
    [String] $Name
    [Nullable[ADGroupCategory]] $GroupCategory
    [Nullable[ADGroupScope]] $GroupScope
    [String] $ObjectClass
    [String] $SamAccountName
    [Nullable[Guid]] $ObjectGuid
    [String] $TargetAccount
    hidden [String] $_DistinguishedName
    hidden [SecurityIdentifier] $_ObjectSid

    ADCustomObject(){
        Write-Debug 'Creating object from ''$null'''
        $this.Initialize()
    }

    ADCustomObject([String] $DistinguishedName){
        Write-Debug "Creating object from string '$DistinguishedName'"
        $this.Initialize()
        $Object = Get-ADGroupOrObject $DistinguishedName -Server $(($DistinguishedName -split ',DC=',2)[1].Replace(',DC=','.').ToUpper()) -Properties *
        $this.Update( $Object )
    }

    ADCustomObject([ADObject] $Object){
        Write-Debug "Creating object from ADObject '$($Object)'"
        $this.Initialize()
        $this.Update( $Object )
    }

    # initialize the instance with additional properties
    hidden Initialize(){
        # set up getter and setter for distinguishedName and objectSid
        # this allows to set/change them and update all properties
        $GetObjectSid = {
            [OutputType([string])]
            param()
            return $this._ObjectSid
        }
        $SetObjectSid = {
            param([SecurityIdentifier] $value)
            Write-Debug "Updating object from SecurityIdentifier $value"
            $NewObject = Get-ADGroupOrObject $value.ToString() -Properties *
            $this.Update( $NewObject )
        }
        $this | Add-Member -MemberType ScriptProperty -Name objectSid -Value $GetObjectSid -SecondValue $SetObjectSid

        $GetDistinguishedName = {
            [OutputType([string])]
            param()
            return $this._DistinguishedName
        }
        $SetDistinguishedName = {
            param([String] $value)
            Write-Debug "Updating object from DistinguishedName $value"
            $Server = ($value -split ',DC=',2)[1].Replace(',DC=','.').ToUpper()
            $NewObject = Get-ADGroupOrObject $value.ToString() -Server $Server -Properties *
            $this.Update( $NewObject )
        }
        $this | Add-Member -MemberType ScriptProperty -Name DistinguishedName -Value $GetDistinguishedName -SecondValue $SetDistinguishedName

        ##Set up the default display set 
        $defaultDisplaySet = 'Domain','Name','TargetAccount','GroupCategory','GroupScope','ObjectClass','ObjectSid'
        $defaultDisplayPropertySet = [PSPropertySet]::new('DefaultDisplayPropertySet',[String[]] $defaultDisplaySet)
        $PSStandardMembers = [PSMemberInfo[]]@($defaultDisplayPropertySet)
        $this | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers
    }

    hidden Update([ADObject] $Object) {
        Write-Debug "Setting properties from $($Object.GetType().Name) $($Object)"
        $this.Domain = ($Object.DistinguishedName -split ',DC=',2)[1].Replace(',DC=','.').ToUpper()
        $this._DistinguishedName = $Object.DistinguishedName
        If ([string]::IsNullOrEmpty($Object.GroupCategory)) {$this.GroupCategory = $null} Else {$this.GroupCategory = $Object.GroupCategory}
        If ([string]::IsNullOrEmpty($Object.GroupScope)) {$this.GroupScope = $null} Else {$this.GroupScope = $Object.GroupScope}
        $this.Name = $Object.Name
        $this.SamAccountName = $Object.SamAccountName
        $this.ObjectClass = $Object.ObjectClass
        $this.ObjectGuid = $Object.ObjectGuid
        If (-not [string]::IsNullOrEmpty($Object.SID)){
            $this._ObjectSid = $Object.SID
        } ElseIf (-not [string]::IsNullOrEmpty($Object.ObjectSid)){
            $this._ObjectSid = $Object.ObjectSid
        } ElseIf (-not [string]::IsNullOrEmpty($Object.'msDS-ShadowPrincipalSid')){
            $this._ObjectSid = $Object.'msDS-ShadowPrincipalSid'
        } Else {
            $this._ObjectSid = $null
        }
    }

    [String] ToString() {
        Return $this.DistinguishedName
    }
}


<#
.SYNOPSIS
    Extends Write-Verbose/Write-Warning/Write-Debug with caller information
#>
Function Write-Verbose {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [String] $Message
    )
    Process {
        $Prefix = '[GLOBAL]:'
        Try {
            $CallStack = Get-PSCallStack
            if ($CallStack.Count -gt 1) {
                $Caller = $CallStack[1]
                $Prefix = "$($Caller.FunctionName)#$($Caller.ScriptLineNumber):"
                if ($Caller.ScriptName) {
                    $Prefix = "$(Split-Path $Caller.ScriptName -Leaf)\" + $Prefix
                }
            }
        } Catch {
            # leave $Prefix as [GLOBAL]: on error
        }
        Microsoft.PowerShell.Utility\Write-Verbose "$Prefix $Message"
    }
}

Function Write-Warning {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [String] $Message
    )
    Process {
        $Prefix = '[GLOBAL]:'
        Try {
            $CallStack = Get-PSCallStack
            if ($CallStack.Count -gt 1) {
                $Caller = $CallStack[1]
                $Prefix = "$($Caller.FunctionName)#$($Caller.ScriptLineNumber):"
                if ($Caller.ScriptName) {
                    $Prefix = "$(Split-Path $Caller.ScriptName -Leaf)\" + $Prefix
                }
            }
        } Catch {
            # leave $Prefix as [GLOBAL]: on error
        }
        Microsoft.PowerShell.Utility\Write-Warning "$Prefix $Message"
    }
}

Function Write-Debug {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [String] $Message
    )
    Begin {
        # trickery with debug/confirm - when -debug is set, DebugPreference is set to Inquire which triggers confirmations for each Write-Debug
        # https://github.com/PowerShell/PowerShell/issues/16158

        If ($DebugPreference -ne 'SilentlyContinue') {
            $DebugPreference = [ActionPreference]::Continue
        }
    }

    Process {
        $Prefix = '[GLOBAL]:'
        Try {
            $CallStack = Get-PSCallStack
            if ($CallStack.Count -gt 1) {
                $Caller = $CallStack[1]
                $Prefix = "$($Caller.FunctionName)#$($Caller.ScriptLineNumber):"
                if ($Caller.ScriptName) {
                    $Prefix = "$(Split-Path $Caller.ScriptName -Leaf)\" + $Prefix
                }
            }
        } Catch {
            # leave $Prefix as [GLOBAL]: on error
        }
        Microsoft.PowerShell.Utility\Write-Debug "$Prefix $Message"
    }
}

<#
.SYNOPSIS
    Helper function to enumerate trusting/trusted domains and sids. Required for cross forest membership resolution
.DESCRIPTION
    Returns a hashtable of Domain SIDs and the related Domain object
.PARAMETER Server
    The name of a server or domain to retrieve trust information from.
.PARAMETER TrustDirection
    The direction of trusts to enumerate - not BiDi, not Inbound or not Outbound
.PARAMETER IgnoreTrustErrors
    Don't stop if a trust, forest or domain fails, even if -ErrorAction Stop is specified.
#>
function Get-DomainSIDs {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String] $Server = $env:USERDNSDOMAIN,
        [ADTrustDirection] $ExcludedTrustDirection = [ADTrustDirection]::Disabled,
        [Switch] $IgnoreTrustErrors
    )
    begin {
        $TrustErrorAction = $ErrorActionPreference
        If ($IgnoreTrustErrors -and $ErrorActionPreference -notin @('Ignore','Continue','SilentlyContinue')) {
            $TrustErrorAction = 'Continue'
        }
    }

    process {
        Write-Verbose "Resolving forest and trusts for '$Server'"
        $RootDomain = (Get-ADForest -Server $Server -ErrorAction $TrustErrorAction).RootDomain
        $Trusts = @((Get-ADTrust -Filter "(Direction -ne '$ExcludedTrustDirection' -and Direction -ne 'Disabled')" -Server $Server -ErrorAction $TrustErrorAction))
        If ($Server -notmatch $RootDomain.Split('.')[0]) {
            # our domain is not the forest root domain - we need not only trusts for our own domain, but also for the forest
            $Trusts += @((Get-ADTrust -Filter "(Direction -ne '$ExcludedTrustDirection' -and Direction -ne 'Disabled')" -Server $RootDomain -ErrorAction $TrustErrorAction))
        }

        # filter out orphaned trusts that do no longer work, but might still exist...
        $Trusts = $Trusts | Select-Object -Unique | Sort-Object -Property Name 

        $Forests = Foreach ($Trust in $Trusts) {
            Write-Verbose "Retrieving forest for '$Trust'"
            Try {
                Get-ADForest $Trust.Name
            } Catch [ADIdentityNotFoundException] {
                # ignore non-existing forests...
                Write-Warning $_.Exception.Message
            } Catch [AuthenticationException] {
                # ignore broken forest trusts...
                Write-Warning $_.Exception.Message
            } Catch {
                # error - we don't know what went wrong if we reach here...
                Write-Error $_ -ErrorAction $TrustErrorAction
            }
        }

        $Domains = Foreach ( $Forest in $Forests | Sort-Object -Property Name ) {
            Foreach ( $Domain in $Forest.Domains | Sort-Object ) {
                Write-Verbose "Retrieving domain '$Domain' in forest '$Forest'"
                Try {
                    Get-ADDomain $Domain
                } Catch [ADIdentityNotFoundException] {
                    # ignore non-existing domains...
                    Write-Warning $_.Exception.Message
                } Catch [AuthenticationException] {
                    # ignore broken domain trusts...
                    Write-Warning $_.Exception.Message
                } Catch {
                    # error - we don't know what went wrong if we reach here...
                    Write-Error $_ -ErrorAction $TrustErrorAction
                }
            }
        }

        Write-Verbose "Current forest root: '$Rootdomain' ($($Trusts.Count) trusts, $($Domains.Count) domains)."

        # create hashtable of domain SIDs to quickly retrieve the domain a foreign security principal belongs to
        $DomainSIDs = @{}
        Foreach ( $Domain in $Domains ) {
            $DomainSIDs[ $Domain.DomainSID.Value ] = $Domain
        }
        Return $DomainSIDs
    }
}
<#
.SYNOPSIS
    Helper function to get AD objects. It first tries to get groups, and if that fails, it will fall back to get ad objects
.DESCRIPTION
    When retrieving a group object, it has groupCategory/groupScope properties. If the group is retrieved as a plain ad object, these properties are missing.
    For ease of coding, we first try to get the $LDAPFilter objects as group objects. If any are missing, we will do a second try to get them as ad objects.
    Then we strip the duplicates and return the rest.
.PARAMETER LDAPFilter
    The LDAP filter string for the objects to return
.PARAMETER ExpectedResultCount
    The number of results that should be returned

#>
function Get-ADGroupOrObject {
    [CmdletBinding(DefaultParameterSetName='Filter')]
    Param(
        [Parameter(ParameterSetName='Filter',Mandatory=$true)]
        [String] $Filter,

        [Parameter(ParameterSetName='Identity',Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [ADObject] $Identity,

        [Parameter(ParameterSetName='LDAPFilter',Mandatory=$true)]
        [String] $LDAPFilter,

        [int] $ExpectedResultCount = -1,
        [ADAuthType] $AuthType = [ADAuthType]::Negotiate,
        [PSCredential] $Credential,
        [String] $Partition,
        [String] $Server = $env:USERDNSDOMAIN,
        [String[]] $Properties
    )
    begin {
        $GetADGroupOrObjectParams = $PSBoundParameters.PSObject.Copy()
        [void] $GetADGroupOrObjectParams.Remove('ExpectedResultCount')
        [void] $GetADGroupOrObjectParams.Remove('LdapFilter')
    }
    process {
        $Results = [Collections.Arraylist]::new()
        If ($PSCmdlet.ParameterSetName -eq 'LDAPFilter'){
            $GetADGroupOrObjectParams['LDAPFilter'] = "(&(objectClass=Group)$LDapFilter)"
        } ElseIf ($PSCmdlet.ParameterSetName -eq 'Identity'){
            $GetADGroupOrObjectParams['Identity'] = $GetADGroupOrObjectParams['Identity'].ToString()
            $ExpectedResultCount = 1
        }
        Try {
            $Objects = @((Get-ADGroup @GetADGroupOrObjectParams))
            $Results.AddRange($Objects)
        } Catch {
        }
        If ($Results.Count -ne $ExpectedResultCount){
            If ($PSCmdlet.ParameterSetName -eq 'LDAPFilter'){
                $GetADGroupOrObjectParams['LDAPFilter'] = "(&(!(objectClass=Group))$LDapFilter)"
            }
            $Results.AddRange(@(Get-ADObject @GetADGroupOrObjectParams))
        }
        Return $Results
    }
}
<#
.SYNOPSIS
    Helper function to remove all parameters from a hashtable that the specified Cmdlet does not have.
#>
function Sanitize-BoundParameters {
    [CmdletBinding()]
    Param(
        [String] $CmdletName,
        [hashtable] $Parameters
    )
    $CmdletParameters = (Get-Command $CmdletName).Parameters
    $Results = @{}
    Foreach ($Key in $Parameters.Keys) {
        If ($CmdletParameters.ContainsKey($Key)) {
            $Results[$Key] = $Parameters[$Key]
        }
    }
    Return $Results
}

<#
.SYNOPSIS
    Gets the Active Directory groups that have a specified user, computer, group, or service account.
.DESCRIPTION
    The Get-ADPrincipalGroupMembership cmdlet gets the Active Directory groups that have a specified user, computer, group, or service account as a member. This cmdlet requires a global catalog to perform the group search. If the forest that contains the user, computer or group does not have a global catalog, the cmdlet returns a non-terminating error. If you want to search for local groups in another domain, use the ResourceContextServer parameter to specify the alternate server in the other domain.
    
    The Identity parameter specifies the user, computer, or group object that you want to determine group membership for. You can identify a user, computer, or group object by its distinguished name (DN), GUID, security identifier (SID) or SAM account name. You can also specify a user, group, or computer object variable, such as $<localGroupObject>, or pass an object through the pipeline to the Identity parameter. For example, you can use the Get-ADGroup cmdlet to retrieve a group object and then pass the object through the pipeline to the Get-ADPrincipalGroupMembership cmdlet. Similarly, you can use Get-ADUser or Get-ADComputer to get user and computer objects to pass through the pipeline.
    
    For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
    
    -The cmdlet is run from an Active Directory provider drive.
    
    -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service agent (DSA) object (nTDSDSA) for the AD LDS instance.
.PARAMETER AuthType
    Specifies the authentication method to use. Possible values for this parameter include:
.PARAMETER Credential
    Specifies the user account credentials to use to perform this task. The default credentials are the credentials of the currently logged on user unless the cmdlet is run from an Active Directory PowerShell provider drive. If the cmdlet is run from such a provider drive, the account associated with the drive is the default.
.PARAMETER Identity
    Specifies an Active Directory principal object by providing one of the following property values. The identifier in parentheses is the LDAP display name for the attribute.
.PARAMETER Partition
    Specifies the distinguished name of an Active Directory partition. The distinguished name must be one of the naming contexts on the current directory server. The cmdlet searches this partition to find the object defined by the Identity parameter.
.PARAMETER Server
    Specifies the Active Directory Domain Services instance to connect to, by providing one of the following values for a corresponding domain name or directory server. The service may be any of the following:  Active Directory Lightweight Domain Services, Active Directory Domain Services or Active Directory Snapshot instance.
.PARAMETER Recursive
    Searches not only groups Identity is a direct member of, but also all groups within the same domain these groups are a member of.
.PARAMETER IncludeTrustingDomains
    If Identity is a direct/nested member of foreign security principals, searches the groups these represent in their domains for members as well. It will also collect all SIDs of groups in the domain of Identity and verify if there are any related shadow principals in trusting domains.
.PARAMETER ExcludeShadowPrincipals
    Do not resolve or follow shadow principals.
.PARAMETER ExcludeForeignSecurityPrincipals
    Do not resolve or follow foreign security principals.
.PARAMETER IgnoreTrustErrors
    For -IncludeTrustingDomains to work, all trusts of the Identity domain need to be enumerated. If any of these trusts are broken and the function is called with -ErrorAction Stop, it will halt. Use this switch to ignore failing trusts even when running with -ErrorAction Stop.
.PARAMETER Depth
    If memberships should be evaluated across more than one trust level, specify the number of levels to traverse. Defaults to 1 (will only resolve in direct trusts)
.SYNTAX
    Get-ADPrincipalGroupMembership [-Identity] <ADPrincipal> [-AuthType ] [-Credential <PSCredential>] [-Partition <String>] [-ResourceContextPartition <String>] [-ResourceContextServer <String>] [-Server <String>] [<Allgemeine Parameter>]
.INPUTS
    Microsoft.ActiveDirectory.Management.ADPrincipal
    A principal object that represents a user, computer or group is received by the Identity parameter. Derived types, such as the following are also received by this parameter.
.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADGroup
    Returns group objects that have the specified user, computer, group or service account as a member.
.NOTES
    This cmdlet does not work with an Active Directory Snapshot.
.EXAMPLE
    C:\PS>get-adprincipalgroupmembership -Identity Administrator
    
    distinguishedName : CN=Domain Users,CN=Users,DC=Fabrikam,DC=com
    GroupCategory     : Security
    GroupScope        : Global
    name              : Domain Users
    objectClass       : group
    objectGUID        : 86c0f0d5-8b4d-4f35-a867-85a006b92902
    SamAccountName    : Domain Users
    SID               : S-1-5-21-41432690-3719764436-1984117282-513
    
    distinguishedName : CN=Administrators,CN=Builtin,DC=Fabrikam,DC=com
    GroupCategory     : Security
    GroupScope        : DomainLocal
    name              : Administrators
    objectClass       : group
    objectGUID        : 02ce3874-dd86-41ba-bddc-013f34019978
    SamAccountName    : Administrators
    SID               : S-1-5-32-544
    
    Retrieve all the groups the administrator is a member of.
.LINKS
    Online Version: http://go.microsoft.com/fwlink/p/?linkid=291037
    Add-ADGroupMember
    Add-ADPrincipalGroupMembership
    Get-ADComputer
    Get-ADGroup
    Get-ADGroupMember
    Get-ADUser
    Remove-ADGroupMember
    Remove-ADPrincipalGroupMembership
#>
function Get-ADPrincipalGroupMembership {
    [CmdletBinding(DefaultParameterSetName='NonRecursive')]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ADPrincipal] $Identity,
        [ADAuthType] $AuthType = [ADAuthType]::Negotiate,
        [PSCredential] $Credential,
        [String] $Partition,
        [String] $Server = $env:USERDNSDOMAIN,
        [Parameter(ParameterSetName='Recursive',Mandatory=$true)]
        [Switch] $Recursive,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('ITD')]
        [Switch] $IncludeTrustingDomains,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('XSP')]
        [Switch] $ExcludeShadowPrincipals,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('XFSP')]
        [Switch] $ExcludeForeignSecurityPrincipals,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('ITE')]
        [Switch] $IgnoreTrustErrors,
        [Parameter(ParameterSetName='Recursive')]
        [Int] $Depth = 1
    )
    
    begin {
        If ($IncludeTrustingDomains -and $Depth -gt 0) {
            # only populate globally if a server was explicitly specified
            If ($PSBoundParameters.ContainsKey('Server')){
                # We need all trusting domains - in all of them, we can be direct or indirect member...
                $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Outbound) -IgnoreTrustErrors:$IgnoreTrustErrors
            }
        } Else {
            $IncludeTrustingDomains = $false
            $Depth = 0
        }
      
        # create parameter hash for Get-ADObject, strip additional parameters the AD cmdlets cannot handle
        $GetADParams = Sanitize-BoundParameters -CmdletName 'Get-ADObject' -Parameters $PSBoundParameters
    }
   
    process {
        $PSBoundParameters | Out-String | Write-Verbose
        # check if $Identity can be parsed as a distinguished name. If yes and no $server is specified, extract $server from the DN
        If ($Identity.ToString() -match 'CN=.+,DC=' -and -not $PSBoundParameters.ContainsKey('Server')){
            $IdentityServer = ($Identity.ToString() -split ',DC=',2)[1].Replace(',DC=','.')
            If ($IdentityServer -ne $Server){
                $Server = $IdentityServer
                Remove-Variable DomainSids -ErrorAction SilentlyContinue
            }
        }

        # add 'server' explicitly - if not provided as a parameter, the default $env:USERDNSDOMAIN will not be in $PSBoundParameters
        $GetADParams['Server'] = $Server

        # remove 'Identity' - Identity will be provided explicitly in each call to AD cmdlets
        [void] $GetADParams.Remove('Identity')

        Write-Verbose "Checking for group memberships of '$Identity' in '$Server'"

        # ldap filter matching rule in chain needs a distinguished name, but a principal could also be a Sid only... So first let's get a proper AD object.
        Write-Debug "Resolving '$Identity' to principal..."
        $ADPrincipal = Get-ADObject $Identity -Properties objectSid, memberOf @GetADParams
        Write-Debug "Identity resolved: '$ADPrincipal'"

        $IdentityServer = ($ADPrincipal.ToString() -split ',DC=',2)[1].Replace(',DC=','.')
        If ($IdentityServer -ne $Server){
            $Server = $IdentityServer
            $GetADParams['Server'] = $Server
            Remove-Variable DomainSids -ErrorAction SilentlyContinue
        }

        # check if we already have a $DomainSids hashtable or if we need to refresh it
        If ($DomainSIDs -isnot [Hashtable] -and $IncludeTrustingDomains){
            $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Outbound) -IgnoreTrustErrors:$IgnoreTrustErrors
        }

        If ($Recursive -and -not [string]::IsNullOrEmpty($ADPrincipal.memberOf)){
            # only do a recursive search if $ADPrincipal is member of any group - no sense to search if .memberOf is empty
            # ldap matching rule in chain - get all groups the specified $ADPrincipal DN is a member of recursively. Returns DirectoryEntry objects.
            $LDAPFilter = "(member:1.2.840.113556.1.4.1941:=$ADPrincipal)"
            $LocalDomainGroups = @((Get-ADObject -LDAPFilter $LDAPFilter @GetADParams | Select-Object -ExpandProperty distinguishedName))
        } Else {
            # Only get the memberOf attribute of $ADPrincipal
            $LocalDomainGroups = @(($ADPrincipal.memberOf))
        }

        If ($LocalDomainGroups.Count -eq 0){
            Return @()
        }

        $Results = @{}
        $LocalAccountSids = [Collections.Arraylist]::new()
        $ShadowPrincipals = [Collections.Arraylist]::new()
        $ShadowPrincipalDomainSids = @{}   # hashtable storing all domains for which shadow principals were found by sid. Each element contains a nested hashtable with all shadow principals for that domain by sid.

        # handle groups in the domain of $ADPrincipal
        $LDAPFilter = '(|' + $(Foreach($LocalDomainGroup in $LocalDomainGroups){"(name=$(($LocalDomainGroup.Substring(3) -split ',(CN|OU)=')[0]))"}) + ')'
        $ADObjects = @((Get-ADGroup -LDAPFilter $LDAPFilter @GetADObjectParams @GetADParams))
        Foreach ($ADObject in $ADObjects) {
            $Results[$ADObject.ObjectGUID] = [ADCustomObject] $ADObject
            If ($Recursive){
                # if we recurse, store all local group sids (only needed if -IncludeTrustingDomains) and shadow principal memberships
                # we need to verify them in their respective domains
                [void] $LocalAccountSids.Add($ADObject.objectSid)
                $ADObjectDE = [ADSI]"LDAP://$($GetADParams['Server'])/$ADObject"
                $ShadowPrincipals.AddRange(@($ADObjectDE.memberOf -match 'CN=Shadow Principal Configuration,CN=Services,CN=Configuration'))
            }
        }

        If ($ShadowPrincipals.Count -gt 0){
            # handle shadow principals in the domain of $ADPrincipal, if any are present
            # with -IncludeTrustingDomains, speed up retrieval of foreign objects through grouping by domain
            # this allows for a single ldap operation to retrieve all shadow principals in a given domain at once instead of fetching them one by one...

            $LDAPFilter = '(|' + $(Foreach($ShadowPrincipal in $ShadowPrincipals | Select-Object -Unique){"(name=$(($ShadowPrincipal.Substring(3) -split ',CN=')[0]))"}) + ')'
            $SearchBase = "CN=$(($ShadowPrincipal -split ',CN=',2)[1])"

            Write-Debug "Retrieving shadow principal objects in domain '$($GetADParams['Server'])'"
            $ShadowPrincipalObjects = @((Get-ADObject -LDAPFilter $LDAPFilter -SearchBase $SearchBase @GetADShadowParams @GetADParams))
            Write-Debug "Found $($ShadowPrincipalObjects.Count) shadow principal objects."

            Foreach ($ShadowPrincipalObject in $ShadowPrincipalObjects) {
                Write-Debug "Processing shadow principal '$($ShadowPrincipalObject.Name)'"
                $Results[$ShadowPrincipalObject.ObjectGUID] = [ADCustomObject] $ShadowPrincipalObject
                $ShadowPrincipalSid = $ShadowPrincipalObject.'msDS-ShadowPrincipalSid'
                $ShadowPrincipalDomainSid = $ShadowPrincipalSid.AccountDomainSid.Value
                If (-not $ShadowPrincipalDomainSids.ContainsKey($ShadowPrincipalDomainSid)){
                    $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid] = @{}
                }
                $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].Add($ShadowPrincipalSid, [ADCustomObject] $ShadowPrincipalObject)
            }
        }

        If (-not $IncludeTrustingDomains){
            Write-Debug "Finished, no trusting domains to process."
            Return $Results.Values
        }

        If ($ExcludeShadowPrincipals){
            $ShadowPrincipalDomainSids.Clear()
        }
        If ($ExcludeForeignSecurityPrincipals){
            $LocalAccountSids.Clear()
        }

        # handle shadow principals - search sid in foreign domain, get members if it is a group.
        Foreach ($ShadowPrincipalDomainSid in $ShadowPrincipalDomainSids.Keys) {
            If ($DomainSIDs.ContainsKey($ShadowPrincipalDomainSid)) {
                # we have a domain object from trust enumeration
                $ShadowPrincipalDomain = $DomainSIDs[$ShadowPrincipalDomainSid]
                $GetADParams['Server'] = $ShadowPrincipalDomain.DNSRoot
                Write-Debug "Retrieving shadow principal target accounts in domain '$($GetADParams['Server'])'"
                $LDAPFilter = "(|" + $(Foreach ($ShadowPrincipalSid in $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].Keys){"(objectSid=$($ShadowPrincipalSid))"}) + ")"
                $ADObjects = @((Get-ADGroupOrObject -LDAPFilter $LDAPFilter -ExpectedResultCount $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].Keys.Count @GetADObjectParams @GetADParams))
                Foreach ($ADObject in $ADObjects){
                    $SourceAccount = $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].$($ADObject.objectSid)
                    $Results[$ADObject.objectGuid] = [ADCustomObject] $ADObject
                    $Results[$ADObject.objectGuid].TargetAccount = "$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)"
                }
                # groups these target accounts are a member of
                Write-Debug "Retrieving shadow principal group memberships in domain '$($GetADParams['Server'])'"
                $ForeignGroupMemberships = @(($ADObjects | Get-ADPrincipalGroupMembership -Recursive:$Recursive -IncludeTrustingDomains:$IncludeTrustingDomains -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                Foreach ($ForeignGroupMembership in $ForeignGroupMemberships){
                    Write-Debug "Adding foreign group membership '$($ForeignGroupMembership.Name)' in domain '$($GetADParams['Server'])'"
                    $Results[$ForeignGroupMembership.objectGuid] = $ForeignGroupMembership
                }
            } Else {
                # we did not find a domain for the current shadow principal domain SID
                $AffectedPrincipals = [Collections.Arraylist]::new()
                Foreach ($Key in $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].Keys){
                    [void] $AffectedPrincipals.Add($ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].$Key.Name)
                }
                $Err = [ADIdentityNotFoundException]::new("Cannot resolve shadow principal SIDs for domain SID '$ShadowPrincipalDomainSid' - SID not found in domain trusts of '$Server'. Affected principals: $($AffectedPrincipals -join ',')")
                $ErrorRecord = [ErrorRecord]::new($Err,'Domain Sid lookup error', [ErrorCategory]::ObjectNotFound, $ShadowPrincipalDomainSid)
                Write-Error -ErrorRecord $ErrorRecord
            }
        }

        # handle local domain group sids - any of these can be a foreign security principal in any trusting domain
        If ($LocalAccountSids.Count -gt 0){
            # build a LDAP filter to query all sids at once - makes a quite long filter, but only one AD query per domain
            $LDAPFilter = "(|" + $(Foreach ($LocalAccountSid in $LocalAccountSids){"(name=$($LocalAccountSid))"}) + ")"
            Foreach ($Domain in $DomainSIDs.Values){
                $GetADParams['Server'] = $Domain.DNSRoot
                Write-Verbose "Checking for foreign security principals in domain '$($GetADParams['Server'])'"
                # we have to query all domains for all SIDs of all local groups...
                $ADObjects = @((Get-ADObject -LDAPFilter $LDAPFilter -SearchBase $Domain.ForeignSecurityPrincipalsContainer @GetADObjectParams @GetADParams))
                If ($ADObjects.Count -gt 0){
                    Foreach ($ADObject in $ADObjects){
                        $SourceAccount = $Results.Values + [ADCustomObject] $ADPrincipal | Where-Object {$_.ObjectSid -eq $ADObject.objectSid}
                        $Results[$ADObject.ObjectGUID] = [ADCustomObject] $ADObject
                        $Results[$ADObject.ObjectGUID].TargetAccount = "$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)"
                    }
                    # get all groups these FSPs are a member of in the target domain
                    $ForeignGroupMemberships = @(($ADObjects | Get-ADPrincipalGroupMembership -Recursive:$Recursive -IncludeTrustingDomains:$IncludeTrustingDomains -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                    Foreach ($ForeignGroupMembership in $ForeignGroupMemberships){
                        $Results[$ForeignGroupMembership.objectGuid] = $ForeignGroupMembership
                    }
                }
            }
        }
        Return $Results.Values
    }
}


<#
.SYNOPSIS
    Gets the members of an Active Directory group.
.DESCRIPTION
    The Get-ADGroupMember cmdlet gets the members of an Active Directory group. Members can be users, groups, and computers.
    
    The Identity parameter specifies the Active Directory group to access. You can identify a group by its distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can also specify the group by passing a group object through the pipeline. For example, you can use the Get-ADGroup cmdlet to retrieve a group object and then pass the object through the pipeline to the Get-ADGroupMember cmdlet.
    
    If the Recursive parameter is specified, the cmdlet gets all members in the hierarchy of the group that do not contain child objects. For example, if the group SaraDavisReports contains the user KarenToh and the group JohnSmithReports, and JohnSmithReports contains the user JoshPollock, then the cmdlet returns KarenToh and JoshPollock.
    
    For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
    
    -The cmdlet is run from an Active Directory provider drive.
    
    -A default naming context or partition is defined for the AD LDS environment. To specify a default naming context for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service agent (DSA) object (nTDSDSA) for the AD LDS instance.
.PARAMETER AuthType
    Specifies the authentication method to use. Possible values for this parameter include:
.PARAMETER Credential
    Specifies the user account credentials to use to perform this task. The default credentials are the credentials of the currently logged on user unless the cmdlet is run from an Active Directory PowerShell provider drive. If the cmdlet is run from such a provider drive, the account associated with the drive is the default.
.PARAMETER Identity
    Specifies an Active Directory group object by providing one of the following values. The identifier in parentheses is the LDAP display name for the attribute.
.PARAMETER Partition
    Specifies the distinguished name of an Active Directory partition. The distinguished name must be one of the naming contexts on the current directory server. The cmdlet searches this partition to find the object defined by the Identity parameter.
.PARAMETER Recursive
    Specifies that the cmdlet get all members in the hierarchy of a group that do not contain child objects. The following example shows a hierarchy for the group SaraDavisReports.
.PARAMETER Server
    Specifies the Active Directory Domain Services instance to connect to, by providing one of the following values for a corresponding domain name or directory server. The service may be any of the following:  Active Directory Lightweight Domain Services, Active Directory Domain Services or Active Directory Snapshot instance.
.PARAMETER IncludeTrustingDomains
    If the group has a foreign security principal as direct/nested member, searches the groups these represent in their domains for their members as well. It will also collect all SIDs of groups in the domain of Identity and verify if there are any related shadow principals in trusting domains.
.PARAMETER ExcludeShadowPrincipals
    Do not resolve or follow shadow principals.
.PARAMETER ExcludeForeignSecurityPrincipals
    Do not resolve or follow foreign security principals.
.PARAMETER IgnoreTrustErrors
    For -IncludeTrustingDomains to work, all trusts of the Identity domain need to be enumerated. If any of these trusts are broken and the function is called with -ErrorAction Stop, it will halt. Use this switch to ignore failing trusts even when running with -ErrorAction Stop.
.PARAMETER Depth
    If memberships should be evaluated across more than one trust level, specify the number of levels to traverse. Defaults to 1 (will only resolve in direct trusts)
.SYNTAX
    Get-ADGroupMember [-Identity] <ADGroup> [-AuthType ] [-Credential <PSCredential>] [-Partition <String>] [-Recursive ] [-Server <String>] [<Allgemeine Parameter>]
.INPUTS
    None or Microsoft.ActiveDirectory.Management.ADGroup
    A group object is received by the Identity parameter
.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADPrincipal
    Returns one or more principal objects that represent users, computers or groups that are members of the specified group.
.NOTES
    This cmdlet does not work with an Active Directory Snapshot.
.EXAMPLE
    C:\PS>get-adgroupmember Administrators
    
    distinguishedName : CN=Domain Admins,CN=Users,DC=Fabrikam,DC=com
    name              : Domain Admins
    objectClass       : group
    objectGUID        : 5ccc6037-c2c9-42be-8e92-c8f98afd0011
    SamAccountName    : Domain Admins
    SID               : S-1-5-21-41432690-3719764436-1984117282-512
    
    distinguishedName : CN=Enterprise Admins,CN=Users,DC=Fabrikam,DC=com
    name              : Enterprise Admins
    objectClass       : group
    objectGUID        : 0215b0a5-aea1-40da-b598-720efe930ddf
    SamAccountName    : Enterprise Admins
    SID               : S-1-5-21-41432690-3719764436-1984117282-519
    
    Get all the members of the administrators groups using the default behavior.
.LINKS
    Online Version: http://go.microsoft.com/fwlink/p/?linkid=291033
    Add-ADGroupMember
    Add-ADPrincipalGroupMembership
    Get-ADGroup
    Get-ADPrincipalGroupMembership
    Remove-ADGroupMember
    Remove-ADPrincipalGroupMembership
#>
function Get-ADGroupMember {
    [CmdletBinding(DefaultParameterSetName='NonRecursive')]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ADGroup] $Identity,

        [ADAuthType] $AuthType = [ADAuthType]::Negotiate,
        [PSCredential] $Credential,
        [String] $Partition,
        [String] $Server = $env:COMPUTERDNSDOMAIN,

        [Parameter(ParameterSetName='Recursive',Mandatory=$true)]
        [Switch] $Recursive,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('ITD')]
        [Switch] $IncludeTrustingDomains,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('XSP')]
        [Switch] $ExcludeShadowPrincipals,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('XFSP')]
        [Switch] $ExcludeForeignSecurityPrincipals,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('ITE')]
        [Switch] $IgnoreTrustErrors,
        [Parameter(ParameterSetName='Recursive')]
        [Int] $Depth = 1
    )
    
    begin {
        If ($IncludeTrustingDomains -and $Depth -gt 0) {
            # only create DomainSids hash here if a server was explicitly passed
            If ($PSBoundParameters.ContainsKey('Server')){
                # We need all trusted domains - in all of them, we can be direct or indirect member...
                $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Inbound) -IgnoreTrustErrors:$IgnoreTrustErrors
            }
        } Else {
            $IncludeTrustingDomains = $false
            $Depth = 0
        }
        
        # create parameter hash for Get-ADObject/Get-ADGroup
        $GetADParams = Sanitize-BoundParameters -CmdletName 'Get-ADObject' -Parameters $PSBoundParameters
    }
    
    process {
        # check if $Identity can be parsed as a distinguished name. If yes and $server is not specified, extract $server from the DN
        If ($Identity.ToString() -match 'CN=.+,DC=' -and -not $PSBoundParameters.ContainsKey('Server')){
            $IdentityServer = ($Identity.ToString() -split ',DC=',2)[1].Replace(',DC=','.')
            If ($IdentityServer -ne $Server){
                $Server = $IdentityServer
                Remove-Variable DomainSids -ErrorAction SilentlyContinue
            }
        }

        # add 'server' explicitly - if not provided as a parameter, the default $env:COMPUTERDNSDOMAIN will not be in $PSBoundParameters
        $GetADParams['Server'] = $Server

        # remove 'Identity - will be provided explicitly for all calls of AD cmdlets
        [void] $GetADParams.Remove('Identity')

        Write-Verbose "Checking for group members of '$Identity' in '$Server'"

        # ldap filter matching rule in chain needs a distinguished name, but a principal could also be a Sid only... So first let's get a proper AD object.
        Write-Debug "Resolving '$Identity' to principal..."
        $ADPrincipal = Get-ADGroup $Identity -Properties objectSid, member @GetADParams
        Write-Debug "Identity resolved: '$ADPrincipal'"

        $IdentityServer = ($ADPrincipal.ToString() -split ',DC=',2)[1].Replace(',DC=','.')
        If ($IdentityServer -ne $Server){
            $Server = $IdentityServer
            $GetADParams['Server'] = $Server
            Remove-Variable DomainSids -ErrorAction SilentlyContinue
        }

        # check if we already have a $DomainSids hashtable or if we need to refresh it
        If ($DomainSIDs -isnot [Hashtable] -and $IncludeTrustingDomains){
            Remove-Variable DomainSids -ErrorAction SilentlyContinue
            $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Inbound) -IgnoreTrustErrors:$IgnoreTrustErrors
        }

        If ($Recursive -and -not [string]::IsNullOrEmpty($ADPrincipal.member)){
            # ldap matching rule in chain - get all principals that are a member of the specified $ADPrincipal recursively. Returns DirectoryEntry objects.
            $LDAPFilter = "(memberOf:1.2.840.113556.1.4.1941:=$ADPrincipal)"
            $LocalGroupMembers = @((Get-ADObject -LDAPFilter $LDAPFilter @GetADParams | Select-Object -ExpandProperty distinguishedName))
        } Else {
            # Only get the memberOf attribute of $ADPrincipal
            $LocalGroupMembers = @(($ADPrincipal.member))
        }

        If ( $LocalGroupMembers.Count -eq 0 ){
            Return @()
        }

        $Results = @{}
        $FSPDomainSids = @{}
        $LocalAccountSids = [Collections.Arraylist]::new()

        # store all SIDs of local groups to check if they belong to a shadow principal in any trusted domain
        [void] $LocalAccountSids.Add($ADPrincipal.objectSid)

        Foreach ($LocalGroupMember in $LocalGroupMembers | Sort-Object){
            Write-Verbose "Getting group member '$LocalGroupMember' in domain '$($GetADParams['Server'])')"
            Try {
                $ADObject = Get-ADGroupOrObject $LocalGroupMember @GetADObjectParams @GetADParams
                [void] $LocalAccountSids.Add($ADObject.objectSID)
                $Results[$ADObject.objectGuid] = [ADCustomObject] $ADObject
                If ($ADObject.ObjectClass -eq 'foreignSecurityPrincipal' -and $IncludeTrustingDomains){
                    # handle FSPs separately - we want the resolved ones if possible and the unresolved if resolution fails
                    $FSPSid = $ADObject.objectSid
                    $FSPDomainSid = $ADObject.objectSid.AccountDomainSid.Value
                    If (-not $FSPDomainSids.ContainsKey($FSPDomainSid)){
                        $FSPDomainSids[$FSPDomainSid] = @{}
                    }
                    $FSPDomainSids[$FSPDomainSid].Add($FSPSid, [ADCustomObject] $ADObject)
                }
            } Catch [ADIdentityNotFoundException] {
                $Err = [ADIdentityNotFoundException]::new("Cannot find the object '$LocalGroupMember' in domain '$($GetADParams['Server'])'.")
                $ErrorRecord = [ErrorRecord]::new($Err,'AD object lookup error', [ErrorCategory]::ObjectNotFound, $LocalGroupMember)
                Write-Error -ErrorRecord $ErrorRecord
            } Catch {
                Write-Warning "Error processing '$LocalGroupMember' in domain '$Server'."
                Write-Error -ErrorRecord $_
            }
        }

        If (-not $IncludeTrustingDomains){
            Return $Results.Values | Sort-Object -Property objectClass -Descending
        }

        If ($ExcludeShadowPrincipals){
            $LocalAccountSids.Clear()
        }
        If ($ExcludeForeignSecurityPrincipals){
            $FSPDomainSids.Clear()
        }

        # handle foreign security principals
        Foreach ($FSPDomainSid in $FSPDomainSids.Keys){
            If ($DomainSIDs.ContainsKey($FSPDomainSid)) {
                # we have a domain object from trust enumeration
                $FSPDomain = $DomainSIDs[$FSPDomainSid]
                $GetADParams['Server'] = $FSPDomain.DNSRoot
                Write-Debug "Retrieving foreign security principal target accounts in domain '$($GetADParams['Server'])'"
                # create LDAP filter to retrieve all FSPs with one query
                $LDAPFilter = "(|" + $(Foreach ($FSPSid in $FSPDomainSids[$FSPDomainSid].Keys){"(objectSid=$($FSPSid))"}) + ")"
                $ADObjects = @((Get-ADGroupOrObject -LDAPFilter $LDAPFilter @GetADObjectParams @GetADParams))
                Foreach ($ADObject in $ADObjects){
                    $SourceAccount = $Results.Values + [ADCustomObject] $ADPrincipal | Where-Object {$_.objectSid -eq $ADObject.objectSid}
                    $SourceAccount.TargetAccount = "$($GetADParams['Server'].Split('.')[0])\$($ADObject.Name)"
                    $Results[$ADObject.objectGuid] = [ADCustomObject] $ADObject
                }
                Write-Debug "Retrieving foreign security principal group members in domain '$($GetADParams['Server'])'"
                $ForeignGroupMemberships = @(($ADObjects | Where-Object {$_.ObjectClass -eq 'Group'} | Get-ADGroupMember -Recursive:$Recursive -IncludeTrustingDomains:$IncludeTrustingDomains -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                Foreach ($ForeignGroupMembership in $ForeignGroupMemberships){
                    Write-Debug "Adding foreign group membership '$($ForeignGroupMembership.Name)' in domain '$($GetADParams['Server'])'"
                    $Results[$ForeignGroupMembership.objectGuid] = $ForeignGroupMembership
                }
            } Else {
                # we did not find a domain for the current FSP domain SID
                $AffectedPrincipals = [Collections.Arraylist]::new()
                Foreach ($Key in $FSPDomainSids[$FSPDomainSid].Keys){
                    [void] $AffectedPrincipals.Add($FSPDomainSids[$FSPDomainSid].$Key.Name)
                }
                $Err = [ADIdentityNotFoundException]::new("Cannot resolve shadow principal SIDs for domain SID '$FSPDomainSid' - SID not found in domain trusts of '$($GetADParams['Server'])'. Affected principals: $($AffectedPrincipals -join ',')")
                $ErrorRecord = [ErrorRecord]::new($Err,'Domain Sid lookup error', [ErrorCategory]::ObjectNotFound, $FSPDomainSid)
                Write-Error -ErrorRecord $ErrorRecord
            }
        }

        # handle shadow principals - create LDAP filter to query all shadow principals at once
        $LDAPFilter = '(|' + $(Foreach ($LocalAccountSid in $LocalAccountSids){"(msDS-ShadowPrincipalSid=$($LocalAccountSid))"}) + ')'
        Foreach ($Domain in $DomainSIDs.Values){
            # we have to query all domains for all SIDs of all local groups...
            $GetADParams['Server'] = $Domain.DNSRoot
            Write-Verbose "Checking for shadow principals in domain '$($GetADParams['Server'])'"
            $ShadowPrincipalObjects = @((Get-ADObject -LDAPFilter $LDAPFilter -SearchBase "CN=Shadow Principal Configuration,CN=Services,CN=Configuration,$Domain" @GetADShadowParams @GetADParams))
            $ShadowPrincipalMembers = [Collections.Arraylist]::new()
            Foreach ($ShadowPrincipalObject in $ShadowPrincipalObjects){
                $SourceAccount = $Results.Values + [ADCustomObject] $ADPrincipal | Where-Object {$_.ObjectSid -eq $ShadowPrincipalObject.'msDS-ShadowPrincipalSid'}
                $Results[$ShadowPrincipalObject.ObjectGUID] = [ADCustomObject] $ShadowPrincipalObject
                $Results[$ShadowPrincipalObject.ObjectGUID].TargetAccount = "$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)"
                $ShadowPrincipalDE = [ADSI]"LDAP://$($GetADParams['Server'])/$ShadowPrincipalObject"
                $ShadowPrincipalMembers.AddRange(@($ShadowPrincipalDE.member))
            }
            If ($ShadowPrincipalMembers.Count -gt 0 ){
                # create LDAP filter to query all shadow principal members at once
                $ShadowMembersLDAPFilter = '(|' + $(Foreach ($ShadowPrincipalMember in $ShadowPrincipalMembers | Select-Object -Unique){"(name=$(($ShadowPrincipalMember.SubString(3) -split ',')[0]))"}) + ')'
                $ADObjects = @((Get-ADGroupOrObject -LDAPFilter $ShadowMembersLDAPFilter @GetADObjectParams @GetADParams))
                Foreach ($ADObject in $ADObjects){
                    $Results[$ADObject.objectGuid] = [ADCustomObject] $ADObject
                }
                Write-Debug "Retrieving members of shadow principals in domain '$($GetADParams['Server'])'."
                If ($ADObjects.Count -gt 0){
                    $ForeignGroupMembers = @(($ADObjects | Get-ADGroupMember -Recursive:$Recursive -IncludeTrustingDomains:$IncludeTrustingDomains -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                    Foreach ($ForeignGroupMember in $ForeignGroupMembers){
                        $Results[$ForeignGroupMember.objectGuid] = $ForeignGroupMember
                    }
                }
            }
        }
        Return $Results.Values | Sort-Object -Property objectClass -Descending
    }
}


If ($MyInvocation.MyCommand -match 'PSM1$'){
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_classes?view=powershell-7.5#export-classes-with-type-accelerators
    # Define the types to export with type accelerators.
    $ExportableTypes =@(
        [ADCustomObject]
    )

    # Get the internal TypeAccelerators class to use its static methods.
    $TypeAcceleratorsClass = [psobject].Assembly.GetType(
        'System.Management.Automation.TypeAccelerators'
    )

    # Ensure none of the types would clobber an existing type accelerator.
    # If a type accelerator with the same name exists, throw an exception.
    $ExistingTypeAccelerators = $TypeAcceleratorsClass::Get
    foreach ($Type in $ExportableTypes) {
        if ($Type.FullName -in $ExistingTypeAccelerators.Keys) {
            # do not throw, but simply remove the type from the exporable types list
            $ExportableTypes = $ExportableTypes -ne $Type
            <#
            $Message = @(
                "Unable to register type accelerator '$($Type.FullName)'"
                'Accelerator already exists.'
            ) -join ' - '

            throw [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new($Message),
                'TypeAcceleratorAlreadyExists',
                [System.Management.Automation.ErrorCategory]::InvalidOperation,
                $Type.FullName
            )
            #>
        }
    }

    # Add type accelerators for every exportable type.
    foreach ($Type in $ExportableTypes) {
        $TypeAcceleratorsClass::Add($Type.FullName, $Type)
    }

    # Remove type accelerators when the module is removed.
    $MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
        foreach($Type in $ExportableTypes) {
            $TypeAcceleratorsClass::Remove($Type.FullName)
        }
    }.GetNewClosure()
}
