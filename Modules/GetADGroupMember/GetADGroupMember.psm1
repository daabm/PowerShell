<#
.SYNOPSIS
Overload für ActiveDirectory\Get-ADGroupMember: Rekursive Auflösung und Berücksichtigung von Foreign Security Principals (FSP) und Shadow principals 
Overload für ActiveDirectory\Get-ADPrincipalGroupMembership: Rekursive Auflösung und Berücksichtigung von Foreign Security Principals (FSP) und Shadow principals

.DESCRIPTION
Mit -Recursive werden Mitgliedschaften (Member/MemberOf) in der aktuellen Domäne ermittelt. Mit -IncludeTrustingDomains werden auch die Namen der FSPs aufgelöst und deren Mitglieder zurückgegeben (beides können die "originalen" Cmdlets nicht). Zusätzlich werden alle Shadow Principals ermittelt und ebenfalls aufgelöst.
Rückgabe sind benutzerdefinierte [ADCustomObject] Objekte. Das ist erforderlich, da unterschiedliche Objektklassen gefunden werden können (Group, ForeignSecurityPrincipal, ShadowPrincipal, Service Accounts, User, Computer etc.). Damit wäre keine einheitliche Darstellung der Ergebnisse möglich.

.EXAMPLE
Get-ADGroupMember 'Administrators' -Recursive -IncludeTrustingDomains
Ermittelt alle Mitglieder der angegebenen Gruppe in der Domäne des Computers inkl. rekursive Mitgliedschaften aus anderen Domänen. Findet in einem Forest damit die Domain Admins der gleichen Domäne sowie die Enterprise Admins der Forest Root Domäne.
Wenn die Gruppe einen FSP als Mitglied hat, wird der Zielaccount aufgelöst und dessen Mitglieder ermittelt.
Wenn es einen PAM-Trust gibt, werden alle in der Domäne von Administrators gefundenen SIDs geprüft, ob es dort einen Shadow Principal dazu gibt. Wenn ja, werden dessen Mitglieder ermittelt.

.EXAMPLE
Get-ADUser $env:USERNAME | Get-ADPrincipalGroupMembership -Recursive
Ermittelt alle Gruppenmitgliedschaften des angemeldeten Benutzers in der Domäne. Gruppenverschachtelungen innerhalb dieser Domäne werden dabei aufgelöst. Mitgliedschaften in FSPs in anderen Domains werden nicht aufgelöst.

.EXAMPLE
Get-ADUser $env:USERNAME -Server $env:USERDNSDOMAIN | Get-ADPrincipalGroupMembership -Recursive -IncludeTrustingDomains
Ermittelt alle Gruppenmitgliedschaften des angemeldeten Benutzers in seiner Domäne und in allen vertrauenden Domänen. Dabei werden auch Mitgliedschaften über Shadow Principals und in Foreign Security Principals ausgewertet.
Wenn der Benutzer Mitglied von Shadow Principals ist, werden deren Zielaccounts ermittelt und deren Mitgliedschaften aufgelöst.
In allen Trusting Domains wird nach FSPs für alle SIDs aus der Domäne des Benutzers gesucht und deren Mitgliedschaften aufgelöst.

.NOTES
Hängt man an den Aufruf
    | Out-Gridview
an, wird das Ergebnis in einer grafischen Tabelle ausgegeben. Mit
    | Export-CSV <PfadZurDatei.csv> -Delimiter ';' -NoTypeInformation
erhält man eine CSV-Datei, die in Excel direkt geöffnet werden kann.
#>

using namespace System.Management
using namespace System.Management.Automation
using namespace System.DirectoryServices
using namespace System.Security
using namespace System.Security.Authentication
using namespace System.Security.Principal
using namespace Microsoft.ActiveDirectory.Management

# Custom class for a common representation of various AD account types (Group, User, ForeignSecurityPrincipal, msDS-ShadowPrincipal and so on)

# Requires the ActiveDirectory module to be already loaded. Happens automatically upon module import.
# If you want to run the code from the .psm1, make sure to Import-Module ActiveDirectory first.

class ADCustomObject {
    [String] $Name
    [Nullable[ADGroupCategory]] $GroupCategory
    [Nullable[ADGroupScope]] $GroupScope
    [String] $ObjectClass
    [String] $SamAccountName
    [Nullable[Guid]] $ObjectGuid
    [string[]] $TargetAccount
    hidden [String] $_Domain
    hidden [String] $_DistinguishedName
    hidden [SecurityIdentifier] $_ObjectSid

    ADCustomObject() {
        Write-Debug "Creating object from '$null'"
        $this.ADCustomObject_Initialize()
    }

    ADCustomObject([String] $DistinguishedName) {
        Write-Debug "Creating object from string '$DistinguishedName'"
        $this.ADCustomObject_Initialize()
        $ADObject = Get-ADObject $DistinguishedName -Server $(($DistinguishedName -split ',DC=',2)[1].Replace(',DC=','.').ToUpper()) -Properties *
        $this.ADCustomObject_Update($ADObject)
    }

    ADCustomObject([DirectoryEntry] $DirectoryEntry) {
        Write-Debug "Creating object from DirectoryEntry '$($DirectoryEntry.Name)'"
        $this.ADCustomObject_Initialize()
        $this.ADCustomObject_Update($DirectoryEntry)
    }

    ADCustomObject([SearchResult] $SearchResult) {
        Write-Debug "Creating object from SearchResult '$($SearchResult.Path)'"
        $this.ADCustomObject_Initialize()
        $this.ADCustomObject_Update($SearchResult)
    }

    ADCustomObject([ADObject] $ADObject) {
        Write-Debug "Creating object from ADObject '$($ADObject.Name)'"
        $this.ADCustomObject_Initialize()
        $this.ADCustomObject_Update($ADObject)
    }

    # initialize the instance with additional scriptproperties
    hidden ADCustomObject_Initialize() {
        # set up getter and setter for distinguishedName and objectSid
        # this allows to set/change them and update all properties
        $GetObjectSid = {
            [OutputType([SecurityIdentifier])]
            param()
            return $this._ObjectSid
        }
        $SetObjectSid = {
            param([SecurityIdentifier] $value)
            Write-Debug "Updating object from SecurityIdentifier '$value'"
            $newObject = Get-ADObject $value.ToString() -Properties *
            $this.ADCustomObject_Update($newObject)
        }
        $this | Add-Member -MemberType ScriptProperty -Name ObjectSid -Value $GetObjectSid -SecondValue $SetObjectSid

        $GetDistinguishedName = {
            [OutputType([string])]
            param()
            return $this._DistinguishedName
        }
        $SetDistinguishedName = {
            param([String] $value)
            Write-Debug "Updating object from DistinguishedName '$value'"
            $Server = ($value -split ',DC=',2)[1].Replace(',DC=','.').ToUpper()
            $newObject = Get-ADObject $value.ToString() -Server $Server -Properties *
            $this.ADCustomObject_Update($newObject)
        }
        $this | Add-Member -MemberType ScriptProperty -Name DistinguishedName -Value $GetDistinguishedName -SecondValue $SetDistinguishedName

        # getter for calculated property 'Domain'
        $GetDomain = {
            [OutputType([string])]
            param()
            return ($this._DistinguishedName -split ',DC=',2)[1].Replace(',DC=','.').ToUpper()
        }
        $this | Add-Member -MemberType ScriptProperty -Name Domain -Value $GetDomain

        ##Set up the default display set 
        $defaultDisplaySet = 'Domain','Name','TargetAccount','GroupCategory','GroupScope','ObjectClass','ObjectSid'
        $defaultDisplayPropertySet = [PSPropertySet]::new('DefaultDisplayPropertySet', [string[]] $defaultDisplaySet)
        $PSStandardMembers = [PSMemberInfo[]] @($defaultDisplayPropertySet)
        $this | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers
    }

    hidden ADCustomObject_Update($Object) {
        Write-Debug "Setting properties from $($Object.GetType().Name)"
        switch ($Object.GetType().Name) {
            'DirectoryEntry' {
                # objects created from [adsi]/[DirectoryEntry]
                $this.Name = $Object.Name
                $this._DistinguishedName = $Object.DistinguishedName
                $this.ObjectGuid = $Object.NativeGuid
                $this.ObjectClass = $Object.ObjectClass | Select-Object -Last 1
                If ($object.Properties.Contains('sAMAccountName')) {
                    $this.SamAccountName = $Object.SamAccountName
                }
                If ($Object.ObjectClass -eq 'Group') {
                    # clear bit 0 from grouptype. this bit signals 'builtin' which [ADGroupCategory] does not know.
                    # in addition, groupType covers both scope and category in one bitmask
                    $this.GroupScope = ([GroupType] $Object.groupType -band 0x0000FFFE).ToString()
                    $this.GroupCategory = ([GroupType] $Object.groupType -band 0xFFFF0000).ToString()
                    If ($this.GroupCategory -ne 'Security') {
                        $this.GroupCategory = [ADGroupCategory]::Distribution
                    }
                } Else {
                    $this.GroupCategory = $null
                    $this.GroupScope = $null
                }
                If ($object.Properties.Contains('objectSid')) {
                    $this._ObjectSid = [SecurityIdentifier]::new($object.objectSid.Value, 0)
                } ElseIf ($object.Properties.Contains('msDS-ShadowPrincipalSid')) {
                    $this._ObjectSid = [SecurityIdentifier]::new($object.'msDS-ShadowPrincipalSid'.Value, 0)
                } Else {
                    $this._ObjectSid = $null
                }
                break
            }
            'SearchResult' {
                # objects returned by [adsisearcher]/[DirectorySearcher]
                $this.Name = $Object.Properties['Name'].Item(0)
                $this._DistinguishedName = $Object.Properties['DistinguishedName'].Item(0)
                $this.ObjectGuid = $Object.Properties['objectGuid'].Item(0)
                $this.ObjectClass = $Object.Properties['ObjectClass'] | Select-Object -Last 1
                If ($object.Properties.Contains('sAMAccountName')) {
                    $this.SamAccountName = $Object.Properties['SamAccountName'].Item(0)
                }
                if ($this.ObjectClass -eq 'Group') {
                    # clear bit 0 from grouptype. this bit signals 'builtin' which [ADGroupCategory] does not know.
                    $this.GroupScope = ([GroupType] $Object.Properties['groupType'].Item(0) -band 0x0000FFFE).ToString()
                    $this.GroupCategory = ([GroupType] $Object.Properties['groupType'].Item(0) -band 0xFFFF0000).ToString()
                    If ($this.GroupCategory -ne 'Security') {
                        $this.GroupCategory = [ADGroupCategory]::Distribution
                    }
                } else {
                    $this.GroupCategory = $null
                    $this.GroupScope = $null
                }
                if ($object.Properties.Contains('objectSid')) {
                    $this._ObjectSid = [SecurityIdentifier]::new($object.Properties['objectSid'].Item(0), 0)
                } elseif ($object.Properties.Contains('msDS-ShadowPrincipalSid')) {
                    $this._ObjectSid = [SecurityIdentifier]::new($object.Properties['msDS-ShadowPrincipalSid'].Item(0), 0)
                } else {
                    $this._ObjectSid = $null
                }
                break
            }
            default {
                # handling all objects that result from AD cmdlets. These have different properties than ADSI objects.
                $this.Name = $Object.Name
                $this._DistinguishedName = $Object.DistinguishedName
                $this.SamAccountName = $Object.SamAccountName
                $this.ObjectGuid = $Object.ObjectGuid
                $this.ObjectClass = $Object.ObjectClass
                if ($Object.ObjectClass -eq 'Group') {
                    if (-not [string]::IsNullOrEmpty($Object.GroupType)) {
                        # clear bit 0 from grouptype. this bit signals 'builtin' which [ADGroupCategory] does not know.
                        $this.GroupScope = ([GroupType] $Object.groupType -band 0x0000FFFE).ToString()
                        $this.GroupCategory = ([GroupType] $Object.groupType -band 0xFFFF0000).ToString()
                    } else {
                        $this.GroupScope = $Object.GroupScope
                        $this.GroupCategory = $Object.GroupCategory
                    }
                } else {
                    $this.GroupCategory = $null
                    $this.GroupScope = $null
                }
                if (-not [string]::IsNullOrEmpty($object.SID)) {
                    $this._objectSid = $Object.SID
                } elseif (-not [string]::IsNullOrEmpty($object.objectSid)) {
                    $this._ObjectSid = $Object.ObjectSid
                } elseif (-not [string]::IsNullOrEmpty($object.'msDS-ShadowPrincipalSid')) {
                    $this._ObjectSid = $Object.'msDS-ShadowPrincipalSid'
                } else {
                    $this._ObjectSid = $null
                }
                break
            }
        }
    }

    [String] ToString() {
        Return $this.DistinguishedName
    }
}

[Flags()] enum TrustAttributes {
    NonTransitive           = 0x00000001 # The trust is nontransitive.
    UplevelOnly             = 0x00000002 # The trust exists only with uplevel domains.
    QuarantinedDomain       = 0x00000004 # The trusted domain is quarantined.
    ForestTransitive        = 0x00000008 # The trust is transitive within a forest.
    CrossOrganization       = 0x00000010 # Cross-organization trust.
    WithinForest            = 0x00000020 # The trust is within the same forest.
    TreatAsExternal         = 0x00000040 # The trust is treated as external.
    UsesRc4Encryption       = 0x00000080 # RC4 encryption is used for the trust.
    UsesAesKeys             = 0x00000100 # AES encryption is used for the trust.
    CrossOrganizationNoTGTDelegation = 0x00000200 # Tickets for this trust must not be enabled for delegation.
    PIMTrust                = 0x00000400 # Privileged identity management trust.
    CrossOrganizationEnableTGTDelegation   = 0x00000800 # Tickets for this trust must be enabled for delegation.
    DisableTargetValidation = 0x00001000 # domain name validation during NTLM pass-through authentication is disabled.
}

[Flags()] enum GroupType {
    Distribution      = 0x00000000
    Builtin           = 0x00000001
    Global            = 0x00000002
    DomainLocal       = 0x00000004
    Universal         = 0x00000008
    AppBasic          = 0x00000010
    AppQuery          = 0x00000020
    Security          = 0x80000000
}

<#
.SYNOPSIS
    Extends Write-Verbose/Write-Warning/Write-Debug with caller information
#>
Function Write-Verbose {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [String] $Message
    )
    process {
        $Prefix = '[GLOBAL]:'
        try {
            $CallStack = Get-PSCallStack
            if ($CallStack.Count -gt 1) {
                $Caller = $CallStack[1]
                $Prefix = "$($Caller.FunctionName)#$($Caller.ScriptLineNumber):"
                if ($Caller.ScriptName) {
                    $Prefix = "$(Split-Path $Caller.ScriptName -Leaf)\" + $Prefix
                }
            }
        } catch {
            # leave $Prefix as [GLOBAL]: on error
        }
        Microsoft.PowerShell.Utility\Write-Verbose "$Prefix $Message"
    }
}

Function Write-Warning {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [String] $Message
    )
    process {
        $Prefix = '[GLOBAL]:'
        try {
            $CallStack = Get-PSCallStack
            if ($CallStack.Count -gt 1) {
                $Caller = $CallStack[1]
                $Prefix = "$($Caller.FunctionName)#$($Caller.ScriptLineNumber):"
                if ($Caller.ScriptName) {
                    $Prefix = "$(Split-Path $Caller.ScriptName -Leaf)\" + $Prefix
                }
            }
        } catch {
            # leave $Prefix as [GLOBAL]: on error
        }
        Microsoft.PowerShell.Utility\Write-Warning "$Prefix $Message"
    }
}

Function Write-Debug {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [String] $Message
    )
    begin {
        # trickery with debug/confirm - with -debug, DebugPreference is set to Inquire which triggers confirmations for each Write-Debug
        # https://github.com/PowerShell/PowerShell/issues/16158
        if ($DebugPreference -ne [ActionPreference]::SilentlyContinue) {
            $DebugPreference = [ActionPreference]::Continue
        }
    }
    process {
        $Prefix = '[GLOBAL]:'
        try {
            $CallStack = Get-PSCallStack
            if ($CallStack.Count -gt 1) {
                $Caller = $CallStack[1]
                $Prefix = "$($Caller.FunctionName)#$($Caller.ScriptLineNumber):"
                if ($Caller.ScriptName) {
                    $Prefix = "$(Split-Path $Caller.ScriptName -Leaf)\" + $Prefix
                }
            }
        } catch {
            # leave $Prefix as [GLOBAL]: on error
        }
        Microsoft.PowerShell.Utility\Write-Debug "$Prefix $Message"
    }
}

<#
.SYNOPSIS
    Logs detailed error information to the error stream and optionally to the Windows Event Log.
.DESCRIPTION
    Collects error details, including information about the error record, formats a comprehensive message, and writes it to the error stream.
.PARAMETER ErrorRecord
    The error record that triggered the event.
.PARAMETER InvocationInfo
    The invocation information (from $MyInvocation or $PSCmdlet.MyInvocation) for context.
.EXAMPLE
    try {
        # some code
    } catch {
        New-ErrorEvent -ErrorRecord $_ -InvocationInfo $MyInvocation -LogEvent
    }
#>
Function New-ErrorEvent {
    [CmdletBinding()]
    Param(
        # the error that raised the event
        [Parameter(Mandatory=$true)]
        [ErrorRecord] $ErrorRecord,

        # the function/script that raised the event
        [Parameter(Mandatory=$true)]
        [InvocationInfo] $InvocationInfo
    )
    process {
        $ItemDetails = [ordered] @{}
        # Extract HResult and error details
        $ErrorDetails = $ErrorRecord.Exception
        $HResult = $null
        if ($ErrorRecord.InnerException -and $ErrorRecord.InnerException.HResult) {
            $HResult = $ErrorRecord.InnerException.HResult
            $ErrorDetails = $ErrorRecord.InnerException
        } elseif ($ErrorRecord.Exception -and $ErrorRecord.Exception.HResult) {
            $HResult = $ErrorRecord.Exception.HResult
        } elseif ($ErrorRecord.HResult) {
            $HResult = $ErrorRecord.HResult
        }
        if ($HResult) {
            $ItemDetails['HResult'] = ('0x{0:X}' -f $HResult)
        }

        # Format summary
        $Summary = ''
        if ($ItemDetails.Count) {
            $Summary = ([PSCustomObject] $ItemDetails | Format-List | Out-String).Trim()
        }

        # Invocation context
        $InvocationCommand = '<unknown>'
        if ($InvocationInfo -and $InvocationInfo.MyCommand) {
            $InvocationCommand = $InvocationInfo.MyCommand.ToString()
        }

        $ScriptStackTrace = ''
        if ($ErrorRecord.ScriptStackTrace) {
            $ScriptStackTrace = $ErrorRecord.ScriptStackTrace
        }

        $ErrorText = ''
        if ($ErrorRecord) {
            $ErrorText = $ErrorRecord | Out-String
        }

        # Compose message
        $Message = "Error in function/script '$InvocationCommand'!`r`n"
        if ($Summary) {
            $Message += "`r`n$Summary`r`n"
        }
        if ($ErrorText) {
            $Message += "`r`n$ErrorText"
        }
        if ($ScriptStackTrace) {
            $Message += "`r`n$ScriptStackTrace"
        }
        if ($ErrorDetails) {
            $Message += "`r`n$ErrorDetails"
        }
        $Message = $Message.Trim()

        # Write to error stream
        Write-Error -Message $Message
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
    param (
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
        if ($Server -notmatch $RootDomain.Split('.')[0]) {
            # our domain is not the forest root domain - we need not only trusts for our own domain, but also for the forest
            $Trusts += @((Get-ADTrust -Filter "(Direction -ne '$ExcludedTrustDirection' -and Direction -ne 'Disabled')" -Server $RootDomain -ErrorAction $TrustErrorAction))
        }

        # filter out orphaned trusts that do no longer work, but might still exist...
        [array] $Trusts = $Trusts | Select-Object -Unique | Sort-Object -Property Name

        # first, get all forests that we trust or trust us
        [array] $Forests = foreach ($Trust in $Trusts) {
            Write-Verbose "Retrieving forest for '$Trust'"
            try {
                Get-ADForest $Trust.Name | Add-Member -NotePropertyName 'TrustAttributes' -NotePropertyValue ([TrustAttributes] $Trust.TrustAttributes) -Force -PassThru
            } catch [ADIdentityNotFoundException] {
                # ignore non-existing forests...
                Write-Warning "Error in '$Server' handling forest '$($Trust.Name)':"
                Write-Warning $_.Exception.Message
            } catch [AuthenticationException] {
                # ignore broken forest trusts...
                Write-Warning "Error in '$Server' handling forest '$($Trust.Name)':"
                Write-Warning $_.Exception.Message
            } catch {
                # error - we don't know what went wrong if we reach here...
                Write-Warning "Error in '$Server' handling forest '$($Trust.Name)':"
                New-ErrorEvent -ErrorRecord $_ -InvocationInfo $MyInvocation -ErrorAction $TrustErrorAction
            }
        }

        # then get the domains for these forests. We need domains because of domain SIDs which
        # we can map to foreign security principals and shadow principals
        [array] $Domains = foreach ($Forest in $Forests | Sort-Object -Property Name) {
            $TrustAttributes = [TrustAttributes] $Forest.TrustAttributes
            foreach ($Domain in $Forest.Domains | Sort-Object) {
                Write-Verbose "Retrieving domain '$Domain' in forest '$Forest'"
                try {
                    Get-ADDomain $Domain | Add-Member -NotePropertyName 'TrustAttributes' -NotePropertyValue $TrustAttributes -Force -PassThru
                } catch [ADIdentityNotFoundException] {
                    # ignore non-existing domains...
                    Write-Warning "Error in '$Server' handling domain '$($Domain)':"
                    Write-Warning $_.Exception.Message
                } catch [AuthenticationException] {
                    # ignore broken domain trusts...
                    Write-Warning "Error in '$Server' handling domain '$($Domain)':"
                    Write-Warning $_.Exception.Message
                } catch {
                    # error - we don't know what went wrong if we reach here...
                    Write-Warning "Error in '$Server' handling domain '$($Domain)':"
                    New-ErrorEvent -ErrorRecord $_ -InvocationInfo $MyInvocation -ErrorAction $TrustErrorAction
                }
            }
        }

        Write-Verbose "Current forest root: '$Rootdomain' ($($Trusts.Count) trusts, $($Domains.Count) domains)."

        # create hashtable of domain SIDs to quickly retrieve the domain a foreign security principal belongs to
        $DomainSIDs = @{}
        foreach ($Domain in $Domains) {
            $DomainSIDs[ $Domain.DomainSID.Value ] = $Domain
        }
        return $DomainSIDs
    }
}

<#
.SYNOPSIS
    Helper function to traverse the member/memberof attribute. Faster than LDAP matching rule in chain if the target domain is huge and the memberships are small
    Returns an array of distinguished names
.PARAMETER ADObject
    The base object from which to traverse member(of) as an [ADObject]
.PARAMETER ADSI
    The base object from which to traverse member(of) as a [DirectoryEntry]
.PARAMETER DN
    The base object from which to traverse member(of) as a [String] distinguished name
.PARAMETER Attribute
    The attribute to traverse (member/memberof)
.PARAMETER Server
    The domain/server to operate against. If omitted, is derived from the base object distinguished name
#>
function Get-ADAttributeChain {
    [CmdletBinding(DefaultParametersetName='ADObject')]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,ParametersetName='ADObject')]
        [ADObject] $ADObject,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,ParametersetName='DirectoryEntry')]
        [ADSI] $ADSI,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0,ParametersetName='DistinguishedName')]
        [String] $DN,

        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet('member','memberof')]
        [String] $Attribute,

        [ValidateScript({[URI]::CheckHostName($_).Value__ -gt 1})]
        [String] $Server,

        [Switch] $Recursing
    )
    process {
        If (-not $PSBoundParameters.ContainsKey('Recursing')){
            # global results hashtable to avoid duplicates and looping due to circular group nesting
            $_Results = [ordered] @{}
        }

        Switch ($PSCmdlet.ParameterSetName){
            'ADObject' {
                $DN = $ADObject.DistinguishedName
                Write-Debug "DN from ADObject: $DN"
                break
            }
            'DirectoryEntry' {
                $DN = $ADSI.DistinguishedName
                Write-Debug "DN from ADSI: $DN"
                break
            }
            default {
                Write-Debug "DN provided directly: $DN"
                #nothing to do - we only have 3 parametersets, so third must be DN already
            }
        }

        If (-not $PSBoundParameters.ContainsKey('Server')){
            $Server = ($DN -split ',DC=',2)[1].Replace(',DC=','.').ToUpper()
            Write-Debug "Server from DN: $Server"
        }

        $DE = [adsi] "LDAP://$Server/$DN"
        If ($_Results.Keys -contains $DN){
            Write-Debug "Skipping, $DN already visited."
        } ElseIf ($DN -match 'CN=Shadow Principal Configuration,CN=Services,CN=Configuration'){
            Write-Debug "Skipping, $DN is a shadow principal."
        } Else {
            $_Results[ $DN ] = $DE
            Foreach ($Tree in $DE.$Attribute){
                Write-Debug "$DN - Following $Attribute for $Tree"
                . Get-ADAttributeChain $Tree -Attribute $Attribute -Server $Server -Recursing
            }
        }
        If (-not $PSBoundParameters.ContainsKey('Recursing')){
            # remove first element which is the account we are evaluating itself
            $Results = $_Results.Values | Select-Object -Skip 1
            Remove-Variable _Results
            Return $Results
        }
    }
}

<#
.SYNOPSIS
    Helper function to remove all parameters from a parameter hashtable that the specified Cmdlet does not have.
#>
function Sanitize-BoundParameters {
    [CmdletBinding()]
    param(
        [String] $CmdletName,
        [hashtable] $Parameters
    )
    $CmdletParameters = (Get-Command $CmdletName).Parameters
    $Results = @{}
    foreach ($Key in $Parameters.Keys) {
        if ($CmdletParameters.ContainsKey($Key)) {
            $Results[$Key] = $Parameters[$Key]
        }
    }
    return $Results
}

<#
.SYNOPSIS
    Gets the Active Directory groups that an AD principal is a member of.
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
    Get all nested memberships of the principal object recursively.
.PARAMETER IncludeTrusts
    Searches for shadow principals and foreign security principals in all trusting domains.
.PARAMETER ExcludeShadowPrincipals
    Do not resolve or enumerate shadow principals.
.PARAMETER ExcludeForeignSecurityPrincipals
    Do not resolve or enumerate foreign security principals.
.PARAMETER IgnoreTrustErrors
    Ignore failing trusts when ErrorAction is 'Stop'.
.PARAMETER Depth
    If memberships should be evaluated across more than one trust level, specify the number of levels to traverse. Defaults to 1 (will only resolve in direct trusts)
.PARAMETER UseLDAPChainFilter
    Enables member:1.2.840.113556.1.4.1941 LDAP matching rule in chain for membership evaluation instead of following memberof attributes. The LDAP filter is slow in large domains, but fast when a lot of memberships are evaluated.
    LDAP matching rule in chain filter 
.INPUTS
    Microsoft.ActiveDirectory.Management.ADPrincipal
    A principal object that represents a user, computer or group is received by the Identity parameter. Derived types, such as the following are also received by this parameter.
.OUTPUTS
    ADCustomObject
    Returns objects that have the specified user, computer, group or service account as a member.
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
.LINK
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
function Get-ADPrincipalGroupMembership2 {
    [CmdletBinding(DefaultParameterSetName='NonRecursive')]
    [Alias('Get-ADPrincipalGroupMembership','gpgm')]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ADPrincipal] $Identity,
        [ADAuthType] $AuthType = [ADAuthType]::Negotiate,
        [PSCredential] $Credential,
        [String] $Partition,
        [String] $Server,
        [Parameter(ParameterSetName='Recursive',Mandatory=$true)]
        [Switch] $Recursive,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('ITD')]
        [Switch] $IncludeTrusts,
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
        [Int] $Depth = 1,
        [Switch] $UseLDAPChainFilter
    )
    begin {
        if ($IncludeTrusts -and $Depth -gt 0) {
            # only populate globally if a server was explicitly specified
            if ($PSBoundParameters.ContainsKey('Server')) {
                # We need all trusting domains - in all of them, we can be direct or indirect member...
                $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Outbound) -IgnoreTrustErrors:$IgnoreTrustErrors
            }
        } else {
            $IncludeTrusts = $false
            $Depth = 0
        }
      
        # create parameter hash for Get-ADObject from what was passed to us, strip additional parameters the AD cmdlets cannot handle
        $GetADParams = Sanitize-BoundParameters -CmdletName 'Get-ADObject' -Parameters $PSBoundParameters
    }
  
    process {
        trap {
            New-ErrorEvent -ErrorRecord $_ -InvocationInfo $MyInvocation
            break
        }

        Write-Debug "Parameters passed:"
        $PSBoundParameters | Out-String | Write-Debug

        if ($PSBoundParameters.ContainsKey('Server')) {
            # nothing to do in this case
        } elseif ($Identity.ToString() -match 'CN=.+?(,DC=)(?<DomainDN>.+)') {
            # check if $Identity can be parsed as a distinguished name. If yes and no $server is specified, extract $server from the DN
            Write-Debug "Deriving target server from '$Identity'"
            $Server = $Matches.DomainDN.Replace(',DC=','.')
        } else {
            $Server = $env:USERDNSDOMAIN
        }
        $GetADParams['Server'] = $Server

        # remove 'Identity' - identity will be provided explicitly in each call to AD cmdlets/ADSI
        [void] $GetADParams.Remove('Identity')

        Write-Verbose "Checking for group memberships of '$Identity' in '$Server'"

        # ldap filter matching rule in chain needs a distinguished name, but ADPrincipal could also be a Sid/Guid only... So first let's get a proper AD object.
        Write-Debug "Resolving '$Identity' to principal..."
        $ADPrincipal = Get-ADObject $Identity -Properties * @GetADParams
        Write-Debug "Identity resolved: '$ADPrincipal'"

        if ($ADPrincipal.memberof.Count -eq 0) {
            Write-Verbose "No group memberships found for '$ADPrincipal' in '$($GetADParams['Server'])'."
            If (-not $IncludeTrusts){
                # early finish - principal is not a member of anything in his own domain, and we don't traverse trusts...
                return
            }
        }

        # check if we already have a $DomainSids hashtable or if we need to refresh it
        If ($DomainSIDs -isnot [Hashtable] -and $IncludeTrusts) {
            Remove-Variable DomainSids -ErrorAction SilentlyContinue
            $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Outbound) -IgnoreTrustErrors:$IgnoreTrustErrors
        }

        # only do a recursive search if $ADPrincipal is member of any group - no sense to search if .memberOf is empty
        if ($Recursive -and -not [string]::IsNullOrEmpty($ADPrincipal.memberOf)) {
            If ($UseLDAPChainFilter){
                # ldap matching rule in chain - get all groups the specified $ADPrincipal DN is a member of recursively.
                $LDAPFilter = "(member:1.2.840.113556.1.4.1941:=$ADPrincipal)"
                Write-Debug "Retrieving recursive group memberships with filter: '$LDAPFilter'"
                $Searcher = [adsisearcher]::new()
                $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])"
                $Searcher.Filter = $LDAPFilter
                $LocalDomainGroups = $Searcher.FindAll()
                $Searcher.Dispose()
            } Else {
                [array] $LocalDomainGroups = Get-ADAttributeChain $ADPrincipal -Attribute memberof -Server $GetADParams['Server']
            }
            Write-Debug "Processing $($LocalDomainGroups.Count) search results."
        } else {
            # Only get the memberOf of $ADPrincipal
            $LocalDomainGroups = Foreach ($MemberOf in $ADPrincipal.memberOf) {
                [adsi] "LDAP://$Server/$MemberOf"
            }
        }

        $ADPrincipal = [ADCustomObject] $ADPrincipal

        $Results = @{}
        $LocalAccountSids = [Collections.Arraylist]::new()
        $ShadowPrincipals = [Collections.Arraylist]::new()
        $ShadowPrincipalDomainSids = @{}   # hashtable storing all domains for which shadow principals were found by sid. Each element contains a nested hashtable with all shadow principals for that domain by sid.

        [void] $LocalAccountSids.Add( $ADPrincipal.ObjectSid )

        # handle groups in the domain of $ADPrincipal
        foreach ($LocalDomainGroup in $LocalDomainGroups) {
            $ADObject = [ADCustomObject] $LocalDomainGroup
            $Results[$ADObject.ObjectGUID] = $ADObject
            # store all local group sids (only needed if -IncludeTrusts)
            [void] $LocalAccountSids.Add($ADObject.ObjectSid)
            # LDAP matching rule in chain does not evaluate shadow principals, so we need to retrieve them from the memberof attribute of all groups we found so far
            # Get-ADAttributeChain also does not evaluate shadow principals, so no code changes needed here
            [void] $ShadowPrincipals.AddRange(@(@(($LocalDomainGroup.Properties['memberof'])) -match 'CN=Shadow Principal Configuration,CN=Services,CN=Configuration'))
        }

        If ($ShadowPrincipals.Count -gt 0) {
            # handle shadow principals in the domain of $ADPrincipal, if any are present, and speed up retrieval of foreign objects through grouping by domain
            # this allows for a single ldap operation to retrieve all shadow principals in a given domain at once instead of fetching them one by one...

            Write-Debug "Retrieving shadow principal objects in domain '$($GetADParams['Server'])'"

            $LDAPFilter = '(|' + $(Foreach($ShadowPrincipal in $ShadowPrincipals | Select-Object -Unique) {"(name=$(($ShadowPrincipal.Substring(3) -split ',CN=')[0]))"}) + ')'
            $SearchBase = "CN=$(($ShadowPrincipal -split ',CN=',2)[1])"

            $Searcher = [adsisearcher]::new()
            $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])/$SearchBase"
            $Searcher.Filter = $LDAPFilter
            $ShadowPrincipalObjects = $Searcher.FindAll()
            $Searcher.Dispose()

            Write-Debug "Found $($ShadowPrincipalObjects.Count) shadow principal objects."

            foreach ($ShadowPrincipalObject in $ShadowPrincipalObjects) {
                Write-Debug "Processing shadow principal '$($ShadowPrincipalObject.Name)'"
                $ADObject = [ADCustomObject] $ShadowPrincipalObject
                $Results[$ADObject.ObjectGUID] = $ADObject
                $ShadowPrincipalSid = $ADObject.ObjectSid
                $ShadowPrincipalDomainSid = $ShadowPrincipalSid.AccountDomainSid.Value
                if (-not $ShadowPrincipalDomainSids.ContainsKey($ShadowPrincipalDomainSid)) {
                    $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid] = @{}
                }
                $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].Add($ShadowPrincipalSid, $ADObject)
            }
        }

        If (-not $IncludeTrusts) {
            Write-Debug 'Finished, no trusting domains to process.'
            return $Results.Values
        }

        If ($ExcludeShadowPrincipals) {
            $ShadowPrincipalDomainSids.Clear()
        }
        If ($ExcludeForeignSecurityPrincipals) {
            $LocalAccountSids.Clear()
        }

        # handle shadow principals - search sid in foreign domain, get members if it is a group.
        foreach ($ShadowPrincipalDomainSid in $ShadowPrincipalDomainSids.Keys) {
            if ($DomainSIDs.ContainsKey($ShadowPrincipalDomainSid)) {
                # we have a domain object from trust enumeration
                $ShadowPrincipalDomain = $DomainSIDs[$ShadowPrincipalDomainSid]
                $GetADParams['Server'] = $ShadowPrincipalDomain.DNSRoot
                Write-Debug "Retrieving shadow principal target accounts in domain '$($GetADParams['Server'])'"
                $LDAPFilter = "(|" + $(Foreach ($ShadowPrincipalSid in $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].Keys) {"(objectSid=$($ShadowPrincipalSid))"}) + ")"
                $Searcher = [adsisearcher]::new()
                $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])"
                $Searcher.Filter = $LDAPFilter
                $ShadowPrincipalTargetAccounts = $Searcher.FindAll()
                $Searcher.Dispose()
                $ADObjectDNs = [Collections.Arraylist]::new()
                foreach ($ShadowPrincipalTargetAccount in $ShadowPrincipalTargetAccounts) {
                    $ADObject = [ADCustomObject] $ShadowPrincipalTargetAccount
                    $SourceAccount = $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].$($ADObject.ObjectSid)
                    Write-Debug "Found shadow principal TargetAccount '$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)' for '$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)'"
                    $Results[$ADObject.ObjectGuid] = [ADCustomObject] $ADObject
                    $Results[$ADObject.ObjectGuid].TargetAccount += "$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)"
                    $Results[$SourceAccount.objectGuid].TargetAccount += "$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)"
                    [void] $ADObjectDNs.Add($ADObject.DistinguishedName)
                }
                # groups these target accounts are a member of
                Write-Debug "Retrieving shadow principal group memberships in domain '$($GetADParams['Server'])'"
                $ForeignGroupMemberships = @(($ADObjectDNs | Get-ADPrincipalGroupMembership -Recursive:$Recursive -IncludeTrusts:$IncludeTrusts -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                foreach ($ForeignGroupMembership in $ForeignGroupMemberships) {
                    Write-Debug "Adding foreign group membership '$($ForeignGroupMembership.Name)' in domain '$($GetADParams['Server'])'"
                    $Results[$ForeignGroupMembership.objectGuid] = $ForeignGroupMembership
                }
            } else {
                # we did not find a domain for the current shadow principal domain SID
                $AffectedPrincipals = [Collections.Arraylist]::new()
                Foreach ($Key in $ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].Keys) {
                    [void] $AffectedPrincipals.Add($ShadowPrincipalDomainSids[$ShadowPrincipalDomainSid].$Key.Name)
                }
                $Err = [ADIdentityNotFoundException]::new("Cannot resolve shadow principal SIDs for domain SID '$ShadowPrincipalDomainSid' - SID not found in domain trusts of '$Server'. Affected principals: $($AffectedPrincipals -join ',')")
                $ErrorRecord = [ErrorRecord]::new($Err,'Domain Sid lookup error', [ErrorCategory]::ObjectNotFound, $ShadowPrincipalDomainSid)
                New-ErrorEvent -ErrorRecord $ErrorRecord -InvocationInfo $MyInvocation
            }
        }

        # handle local domain group sids - any of these can be a foreign security principal in any trusting domain
        if ($LocalAccountSids.Count -gt 0) {
            # build a LDAP filter to query all sids at once - makes a quite long filter, but only one AD query per domain
            $LDAPFilter = "(|" + $(Foreach ($LocalAccountSid in $LocalAccountSids) {"(name=$($LocalAccountSid))"}) + ")"
            foreach ($Domain in $DomainSIDs.Values) {
                $GetADParams['Server'] = $Domain.DNSRoot
                Write-Verbose "Checking for foreign security principals in domain '$($GetADParams['Server'])'"
                # we have to query all domains for all SIDs of all local groups...
                $Searcher = [adsisearcher]::new()
                $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])"
                $Searcher.Filter = $LDAPFilter
                $FSPTargetAccounts = $Searcher.FindAll()
                $Searcher.Dispose()
                if ($FSPTargetAccounts.Count -gt 0) {
                    $FSPTargetDNs = [Collections.Arraylist]::new()
                    foreach ($FSPTargetAccount in $FSPTargetAccounts) {
                        $ADObject = [ADCustomObject] $FSPTargetAccount
                        $Results[$ADObject.ObjectGUID] = $ADObject
                        $SourceAccount = $Results.Values + $ADPrincipal | Where-Object {$_.ObjectSid -eq $ADObject.objectSid -and $_.objectClass -ne 'ForeignSecurityPrincipal'}
                        if ($SourceAccount) {
                            Write-Debug "Found FSP TargetAccount '$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)' for '$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)'"
                            $Results[$ADObject.ObjectGUID].TargetAccount += "$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)"
                            [void] $FSPTargetDNs.Add($ADObject.DistinguishedName)
                            if ($Results.ContainsKey($SourceAccount.ObjectGuid)) {
                                $Results[$SourceAccount.ObjectGuid].TargetAccount += "$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)"
                            }
                        }
                    }
                    # get all groups these FSPs are a member of in the target domain
                    $ForeignGroupMemberships = @(($FSPTargetDNs | Get-ADPrincipalGroupMembership -Recursive:$Recursive -IncludeTrusts:$IncludeTrusts -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                    foreach ($ForeignGroupMembership in $ForeignGroupMemberships) {
                        Write-Debug "Adding foreign group membership '$($ForeignGroupMembership.Name)' in domain '$($GetADParams['Server'])'"
                        $Results[$ForeignGroupMembership.objectGuid] = $ForeignGroupMembership
                    }
                }
            }
        }
        return $Results.Values
    }
}


<#
.SYNOPSIS
    Gets the members of an Active Directory group.
.DESCRIPTION
    The Get-ADGroupMember cmdlet gets the members of an Active Directory group. Members can be users, groups, and computers.
    
    The Identity parameter specifies the Active Directory group to access. You can identify a group by its distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name. You can also specify the group by passing a group object through the pipeline. For example, you can use the Get-ADGroup cmdlet to retrieve a group object and then pass the object through the pipeline to the Get-ADGroupMember cmdlet.
    
    If the Recursive parameter is specified, the cmdlet gets all members in the hierarchy of the group within the domain of the group. If the IncludeTrusts parameter is specified, the function traverses all trusted domains to resolve foreign security principals and in the case of a PAM trust, also shadow principals.
    
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
    Get all nested members of the group recursively.
.PARAMETER Server
    Specifies the Active Directory Domain Services instance to connect to, by providing one of the following values for a corresponding domain name or directory server. The service may be any of the following:  Active Directory Lightweight Domain Services, Active Directory Domain Services or Active Directory Snapshot instance.
.PARAMETER IncludeTrusts
    Searches for shadow principals and foreign security principals in all trusted domains.
.PARAMETER ExcludeShadowPrincipals
    Do not resolve or enumerate shadow principals.
.PARAMETER ExcludeForeignSecurityPrincipals
    Do not resolve or enumerate foreign security principals.
.PARAMETER IgnoreTrustErrors
    Ignore failing trusts when ErrorAction is 'Stop'.
.PARAMETER Depth
    Specify the number of trusts to traverse with IncludeTrusts. Defaults to 1 (will only resolve in direct trusts)
.PARAMETER UseLDAPChainFilter
    Enables member:1.2.840.113556.1.4.1941 LDAP matching rule in chain for membership evaluation instead of following memberof attributes. The LDAP filter is slow in large domains, but fast when a lot of memberships are evaluated.
    LDAP matching rule in chain filter 
.INPUTS
    None or Microsoft.ActiveDirectory.Management.ADGroup
    A group object is received by the Identity parameter
.OUTPUTS
    ADCustomObject
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
.LINK
    Online Version: http://go.microsoft.com/fwlink/p/?linkid=291033
    Add-ADGroupMember
    Add-ADPrincipalGroupMembership
    Get-ADGroup
    Get-ADPrincipalGroupMembership
    Remove-ADGroupMember
    Remove-ADPrincipalGroupMembership
#>
function Get-ADGroupMember2 {
    [CmdletBinding(DefaultParameterSetName='NonRecursive')]
    [Alias('Get-ADGroupMember','ggm')]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [ADGroup] $Identity,

        [ADAuthType] $AuthType = [ADAuthType]::Negotiate,
        [PSCredential] $Credential,
        [String] $Partition,
        [String] $Server,

        [Parameter(ParameterSetName='Recursive',Mandatory=$true)]
        [Switch] $Recursive,
        [Parameter(ParameterSetName='Recursive')]
        [Alias('ITD')]
        [Switch] $IncludeTrusts,
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
        [Int] $Depth = 1,
        [Switch] $UseLDAPChainFilter
    )
    begin {
        if ($IncludeTrusts -and $Depth -gt 0) {
            # only create DomainSids hash here if a server was explicitly passed
            if ($PSBoundParameters.ContainsKey('Server')) {
                # We need all trusted domains - in all of them, we can be direct or indirect member...
                $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Inbound) -IgnoreTrustErrors:$IgnoreTrustErrors
            }
        } else {
            $IncludeTrusts = $false
            $Depth = 0
        }
        
        # create parameter hash for Get-ADObject/Get-ADGroup
        $GetADParams = Sanitize-BoundParameters -CmdletName 'Get-ADObject' -Parameters $PSBoundParameters
    }
    process {
        trap {
            New-ErrorEvent -ErrorRecord $_ -InvocationInfo $MyInvocation
            break
        }

        Write-Debug "Parameters passed:"
        $PSBoundParameters | Out-String | Write-Debug

        if ($PSBoundParameters.ContainsKey('Server')) {
            # nothing to do here
        } elseif ($Identity.ToString() -match 'CN=.+?(,DC=)(?<DomainDN>.+)') {
            # check if $Identity can be parsed as a distinguished name. If yes and $server is not specified, extract $server from the DN
            Write-Debug "Deriving target server from '$Identity'"
            $Server = $Matches.DomainDN.Replace(',DC=','.')
        } else {
            $Server = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
        }

        # add 'server' explicitly - if not provided as a parameter, the default $env:COMPUTERDNSDOMAIN will not be in $PSBoundParameters
        $GetADParams['Server'] = $Server

        # remove 'Identity - will be provided explicitly for all calls of AD cmdlets
        [void] $GetADParams.Remove('Identity')

        Write-Verbose "Checking for group members of '$Identity' in '$Server'"

        # ldap filter matching rule in chain needs a distinguished name, but ADGroup could also be a Sid/Guid only... So first let's get a proper AD object.
        Write-Debug "Resolving '$Identity' to principal..."
        $ADPrincipal = Get-ADGroup $Identity -Properties * @GetADParams
        Write-Debug "Identity resolved: '$ADPrincipal'"

        if ($ADPrincipal.member.Count -eq 0) {
            Write-Verbose "'$Identity' has no members."
            If (-not $IncludeTrusts){
                # Identity has no members and we don't traverse across trusts, so we are done.
                Return
            }
        }

        # check if we already have a $DomainSids hashtable or if we need to refresh it
        if ($DomainSIDs -isnot [Hashtable] -and $IncludeTrusts) {
            Remove-Variable DomainSids -ErrorAction SilentlyContinue
            $DomainSIDs = Get-DomainSIDs -Server $Server -ExcludedTrustDirection ([ADTrustDirection]::Inbound) -IgnoreTrustErrors:$IgnoreTrustErrors
        }

        if ($Recursive -and -not [string]::IsNullOrEmpty($ADPrincipal.member)) {
            If ($UseLDAPChainFilter){
                # ldap matching rule in chain - get all principals that are a member of the specified $ADPrincipal recursively.
                $LDAPFilter = "(memberOf:1.2.840.113556.1.4.1941:=$ADPrincipal)"
                Write-Debug "Retrieving recursive group members with filter: '$LDAPFilter'"
                $Searcher = [adsisearcher]::new()
                $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])"
                $Searcher.Filter = $LDAPFilter
                $LocalGroupMembers = $Searcher.FindAll()
                $Searcher.Dispose()
            } Else {
                [array] $LocalGroupMembers = Get-ADAttributeChain $ADPrincipal -Attribute member
            }
            Write-Debug "Processing $($LocalGroupMembers.Count) search results."
        } else {
            # Only get member of $ADPrincipal
            $LocalGroupMembers = Foreach ($Member in $ADPrincipal.member) {
                [adsi] "LDAP://$($GetADParams['Server'])/$Member"
            }
        }

        $ADPrincipal = [ADCustomObject] $ADPrincipal

        $Results = @{}
        $FSPDomainSids = @{}
        $LocalAccountSids = [Collections.Arraylist]::new()

        # store all SIDs of local groups to check if they belong to a shadow principal in any trusted domain
        [void] $LocalAccountSids.Add($ADPrincipal.objectSid)

        foreach ($LocalGroupMember in $LocalGroupMembers | Sort-Object) {
            $ADObject = [ADCustomObject] $LocalGroupMember
            $Results[$ADObject.objectGuid] = $ADObject
            [void] $LocalAccountSids.Add($ADObject.objectSID)
            if ($ADObject.ObjectClass -eq 'foreignSecurityPrincipal' -and $IncludeTrusts) {
                # handle FSPs separately - we want the resolved ones if possible and the unresolved if resolution fails
                $FSPSid = $ADObject.objectSid
                $FSPDomainSid = $ADObject.objectSid.AccountDomainSid.Value
                if (-not $FSPDomainSids.ContainsKey($FSPDomainSid)) {
                    $FSPDomainSids[$FSPDomainSid] = @{}
                }
                $FSPDomainSids[$FSPDomainSid].Add($FSPSid, $ADObject)
            }
        }

        if (-not $IncludeTrusts) {
            return $Results.Values | Sort-Object -Property objectClass -Descending
        }

        if ($ExcludeShadowPrincipals) {
            $LocalAccountSids.Clear()
        }
        if ($ExcludeForeignSecurityPrincipals) {
            $FSPDomainSids.Clear()
        }

        # handle foreign security principals
        foreach ($FSPDomainSid in $FSPDomainSids.Keys) {
            if ($DomainSIDs.ContainsKey($FSPDomainSid)) {
                # we have a domain object from trust enumeration
                $FSPDomain = $DomainSIDs[$FSPDomainSid]
                $GetADParams['Server'] = $FSPDomain.DNSRoot
                Write-Debug "Retrieving foreign security principal target accounts in domain '$($GetADParams['Server'])'"
                # create LDAP filter to retrieve all FSPs with one query
                $LDAPFilter = "(|" + $(Foreach ($FSPSid in $FSPDomainSids[$FSPDomainSid].Keys) {"(objectSid=$($FSPSid))"}) + ")"
                $Searcher = [adsisearcher]::new()
                $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])"
                $Searcher.Filter = $LDAPFilter
                $FSPTargetAccounts = $Searcher.FindAll()
                $Searcher.Dispose()
                $FSPTargetDNs = [Collections.Arraylist]::new()
                foreach ($FSPTargetAccount in $FSPTargetAccounts) {
                    $ADObject = [ADCustomObject] $FSPTargetAccount
                    $Results[$ADObject.objectGuid] = $ADObject
                    $SourceAccount = $Results.Values + $ADPrincipal | Where-Object {$_.objectSid -eq $ADObject.objectSid -and $_.objectClass -eq 'ForeignSecurityPrincipal'}
                    if ($SourceAccount) {
                        Write-Debug "Found FSP TargetAccount '$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)' for '$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)'"
                        $Results[$ADObject.objectGuid].TargetAccount = "$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)"
                        if ($Results.ContainsKey($SourceAccount.ObjectGuid)) {
                            $Results[$SourceAccount.ObjectGuid].TargetAccount += "$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)"
                        }
                    }
                    # if the FSP is a group, we need to retrieve members
                    if ($ADObject.ObjectClass -eq 'Group') {
                        [void] $FSPTargetDNs.Add($ADObject.DistinguishedName)
                    }
                }
                Write-Debug "Retrieving foreign security principal group members in domain '$($GetADParams['Server'])'"
                $ForeignGroupMembers = @(($FSPTargetDNs | Get-ADGroupMember -Recursive:$Recursive -IncludeTrusts:$IncludeTrusts -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                foreach ($ForeignGroupMember in $ForeignGroupMembers) {
                    Write-Debug "Adding foreign security principal group member '$($ForeignGroupMember.Name)' in domain '$($GetADParams['Server'])'"
                    $Results[$ForeignGroupMember.objectGuid] = $ForeignGroupMember
                }
            } else {
                # we did not find a domain for the current FSP domain SID
                $AffectedPrincipals = [Collections.Arraylist]::new()
                foreach ($Key in $FSPDomainSids[$FSPDomainSid].Keys) {
                    [void] $AffectedPrincipals.Add($FSPDomainSids[$FSPDomainSid].$Key.Name)
                }
                $Err = [ADIdentityNotFoundException]::new("Cannot resolve shadow principal SIDs for domain SID '$FSPDomainSid' - SID not found in domain trusts of '$($GetADParams['Server'])'. Affected principals: $($AffectedPrincipals -join ',')")
                $ErrorRecord = [ErrorRecord]::new($Err,'Domain Sid lookup error', [ErrorCategory]::ObjectNotFound, $FSPDomainSid)
                New-ErrorEvent -ErrorRecord $ErrorRecord -InvocationInfo $MyInvocation
            }
        }

        # handle shadow principals - create LDAP filter to query all shadow principals at once
        $LDAPFilter = '(|' + $(Foreach ($LocalAccountSid in $LocalAccountSids) {"(msDS-ShadowPrincipalSid=$($LocalAccountSid))"}) + ')'
        foreach ($Domain in $DomainSIDs.Values | Where-Object {$_.TrustAttributes -band [TrustAttributes]::PIMTrust}) {
            # we have to query all domains for all SIDs of all local groups...
            $GetADParams['Server'] = $Domain.DNSRoot
            Write-Verbose "Checking for shadow principals in domain '$($GetADParams['Server'])'"
            $Searcher = [adsisearcher]::new()
            $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])/CN=Shadow Principal Configuration,CN=Services,CN=Configuration,$Domain"
            $Searcher.Filter = $LDAPFilter
            $ShadowPrincipalObjects = $Searcher.FindAll()
            $Searcher.Dispose()
            $ShadowPrincipalMemberDNs = [Collections.Arraylist]::new()
            foreach ($ShadowPrincipalObject in $ShadowPrincipalObjects) {
                $ADObject = [ADCustomObject] $ShadowPrincipalObject
                $Results[$ADObject.ObjectGuid] = $ADObject
                $SourceAccount = $Results.Values + $ADPrincipal | Where-Object {$_.ObjectSid -eq $ADObject.ObjectSid -and $_.ObjectClass -ne 'msDS-ShadowPrincipal'}
                if ($SourceAccount) {
                    Write-Debug "Found shadow principal TargetAccount '$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)' for '$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)'"
                    $Results[$ADObject.ObjectGuid].TargetAccount += "$($SourceAccount.Domain.Split('.')[0])\$($SourceAccount.Name)"
                    if ($Results.ContainsKey($SourceAccount.ObjectGuid)) {
                        $Results[$SourceAccount.ObjectGuid].TargetAccount += "$($ADObject.Domain.Split('.')[0])\$($ADObject.Name)"
                    }
                }
                $ShadowPrincipalMemberDNs.AddRange(@($ShadowPrincipalObject.Properties['Member']))
            }
            if ($ShadowPrincipalMemberDNs.Count -gt 0) {
                # create LDAP filter to query all shadow principal members at once
                $ShadowMembersLDAPFilter = '(|' + $(Foreach ($ShadowPrincipalMember in $ShadowPrincipalMemberDNs | Select-Object -Unique) {"(name=$(($ShadowPrincipalMember.SubString(3) -split ',')[0]))"}) + ')'
                $Searcher = [adsisearcher]::new()
                $Searcher.SearchRoot = [adsi] "LDAP://$($GetADParams['Server'])"
                $Searcher.Filter = $ShadowMembersLDAPFilter
                $ShadowPrincipalMembers = $Searcher.FindAll()
                $Searcher.Dispose()
                foreach ($ShadowPrincipalMember in $ShadowPrincipalMembers) {
                    $ADObject = [ADCustomObject] $ShadowPrincipalMember
                    $Results[$ADObject.objectGuid] = $ADObject
                    if ($ADObject.ObjectClass -eq 'Group') {
                        Write-Debug "Retrieving members of shadow principals in domain '$($GetADParams['Server'])'."
                        $ForeignGroupMembers = @(($ADObject.DistinguishedName | Get-ADGroupMember -Recursive:$Recursive -IncludeTrusts:$IncludeTrusts -IgnoreTrustErrors:$IgnoreTrustErrors -Depth ($Depth - 1) @GetADParams))
                        foreach ($ForeignGroupMember in $ForeignGroupMembers) {
                            Write-Debug "Adding shadow principal group member '$($ForeignGroupMember.Name)' in domain '$($GetADParams['Server'])'"
                            $Results[$ForeignGroupMember.objectGuid] = $ForeignGroupMember
                        }
                    }
                }
            }
        }
        return $Results.Values | Sort-Object -Property objectClass -Descending
    }
}


If ($MyInvocation.MyCommand -match 'PSM1$') {
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
