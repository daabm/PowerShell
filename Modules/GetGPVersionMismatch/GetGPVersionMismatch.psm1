<#
.SYNOPSIS

Retrieves GPOs in a domain. For each GPO, it determines user and computer versions in AD and sysvol.
GPOs with version mismatches are returned.

.DESCRIPTION

GPO processing on client side will break if any GPO to process has a version mismatch between AD and sysvol.
This mismatch is usually a result of either replication errors or of simultaneous GPO editing on different
Domain Controllers.

GPMC will by default connect to AD on the PDC emulator, but sysvol activities will pick a random sysvol replica
(site aware if DFS is used for replication). In addition, AD and sysvol replication latency are different.

Imagine the following scenario:

2 Administrators are editing the same policy (all versions zero) at almost the same time, where one admin has a
sysvol connection to DC 1 and the other has a connection to a different DC 2. Admin 1 edits and commits a write
to the policy. AD and sysvol versions are updated to 1, both on the PDC. AD replication occurs at some point in
time. Now Admin 2 edits and commits the next write. AD is already replicated, so AD version is updated from 1 to 2.
Sysvol replication is outstanding, so sysvol version is updated from 0 to 1. Sysvol replication resolves write
conflicts with "last writer wins", so after both AD and sysvol replication, the GPO now has AD version 2 and
sysvol version 1.

DYNAMIC PARAMETERS

-TargetDomain <String>
    The domain where the operation should be performed. Defaults to the current user's domain.
    Tab completion searches through the list of possible target domains (trusting domains).

    Required?                    True
    Default value                None
    Accept pipeline input?       False
    Accept wildcard characters?  False

.PARAMETER GPObject

Use this parameter if you want to pipe a GPO object from Get-GPO to this cmdlet.
You can also use this to first examine all version mismatches ($errorGPOs = Get-GPVersionMismatch -PassThru)
and then repair them ($errorGPOs | Get-GPVersionMismatch -Repair)

.PARAMETER GPOName

Use this parameter to verify specific GPOs by name. You can specify the full name for a single GPO
or - with the -regex switch - a regex pattern for multiple GPOs.

.PARAMETER Regex

If this switch is present, the GPOName is evaluated as a regex pattern. If ommitted, it is evaluated
as the exact name of an existing GPO.

.PARAMETER GPOID

Use this parameter to verify a single GPO by GUID.

.PARAMETER ServerNamePattern

Regular expression to filter for specific servers in the target domain. By default, GPOs are verified on
all servers in the domain.

.PARAMETER PdcOnly

By default, this cmdlet will verify GPOs on all servers in the domain or on a selected subset selected
with ServerNamePattern. Use this switch to verify GPOs only on the PDC emulator.

.PARAMETER Repair

If version mismatches are found, a random registry value is added and removed. This usually fixes the version
mismatch. It also will increase the AD version by 2 (1 on adding, 1 on removing).

This repair is only attempted if the GPO has a version mismatch on the PDC emulator. All mismatches that are
only found on other servers are usually a result of replication errors in AD or Sysvol. These replication
errors can NOT be fixed with this cmdlet, you have to repair them on your own.

.PARAMETER PassThru

Return the collection of GP objects that have a version mismatch. By default, this cmdlet does not return anything.

.INPUTS

[[Microsoft.GroupPolicy.GPMGPO]]

.OUTPUTS

[[Microsoft.GroupPolicy.GPMGPO]]

.EXAMPLE

Get-GPVersionMismatch -Domain corp.contoso.com

Gets all GPOs in the corp.contos.com domain and returns all GPOs with version mismatches.

.EXAMPLE

Get-GPVersionMismatch -Domain corp.contoso.com -Name "Default Domain Policy" -Repair

Gets the "Default Domain Policy" in the corp.contoso.com domain and checks it for a version mismatch. If a mismatch is found, a random registry value is added to administrative templates and removed immediately.

.NOTES

#>

function Get-GPVersionMismatch
{
    [CmdletBinding( SupportsShouldProcess = $True, DefaultParameterSetName = 'GpoByName' )]
    [Alias()]
    [OutputType([Microsoft.GroupPolicy.Gpo])]
    Param
    (
        [Parameter( ParameterSetName = 'GPObject', ValueFromPipeline = $True )]
        [Microsoft.GroupPolicy.Gpo]
        $GPObject,
        [Parameter( ParameterSetName = 'GpoByName' )]
        [String]
        $GPOName,
        [Parameter( ParameterSetName = 'GpoByName' )]
        [Switch]
        $Regex,
        [Parameter( ParameterSetName = 'GpoByID' )]
        [System.Guid]
        $GPOID,
        [Parameter()][String]$ServerNamePattern,
        [Parameter()][Switch]$PdcOnly,
        [Parameter()][Switch]$Repair,
        [Parameter()][Switch]$PassThru
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
                Name = 'TargetDomain'
                # ValidateCount = @( [int]Min, [int]Max )
                # ValidateLenght = @( [int]Min, [int]Max )
                # ValidateRange = @( [int]Min, [int]Max )
                # ValidateSet = @( 'a', 'b', 'c' )
                ValidateSet = $DomainArray
                DefaultValue = $env:USERDNSDOMAIN
                ParameterAttributes = @(
                    @{
                        # ParameterSetName = 'a'
                        # Mandatory = $True
                        # ValueFromPipeline = $True
                        # ValueFromPipelineByPropertyName = $True
                        Mandatory = $False
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

        If ( -not $TargetDomain ) { $TargetDomain = $env:USERDNSDOMAIN }

        $Domain    = Get-ADDomain -Identity $TargetDomain
        $DomainDN  = $Domain.DistinguishedName
        $DomainDNS = $Domain.DNSRoot
        $PDC       = $Domain.PDCEmulator

    }

    Process {
        $ErrorGPOs = New-Object -TypeName System.Collections.ArrayList

        Write-Verbose -Message "Enumerating servers in domain $DomainDNS..."
        
        If ( $PdcOnly ) {
            $Servers = @( $PDC )
        } Else {
            $Servers = $Domain.ReplicaDirectoryServers.Value
            If ( $Domain.ReadOnlyReplicaDirectoryServers.Count -gt 0 ) { $Servers += $Domain.ReadOnlyReplicaDirectoryServers.Value }
            If ( $ServerNamePattern ) {
                $Servers = $Servers | Where-Object { $_ -match $ServerNamePattern }
            }
        }
        Write-Verbose -Message "Processing $( $Servers.Count ) servers in domain $DomainDNS."

        $Counter = 0
        Foreach ( $Server in $Servers ) {
            $Counter += 1
            $ActivityParms = @{
                Activity = 'Processing servers in domain {2} ({0}/{1})' -f $Counter, $Servers.Count, $DomainDNS
                Status = "Retrieving GPOs from $Server"
                PercentComplete = ( $Counter - 1 ) * 100 / $Servers.Count
            }
            Write-Progress @ActivityParms -Id 0 

            $ErrorGPOsOnCurrentServer = 0
            $GPParms = @{
                Server = $Server
                Domain = $DomainDNS
            }

            $ProcessingTime = ( Measure-Command {
                If ( $PSCmdlet.ParameterSetName -eq 'GPObject' ){
                    Write-Verbose -Message "Retrieving GPO from server $Server by object"
                    [array]$GPOs = @( ( Get-GPO -Name $GPObject.Name @GPParms ) )
                } ElseIf ( $PSCmdlet.ParameterSetName -eq 'GpoById') {
                    Write-Verbose -Message "Retrieving GPO from server $Server by GUID"
                    [array]$GPOs = @( ( Get-GPO -Guid $GPOID @GPParms ) )
                } ElseIf ( $PSCmdlet.ParameterSetName -eq 'GpoByName' -and $GPOName -and -not $Regex.IsPresent ) {
                    Write-Verbose -Message "Retrieving GPO from server $Server by name"
                    [array]$GPOs = @( ( Get-GPO -Name $GPOName @GPParms ) )
                } Else {
                    Write-Verbose -Message "Retrieving all GPOs from server $Server"
                    [array]$GPOs = @( ( Get-GPO -All @GPParms ) ) | Select-Object -Property * 
                    If ( $PSCmdlet.ParameterSetName -eq 'GpoByName' -and $Regex.IsPresent ){
                        Write-Verbose -Message "Filtering GPO names by regex $GPOName"
                        [array]$GPOs = $GPOs | Where-Object { $_.DisplayName -match $GPOName }
                    }
                }
            } ).TotalSeconds
            Write-Verbose "Found $( $GPOs.Count ) GPOs in $( $ProcessingTime.ToString( '0.##' ) ) seconds."

            $ActivityParms = @{
                Activity = 'Processing servers in domain {2} ({0}/{1})' -f $Counter, $Servers.Count, $DomainDNS
                Status = "Checking version mismatch GPOs on $Server"
                PercentComplete = ( $Counter - 1 ) * 100 / $Servers.Count
            }
            Write-Progress @ActivityParms -Id 0 

            $ProcessingTime = ( Measure-Command {
                $Counter2 = 0
                Foreach ( $GPO  in $GPOs ) {
                    $Counter2 += 1
                    $ActivityParms = @{
                        Activity = 'Processing GPOs on server {2} ({0}/{1})' -f $Counter2, $GPOs.Count, $Server
                        Status = $GPO.DisplayName
                        PercentComplete = ( $Counter2 - 1 ) * 100 / $GPOs.Count
                    }
                    Write-Progress @ActivityParms -Id 1 -ParentId 0

                    If ( $GPO.User.DSVersion -ne $GPO.User.SysvolVersion -or $GPO.Computer.DSVersion -ne $GPO.Computer.SysvolVersion ) {
                        $ErrorGPOsOnCurrentServer += 1
                        Add-Member -InputObject $GPO -MemberType NoteProperty -Name 'Server' -Value $Server
                        [void]$ErrorGPOs.Add( $GPO )
                    }
                }
            } ).TotalSeconds
            Write-Verbose "Checked $( $GPOs.Count ) GPOs for version mismatch in $( $ProcessingTime.ToString( '0.##' ) ) seconds."
            If ( $ErrorGPOsOnCurrentServer ) {
                Write-Warning -Message "Found $ErrorGPOsOnCurrentServer version mismatches on $Server."
            }

            Write-Progress -Activity ( 'Processing GPOs on server {0}' -f $Server ) -Id 1 -ParentId 0 -PercentComplete 100 -Completed

        }

        Write-Progress -Activity ( 'Processing Servers in domain {0}' -f $DomainDNS ) -Id 0 -PercentComplete 100 -Completed

        Write-Verbose -Message "Number of Errors found: $( $ErrorGPOs.Count )"

        If ( $Repair.IsPresent ) {
            Write-Verbose -Message "Trying to repair version mismatch GPOs on PDCe $PDC."
            $GPParms = @{
                Server = $PDC
                Domain = $DomainDNS
            }

            $Counter = 0
            Foreach ( $ErrorGPO in $ErrorGPOs | Where-Object { $_.Server -eq $PDC }) {
                $Counter += 1
                $ActivityParms = @{
                    Activity = 'Trying to repair version mismatch GPOs on PDCe {2} ({0}/{1})' -f $Counter, $ErrorGPOs.Count, $PDC
                    Status = $ErrorGPO.DisplayName
                    PercentComplete = ( $Counter - 1 ) * 100 / $ErrorGPOs.Count
                }
                Write-Progress @ActivityParms -Id 0 

                If ( $ErrorGPO.Computer.DSVersion -ne $ErrorGPO.Computer.SysvolVersion ) {
                        Write-Verbose -Message "Repairing $( $ErrorGPO.DisplayName ) computer version mismatch..."
                        $null = Set-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKLM\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" -Value 1 -Type DWord @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                        $null = Remove-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKLM\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                }
                If ( $ErrorGPO.User.DSVersion -ne $ErrorGPO.User.SysvolVersion ) {
                        Write-Verbose -Message "Repairing $( $ErrorGPO.DisplayName ) user version mismatch..."
                        $null = Set-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKCU\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" -Value 1 -Type DWord @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                        $null = Remove-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKCU\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                }


            }

            Write-Progress -Activity ( 'Processing version mismatch GPOs in domain {0}' -f $DomainDNS ) -Id 0 -PercentComplete 100 -Completed
        }
    }

    End {

        If ( $PassThru.IsPresent ) { $ErrorGPOs }

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

        [Parameter()][ValidateNotNullOrEmpty()]
        [String] $DefaultValue,

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
    If ( $DefaultValue.IsPresent ){
        $RuntimeParam.Value = $DefaultValue
    }

    Return $RuntimeParam
	
}

