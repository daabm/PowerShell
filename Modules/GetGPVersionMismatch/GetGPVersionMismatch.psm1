<#
.SYNOPSIS

Retrieves GPOs in a domain. For each GPO, it determines user and computer versions in AD and sysvol.
GPOs with version mismatches are output or returned.

.DESCRIPTION

GPO processing on client side will break if any GPO to process has a version mismatch between AD and sysvol.
This mismatch is usually a result of either replication errors or of simultaneous GPO editing on different
Domain Controllers.

GPMC will by default connect to AD on the PDC emulator, but sysvol activities will pick a random sysvol replica
(site aware if DFS is used for replication). In addition, AD and sysvol replication latency are different.

If you store the results in an array variable, you can pipe this variable to the Get-GPVersionMismatch function.
For this to work, GPOID has an alias "ID", and GPONAME has an alias "DisplayName".

DYNAMIC PARAMETERS

-TargetDomain <String>
    The domain where the operation should be performed. Defaults to the current user's domain.
    Tab completion searches through the list of possible target domains (trusting domains).

    Required?                    True
    Default value                None
    Accept pipeline input?       False
    Accept wildcard characters?  False

.PARAMETER GPOID

Use this parameter to verify a single GPO by GUID. You can also use its alias -ID.

.PARAMETER GPOName

Use this parameter to verify specific GPOs by name. You can specify the full name for a single GPO
or - with the -regex switch - a regex pattern for multiple GPOs. You can also use its alias -DisplayName.

.PARAMETER Regex

If this switch is present, the GPOName is evaluated as a regex pattern. If ommitted, it is evaluated
as the exact name of an existing GPO.

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

.EXAMPLE

Get-GPVersionMismatch -Domain corp.contoso.com

Gets all GPOs in the corp.contos.com domain and returns all GPOs with version mismatches.

.EXAMPLE

Get-GPVersionMismatch -Domain corp.contoso.com -Name "Default Domain Policy" -Repair

Gets the "Default Domain Policy" in the corp.contoso.com domain and checks it for a version mismatch. If a mismatch is found, a random registry value is added to administrative templates and removed immediately.

.EXAMPLE

$ErrorGPOs = Get-GPVersionMismatch -PDCOnly

Checks all GPOs in the current user's domain and stores the results in $ErrorGPOs. You can then examine the results and act properly.

.EXAMPLE

$ErrorGPOs | Get-GPVersionMismatch -Repair

Takes the results from the previous example and tries to repair the GPOs.

.NOTES

#>

function Get-GPVersionMismatch {

    [CmdletBinding( SupportsShouldProcess = $True, DefaultParameterSetName = 'GpoByName' )]
    [Alias()]
    [OutputType([Microsoft.GroupPolicy.Gpo])]
    Param (
        [Parameter( ParameterSetName = 'GpoByID', ValueFromPipelineByPropertyName = $true )]
        [Alias( 'ID' )]
        [System.Guid]
        $GPOID,
        [Parameter( ParameterSetName = 'GpoByName', ValueFromPipelineByPropertyName = $true )]
        [Alias( 'DisplayName' )]
        [String]
        $GPOName,
        [Parameter( ParameterSetName = 'GpoByName' )]
        [Switch]
        $Regex,
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

        Write-Verbose "Enumerating servers in domain $DomainDNS..."
        
        If ( $PdcOnly ) {
            $Servers = @( $PDC )
        } Else {
            $Servers = $Domain.ReplicaDirectoryServers.Value
            If ( $Domain.ReadOnlyReplicaDirectoryServers.Count -gt 0 ) { $Servers += $Domain.ReadOnlyReplicaDirectoryServers.Value }
            If ( $ServerNamePattern ) {
                $Servers = $Servers | Where-Object { $_ -match $ServerNamePattern }
            }
        }
        $TargetServers = [Collections.ArrayList]::new()
        Foreach ( $Server in $Servers | Sort-Object ) {
            [void] $TargetServers.Add( [PSCustomObject]@{
                Name = $Server
                Domain = $DomainDNS
                GetGPOJob = $null
            } )
        }
        Write-Verbose "Processing $( $TargetServers.Count ) servers in domain $DomainDNS."

        $ScriptBlockRetrieveGPOs = {
            $Server = $args[0]
            $GetGpoCommand = $args[1]
            $Results = $args[2]

            $GPOs = Invoke-Expression $GetGpoCommand

            Foreach ( $GPO  in $GPOs ) {
                If ( $GPO.User.DSVersion -ne $GPO.User.SysvolVersion -or $GPO.Computer.DSVersion -ne $GPO.Computer.SysvolVersion ) {
                    Add-Member -InputObject $GPO -NotePropertyMembers @{
                        Server = $Server
                        UserAD = $GPO.User.DSVersion
                        UserSysvol = $GPO.User.SysvolVersion
                        ComputerAD = $GPO.Computer.DSVersion
                        ComputerSysvol = $GPO.Computer.SysvolVersion
                    }
                    [void]$Results.Add( ( $GPO | Select-Object -Property * ) )
                }
            }
        }

        Function New-RunspaceJob {
            [CmdletBinding()]
            Param(
                [Management.Automation.Runspaces.RunspacePool] $Pool,
                [String] $ScriptBlock,
                [Array] $Arguments
            )
            $Job = [PSCustomObject] @{ Powershell = $null; AsyncResult = $null }
            $Job.Powershell = [Powershell]::Create().AddScript( $ScriptBlock )
            Foreach ( $Argument in $Arguments ) {
                [void] $Job.Powershell.AddArgument( $Argument )
            }
            $Job.Powershell.RunspacePool = $Pool
            $Job.AsyncResult = $Job.Powershell.BeginInvoke()
            Return $Job
        }

        # Initialize RunspacePool
        $RunspacePool = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool( 16, 256 )
        $RunspacePool.ThreadOptions = [Management.Automation.Runspaces.PSThreadOptions]::Default
        $RunspacePool.ApartmentState = [Threading.ApartmentState]::MTA
        $RunspacePool.Open()

        $ErrorGPOs = [Collections.Arraylist]::Synchronized( [Collections.Arraylist]::new() )
        # [Collections.ArrayList]::new()
    }

    Process {

        Foreach ( $Server in $TargetServers ) {

            If ( $PSCmdlet.ParameterSetName -eq 'GPObject' ){

                Write-Verbose "Preparing to retrieve GPOs from server $( $Server.Name ) by object"
                $GetGpoCommand = "Get-GPO -Name $( $GPObject.Name ) -Server $( $Server.Name ) -Domain $( $Server.Domain )"

            } ElseIf ( $PSCmdlet.ParameterSetName -eq 'GpoById') {

                Write-Verbose "Preparing to retrieve GPOs from server $( $Server.Name ) by GUID"
                $GetGpoCommand = "Get-GPO -Guid $GPOID -Server $( $Server.Name ) -Domain $( $Server.Domain )"

            } ElseIf ( $PSCmdlet.ParameterSetName -eq 'GpoByName' -and $GPOName -and -not $Regex.IsPresent ) {

                Write-Verbose "Preparing to retrieve GPOs from server $( $Server.Name ) by name"
                $GetGpoCommand = "Get-GPO -Name $GPOName -Server $( $Server.Name ) -Domain $( $Server.Domain )"

            } Else {

                Write-Verbose "Preparing to retrieve all GPOs from server $( $Server.Name )"
                $GetGpoCommand = "Get-GPO -All -Server $( $Server.Name ) -Domain $( $Server.Domain )" # | Select-Object -Property *"

                If ( $PSCmdlet.ParameterSetName -eq 'GpoByName' -and $Regex.IsPresent ){

                    Write-Verbose "Filtering GPO names by regex $GPOName"
                    $GetGpoCommand += ' | Where-Object { $_.DisplayName -match ' + $GPOName + ' }'
                }
            }
            Write-Verbose "Created GetGpoCommand: $GetGpoCommand"
            Write-Verbose "Detaching GPO search job for $( $Server.Name )..."

            $Server.GetGpoJob = New-RunspaceJob -Pool $RunspacePool -ScriptBlock $ScriptBlockRetrieveGPOs -Arguments @( $Server.Name, $GetGpoCommand, $ErrorGPOs )

        }

    }

    End {
        Write-Verbose "Collecting GPO search results..."
        Foreach ( $Server in $TargetServers ) {
            Write-Verbose "Collecting results from $( $Server.Name )"
            $null = $Server.GetGpoJob.Powershell.EndInvoke( $Server.GetGpoJob.AsyncResult )
        }

        Write-Verbose "Number of Errors found: $( $ErrorGPOs.Count )"

        If ( $Repair.IsPresent ) {
            Write-Verbose "Trying to repair version mismatches GPOs on PDCe $PDC."
            $GPParms = @{
                Server = $PDC
                Domain = $DomainDNS
            }

            Foreach ( $ErrorGPO in $ErrorGPOs | Where-Object { $_.Server -eq $PDC }) {
                If ( $ErrorGPO.ComputerAD -ne $ErrorGPO.ComputerSysvol ) {
                        Write-Verbose "Repairing $( $ErrorGPO.DisplayName ) computer version mismatch..."
                        $null = Set-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKLM\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" -Value 1 -Type DWord @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                        $null = Remove-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKLM\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                }
                If ( $ErrorGPO.UserAD -ne $ErrorGPO.UserSysvol ) {
                        Write-Verbose "Repairing $( $ErrorGPO.DisplayName ) user version mismatch..."
                        $null = Set-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKCU\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" -Value 1 -Type DWord @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                        $null = Remove-GPRegistryValue -Guid $ErrorGPO.ID -Key "HKCU\Software\FixGpoVersionMismatch" -ValueName "FixGPOVersions" @GPParms
                        Start-Sleep -Seconds 1 # allow changes to be committed in AD and Sysvol
                }
            }
        }

        $RunspacePool.Close()
        $RunspacePool.Dispose()

        If ( $PassThru ) { 
            $ErrorGPOs
        } Else {
            $ErrorGPOs | Format-Table -Property ID, DisplayName, Server, UserAD, UserSysvol, ComputerAD, ComputerSysvol
        }
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

