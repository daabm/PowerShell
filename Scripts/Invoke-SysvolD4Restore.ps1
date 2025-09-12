<#
.SYNOPSIS
Führt eine autorisierende Wiederherstellung von Sysvol durch, wenn mit DFSR repliziert wird. Das sind leider relativ viele Einzelschritte auf allen beteiligten DCs...

.DESCRIPTION
Nach Ermitteln aller Domain Controller inkl. PDC werden die von Microsoft dokumentierten Einzelschritte durchgefürt. Für den PDC wird dabei das korrekte Initialisieren der autorisierenden Wiederherstellung geprüft.

.LINK
DFSR authoritative restore - https://learn.microsoft.com/de-de/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization

#>

[CmdletBinding(SupportsShouldProcess=$true)]

Param(
    # Die Zieldomäne der Reparatur
    [Validatescript({ Get-ADDomain $_ })]
    [string] $TargetDomain = ( Get-AdDomain -Current LocalComputer )
)

$Domain = Get-ADDomain $TargetDomain
$DomainDN = $Domain.DistinguishedName
$SysvolDN = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings'

$DFSRSleep = 5
$ServiceProperties = @( 'MachineName', 'DisplayName', 'Status', 'StartType' )

$AllDCs = [Collections.Arraylist]::new()
Foreach ( $Computer in $Domain.ReplicaDirectoryServers ) {
    $DC = [PSCustomObject]@{
        HostName = $Computer
        SysvolDN = "$SysvolDN,CN=$( $Computer.Split( '.' )[0] ),OU=Domain Controllers,$DomainDN"
    }
    [void] $AllDCs.Add( $DC )

    # create extra object for PDC
    If ( $Computer -eq $Domain.PDCEmulator ) {
        $PDC = $DC
    }
}

Write-Host "Processing domain $( $Domain.DNSRoot ) - found domain controllers:"
$AllDCs | Select-Object -Property Hostname, @{ Name = 'IsPDC'; Expression = { $_ -eq $PDC }} | Out-String | Write-Host

#
#
Write-Host "Step 0: Checking prerequisites - DFSR management tools must be enabled on all DCs" -ForegroundColor Green
#

$Features = @( 'FS-DFS-Namespace', 'FS-DFS-Replication' )

Foreach ( $DC in $AllDCs ) {
    Write-Verbose "Checking feature states on $( $DC.HostName )..."
    $FeatureStates = Get-WindowsFeature -Name $Features -ComputerName $DC.HostName -Verbose:$false
    Foreach ( $FeatureState in $FeatureStates | Where-Object { -not $_.Installed } ) {
        Write-Warning "$( $DC.HostName ): Feature $( $FeatureState.Name ) missing, starting installation..."
        Install-WindowsFeature -Name $FeatureState.Name -ComputerName $DC.HostName
    }
}

#
#
Write-Host "Step 1: Set dfsr to manual mode and stop on all DCs" -ForegroundColor Green
#

Get-Service 'dfsr' -ComputerName $AllDCs.HostName | Stop-Service -PassThru | Select-Object -Property $ServiceProperties | Out-String | Write-Verbose
Set-Service 'dfsr' -StartupType Manual -ComputerName $AllDCs.HostName -PassThru | Select-Object -Property $ServiceProperties | Out-String | Write-Verbose

#
#
Write-Host "Step 2: Set PDC to authoritative (msDFSR-Options=1)" -ForegroundColor Green
#

Set-ADObject $PDC.SysvolDN -Replace @{ 'msDFSR-options' = 1 } -Server $PDC.HostName -PassThru | Write-Verbose

#
#
Write-Host "Step 3: Disable Sysvol replication" -ForegroundColor Green
#

Foreach ( $DC in $AllDCs ) {
    Set-ADObject $DC.SysvolDN -Replace @{ 'msDFSR-Enabled' = $false } -Server $PDC.HostName -PassThru | Write-Verbose
}

#
#
Write-Host "Step 4: Replicate AD objects from PDC to all other DCs" -ForegroundColor Green
#

# loop over each DC for its sysvol object
Foreach ( $ADObject in $AllDCs ) {
    # loop over each DC as a destination except PDC
    Foreach ( $DestinationDC in ( $AllDCs -ne $PDC )) {
        # sync all sysvol objects to the current DC
        Sync-ADObject -Object $ADObject.SysvolDN -Source $PDC.HostName -Destination $DestinationDC.HostName -PassThru | Write-Verbose
    }
}

#
#
Write-Host "Step 5: Start dfsr on authoritative PDC" -ForegroundColor Green
#

$Timestamp = Get-Date
Start-Sleep 2 # ensure Get-Eventlog -After works correctly...
Get-Service 'dfsr' -ComputerName $PDC.HostName | Start-Service -PassThru | Select-Object -Property $ServiceProperties | Out-String | Write-Verbose

#
#
Write-Host "Step 6: Check for event 4114 in DFSR event log on PDC" -ForegroundColor Green
#

If ( $PSCmdlet.ShouldProcess( $PDC.HostName, 'Wait for DFSR event 4114' )) {
    $DfsrSuccess = $false
    For ( $i = 0; $i -lt $DFSRSleep; $i++ ) {
        Start-Sleep 1
        $Events = Get-EventLog -LogName 'DFS Replication' -ComputerName $PDC.HostName -After $Timestamp | Where-Object { $_.EventID -eq 4114 }
        If ( $Events.Count -gt 0 ) {
            $DfsrSuccess = $true
            break
        }
    }
    If ( -not $DfsrSuccess ) {
        Throw "No event 4114 found on $( $pdc.HostName ) within $DFSRSleep seconds after starting dfsr service."
    }
}

#
#
Write-Host "Step 7: Set msDFSR-Enabled=TRUE on PDC" -ForegroundColor Green
#

Set-ADObject $PDC.SysvolDN -Replace @{ 'msDFSR-Enabled' = $true } -Server $PDC.HostName -PassThru | Write-Verbose

#
#
Write-Host "Step 8: Replicate from PDC to all other DCs" -ForegroundColor Green
#

Foreach ( $DestinationDC in ( $AllDCs -ne $PDC )) {
    Sync-ADObject -Object $PDC.SysvolDN -Source $PDC.HostName -Destination $DestinationDC.HostName -PassThru | Write-Verbose
}

#
#
Write-Host "Step 9: Poll AD on PDC" -ForegroundColor Green
#

$Timestamp = Get-Date
Start-Sleep 2
Update-DfsrConfigurationFromAD -ComputerName $PDC.HostName | Write-Host -ForegroundColor Yellow

#
#
Write-Host "Step 10: Check for event 4602 in DFSR event log on PDC" -ForegroundColor Green
#
If ( $PSCmdlet.ShouldProcess( $PDC.HostName, 'Wait for DFSR event 4602' )) {
    $DfsrSuccess = $false
    For ( $i = 0; $i -lt $DFSRSleep; $i++ ) {
        Start-Sleep 1
        $Events = Get-EventLog -LogName 'DFS Replication' -ComputerName $PDC.HostName -After $Timestamp | Where-Object { $_.EventID -eq 4602 }
        If ( $Events.Count -gt 0 ) {
            $DfsrSuccess = $true
            break
        }
    }
    If ( -not $DfsrSuccess ) {
        Throw "No event 4602 found on $( $PDC.HostName ) within $DFSRSleep seconds after starting dfsr service!"
    }
}

#
#
Write-Host "Step 11: start dfsr on all other DCs" -ForegroundColor Green
#

Get-Service 'dfsr' -ComputerName ( $AllDCs -ne $PDC ).HostName | Start-Service -PassThru | Select-Object -Property $ServiceProperties | Out-String | Write-Verbose

# sleep only, no sense in checking for event 4114 on additional DCs...
Write-Host "Sleeping $DFSRSleep seconds to allow dfsr to initialize properly..." -ForegroundColor Yellow
Start-Sleep -Seconds $DFSRSleep

#
#
Write-Host "Step 12: Set msDFSR-Enabled=TRUE on all other DCs and replicate to all DCs" -ForegroundColor Green
#

Foreach ( $ADObject in ( $AllDCs -ne $PDC )) {
    Set-ADObject $ADObject.SysvolDN -Replace @{ 'msDFSR-Enabled' = $true } -Server $PDC.HostName
    Foreach ( $DestinationDC in $AllDCs -ne $PDC ) {
        # sync current sysvol object to all other DCs
        Sync-ADObject -Object $ADObject.SysvolDN -Source $PDC.HostName -Destination $DestinationDC.HostName -PassThru | Write-Verbose
    }
}

#
#
Write-Host "Step 13: Poll AD on all other DCs" -ForegroundColor Green
#

Update-DfsrConfigurationFromAD -ComputerName ( $AllDCs -ne $PDC ).HostName | Write-Host -ForegroundColor Yellow

# again no sense in checking for any events. If it works - ok. If not - check and repeat...

#
#
Write-Host "Step 14: Set dfsr to automatic on all DCs" -ForegroundColor Green
#

Set-Service 'dfsr' -StartupType Automatic -ComputerName $AllDCs.HostName -PassThru | Select-Object -Property $ServiceProperties | Out-String | Write-Verbose
