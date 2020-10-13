# Get-GPVersionMismatch

PowerShell module for maintenance of GPO version conflicts in AD and sysvol

<a name="Get-GPVersionMismatch"></a>
## Get-GPVersionMismatch
### Synopsis
Retrieves GPOs in a domain. For each GPO, it determines user and computer versions in AD and sysvol.
GPOs with version mismatches are returned.
### Description
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

### Syntax
```powershell
Get-GPVersionMismatch [-GPOName <string>] [-Regex] [-ServerNamePattern <string>] [-PdcOnly] [-Repair] [-PassThru] [-WhatIf] [-Confirm] [-TargetDomain <string>] [<CommonParameters>]

Get-GPVersionMismatch [-GPObject <Gpo>] [-ServerNamePattern <string>] [-PdcOnly] [-Repair] [-PassThru] [-WhatIf] [-Confirm] [-TargetDomain <string>] [<CommonParameters>]

Get-GPVersionMismatch [-GPOID <guid>] [-ServerNamePattern <string>] [-PdcOnly] [-Repair] [-PassThru] [-WhatIf] [-Confirm] [-TargetDomain <string>] [<CommonParameters>]
```
### Output Type(s)

- Microsoft.GroupPolicy.Gpo

### Parameters
#### GPObject &lt;Gpo&gt;
    Use this parameter if you want to pipe a GPO object from Get-GPO to this cmdlet.
    You can also use this to first examine all version mismatches ($errorGPOs = Get-GPVersionMismatch -PassThru)
    and then repair them ($errorGPOs | Get-GPVersionMismatch -Repair)
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?true (ByValue)
    Platzhalterzeichen akzeptieren?false
#### GPOName &lt;String&gt;
    Use this parameter to verify specific GPOs by name. You can specify the full name for a single GPO
    or - with the -regex switch - a regex pattern for multiple GPOs.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Regex [&lt;SwitchParameter&gt;]
    If this switch is present, the GPOName is evaluated as a regex pattern. If ommitted, it is evaluated
    as the exact name of an existing GPO.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### GPOID &lt;Guid&gt;
    Use this parameter to verify a single GPO by GUID.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### ServerNamePattern &lt;String&gt;
    Regular expression to filter for specific servers in the target domain. By default, GPOs are verified on
    all servers in the domain.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### PdcOnly [&lt;SwitchParameter&gt;]
    By default, this cmdlet will verify GPOs on all servers in the domain or on a selected subset selected
    with ServerNamePattern. Use this switch to verify GPOs only on the PDC emulator.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Repair [&lt;SwitchParameter&gt;]
    If version mismatches are found, a random registry value is added and removed. This usually fixes the version
    mismatch. It also will increase the AD version by 2 (1 on adding, 1 on removing).
    
    This repair is only attempted if the GPO has a version mismatch on the PDC emulator. All mismatches that are
    only found on other servers are usually a result of replication errors in AD or Sysvol. These replication
    errors can NOT be fixed with this cmdlet, you have to repair them on your own.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### PassThru [&lt;SwitchParameter&gt;]
    Return the collection of GP objects that have a version mismatch. By default, this cmdlet does not return anything.
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 False
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### WhatIf [&lt;SwitchParameter&gt;]
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Confirm [&lt;SwitchParameter&gt;]
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
### Examples
#### BEISPIEL 1 
```powershell
Get-GPVersionMismatch -Domain corp.contoso.com

```
Gets all GPOs in the corp.contos.com domain and returns all GPOs with version mismatches.
#### BEISPIEL 2 
```powershell
Get-GPVersionMismatch -Domain corp.contoso.com -Name "Default Domain Policy" -Repair

```
Gets the "Default Domain Policy" in the corp.contoso.com domain and checks it for a version mismatch. If a mismatch is found, a random registry value is added to administrative templates and removed immediately.
<div style='font-size:small; color: #ccc'>Generated 13-10-2020 12:47</div>
