# UpdateInstalledModule

## Index

| Command | Synopsis |
| ------- | -------- |
| [Update-InstalledModule](#Update-InstalledModule) | This function updates one or more modules that were installed from the PowerShell gallery if newer versions are available. It accepts pipeline input for the module name as well as an array of names.  It wraps the PowerShellGet function Update-Module and works way faster. |
| [Get-PublishedModuleVersion](#Get-PublishedModuleVersion) | Takes a module name and searches the Powershell gallery for its current version number. It accepts pipeline input for the module name. Matches are returned as custom objects with a Name and a Version property. |

<a name="Update-InstalledModule"></a>
## Update-InstalledModule
### Synopsis
This function updates one or more modules that were installed from the PowerShell gallery if newer versions are available. It accepts pipeline input for the module name as well as an array of names.

It wraps the PowerShellGet function Update-Module and works way faster.
### Description
Updating modules from the Powershell Gallery can be done via calling Update-Module. This can even be used in a pipeline with Get-InstalledModule | Update-Module. But that's a quite slow command - so this workaround was created. Update-InstalledModule checks the module's download URL for the most current version number, and it calls the original Update-Module only if the local version is older.

For modules that are installed for all users, it obviously requires an elevated session to work - unlike the original Update-Module function, this wrapper does not check where the module is installed and whether admin rights are required or not.

The main reason for the original Update-Module slowness are its connectivity checks to various web sites via ping or http get requests. The helper function Get-PublishedModuleVersion omits all of these checks and only sends a single http get. The response is then parsed for the location which contains the version number. This check is performed for all modules passed in, and finally all modules that need to be updated are passed to Update-Module.

### Syntax
```powershell
Update-InstalledModule [[-Name] <string[]>] [-Scope <string>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```
### Parameters
#### Name &lt;String[]&gt;
    The name of the module(s) to update. Can also be a module object returned from Get-Module or Get-InstalledModule. If the module name is omitted, all installed modules are checked.
    
    Erforderlich?                false
    Position?                    1
    Standardwert                 
    Pipelineeingaben akzeptieren?true (ByPropertyName)
    Platzhalterzeichen akzeptieren?false
#### Scope &lt;String&gt;
    
    Erforderlich?                false
    Position?                    named
    Standardwert                 
    Pipelineeingaben akzeptieren?false
    Platzhalterzeichen akzeptieren?false
#### Force [&lt;SwitchParameter&gt;]
    Updates the module even if the currently installed version is up to date.
    
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
Update-InstalledModule

```
Checks if newer versions for any installed module are available.
#### BEISPIEL 2 
```powershell
Update-InstalledModule Foo -Force

```
Updates the module Foo regardless of the current version.
#### BEISPIEL 3 
```powershell
Update-InstalledModule -Name ScriptCop,EzOut

```
Checks if newer versions are available for ScriptCop and EzOut.
<a name="Get-PublishedModuleVersion"></a>
## Get-PublishedModuleVersion
### Synopsis
Takes a module name and searches the Powershell gallery for its current version number. It accepts pipeline input for the module name. Matches are returned as custom objects with a Name and a Version property.
### Description
When using Get-InstalledModule | Update-Module, this takes a long time. So some smart people on the web thought about how to improve this process.
The result is impressing - fetching the version number from the Powershell gallery location for a module is a huge improvement over relying on Update-Module to detect the version numbers on its own.
The function was originally published by Tobias Weltner from powertheshell.com - credits to him! His function is based on an approach that ScriptingFee developed - credits to her, too. See the related links for more information about the evolvment of the idea.

### Syntax
```powershell
Get-PublishedModuleVersion [-Name] <string[]> [<CommonParameters>]
```
### Parameters
#### Name &lt;String[]&gt;
    Specifies one or more module names to search the current version for. Can also be a module object as retrieved from Get-Module or Get-InstalledModule.
    
    Erforderlich?                true
    Position?                    1
    Standardwert                 
    Pipelineeingaben akzeptieren?true (ByPropertyName)
    Platzhalterzeichen akzeptieren?false
### Examples
#### BEISPIEL 1 
```powershell
Get-PublishedModuleVersion -Name IseSteroids

```
Searches for the IseSteroids version in the Powershell gallery and returns its version number.
#### BEISPIEL 2 
```powershell
Get-InstalledModule | Get-PublishedModuleVersion

```
Searches for all modules that were installed from the gallery and returns their version numbers.
<div style='font-size:small; color: #ccc'>Generated 13-10-2020 13:18</div>
