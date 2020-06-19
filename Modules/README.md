# Module Overview

## AddGPLink

Updates GPO links on OUs in active directory. Takes a reference GPO whose links serve as a template, and a new GPO that is linked where the reference GPO is already linked. Optionally removes the link to the reference GPO.

## GetUnlinkedGPOs

Gets all unlinked GPOs in the targeted domain. Does not use the usual approach with Get-GPReport, because that is too slow in larger environments. Instead it crawls all GPLink attributes.'

## UpdateInstalledModule

Updates a module from the Powershell Gallery if a newer version is available. Wraps the PowerShellGet function Update-Module and is much faster.
This module exports 2 functions: Get-PublishedModuleVersion and Update-InstalledModule.
Get-PublishedModuleVersion checks the most recent version of a module in the Powershell gallery. It is based on ideas from Tobias Weltner (powertheshell.com) and scriptingfee.de
Update-InstalledModule uses this version check to prepare a list of modules that are outdated. This list then is passed on to the original Update-Module function. If there are no outdated modules found, Update-Module is not called at all.
The fast check for outdated versions makes it easy to include an update check in your profile script. Simply add the following lines to your profile:
```
Try { Import-Module -Name UpdateInstalledModule; Update-InstalledModule }
Catch { $_ }
```
