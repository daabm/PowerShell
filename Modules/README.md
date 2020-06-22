# Module Overview

## AddGPLink

Updates GPO links on OUs in active directory. Takes a reference GPO whose links serve as a template, and a new GPO that is linked where the reference GPO is already linked. Optionally removes the link to the reference GPO.

## GetUnlinkedGPOs

Gets all unlinked GPOs in the targeted domain. Does not use the usual approach with Get-GPReport, because that is too slow in larger environments. Instead it crawls all GPLink attributes.

Sample results from a quite large environment - compare this to all solutions using Get-GPReport and be surprised  :smile:

```
VERBOSE: Retrieving GPOs...
VERBOSE: Found 8823 GPOs in 1.2907343 seconds.

VERBOSE: Retrieving GPLink SOMs...
VERBOSE: Found 4876 SOMs in 3.7403677 seconds.

VERBOSE: Preparing linked GPO hashtable...
VERBOSE: GPO hashtable containing 8110 GUIDs prepared in 1.1557533 seconds.

VERBOSE: Processing 8823 GPOs...
VERBOSE: 8823 GPOs processed in 5.1660301 seconds.

VERBOSE: 721 unlinked GPOs found.
```

That's about 10 seconds to get more than 700 unlinked GPOs in a domain with almost 9k GPOs and about 5k OUs with linked GPOs... Creating a single GPO report usually takes about 7 seconds and more, so as soon as you have more than 1 GPO in your domain, this module will outperform all others that I'm aware of.

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
