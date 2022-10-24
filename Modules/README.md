## Add-GPLink
### Synopsis
Links a new GPO to all OUs where a given GPO is already linked. Optionally removes the given GPO. Does not process GPOs linked to sites or the domain itself.
### Description
Sometimes, new GPOs need to be deployed everywhere a given GPO is already in use. Or a given GPO needs to be replaced globally after testing.

The Append-GPLink function takes a reference GPO and a new GPO (both must already exist). Then it enumerates the OUs where the reference GPO is linked. It then links the new GPO to these OUs (bottom most link order by default). Link order and link properties can be modified.

## Copy-GPOLinks
### Synopsis
Copies the GPLink attribute from a specified source OU to a target OU in the same domain. Optionally appends or prepends to existing GPO links and recurses through child OUs.
### Description
When staging environments in a single AD, it is common to create a new identical OU structure for testing purposes. This structure should match the original one, including all child OUs and their linked GPOs. Copy-GPOLinks copies all linked GPOs from a source OU to a target OU in a given domain. Optionally, it recurses through child OUs and copies their GPOs, too. It also can create missing target child OUs automatically.

Note: By default, Copy-GPOLinks will not produce any screen output. If you want on-screen information, run it -verbose. If you need logging, intercept output streams or pipe to a file.

## Add-CopyScriptToISEMenu
### Synopsis
Adds 2 menu entries to the ISE Add-Ons menu.
Copy Script to Clipboard: Copies the entire script in the current ISE tab to the clipboard.
Copy Selection to Clipboard (Ctrl-Shift-C): Copies the current selection in the current ISE tab to the clipboard.
Function is called automatically during module import.

## Get-GPVersionMismatch
### Synopsis
Retrieves GPOs in a domain. For each GPO, it determines user and computer versions in AD and sysvol.
GPOs with version mismatches are output or returned.
### Description
GPO processing on client side will break if any GPO to process has a version mismatch between AD and sysvol.
This mismatch is usually a result of either replication errors or of simultaneous GPO editing on different
Domain Controllers.

GPMC will by default connect to AD on the PDC emulator, but sysvol activities will pick a random sysvol replica
(site aware if DFS is used for replication). In addition, AD and sysvol replication latency are different.

If you store the results in an array variable, you can pipe this variable to the Get-GPVersionMismatch function.
For this to work, GPOID has an alias "ID", and GPONAME has an alias "DisplayName".

## Get-UnlinkedGPOs
### Synopsis
Retrieves all GPOs in a domain. For each GPO, it determines whether the GPO is linked to any OU. All unlinked GPOs are returned.
### Description
For housekeeping reasons, you might want to get rid of GPOs that do not apply to anything. This includes unlinked GPOs as well as GPOs that have disabled links only or where both computer and user part are disabled.

The Get-UnlinkedGPOs function searches a domain for these GPOs and returns the resulting GPO objects. It also adds 3 boolean properties to each returned GPO:
$GPO.Unlinked: The GPO is selected because it is not linked at all
$GPO.AllLinksDisabled: The GPO is selected because it has links, but all of these links are disabled
$GPO.AllSettingsDisabled: The GPO is selected because all settings are disabled. Already contained in $GPO.GPOStatus, but for convenience.

## Update-InstalledModule
### Synopsis
This function updates one or more modules that were installed from the PowerShell gallery if newer versions are available. It accepts pipeline input for the module name as well as an array of names.

It wraps the PowerShellGet function Update-Module and works way faster.
