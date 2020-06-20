<a name="Get-UnlinkedGPOs"></a>
## Get-UnlinkedGPOs
### Synopsis
Retrieves all GPOs in a domain. For each GPO, it determines whether the GPO is linked to any OU. All unlinked GPOs are returned.
### Description
For housekeeping reasons, you might want to get rid of GPOs that do not apply to anything. This includes unlinked GPOs as well as GPOs that have disabled links only or where both computer and user part are disabled.

The Get-UnlinkedGPOs function searches a domain for these GPOs and returns the resulting GPO objects. It also adds 3 boolean properties to each returned GPO:

##### $GPO.Unlinked
The GPO is selected because it is not linked at all

##### $GPO.AllLinksDisabled
The GPO is selected because it has links, but all of these links are disabled

##### $GPO.AllSettingsDisabled
The GPO is selected because all settings are disabled. Already contained in $GPO.GPOStatus, but for convenience.

### Dynamic Parameters
#### Domain [&lt;String&gt;]
    The domain where the operation should be performed. This must the user's current domain or a trusting domain. Tab completion searches through the list of possible target domains.

    Required?                    true
    Position?                    1
    Default value                False
    Accept pipeline input?       false
    Accept wildcard characters?  false

### Syntax
```powershell
Get-UnlinkedGPOs -Domain <string> [-IncludeDisabledLinks] [-IncludeDisabledGPOs] [<CommonParameters>]
```
### Parameters
#### IncludeDisabledLinks [&lt;SwitchParameter&gt;]
    By default, only GPOs are returned that have no links at all. Use this switch to also return all GPOs that have no enabled links (all links are disabled).
    
    Required?                    false
    Position?                    named
    Default value                False
    Accept pipeline input?       false
    Accept wildcard characters?  false
#### IncludeDisabledGPOs [&lt;SwitchParameter&gt;]
    By default, only GPOs are returned that have no links at all. Use this switch to also return all GPOs where all settings are disabled (both user and computer settings).
    
    Required?                    false
    Position?                    named
    Default value                False
    Accept pipeline input?       false
    Accept wildcard characters?  false
### Examples
#### Example 1 
```powershell
Get-UnlinkedGPOs -Domain corp.contoso.com

```

Gets all unlinked GPOs in the corp.contoso.com domain.
#### Example 2 
```powershell
Get-UnlinkedGPOs -Domain corp.contoso.com -IncludeDisabledLinks | Remove-GPO -Confirm:$False

```

Gets all unlinked GPOs including those with disabled links and pipes them to Remove-GPO for instant deletion (not recommended to use in the first place).
<div style='font-size:small; color: #ccc'>Generated 20-06-2020 13:19</div>
